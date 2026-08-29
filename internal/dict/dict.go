// Package dict 管理端点探测字典：内置默认字典 + 用户自定义字典文件。
// 支持三种模式：默认字典、-d 合并自定义、-D 仅用自定义。
package dict

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

// defaultEndpoints 为 v1 内置探测路径，运行时去重后作为默认字典。
var defaultEndpoints = []string{
	"api-docs",
	"actuator",
	"actuator/./env",
	"actuator/auditLog",
	"actuator/auditevents",
	"actuator/autoconfig",
	"actuator/beans",
	"actuator/caches",
	"actuator/conditions",
	"actuator/configurationMetadata",
	"actuator/configprops",
	"actuator/dump",
	"actuator/env",
	"actuator/events",
	"actuator/exportRegisteredServices",
	"actuator/features",
	"actuator/flyway",
	"actuator/health",
	"actuator/healthcheck",
	"actuator/httptrace",
	"actuator/hystrix.stream",
	"actuator/info",
	"actuator/integrationgraph",
	"actuator/jolokia",
	"actuator/logfile",
	"actuator/loggers",
	"actuator/loggingConfig",
	"actuator/liquibase",
	"actuator/metrics",
	"actuator/mappings",
	"actuator/scheduledtasks",
	"actuator/swagger-ui.html",
	"actuator/prometheus",
	"actuator/refresh",
	"actuator/registeredServices",
	"actuator/releaseAttributes",
	"actuator/resolveAttributes",
	"actuator/sessions",
	"actuator/springWebflow",
	"actuator/sso",
	"actuator/ssoSessions",
	"actuator/statistics",
	"actuator/status",
	"actuator/threaddump",
	"actuator/trace",
	"actuator/env.css",
	"artemis-portal/artemis/env",
	"artemis/api",
	"artemis/api/env",
	"auditevents",
	"autoconfig",
	"api",
	"api.html",
	"api/actuator",
	"api/doc",
	"api/index.html",
	"api/swaggerui",
	"api/swagger-ui.html",
	"api/swagger",
	"api/swagger/ui",
	"api/v2/api-docs",
	"api/v2;%0A/api-docs",
	"api/v2;%252Ftest/api-docs",
	"beans",
	"caches",
	"cloudfoundryapplication",
	"conditions",
	"configprops",
	"distv2/index.html",
	"docs",
	"doc.html",
	"druid",
	"druid/index.html",
	"druid/login.html",
	"druid/websession.html",
	"dubbo-provider/distv2/index.html",
	"dump",
	"decision/login",
	"entity/all",
	"env",
	"env.css",
	"env/(name)",
	"eureka",
	"flyway",
	"functionRouter",
	"gateway/actuator",
	"gateway/actuator/auditevents",
	"gateway/actuator/beans",
	"gateway/actuator/conditions",
	"gateway/actuator/configprops",
	"gateway/actuator/env",
	"gateway/actuator/health",
	"gateway/actuator/httptrace",
	"gateway/actuator/hystrix.stream",
	"gateway/actuator/info",
	"gateway/actuator/jolokia",
	"gateway/actuator/logfile",
	"gateway/actuator/loggers",
	"gateway/actuator/mappings",
	"gateway/actuator/metrics",
	"gateway/actuator/scheduledtasks",
	"gateway/actuator/swagger-ui.html",
	"gateway/actuator/threaddump",
	"gateway/actuator/trace",
	"gateway/routes",
	"health",
	"httptrace",
	"hystrix",
	"info",
	"integrationgraph",
	"jolokia",
	"jolokia/list",
	"jeecg/swagger-ui",
	"jeecg/swagger/",
	"libs/swaggerui",
	"liquibase",
	"list",
	"logfile",
	"loggers",
	"metrics",
	"mappings",
	"monitor",
	"nacos",
	"prod-api/actuator",
	"prometheus",
	"portal/conf/config.properties",
	"portal/env/",
	"refresh",
	"scheduledtasks",
	"sessions",
	"spring-security-oauth-resource/swagger-ui.html",
	"spring-security-rest/api/swagger-ui.html",
	"static/swagger.json",
	"sw/swagger-ui.html",
	"swagger",
	"swagger/codes",
	"swagger/doc.json",
	"swagger/index.html",
	"swagger/static/index.html",
	"swagger/swagger-ui.html",
	"Swagger/ui/index",
	"swagger/ui",
	"swagger/v1/swagger.json",
	"swagger/v2/swagger.json",
	"swagger-dubbo/api-docs",
	"swagger-resources",
	"swagger-resources/configuration/ui",
	"swagger-resources/configuration/security",
	"swagger-ui",
	"swagger-ui.html",
	"swagger-ui.html;",
	"swagger-ui/html",
	"swagger-ui/index.html",
	"system/druid/index.html",
	"system/druid/webseesion.html",
	"threaddump",
	"template/swagger-ui.html",
	"trace",
	"users",
	"user/swagger-ui.html",
	"version",
	"v1/api-docs/",
	"v2/api-docs/",
	"v3/api-docs/",
	"v1/swagger-resources",
	"v2/swagger-resources",
	"v3/swagger-resources",
	"v1.1/swagger-ui.html",
	"v1.1;%0A/api-docs",
	"v1.2/swagger-ui.html",
	"v1.2;%0A/api-docs",
	"v1.3/swagger-ui.html",
	"v1.3;%0A/api-docs",
	"v1.4/swagger-ui.html",
	"v1.4;%0A/api-docs",
	"v1.5/swagger-ui.html",
	"v1.5;%0A/api-docs",
	"v1.6/swagger-ui.html",
	"v1.6;%0A/api-docs",
	"v1.7/swagger-ui.html",
	"v1.7;%0A/api-docs",
	"v1.8/swagger-ui.html",
	"v1.8;%0A/api-docs",
	"v1.9/swagger-ui.html",
	"v1.9;%0A/api-docs",
	"v2.0/swagger-ui.html",
	"v2.0;%0A/api-docs",
	"v2.1/swagger-ui.html",
	"v2.1;%0A/api-docs",
	"v2.2/swagger-ui.html",
	"v2.2;%0A/api-docs",
	"v2.3/swagger-ui.html",
	"v2.3;%0A/api-docs",
	"v1/swagger.json",
	"v2/swagger.json",
	"v3/swagger.json",
	"v2;%0A/api-docs",
	"v3;%0A/api-docs",
	"v2;%252Ftest/api-docs",
	"v3;%252Ftest/api-docs",
	"webpage/system/druid/websession.html",
	"webpage/system/druid/index.html",
	"webroot/decision/login",
	"webjars/springfox-swagger-ui/swagger-ui-standalone-preset.js",
	"webjars/springfox-swagger-ui/swagger-ui-standalone-preset.js?v=2.9.2",
	"webjars/springfox-swagger-ui/springfox.js",
	"webjars/springfox-swagger-ui/springfox.js?v=2.9.2",
	"webjars/springfox-swagger-ui/swagger-ui-bundle.js",
	"webjars/springfox-swagger-ui/swagger-ui-bundle.js?v=2.9.2",
	"%20/swagger-ui.html",
}

var (
	defaultOnce sync.Once
	defaultList []string
)

// Default 返回去重后的内置默认字典。
func Default() []string {
	defaultOnce.Do(func() {
		defaultList = dedupe(defaultEndpoints)
	})
	return defaultList
}

// LoadFile 从文件加载自定义字典：每行一条路径，
// 自动跳过空行与 # 注释行，去除首尾空白与开头的 /，并去重。
func LoadFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var (
		lines []string
		seen  = map[string]bool{}
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		ep := Normalize(raw)
		if ep == "" || seen[ep] {
			continue
		}
		seen[ep] = true
		lines = append(lines, ep)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// Merge 合并两个字典并去重，保持 base 在前的顺序。
func Merge(base, extra []string) []string {
	return dedupe(append(append([]string{}, base...), extra...))
}

// Normalize 清洗单条字典项：去空白、去 BOM、去开头 /。
func Normalize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "\uFEFF")
	s = strings.TrimLeft(s, "/")
	if s == "." || s == ".." {
		return ""
	}
	return s
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
