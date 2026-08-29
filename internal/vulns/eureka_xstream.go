package vulns

import (
	"context"
	"net/http"
	"strings"

	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// Eureka-Xstream-RCE：Eureka client serviceUrl 注入触发 XStream 反序列化。
type eurekaXstream struct{}

func init() { Register(&eurekaXstream{}) }

const eurekaProbeValue = "http://127.0.0.2/example.yml"

func (e *eurekaXstream) Info() model.Info {
	return model.Info{
		ID:         "Eureka-Xstream-RCE",
		Name:       "Eureka XStream 反序列化",
		Type:       "Deserialization",
		Severity:   "critical",
		Affected:   "Spring Cloud Netflix Eureka（actuator/env 可写）",
		Reference:  "",
		HasExploit: false,
	}
}

func (e *eurekaXstream) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: e.Info().ID, Name: e.Info().Name, Target: t.URL}

	formHeaders := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	jsonHeaders := map[string]string{"Content-Type": "application/json"}

	probes := []struct {
		path    string
		headers map[string]string
		payload string
	}{
		{"env", formHeaders, "eureka.client.serviceUrl.defaultZone=" + eurekaProbeValue},
		{"actuator/env", jsonHeaders, `{"name":"eureka.client.serviceUrl.defaultZone","value":"` + eurekaProbeValue + `"}`},
	}
	for _, p := range probes {
		_, body, err := do(ctx, t, http.MethodPost, p.path, p.headers, p.payload)
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(body), "127.0.0.2") {
			v.Vulnerable = true
			v.Evidence = "env 端点回显了注入的 serviceUrl 配置"
			v.Detail = "返回恶意 XStream payload 即可 RCE"
			return v, nil
		}
	}
	return v, nil
}
