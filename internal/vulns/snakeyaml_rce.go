package vulns

import (
	"context"
	"net/http"
	"strings"

	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// SnakeYAML-RCE：Spring Boot actuator env 配置注入触发 SnakeYAML 反序列化。
// 需要目标回连攻击者控制的 yml 地址，故只做存在性检测。
type snakeyamlRCE struct{}

func init() { Register(&snakeyamlRCE{}) }

const yamlProbeValue = "http://127.0.0.1/example.yml"

func (s *snakeyamlRCE) Info() model.Info {
	return model.Info{
		ID:         "SnakeYAML-RCE",
		Name:       "Spring Boot SnakeYAML 反序列化",
		Type:       "Deserialization",
		Severity:   "critical",
		Affected:   "Spring Boot 1.x-2.x（actuator/env 可写 + SnakeYAML 在 classpath）",
		Reference:  "https://github.com/artsploit/yaml-payload",
		HasExploit: false,
	}
}

func (s *snakeyamlRCE) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: s.Info().ID, Name: s.Info().Name, Target: t.URL}

	formHeaders := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	jsonHeaders := map[string]string{"Content-Type": "application/json"}

	_, body1, err := do(ctx, t, http.MethodPost, "env", formHeaders,
		"spring.cloud.bootstrap.location="+yamlProbeValue)
	if err != nil {
		return nil, err
	}
	_, body2, err := do(ctx, t, http.MethodPost, "env", jsonHeaders,
		`{"name":"spring.main.sources","value":"`+yamlProbeValue+`"}`)
	if err != nil {
		return nil, err
	}

	switch {
	case strings.Contains(string(body1), "example.yml"):
		v.Vulnerable = true
		v.Evidence = "env 端点接受 spring.cloud.bootstrap.location 注入（表单格式）"
	case strings.Contains(string(body2), "example.yml"):
		v.Vulnerable = true
		v.Evidence = "env 端点接受 spring.main.sources 注入（JSON 格式）"
	}
	if v.Vulnerable {
		v.Detail = "搭建恶意 yml 服务（yaml-payload）后即可 RCE"
	}
	return v, nil
}
