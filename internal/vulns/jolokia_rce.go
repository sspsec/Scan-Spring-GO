package vulns

import (
	"context"
	"net/http"
	"strings"

	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// Jolokia-JNDI-RCE：Jolokia 暴露 reloadByURL/createJNDIRealm 导致 JNDI 注入。
// 利用需要攻击者控制的 LDAP/RMI 服务，故只做存在性检测。
type jolokiaRCE struct{}

func init() { Register(&jolokiaRCE{}) }

var jolokiaKeywords = []string{"reloadByURL", "createJNDIRealm"}

func (j *jolokiaRCE) Info() model.Info {
	return model.Info{
		ID:         "Jolokia-JNDI-RCE",
		Name:       "Jolokia JNDI 注入 RCE",
		Type:       "RCE",
		Severity:   "critical",
		Affected:   "Jolokia < 1.5.0（jolokia/list 可达）",
		Reference:  "https://github.com/laluka/jolokia-exploitation-toolkit",
		HasExploit: false,
	}
}

func (j *jolokiaRCE) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: j.Info().ID, Name: j.Info().Name, Target: t.URL}

	for _, path := range []string{"jolokia", "actuator/jolokia"} {
		resp, _, err := do(ctx, t, http.MethodPost, path, nil, "")
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			continue
		}

		_, body, err := do(ctx, t, http.MethodGet, path+"/list", nil, "")
		if err != nil {
			return nil, err
		}
		for _, kw := range jolokiaKeywords {
			if strings.Contains(string(body), kw) {
				v.Vulnerable = true
				v.Evidence = path + "/list 暴露敏感 MBean：" + kw
				v.Detail = "配合恶意 LDAP/RMI 服务可实现 JNDI 注入 RCE"
				return v, nil
			}
		}
	}
	return v, nil
}
