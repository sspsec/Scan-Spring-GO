package poc

import (
	"fmt"
	"github.com/fatih/color"
	"ssp/common"
	"strings"
)

func JolokiaRCE(url, proxyURL string) {
	path1 := "jolokia"
	path2 := "actuator/jolokia"
	path3 := "jolokia/list"

	// 尝试访问不同的路径
	tryPaths := []string{path1, path2}
	vulnKeywords := []string{"reloadByURL", "createJNDIRealm"}

	for _, path := range tryPaths {
		// 使用 MakeRequest 发送 POST 请求
		resp, _, err := common.MakeRequest(url+path, "POST", proxyURL, nil, "")
		if err != nil {
			color.Yellow("[-] %s 请求失败，跳过漏洞检查\n", url)
			return
		}

		code := resp.StatusCode
		if code == 200 {
			// 检查是否存在漏洞关键词
			for _, keyword := range vulnKeywords {
				// 使用 MakeRequest 进行 GET 请求
				retest, bodytest, err := common.MakeRequest(url+path3, "GET", proxyURL, nil, "")
				if err != nil {
					fmt.Println("Error performing retest request:", err)
					return
				}

				code2 := retest.StatusCode
				if strings.Contains(string(bodytest), keyword) && code2 == 200 {
					// 打印漏洞确认信息
					common.PrintVulnerabilityConfirmation("Jolokia-Realm-JNDI-RCE", url, "Null", "8")
					common.Vulnum++
					return
				}
			}
		}
	}

	color.Yellow("[-] %s 未发现Jolokia系列RCE漏洞\n", url)
}
