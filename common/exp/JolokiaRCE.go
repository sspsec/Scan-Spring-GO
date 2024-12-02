package exppackage

import (
	"github.com/fatih/color"
	"ssp/common"
	"strings"
)

func JolokiaRCE(url, proxyURL string) {
	path1 := "jolokia"
	path2 := "actuator/jolokia"
	path3 := "jolokia/list"
	headers1 := map[string]string{"User-Agent": common.GetRandomUserAgent()}

	// 尝试访问不同的路径
	tryPaths := []string{path1, path2}
	vulnKeywords := []string{"reloadByURL", "createJNDIRealm"}

	for _, path := range tryPaths {
		// 使用 MakeRequest 发送 POST 请求
		resp1, _, err := common.MakeRequest(url+path, "POST", proxyURL, headers1, "")
		if err != nil {
			color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
			return
		}

		code1 := resp1.StatusCode
		if code1 != 200 {
			continue
		}

		// 使用 MakeRequest 进行 GET 请求检查
		retest, bodytest, err := common.MakeRequest(url+path3, "GET", proxyURL, headers1, "")
		if err != nil {
			color.Yellow("[-] %s 请求失败，跳过漏洞检查\n", url)
			return
		}

		code2 := retest.StatusCode
		if code2 == 200 {
			// 检查返回内容中是否包含关键字
			for _, keyword := range vulnKeywords {
				if strings.Contains(string(bodytest), keyword) {
					// 漏洞确认
					common.PrintVulnerabilityConfirmation("Jolokia-Realm-JNDI-RCE", url, url+path3, "8")
					return
				}
			}

			color.Yellow("[-] 未发现jolokia/list路径存在关键词，请手动验证：" + url + path3)
		}
	}

	color.Yellow("[-] %s 未发现Jolokia系列RCE漏洞\n", url)
}
