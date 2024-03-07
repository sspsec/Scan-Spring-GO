package exppackage

import (
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
	"ssp/common"
	"strings"
)

func JolokiaRCE(url string) {
	path1 := "jolokia"
	path2 := "actuator/jolokia"
	path3 := "jolokia/list"
	oldHeader := map[string]string{"User-Agent": common.GetRandomUserAgent()}

	headers1 := make(http.Header)
	for key, value := range oldHeader {
		headers1.Set(key, value)
	}

	client := &http.Client{}

	req1, err := http.NewRequest("POST", url+path1, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req1.Header = headers1

	resp1, err := client.Do(req1)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer resp1.Body.Close()

	code1 := resp1.StatusCode

	req2, err := http.NewRequest("POST", url+path2, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req2.Header = headers1

	resp2, err := client.Do(req2)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer resp2.Body.Close()

	code2 := resp2.StatusCode

	if code1 == 200 || code2 == 200 {

		req3, err := http.NewRequest("GET", url+path3, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}
		req3.Header = headers1

		resp3, err := client.Do(req3)
		if err != nil {
			color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
			return
		}
		defer resp3.Body.Close()

		code3 := resp3.StatusCode
		body, err := ioutil.ReadAll(resp3.Body)
		if err != nil {
			fmt.Println("Error reading response:", err)
			return
		}

		if strings.Contains(string(body), "reloadByURL") && code3 == 200 {
			common.PrintVulnerabilityConfirmation("Jolokia-Realm-JNDI-RCE", url, url+path3, "8")
		} else if strings.Contains(string(body), "createJNDIRealm") && code3 == 200 {
			common.PrintVulnerabilityConfirmation("Jolokia-Realm-JNDI-RCE", url, url+path3, "8")
			fmt.Println(url + path3)
		} else {
			fmt.Println("[.] 未发现jolokia/list路径存在关键词，请手动验证：")
			fmt.Println(url + path3)
		}
	} else {
		color.Yellow("[-] %s 未发现Jolokia系列RCE漏洞\n", url)
	}
}
