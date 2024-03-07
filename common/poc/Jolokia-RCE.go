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

func JolokiaRCE(url string) {
	path1 := "jolokia"
	path2 := "actuator/jolokia"
	path3 := "jolokia/list"

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

	tryPaths := []string{path1, path2}
	vulnKeywords := []string{"reloadByURL", "createJNDIRealm"}

	for _, path := range tryPaths {
		req, err := http.NewRequest("POST", url+path, nil)
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

		code := resp.StatusCode
		if code == 200 {
			for _, keyword := range vulnKeywords {
				retest, err := http.Get(url + path3)
				if err != nil {
					fmt.Println("Error performing retest request:", err)
					return
				}
				defer retest.Body.Close()

				code := retest.StatusCode
				body, err := ioutil.ReadAll(retest.Body)
				if err != nil {
					fmt.Println("Error reading retest response:", err)
					return
				}

				if strings.Contains(string(body), keyword) && code == 200 {
					common.PrintVulnerabilityConfirmation("Jolokia-Realm-JNDI-RCE", url, "Null", "8")
					common.Vulnum++
					return
				}
			}
		}
	}
	color.Yellow("[-] %s 未发现Jolokia系列RCE漏洞\n", url)

}
