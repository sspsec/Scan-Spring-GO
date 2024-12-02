package scan

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"ssp/common"
	exppackage "ssp/common/exp"
	"ssp/common/poc"
	"strconv"
	"strings"
	"sync"
)

func ScanVuln(url string) {
	url = common.FormatURL(url)
	proxyURL := *common.ProxyPtr
	poc.CVE_2022_22965(url, proxyURL)
	poc.CVE_2022_22963(url, proxyURL)
	poc.CVE_2021_21234(url, proxyURL)
	poc.CVE_2022_22947(url, proxyURL)
	poc.JeeSpring_2023(url, proxyURL)
	poc.SnakeYAML_RCE(url, proxyURL)
	poc.EurekaXstreamRCE(url, proxyURL)
	poc.JolokiaRCE(url, proxyURL)
	poc.CVE_2018_1273(url, proxyURL)

}

func VulFromFile(filename string) {
	urls, _ := common.ReadUrlFromFile(filename)
	var wg sync.WaitGroup
	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			ScanVuln(url)
		}(url)
	}
	wg.Wait()
}

type vulnerability func(url string, proxyURL string)

func vul(url string) {
	url = common.FormatURL(url)
	proxyURL := *common.ProxyPtr

	vulnerabilities := map[int]vulnerability{
		1: exppackage.CVE_2018_1273,
		2: exppackage.CVE_2021_21234,
		3: exppackage.CVE_2022_22947,
		4: exppackage.CVE_2022_22963,
		5: exppackage.CVE_2022_22965,
		6: exppackage.Eureka_xstream_RCE,
		7: exppackage.JeeSpring_2023,
		8: exppackage.JolokiaRCE,
		9: exppackage.SnakeYAML_RCE,
	}

	fmt.Println("[+] 目前支持漏洞如下：")
	for num, vulnFunc := range vulnerabilities {
		funcName := runtime.FuncForPC(reflect.ValueOf(vulnFunc).Pointer()).Name()
		fmt.Printf(" %d: %s\n", num, funcName)
	}

	fmt.Print("\n输入漏洞编号: ")
	reader := bufio.NewReader(os.Stdin)
	choicesStr, _ := reader.ReadString('\n')
	choicesStr = strings.TrimSpace(choicesStr)

	if choicesStr == "" {
		choicesStr = "1,2,3,4,5,6,7,8,9"
	}

	selectedChoices := strings.Split(choicesStr, ",")
	for _, choiceStr := range selectedChoices {
		choiceStr = strings.TrimSpace(choiceStr)
		if choiceStr == "" {
			continue
		}

		choice, err := strconv.Atoi(choiceStr)
		if err != nil {
			fmt.Println("输入错误，请输入数字")
			os.Exit(1)
		}

		selectedFunc, ok := vulnerabilities[choice]
		if !ok {
			fmt.Printf("%d 输入错误，请重新输入漏洞选择模块\n", choice)
			continue
		}

		selectedFunc(url, proxyURL)
	}
	os.Exit(0)
}
