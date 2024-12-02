package scan

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/fatih/color"
	"net"
	"os"
	"regexp"
	"runtime"
	"ssp/common"
	"strings"
	"sync"
)

var EnableColor bool
var headers = map[string]string{
	"User-Agent": common.GetRandomUserAgent(),
}

var SpringHash = "0488faca4c19046b94d07c3ee83cf9d6"
var encounteredHashes = make(map[string]bool)

func SpringCheck(url string) {
	fmt.Println("[-] 正在进行Spring的指纹识别")
	Paths := []string{"favicon.ico"}

	for _, path := range Paths {
		testURL := url + path
		resp, body, err := common.MakeRequest(testURL, "GET", *common.ProxyPtr, headers, "")
		if err != nil {
			color.Yellow("[-] %s 请求失败，跳过端点扫描\n", url)
			continue
		}

		contentType := resp.Header.Get("Content-Type")
		if isImage(contentType) {
			handleFavicon(body)
		} else if containsSpringError(body) {
			fmt.Println("[+] 站点报错内容符合Spring特征，识别成功")
		}
		ScanURLs(url)
	}
}

func isImage(contentType string) bool {
	return strings.Contains(contentType, "image") || strings.Contains(contentType, "octet-stream")
}

func handleFavicon(body []byte) {
	hash := md5.Sum(body)
	faviconHash := hex.EncodeToString(hash[:])
	if faviconHash == SpringHash {
		fmt.Println("[+] 站点Favicon是Spring图标，识别成功")
	} else if containsSpringError(body) {
		fmt.Println("[+] 站点报错内容符合Spring特征，识别成功")
	} else {
		fmt.Println("[-] 站点指纹不符合Spring特征")
	}
}

func containsSpringError(body []byte) bool {
	return strings.Contains(string(body), "timestamp")
}

func ScanURLs(baseURL string) {
	checkColorSupport()
	var wg sync.WaitGroup

	resultFile, err := os.Create("result.txt")
	if err != nil {
		fmt.Printf("%s创建文件失败: %s\n", common.Red, err)
		return
	}
	defer resultFile.Close()

	for _, endpoint := range common.Endpoints {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			u := baseURL + endpoint
			handleEndpointRequest(u)
		}(endpoint)
		common.SleepIfNeeded()
	}
	wg.Wait()
}

func handleEndpointRequest(url string) {

	resp, body, err := common.MakeRequest(url, "GET", *common.ProxyPtr, headers, "")
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {

			fmt.Printf("\033[0;33m[*] URL: %s 请求超时，目标拒绝请求\033[0m\n", url)
		} else {

			fmt.Printf("\033[0;31m[*] URL: %s 未知请求失败\033[0m\n", url)
		}
		return
	}

	switch resp.StatusCode {
	case 503:
		fmt.Printf("\033[0;33m[*] 服务器返回503，程序退出：%s\033[0m\n", url)
		os.Exit(0)
	case 200:
		if isValidResponse(body) {
			contentHash := calculateMD5Hash(body)
			if !encounteredHashes[contentHash] {

				encounteredHashes[contentHash] = true
				message := fmt.Sprintf("\033[0;32m[+] 状态码%d 信息泄露URL为:%s 页面长度为:%d\033[0m\n", resp.StatusCode, url, len(body))
				fmt.Print(message)
				messageWithoutColor := removeColorCodes(message)
				if err := common.WriteToFile("result.txt", messageWithoutColor); err != nil {
					fmt.Printf("\033[0;31m[*] 写入文件失败: %s\033[0m\n", err)
				}
			} else {

				fmt.Printf("\033[0;33m[*] 已存在重复内容的URL: %s\033[0m\n", url)
			}
		} else {

			fmt.Printf("\033[0;35m[*] 状态码%d 但无法获取有用信息 URL: %s 页面长度: %d\033[0m\n", resp.StatusCode, url, len(body))
		}
	default:

		fmt.Printf("\033[0;33m[*] 状态码%d 无法访问URL: %s\033[0m\n", resp.StatusCode, url)
	}
}

func calculateMD5Hash(body []byte) string {
	hash := md5.Sum(body)
	return hex.EncodeToString(hash[:])
}

func isValidResponse(body []byte) bool {
	bodyStr := string(body)
	return !strings.Contains(bodyStr, "need login") && !strings.Contains(bodyStr, "禁止访问") &&
		len(body) != 3318 && !strings.Contains(bodyStr, "无访问权限") && !strings.Contains(bodyStr, "认证失败")
}

func checkColorSupport() {
	if runtime.GOOS == "windows" {
		EnableColor = isTerminal() && !isOldCMD()
	} else {
		EnableColor = true
	}
}

func isTerminal() bool {
	return true
}

func isOldCMD() bool {
	return false
}

func CheckFromFile(filename string) {
	urls, err := common.ReadUrlFromFile(filename)
	if err != nil {
		fmt.Println("读取文件失败:", err)
		return
	}
	var wg sync.WaitGroup
	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			ScanURLs(url)
		}(url)
	}
	wg.Wait()
}

func Check(url string) {
	url = common.FormatURL(url)
	SpringCheck(url)
}

func removeColorCodes(input string) string {
	re := regexp.MustCompile("\033\\[[0-9;]*m")
	output := re.ReplaceAllString(input, "")

	return strings.TrimSuffix(output, "\n")
}
