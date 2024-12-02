package common

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"github.com/fatih/color"
	"golang.org/x/net/proxy"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

func ReadUrlFromFile(filePath string) ([]string, error) {
	var urls []string

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		url = FormatURL(url)
		urls = append(urls, url)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

func FormatURL(url string) string {
	if !strings.Contains(url, "://") {
		if strings.Contains(url, ":443") {
			url = strings.Replace(url, ":443", "", 1)
			url = "https://" + url
		} else {
			url = "http://" + url
		}
	}

	if !strings.HasSuffix(url, "/") {
		url = url + "/"
	}
	return url
}

func GetRandomUserAgent() string {
	randomIndex := rand.Intn(len(userAgents))
	return userAgents[randomIndex]
}

func MergeHeaders(headerMaps ...map[string]string) map[string]string {
	merged := make(map[string]string)
	for _, headers := range headerMaps {
		for key, value := range headers {
			merged[key] = value
		}
	}
	return merged
}

func ExtractResult(input string, regex string) string {

	re := regexp.MustCompile(regex)

	matches := re.FindStringSubmatch(input)

	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func PrintVulnerabilityConfirmation(vulnerabilityName, targetURL, confirmationMessage string, id string) {
	color.Red("[+] %s已确认存在:\n", vulnerabilityName)
	color.Red("    - 目标: %s\n", targetURL)
	color.Red("    - Poc: %s\n", confirmationMessage)
	color.Red("    - 漏洞编号: %s\n", id)
	fmt.Println()
}

func ContainsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func WriteToFile(filename, content string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(content + "\n"); err != nil {
		return err
	}
	return nil
}

func SleepIfNeeded() {
	if *DelayPtr > 0 {
		time.Sleep(time.Duration(*DelayPtr) * time.Second)
	}
}

func MakeRequest(urls string, method string, proxyURL string, headers map[string]string, payload string) (*http.Response, []byte, error) {
	client := &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if proxyURL != "" {
		if strings.HasPrefix(proxyURL, "socks5") {
			parsedURL, err := url.Parse(proxyURL)
			if err != nil {
				return nil, nil, fmt.Errorf("无效的 SOCKS 代理 URL: %w", err)
			}

			auth := parsedURL.User
			var username, password string
			if auth != nil {
				username = auth.Username()
				password, _ = auth.Password()
			}

			dialer, err := proxy.SOCKS5("tcp", parsedURL.Host, &proxy.Auth{
				User:     username,
				Password: password,
			}, proxy.Direct)
			if err != nil {
				return nil, nil, fmt.Errorf("无法创建 SOCKS 代理: %w", err)
			}

			client.Transport = &http.Transport{
				Dial: dialer.Dial,
			}
		} else {
			parsedURL, err := url.Parse(proxyURL)
			if err != nil {
				return nil, nil, fmt.Errorf("无效的 HTTP 代理 URL: %w", err)
			}

			auth := parsedURL.User
			var username, password string
			if auth != nil {
				username = auth.Username()
				password, _ = auth.Password()
			}

			// 设置 HTTP 代理的认证
			client.Transport = &http.Transport{
				Proxy: http.ProxyURL(parsedURL),
				ProxyConnectHeader: http.Header{
					"Proxy-Authorization": []string{
						"Basic " + basicAuth(username, password),
					},
				},
			}
		}
	}

	var req *http.Request
	var err error

	if method == "POST" {
		req, err = http.NewRequest(method, urls, strings.NewReader(payload))
	} else {
		req, err = http.NewRequest(method, urls, nil)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("创建请求失败: %w", err)
	}

	// 设置请求头
	req.Header.Set("User-Agent", GetRandomUserAgent())

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	return resp, body, nil
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
