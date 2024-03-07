package scan

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
	"os"
	"ssp/common"
	"strings"
	"sync"
	"time"
)

func SpringCheck(url string) {
	fmt.Println("[-] 正在进行Spring的指纹识别")
	SpringHash := "0488faca4c19046b94d07c3ee83cf9d6"
	Paths := []string{"favicon.ico"}

	for _, path := range Paths {
		testURL := url + path
		client := &http.Client{}
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			fmt.Println("[-] 创建请求失败:", err)
			return
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("[-] 请求失败:", err)
			return
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("[-] 读取响应体失败:", err)
			return
		}

		contentType := resp.Header.Get("Content-Type")
		find1 := strings.Contains(contentType, "image")
		find2 := strings.Contains(contentType, "octet-stream")
		if find1 || find2 {
			hash := md5.Sum(body)
			faviconHash := hex.EncodeToString(hash[:])
			if faviconHash == SpringHash {
				fmt.Println("[+] 站点Favicon是Spring图标，识别成功")
			} else if strings.Contains(string(body), "timestamp") {
				fmt.Println("[+] 站点报错内容符合Spring特征，识别成功")
			}
		}
		fmt.Println("[-] 站点指纹不符合Spring特征，可能不是Spring框架")
		ScanURLs(url)
	}
}

func ScanURLs(baseURL string) {

	var wg sync.WaitGroup
	for _, endpoint := range common.Endpoints {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			u := baseURL + endpoint

			header := map[string]string{"User-Agent": "Mozilla/5.0"} // 可以根据需要修改User-Agent

			client := &http.Client{
				Timeout: 6 * time.Second, // 设置超时时间为6秒
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse // 禁止跟随重定向
				},
			}

			req, err := http.NewRequest("GET", u, nil)
			if err != nil {
				fmt.Println("创建请求失败:", err)
				return
			}

			// 添加自定义头部
			for key, value := range header {
				req.Header.Set(key, value)
			}

			resp, err := client.Do(req)
			if err != nil {
				color.Yellow("[+] URL为：%s，的目标积极拒绝请求，予以跳过\n", u)
				return
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return
			}

			if resp.StatusCode == 503 {
				fmt.Println("状态码为503，程序退出")
				os.Exit(0)
			} else if resp.StatusCode == 200 && !strings.Contains(string(body), "need login") &&
				!strings.Contains(string(body), "禁止访问") && len(body) != 3318 && !strings.Contains(string(body), "无访问权限") &&
				!strings.Contains(string(body), "认证失败") {
				color.Red("[+] 状态码%d 信息泄露URL为:%s 页面长度为:%d\n", resp.StatusCode, u, len(body))
			} else if resp.StatusCode == 200 {
				color.Red("[+] 状态码%d 但无法获取信息 URL为:%s 页面长度为:%d\n", resp.StatusCode, u, len(body))
			} else {
				color.Yellow("[-] 状态码%d 无法访问URL为:%s\n", resp.StatusCode, u)
			}
		}(endpoint)
	}
	wg.Wait()

	os.Exit(0)
}

func CheckFromFile(filename string) {
	urls, _ := common.ReadUrlFromFile(filename)
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
