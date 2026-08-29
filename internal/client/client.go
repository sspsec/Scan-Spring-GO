// Package client 提供整轮扫描共享的 HTTP 客户端与请求封装。
// 共享 Client 以复用连接池，避免旧版每请求新建 Client 的开销。
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36",
	"Mozilla/5.0 (X11; NetBSD) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20130406 Firefox/23.0",
	"Opera/9.80 (Windows NT 5.1; U; zh-sg) Presto/2.9.181 Version/12.00",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

func RandomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// New 构建共享 HTTP 客户端。proxyURL 支持 http/https/socks5，
// 凭据可直接写在 URL 的 userinfo 部分。
func New(proxyURL string, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}

	if proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			switch {
			case strings.HasPrefix(proxyURL, "socks5"):
				var auth *proxy.Auth
				if u.User != nil {
					pw, _ := u.User.Password()
					auth = &proxy.Auth{User: u.User.Username(), Password: pw}
				}
				if d, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct); err == nil {
					if cd, ok := d.(proxy.ContextDialer); ok {
						transport.DialContext = cd.DialContext
					}
				}
			default:
				// userinfo 中的代理凭据由 Transport 自动生成 Proxy-Authorization
				transport.Proxy = http.ProxyURL(u)
			}
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// 不跟随跳转，保留原始响应码供判定
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Do 发送请求并读取完整响应体。headers 未指定 User-Agent 时随机选取。
func Do(ctx context.Context, c *http.Client, method, rawURL string, headers map[string]string, payload string) (*http.Response, []byte, error) {
	var body io.Reader
	if payload != "" {
		body = strings.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, nil, fmt.Errorf("创建请求失败: %w", err)
	}

	if _, ok := headers["User-Agent"]; !ok {
		req.Header.Set("User-Agent", RandomUA())
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("读取响应体失败: %w", err)
	}
	return resp, data, nil
}
