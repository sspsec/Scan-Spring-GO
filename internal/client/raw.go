// 原始 HTTP 发送器：按调用方给定的头名与请求行逐字发送。
// 标准库 client 会把头名规范化（如 spring.cloud.function.routing-expression
// → Spring.Cloud.Function.Routing-Expression），并对 URL 做再编码，而部分
// 漏洞的利用路径依赖精确的头名/原始字节（如 CVE-2025-41242 的 Unicode
// 路径穿越），此类模块必须走本文件。
package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// bufferedConn 让 TLS 握手能读到 CONNECT 阶段残留的缓冲数据。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func basicAuth(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

func hostOnly(addr string) string {
	if i := strings.LastIndex(addr, ":"); i > strings.LastIndex(addr, "]") {
		return addr[:i]
	}
	return addr
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func readAll(conn net.Conn) ([]byte, error) {
	var out []byte
	buf := make([]byte, 8192)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			return out, nil // Connection: close 下 EOF 即正常结束
		}
		if len(out) > 10<<20 {
			return out, nil
		}
	}
}

// dialTarget 建立到目标的连接（直连/SOCKS5/HTTP 代理 CONNECT + TLS），
// 返回可直接读写的连接。HTTP 代理的明文请求需由调用方以绝对 URI 形态发送。
func dialTarget(ctx context.Context, proxyURL, host string, isTLS bool) (net.Conn, error) {
	dialTimeout := func(addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 10 * time.Second}
		if deadline, ok := ctx.Deadline(); ok {
			d.Deadline = deadline
		}
		return d.DialContext(ctx, "tcp", addr)
	}

	switch {
	case proxyURL == "":
		conn, err := dialTimeout(host)
		if err != nil {
			return nil, err
		}
		if isTLS {
			conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: hostOnly(host)})
		}
		return conn, nil

	case strings.HasPrefix(proxyURL, "socks5"):
		pu, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		var auth *proxy.Auth
		if pu.User != nil {
			pw, _ := pu.User.Password()
			auth = &proxy.Auth{User: pu.User.Username(), Password: pw}
		}
		dialer, err := proxy.SOCKS5("tcp", pu.Host, auth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		conn, err := dialer.Dial("tcp", host)
		if err != nil {
			return nil, err
		}
		if isTLS {
			conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: hostOnly(host)})
		}
		return conn, nil

	default: // HTTP 代理
		pu, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		conn, err := dialTimeout(pu.Host)
		if err != nil {
			return nil, err
		}
		if !isTLS {
			return conn, nil
		}
		// CONNECT 隧道：建立后对隧道流做 TLS
		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", host, host)
		if pu.User != nil {
			pw, _ := pu.User.Password()
			connectReq += "Proxy-Authorization: Basic " + basicAuth(pu.User.Username(), pw) + "\r\n"
		}
		connectReq += "\r\n"
		if _, werr := conn.Write([]byte(connectReq)); werr != nil {
			conn.Close()
			return nil, werr
		}
		br := bufio.NewReader(conn)
		status, rerr := br.ReadString('\n')
		if rerr != nil || !strings.Contains(status, " 200") {
			conn.Close()
			return nil, fmt.Errorf("代理 CONNECT 失败: %s", strings.TrimSpace(status))
		}
		return tls.Client(&bufferedConn{Conn: conn, r: br},
			&tls.Config{InsecureSkipVerify: true, ServerName: hostOnly(host)}), nil
	}
}

func setConnDeadline(ctx context.Context, conn net.Conn) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
}

func parseStatus(raw []byte) (int, []byte, error) {
	text := string(raw)
	statusLine := text
	if i := strings.Index(text, "\r\n"); i >= 0 {
		statusLine = text[:i]
	}
	parts := strings.SplitN(statusLine, " ", 3)
	code := 0
	if len(parts) >= 2 {
		code = atoiSafe(parts[1])
	}
	if bodyStart := strings.Index(text, "\r\n\r\n"); bodyStart >= 0 {
		return code, []byte(text[bodyStart+4:]), nil
	}
	return code, nil, nil
}

func buildRequest(method, target, host string, headers map[string]string, payload string) string {
	var sb strings.Builder
	sb.WriteString(method + " " + target + " HTTP/1.1\r\n")
	sb.WriteString("Host: " + host + "\r\n")
	for k, v := range headers {
		sb.WriteString(k + ": " + v + "\r\n")
	}
	if payload != "" {
		sb.WriteString("Content-Length: " + strconv.Itoa(len(payload)) + "\r\n")
	}
	sb.WriteString("Connection: close\r\n\r\n")
	sb.WriteString(payload)
	return sb.String()
}

func writeRequest(conn net.Conn, request string) error {
	_, err := conn.Write([]byte(request))
	return err
}

// DialRaw 建立到目标的原始连接（直连/SOCKS5/HTTP 代理 CONNECT + TLS），
// 供需要流式读写的模块（如 SockJS 会话流）使用。
func DialRaw(ctx context.Context, proxyURL, host string, isTLS bool) (net.Conn, error) {
	return dialTarget(ctx, proxyURL, host, isTLS)
}

// RawHTTP 发送单个 HTTP 请求：头名逐字保真，URL 由标准库解析。
func RawHTTP(ctx context.Context, proxyURL, method, rawURL string, headers map[string]string, payload string) (int, []byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0, nil, fmt.Errorf("解析 URL 失败: %w", err)
	}
	host := u.Host
	isTLS := u.Scheme == "https"

	conn, err := dialTarget(ctx, proxyURL, host, isTLS)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	setConnDeadline(ctx, conn)

	target := u.RequestURI()
	if proxyURL != "" && !strings.HasPrefix(proxyURL, "socks5") {
		target = rawURL // HTTP 代理明文请求用绝对 URI
	}

	if werr := writeRequest(conn, buildRequest(method, target, host, headers, payload)); werr != nil {
		return 0, nil, werr
	}
	raw, rerr := readAll(conn)
	if rerr != nil && len(raw) == 0 {
		return 0, nil, rerr
	}
	code, body, _ := parseStatus(raw)
	return code, body, nil
}

// RawHTTPRaw 同 RawHTTP，但请求行中的 target（路径+查询）逐字写入，
// 不做任何 URL 解析与再编码——用于 CVE-2025-41242 这类必须发送
// 原始 UTF-8 字节的场景。host 形如 example.com:8080。
func RawHTTPRaw(ctx context.Context, proxyURL, method, host string, isTLS bool, rawTarget string, headers map[string]string, payload string) (int, []byte, error) {
	conn, err := dialTarget(ctx, proxyURL, host, isTLS)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	setConnDeadline(ctx, conn)

	target := rawTarget
	if proxyURL != "" && !strings.HasPrefix(proxyURL, "socks5") {
		scheme := "http"
		if isTLS {
			scheme = "https"
		}
		target = scheme + "://" + host + rawTarget
	}

	if werr := writeRequest(conn, buildRequest(method, target, host, headers, payload)); werr != nil {
		return 0, nil, werr
	}
	raw, rerr := readAll(conn)
	if rerr != nil && len(raw) == 0 {
		return 0, nil, rerr
	}
	code, body, _ := parseStatus(raw)
	return code, body, nil
}
