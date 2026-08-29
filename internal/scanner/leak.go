// Package scanner 实现信息泄露端点探测引擎：
// worker pool 控制并发、可选全局限速、按目标去重，
// 任何单点失败只影响当前请求，绝不终止进程。
package scanner

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// Options 控制一次端点探测的行为。
type Options struct {
	Endpoints []string      // 待探测的端点字典
	Threads   int           // 并发 worker 数
	Delay     time.Duration // 全局请求间隔（0 为不限速）
	// Verbose 为 true 时，通过 Logf 输出每个失败请求的详情。
	Verbose bool
	// Logf 是 Verbose 模式的输出回调，由 CLI 层注入，引擎不直接依赖呈现。
	Logf func(format string, args ...any)
}

// noiseBodyLengths 为已知的中间件默认 200 干扰页长度，
// 命中即跳过（按需增删）。
var noiseBodyLengths = map[int]bool{
	3318: true,
}

// noiseKeywords 为明显的"需要登录/无权限"干扰页关键词。
var noiseKeywords = []string{
	"need login", "禁止访问", "无访问权限", "认证失败",
}

// LeakScan 对单个目标并发探测端点，返回去重后的命中列表。
// 第二个返回值非空表示目标中途返回 503，剩余端点已放弃。
func LeakScan(ctx context.Context, t model.Target, opt Options) ([]model.Finding, string) {
	if len(opt.Endpoints) == 0 {
		return nil, ""
	}
	if opt.Threads <= 0 {
		opt.Threads = 20
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu   sync.Mutex
		seen = make(map[string]bool, len(opt.Endpoints))
		out  []model.Finding
		skip string
	)

	var limiter *rate.Limiter
	if opt.Delay > 0 {
		limiter = rate.NewLimiter(rate.Every(opt.Delay), 1)
	}

	sem := make(chan struct{}, opt.Threads)
	var wg sync.WaitGroup
	for _, ep := range opt.Endpoints {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			if limiter != nil {
				if err := limiter.Wait(ctx); err != nil {
					return
				}
			}

			u := t.URL + endpoint
			resp, body, err := client.Do(ctx, t.Client, http.MethodGet, u, nil, "")
			if err != nil {
				if opt.Verbose && opt.Logf != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						opt.Logf("[*] URL: %s 请求超时，目标拒绝请求", u)
					} else {
						opt.Logf("[*] URL: %s 请求失败: %v", u, err)
					}
				}
				return
			}

			if resp.StatusCode == http.StatusServiceUnavailable {
				mu.Lock()
				if skip == "" {
					skip = "目标返回 503，疑似过载或 WAF 拦截，已放弃该目标剩余端点"
				}
				mu.Unlock()
				cancel()
				return
			}
			if resp.StatusCode != http.StatusOK || !isValidResponse(body) {
				return
			}

			sum := md5.Sum(body)
			key := hex.EncodeToString(sum[:])

			mu.Lock()
			defer mu.Unlock()
			if seen[key] {
				return
			}
			seen[key] = true
			out = append(out, model.Finding{
				URL:    u,
				Status: resp.StatusCode,
				Length: len(body),
				Kind:   classify(endpoint),
			})
		}(ep)
	}
	wg.Wait()

	return out, skip
}

func isValidResponse(body []byte) bool {
	s := string(body)
	if noiseBodyLengths[len(body)] {
		return false
	}
	for _, kw := range noiseKeywords {
		if strings.Contains(s, kw) {
			return false
		}
	}
	return true
}

func classify(endpoint string) string {
	switch {
	case strings.Contains(endpoint, "actuator"):
		return "actuator"
	case strings.Contains(endpoint, "swagger") || strings.Contains(endpoint, "api-docs"):
		return "swagger"
	case strings.Contains(endpoint, "druid"):
		return "druid"
	default:
		return "other"
	}
}
