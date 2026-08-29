// Package vulns 是漏洞模块注册表。
// 每个漏洞一个文件，实现 Vuln 接口并在 init 中自注册；
// 新增漏洞只需新增一个文件，CLI 菜单与 MCP 工具列表自动收录。
package vulns

import (
	"context"
	"net/http"
	"sort"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// Vuln 是所有漏洞模块的最小接口：元数据 + 无害检测。
type Vuln interface {
	Info() model.Info
	Detect(ctx context.Context, t model.Target) (*model.Verdict, error)
}

// Exploiter 是可选的利用接口：arg 通常为要执行的命令，
// 文件读取类漏洞则为要读取的路径。实现与否由各漏洞自行决定。
type Exploiter interface {
	Vuln
	Exploit(ctx context.Context, t model.Target, arg string) (output string, note string, err error)
}

var registry []Vuln

// Register 供各漏洞文件的 init 调用。
func Register(v Vuln) {
	registry = append(registry, v)
}

// All 返回按 ID 排序的全部漏洞模块。
func All() []Vuln {
	out := make([]Vuln, len(registry))
	copy(out, registry)
	sort.Slice(out, func(i, j int) bool { return out[i].Info().ID < out[j].Info().ID })
	return out
}

// Get 按 ID（如 CVE-2022-22963）查找漏洞模块。
func Get(id string) (Vuln, bool) {
	for _, v := range registry {
		if v.Info().ID == id {
			return v, true
		}
	}
	return nil, false
}

// do 基于 Target 发送相对路径请求，供各漏洞模块复用。
func do(ctx context.Context, t model.Target, method, path string, headers map[string]string, payload string) (*http.Response, []byte, error) {
	return client.Do(ctx, t.Client, method, t.URL+path, headers, payload)
}
