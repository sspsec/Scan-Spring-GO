// Package model 定义引擎层与展示层共享的数据结构。
// 所有扫描/检测结果均以结构化数据返回，终端输出、文件落盘、
// JSON 导出与未来的 MCP 接口都消费同一份类型。
package model

import "net/http"

// Target 是一次扫描的目标上下文。
type Target struct {
	// URL 为规范化后的目标地址，保证以 / 结尾。
	URL string
	// Client 为整轮扫描共享的 HTTP 客户端（含代理/超时配置）。
	Client *http.Client
	// Proxy 为原始 socket 请求（保真头名）使用的代理配置，可为空。
	Proxy string
}

// Info 描述一个漏洞的静态元数据。
type Info struct {
	ID         string `json:"id"`        // 如 CVE-2022-22963、JeeSpring-2023
	Name       string `json:"name"`      // 漏洞名称
	Type       string `json:"type"`      // RCE / FileUpload / FileRead / Deserialization
	Severity   string `json:"severity"`  // critical / high / medium
	Affected   string `json:"affected"`  // 影响范围
	Reference  string `json:"reference"` // 参考链接
	HasExploit bool   `json:"has_exploit"`
	// ArgHint 描述 Exploiter 参数的含义（命令/文件路径/回连 URL），
	// 供交互菜单与未来的 MCP 工具描述使用。
	ArgHint string `json:"arg_hint,omitempty"`
}

// Verdict 是单个漏洞在单个目标上的判定结果。
type Verdict struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Target     string `json:"target"`
	Vulnerable bool   `json:"vulnerable"`
	Evidence   string `json:"evidence,omitempty"` // 命中依据（如回显内容、WebShell 地址）
	Detail     string `json:"detail,omitempty"`   // 补充说明（如无回显需 OOB 验证）
	Err        string `json:"error,omitempty"`
}

// Finding 是信息泄露探测的单条命中。
type Finding struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Length int    `json:"length"`
	Kind   string `json:"kind"` // actuator / swagger / druid / other
}

// FingerprintResult 是指纹识别结论。
type FingerprintResult struct {
	IsSpring   bool     `json:"is_spring"`
	Confidence string   `json:"confidence"` // high / medium / none
	Signals    []string `json:"signals"`
}
