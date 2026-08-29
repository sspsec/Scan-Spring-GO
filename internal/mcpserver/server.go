// Package mcpserver 将 Scan-Spring-GO 的检测/利用能力暴露为 MCP 工具，
// 供 AI 客户端（Claude Desktop、ZCode、Cursor 等）安全调用。
//
// 安全设计：
//   - 目标白名单：--scope 限定可测试的主机，出界请求直接拒绝；
//   - 利用闸门：spring_exploit 仅在 --enable-exploit 启动时注册；
//   - 审计日志：每次工具调用写一行 stderr 审计记录（stdout 为协议通道）。
package mcpserver

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/dict"
	"github.com/sspsec/Scan-Spring-GO/internal/fingerprint"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
	"github.com/sspsec/Scan-Spring-GO/internal/scanner"
	"github.com/sspsec/Scan-Spring-GO/internal/vulns"
)

// Config 为 MCP 服务端的启动配置。
type Config struct {
	Scope         []string
	EnableExploit bool
	Proxy         string
	Timeout       time.Duration
}

// version 为 MCP 服务端上报的版本号。
const version = "2.1.0"

type mcpServer struct {
	cfg    Config
	client *http.Client
}

// Main 是 `Scan-Spring-GO mcp` 子命令入口，返回进程退出码。
func Main(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	scope := fs.String("scope", "", "目标白名单（逗号分隔的域名/IP），为空则不限制")
	enableExploit := fs.Bool("enable-exploit", false, "注册 spring_exploit 利用工具（默认关闭）")
	proxy := fs.String("p", "", "HTTP/SOCKS5 代理")
	timeout := fs.Int("timeout", 300, "单次工具调用内的请求超时（秒）")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfg := Config{
		Scope:         nil,
		EnableExploit: *enableExploit,
		Proxy:         *proxy,
		Timeout:       time.Duration(*timeout) * time.Second,
	}
	if strings.TrimSpace(*scope) != "" {
		for _, s := range strings.Split(*scope, ",") {
			if s = strings.TrimSpace(s); s != "" {
				cfg.Scope = append(cfg.Scope, strings.ToLower(s))
			}
		}
	} else {
		fmt.Fprintln(os.Stderr, "[warn] 未设置 --scope 白名单，MCP 工具将允许访问任意目标——请仅在授权环境使用")
	}

	s := &mcpServer{cfg: cfg, client: client.New(*proxy, 15*time.Second)}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "scan-spring-go",
		Version: version,
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_vulns",
		Description: "列出当前支持的全部 Spring 漏洞模块（ID/名称/类型/严重级别/影响范围/是否可利用）",
	}, s.handleListVulns)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "spring_fingerprint",
		Description: "识别目标是否为 Spring/SpringBoot（favicon 哈希 + Whitelabel 错误页 + Boot JSON 错误体三路信号）",
	}, s.handleFingerprint)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "spring_leak_scan",
		Description: "探测 Spring Boot actuator/swagger/druid 等信息泄露端点，返回结构化命中列表",
	}, s.handleLeakScan)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "spring_vuln_detect",
		Description: "对目标运行全部（或指定 CVE 的）漏洞无害检测，返回结构化判定结果",
	}, s.handleVulnDetect)

	if cfg.EnableExploit {
		mcp.AddTool(server, &mcp.Tool{
			Name:        "spring_exploit",
			Description: "对已确认的漏洞执行利用（命令执行/文件读取/认证绕过）。仅在服务端显式开启 --enable-exploit 时可用",
		}, s.handleExploit)
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "batch_scan",
		Description: "对多个目标批量执行漏洞检测，返回聚合的结构化结果",
	}, s.handleBatchScan)

	fmt.Fprintln(os.Stderr, "[mcp] scan-spring-go MCP 服务端已启动（stdio）")
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "[mcp] 服务端退出:", err)
		return 1
	}
	return 0
}

// checkScope 校验目标是否在白名单内。
func (s *mcpServer) checkScope(rawURL string) error {
	if len(s.cfg.Scope) == 0 {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("URL 无法解析: %w", err)
	}
	host := strings.ToLower(u.Hostname())
	for _, sc := range s.cfg.Scope {
		if host == sc || strings.HasSuffix(host, "."+sc) || sc == host {
			return nil
		}
	}
	return fmt.Errorf("目标 %s 不在 --scope 白名单内，已拒绝", host)
}

// audit 输出一条审计记录（stderr，不污染 stdout 协议通道）。
func (s *mcpServer) audit(tool, target string) {
	fmt.Fprintf(os.Stderr, "[audit] %s tool=%s target=%s\n", time.Now().Format(time.RFC3339), tool, target)
}

// targetFor 由 URL 构造扫描目标（白名单校验 + 共享客户端）。
func (s *mcpServer) targetFor(rawURL string) (model.Target, error) {
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	if err := s.checkScope(rawURL); err != nil {
		return model.Target{}, err
	}
	return model.Target{URL: normalizeMCPURL(rawURL), Client: s.client}, nil
}

func normalizeMCPURL(u string) string {
	if !strings.HasSuffix(u, "/") {
		u += "/"
	}
	return u
}

// ---------- 工具输入/输出类型 ----------

type listVulnsIn struct{}
type listVulnsOut struct {
	Vulns []vulnSummary `json:"vulns"`
}
type vulnSummary struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Affected   string `json:"affected"`
	HasExploit bool   `json:"has_exploit"`
	ArgHint    string `json:"arg_hint,omitempty"`
}

func (s *mcpServer) handleListVulns(ctx context.Context, req *mcp.CallToolRequest, _ listVulnsIn) (*mcp.CallToolResult, listVulnsOut, error) {
	out := listVulnsOut{}
	for _, v := range vulns.All() {
		out.Vulns = append(out.Vulns, vulnSummary{
			ID: v.Info().ID, Name: v.Info().Name, Type: v.Info().Type,
			Severity: v.Info().Severity, Affected: v.Info().Affected,
			HasExploit: v.Info().HasExploit, ArgHint: v.Info().ArgHint,
		})
	}
	return nil, out, nil
}

type fingerprintIn struct {
	URL string `json:"url" jsonschema:"目标 URL，如 http://127.0.0.1:8080"`
}
type fingerprintOut struct {
	IsSpring   bool     `json:"is_spring"`
	Confidence string   `json:"confidence"`
	Signals    []string `json:"signals"`
}

func (s *mcpServer) handleFingerprint(ctx context.Context, req *mcp.CallToolRequest, in fingerprintIn) (*mcp.CallToolResult, fingerprintOut, error) {
	s.audit("spring_fingerprint", in.URL)
	t, err := s.targetFor(in.URL)
	if err != nil {
		return nil, fingerprintOut{}, err
	}
	res, err := fingerprint.Detect(ctx, t)
	if err != nil {
		return nil, fingerprintOut{}, err
	}
	return nil, fingerprintOut{
		IsSpring: res.IsSpring, Confidence: res.Confidence, Signals: res.Signals,
	}, nil
}

type leakScanIn struct {
	URL      string `json:"url" jsonschema:"目标 URL"`
	DictPath string `json:"dict_path,omitempty" jsonschema:"自定义字典文件路径（与内置字典合并）"`
	Threads  int    `json:"threads,omitempty" jsonschema:"并发数（默认 20）"`
}
type leakScanOut struct {
	Findings []model.Finding `json:"findings"`
	Skipped  string          `json:"skipped,omitempty"`
}

func (s *mcpServer) handleLeakScan(ctx context.Context, req *mcp.CallToolRequest, in leakScanIn) (*mcp.CallToolResult, leakScanOut, error) {
	s.audit("spring_leak_scan", in.URL)
	t, err := s.targetFor(in.URL)
	if err != nil {
		return nil, leakScanOut{}, err
	}
	endpoints := dict.Default()
	if strings.TrimSpace(in.DictPath) != "" {
		extra, err := dict.LoadFile(in.DictPath)
		if err != nil {
			return nil, leakScanOut{}, fmt.Errorf("读取字典失败: %w", err)
		}
		endpoints = dict.Merge(endpoints, extra)
	}
	threads := in.Threads
	if threads <= 0 {
		threads = 20
	}
	findings, skip := scanner.LeakScan(ctx, t, scanner.Options{
		Endpoints: endpoints, Threads: threads,
	})
	return nil, leakScanOut{Findings: findings, Skipped: skip}, nil
}

type vulnDetectIn struct {
	URL  string   `json:"url" jsonschema:"目标 URL"`
	CVEs []string `json:"cves,omitempty" jsonschema:"仅检测这些漏洞 ID（为空则全部检测）"`
}
type vulnDetectOut struct {
	Target   string          `json:"target"`
	Verdicts []model.Verdict `json:"verdicts"`
}

func (s *mcpServer) handleVulnDetect(ctx context.Context, req *mcp.CallToolRequest, in vulnDetectIn) (*mcp.CallToolResult, vulnDetectOut, error) {
	s.audit("spring_vuln_detect", in.URL)
	t, err := s.targetFor(in.URL)
	if err != nil {
		return nil, vulnDetectOut{}, err
	}
	out := vulnDetectOut{Target: t.URL}
	for _, v := range vulns.All() {
		if len(in.CVEs) > 0 && !containsID(in.CVEs, v.Info().ID) {
			continue
		}
		verdict, err := v.Detect(ctx, t)
		if err != nil {
			out.Verdicts = append(out.Verdicts, model.Verdict{
				ID: v.Info().ID, Name: v.Info().Name, Target: t.URL, Err: err.Error(),
			})
			continue
		}
		out.Verdicts = append(out.Verdicts, *verdict)
	}
	return nil, out, nil
}

func containsID(ids []string, id string) bool {
	for _, s := range ids {
		if strings.EqualFold(s, id) {
			return true
		}
	}
	return false
}

type exploitIn struct {
	URL string `json:"url" jsonschema:"目标 URL（须已通过 spring_vuln_detect 确认）"`
	CVE string `json:"cve" jsonschema:"漏洞 ID，如 CVE-2022-22963"`
	Arg string `json:"arg" jsonschema:"利用参数：命令执行类为命令，文件读取类为文件路径（见 list_vulns 的 arg_hint）"`
}
type exploitOut struct {
	Output string `json:"output"`
	Note   string `json:"note,omitempty"`
}

func (s *mcpServer) handleExploit(ctx context.Context, req *mcp.CallToolRequest, in exploitIn) (*mcp.CallToolResult, exploitOut, error) {
	s.audit("spring_exploit", in.URL+" cve="+in.CVE+" arg="+in.Arg)
	t, err := s.targetFor(in.URL)
	if err != nil {
		return nil, exploitOut{}, err
	}
	v, ok := vulns.Get(in.CVE)
	if !ok {
		return nil, exploitOut{}, fmt.Errorf("未知漏洞 ID: %s", in.CVE)
	}
	ex, ok := v.(vulns.Exploiter)
	if !ok {
		return nil, exploitOut{}, fmt.Errorf("%s 无内置利用模块", in.CVE)
	}
	out, note, err := ex.Exploit(ctx, t, in.Arg)
	if err != nil {
		return nil, exploitOut{}, err
	}
	return nil, exploitOut{Output: out, Note: note}, nil
}

type batchScanIn struct {
	URLs     []string `json:"urls" jsonschema:"目标 URL 列表"`
	Threads  int      `json:"threads,omitempty" jsonschema:"端点探测并发数（默认 20）"`
	DictPath string   `json:"dict_path,omitempty" jsonschema:"自定义字典文件路径"`
}
type batchScanOut struct {
	Results []targetResult `json:"results"`
}
type targetResult struct {
	URL      string          `json:"url"`
	Findings []model.Finding `json:"findings,omitempty"`
	Verdicts []model.Verdict `json:"verdicts,omitempty"`
}

func (s *mcpServer) handleBatchScan(ctx context.Context, req *mcp.CallToolRequest, in batchScanIn) (*mcp.CallToolResult, batchScanOut, error) {
	s.audit("batch_scan", fmt.Sprintf("%d 个目标", len(in.URLs)))
	endpoints := dict.Default()
	if strings.TrimSpace(in.DictPath) != "" {
		extra, err := dict.LoadFile(in.DictPath)
		if err != nil {
			return nil, batchScanOut{}, fmt.Errorf("读取字典失败: %w", err)
		}
		endpoints = dict.Merge(endpoints, extra)
	}
	threads := in.Threads
	if threads <= 0 {
		threads = 20
	}

	out := batchScanOut{}
	for _, raw := range in.URLs {
		t, err := s.targetFor(raw)
		if err != nil {
			out.Results = append(out.Results, targetResult{URL: raw})
			continue
		}
		tr := targetResult{URL: t.URL}
		findings, _ := scanner.LeakScan(ctx, t, scanner.Options{
			Endpoints: endpoints, Threads: threads,
		})
		tr.Findings = findings
		for _, v := range vulns.All() {
			verdict, verr := v.Detect(ctx, t)
			if verr == nil && verdict.Vulnerable {
				tr.Verdicts = append(tr.Verdicts, *verdict)
			}
		}
		out.Results = append(out.Results, tr)
	}
	return nil, out, nil
}
