// Package cli 负责命令行交互：参数解析、终端呈现、result.txt 落盘
// 与交互式利用菜单。所有引擎层（internal/*）只返回结构化数据，
// 呈现逻辑全部收敛在本包。
package cli

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"golang.org/x/term"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/dict"
	"github.com/sspsec/Scan-Spring-GO/internal/fingerprint"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
	"github.com/sspsec/Scan-Spring-GO/internal/scanner"
	"github.com/sspsec/Scan-Spring-GO/internal/vulns"
)

// targetWorkers 为批量目标模式下的目标级并发数。
const targetWorkers = 5

// fileMu 保护 result.txt 的并发写入。
var fileMu sync.Mutex

// Run 是 CLI 主入口，返回进程退出码。
func Run() int {
	Parse()
	if *showVersion {
		fmt.Println("Scan-Spring-GO v" + Version)
		return 0
	}
	Banner()

	if *urlPtr == "" && *urlFilePtr == "" && *vulPtr == "" && *vulFilePtr == "" {
		usageHint()
		return 1
	}

	endpoints, err := loadDict()
	if err != nil {
		color.Red("[!] %s", err)
		return 1
	}

	cl := client.New(*proxyPtr, time.Duration(*timeoutPtr)*time.Second)
	delay := time.Duration(*delayPtr) * time.Second

	exit := 0
	if *urlPtr != "" || *urlFilePtr != "" {
		if code := runLeakScan(cl, endpoints, delay); code != 0 {
			exit = code
		}
	}
	if *vulPtr != "" || *vulFilePtr != "" {
		if code := runVulnScan(cl); code != 0 {
			exit = code
		}
	}
	return exit
}

// loadDict 按优先级装配探测字典：-D 替换 > -d 合并 > 内置默认。
func loadDict() ([]string, error) {
	switch {
	case *dictReplace != "":
		eps, err := dict.LoadFile(*dictReplace)
		if err != nil {
			return nil, fmt.Errorf("读取字典 %s 失败: %w", *dictReplace, err)
		}
		if len(eps) == 0 {
			return nil, fmt.Errorf("字典 %s 为空", *dictReplace)
		}
		color.Green("[*] 已使用自定义字典 %s（%d 条）", *dictReplace, len(eps))
		return eps, nil

	case *dictMerge != "":
		extra, err := dict.LoadFile(*dictMerge)
		if err != nil {
			return nil, fmt.Errorf("读取字典 %s 失败: %w", *dictMerge, err)
		}
		merged := dict.Merge(dict.Default(), extra)
		color.Green("[*] 字典已合并：内置 %d 条 + 自定义 %d 条 = %d 条", len(dict.Default()), len(extra), len(merged))
		return merged, nil

	default:
		return dict.Default(), nil
	}
}

// runLeakScan 信息泄露扫描模式（-u / -uf）。
func runLeakScan(cl *http.Client, endpoints []string, delay time.Duration) int {
	targets, err := collectTargets(*urlPtr, *urlFilePtr)
	if err != nil {
		color.Red("[!] %s", err)
		return 1
	}

	resultFile, err := os.OpenFile(*outPtr, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		color.Red("[!] 创建结果文件 %s 失败: %s", *outPtr, err)
		return 1
	}
	defer resultFile.Close()

	ctx := context.Background()
	var wg sync.WaitGroup
	sem := make(chan struct{}, targetWorkers)
	for _, raw := range targets {
		wg.Add(1)
		go func(raw string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			t := model.Target{URL: formatURL(raw), Client: cl, Proxy: *proxyPtr}
			scanOneTarget(ctx, t, endpoints, delay, resultFile)
		}(raw)
	}
	wg.Wait()
	return 0
}

func scanOneTarget(ctx context.Context, t model.Target, endpoints []string, delay time.Duration, resultFile *os.File) {
	color.Cyan("[*] 开始扫描目标: %s", t.URL)

	if fp, err := fingerprint.Detect(ctx, t); err != nil {
		color.Yellow("[-] %s 指纹识别请求失败: %s", t.URL, err)
	} else if fp.IsSpring {
		color.Green("[+] Spring 指纹命中（置信度 %s）：%s", fp.Confidence, strings.Join(fp.Signals, "、"))
	} else {
		color.Yellow("[-] 未识别到 Spring 指纹，继续端点探测")
	}

	findings, skip := scanner.LeakScan(ctx, t, scanner.Options{
		Endpoints: endpoints,
		Threads:   *threadsPtr,
		Delay:     delay,
		Verbose:   *debugPtr,
		Logf: func(format string, args ...any) {
			fmt.Println(color.YellowString(format, args...))
		},
	})
	for _, f := range findings {
		msg := fmt.Sprintf("[+] 状态码%d 信息泄露URL:%s 页面长度:%d 类型:%s", f.Status, f.URL, f.Length, f.Kind)
		fmt.Println(color.GreenString(msg))
		fileMu.Lock()
		_, werr := fmt.Fprintln(resultFile, msg)
		fileMu.Unlock()
		if werr != nil {
			color.Yellow("[!] 写入 %s 失败: %s", *outPtr, werr)
		}
	}
	if skip != "" {
		color.Yellow("[!] %s：%s", t.URL, skip)
	}
	color.Cyan("[*] 目标完成: %s（命中 %d 条）", t.URL, len(findings))
}

// runVulnScan 漏洞检测模式（-v / -vf）。
func runVulnScan(cl *http.Client) int {
	ctx := context.Background()

	// 单目标：检测后按需执行命令或进入交互利用
	if *vulPtr != "" {
		t := model.Target{URL: formatURL(*vulPtr), Client: cl, Proxy: *proxyPtr}
		hits := detectTarget(ctx, t)
		switch {
		case *cmdPtr != "":
			runCommand(ctx, t, hits)
		case len(hits) > 0 && stdinInteractive():
			exploitMenu(ctx, t, hits)
		}
	}

	if *vulFilePtr != "" {
		targets, err := collectTargets("", *vulFilePtr)
		if err != nil {
			color.Red("[!] %s", err)
			return 1
		}
		var wg sync.WaitGroup
		sem := make(chan struct{}, targetWorkers)
		for _, raw := range targets {
			wg.Add(1)
			go func(raw string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				detectTarget(ctx, model.Target{URL: formatURL(raw), Client: cl, Proxy: *proxyPtr})
			}(raw)
		}
		wg.Wait()
	}
	return 0
}

// detectTarget 对单目标跑全部漏洞检测并打印结果，返回命中模块。
func detectTarget(ctx context.Context, t model.Target) []vulns.Vuln {
	color.Cyan("[*] 开始漏洞检测: %s", t.URL)

	var hits []vulns.Vuln
	for _, v := range vulns.All() {
		verdict, err := v.Detect(ctx, t)
		if err != nil {
			color.Yellow("[-] %s 检测 %s 失败: %s", t.URL, v.Info().ID, err)
			continue
		}
		if !verdict.Vulnerable {
			continue
		}
		color.Red("[+] %s 已确认存在：%s", verdict.Name, verdict.ID)
		color.Red("    - 目标: %s", t.URL)
		if verdict.Evidence != "" {
			color.Red("    - 依据: %s", verdict.Evidence)
		}
		if verdict.Detail != "" {
			color.Red("    - 说明: %s", verdict.Detail)
		}
		fmt.Println()
		hits = append(hits, v)
	}
	if len(hits) == 0 {
		color.Yellow("[-] %s 未发现已知漏洞", t.URL)
	}
	return hits
}

// runCommand 非交互执行单条命令：-c 指定命令，-ce 可选指定漏洞模块。
// 仅在显式传入 -c 时触发，交互场景仍走 exploitMenu 人工确认。
func runCommand(ctx context.Context, t model.Target, hits []vulns.Vuln) {
	var candidates []vulns.Exploiter
	for _, v := range hits {
		if e, ok := v.(vulns.Exploiter); ok {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 0 {
		color.Yellow("[*] 命中漏洞均无内置利用模块，无法执行命令")
		return
	}

	var e vulns.Exploiter
	if *cmdCvePtr != "" {
		for _, c := range candidates {
			if c.Info().ID == *cmdCvePtr {
				e = c
				break
			}
		}
		if e == nil {
			color.Red("[-] 指定的 %s 未命中或不可利用，命中项：%v", *cmdCvePtr, ids(candidates))
			return
		}
	} else {
		e = candidates[0]
	}

	info := e.Info()
	color.Cyan("[*] 通过 %s 执行：%s", info.ID, *cmdPtr)
	out, note, err := e.Exploit(ctx, t, *cmdPtr)
	if err != nil {
		color.Red("[-] 执行失败: %s", err)
		return
	}
	if out != "" {
		fmt.Println(out)
	}
	if note != "" {
		color.Yellow("[*] %s", note)
	}
}

// ids 返回可利用模块的 ID 列表，用于提示信息。
func ids(candidates []vulns.Exploiter) []string {
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, c.Info().ID)
	}
	return out
}

// exploitMenu 交互式利用菜单：选择漏洞后进入逐条命令模式。
// stdin 读取只存在于本函数，引擎层保持可编程调用。
func exploitMenu(ctx context.Context, t model.Target, hits []vulns.Vuln) {
	var exploitable []vulns.Exploiter
	for _, v := range hits {
		if e, ok := v.(vulns.Exploiter); ok {
			exploitable = append(exploitable, e)
		}
	}
	if len(exploitable) == 0 {
		color.Yellow("[*] 命中漏洞均无内置利用模块")
		return
	}

	fmt.Println("[+] 可利用漏洞如下：")
	for i, e := range exploitable {
		fmt.Printf(" %d: %s（%s）\n", i+1, e.Info().Name, e.Info().ID)
	}
	fmt.Print("\n输入漏洞编号（回车跳过利用）: ")

	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	idx, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || idx < 1 || idx > len(exploitable) {
		return
	}

	e := exploitable[idx-1]
	info := e.Info()
	fmt.Printf("[*] 进入 %s 交互模式，输入 exit 退出\n", info.ID)
	if info.ArgHint != "" {
		fmt.Printf("[*] 参数说明：%s\n", info.ArgHint)
	}
	for {
		fmt.Print("shell > ")
		arg, _ := reader.ReadString('\n')
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		if arg == "exit" {
			return
		}
		out, note, err := e.Exploit(ctx, t, arg)
		if err != nil {
			color.Yellow("[-] 执行失败: %s", err)
			continue
		}
		if out != "" {
			fmt.Println(out)
		}
		if note != "" {
			color.Yellow("[*] %s", note)
		}
	}
}

// collectTargets 汇总单 URL 与文件两类目标。
func collectTargets(single, file string) ([]string, error) {
	var targets []string
	if single != "" {
		targets = append(targets, single)
	}
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("读取目标文件 %s 失败: %w", file, err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			targets = append(targets, line)
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("解析目标文件 %s 失败: %w", file, err)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("目标列表为空")
	}
	return targets, nil
}

// formatURL 规范化目标：补协议头、保留 443 转 https、补尾部斜杠。
func formatURL(u string) string {
	if !strings.Contains(u, "://") {
		if strings.Contains(u, ":443") {
			u = strings.Replace(u, ":443", "", 1)
			u = "https://" + u
		} else {
			u = "http://" + u
		}
	}
	if !strings.HasSuffix(u, "/") {
		u += "/"
	}
	return u
}

// stdinInteractive 判断标准输入是否为真实交互终端。
// /dev/null 与管道会混过字符设备检查，必须用终端探测区分，
// 否则脚本与 MCP 等自动化场景会误触发交互菜单。
func stdinInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}
