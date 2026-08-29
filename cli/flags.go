package cli

import (
	"flag"
	"fmt"
)

// Version 语义化版本号，-version 输出。
const Version = "2.1.0"

var (
	urlPtr      = flag.String("u", "", "对单一 URL 进行信息泄露扫描")
	urlFilePtr  = flag.String("uf", "", "读取目标 TXT 进行信息泄露扫描")
	vulPtr      = flag.String("v", "", "对单一 URL 进行漏洞检测（命中后可交互利用）")
	vulFilePtr  = flag.String("vf", "", "读取目标 TXT 进行批量漏洞检测")
	proxyPtr    = flag.String("p", "", "HTTP/SOCKS5 代理，格式：socks5|http://<user>:<pass>@<host>:<port>")
	delayPtr    = flag.Int("delay", 0, "请求全局间隔（秒），0 为不限速")
	threadsPtr  = flag.Int("t", 20, "单目标端点探测并发数")
	timeoutPtr  = flag.Int("timeout", 6, "单请求超时（秒）")
	dictMerge   = flag.String("d", "", "自定义字典文件，与内置字典合并")
	dictReplace = flag.String("D", "", "自定义字典文件，完全替换内置字典")
	outPtr      = flag.String("o", "result.txt", "信息泄露扫描结果输出文件")
	debugPtr    = flag.Bool("debug", false, "输出每个失败请求的详情")
	cmdPtr      = flag.String("c", "", "命中漏洞后执行单条命令（配合 -v，非交互）")
	cmdCvePtr   = flag.String("ce", "", "指定执行命令的漏洞 ID（默认首个命中且可利用的模块）")
	showVersion = flag.Bool("version", false, "输出版本号")
)

// Parse 注册并解析命令行参数。
func Parse() {
	flag.Parse()
}

// usageHint 在未提供任何目标时打印参数说明。
func usageHint() {
	fmt.Println("未指定目标，可用参数如下：")
	flag.PrintDefaults()
	fmt.Println("\n示例：")
	fmt.Println("  Scan-Spring-GO -u https://target.com")
	fmt.Println("  Scan-Spring-GO -uf urls.txt -t 30 -d mydict.txt")
	fmt.Println("  Scan-Spring-GO -v https://target.com")
}
