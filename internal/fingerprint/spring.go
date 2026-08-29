// Package fingerprint 实现 Spring/SpringBoot 指纹识别：
// 默认 favicon 哈希、Whitelabel 错误页、Boot 标准 JSON 错误体三路信号加权判定。
package fingerprint

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"strings"

	"github.com/sspsec/Scan-Spring-GO/internal/client"
	"github.com/sspsec/Scan-Spring-GO/internal/model"
)

// Spring Boot 默认 favicon（绿色叶片）的 MD5。
const springFaviconMD5 = "0488faca4c19046b94d07c3ee83cf9d6"

// Detect 对目标做指纹识别，任何网络错误都不会导致整体失败，
// 仅降低置信度。
func Detect(ctx context.Context, t model.Target) (*model.FingerprintResult, error) {
	res := &model.FingerprintResult{Confidence: "none"}

	// 信号一：默认 favicon
	if resp, body, err := client.Do(ctx, t.Client, http.MethodGet, t.URL+"favicon.ico", nil, ""); err == nil {
		ct := resp.Header.Get("Content-Type")
		if strings.Contains(ct, "image") || strings.Contains(ct, "octet-stream") {
			sum := md5.Sum(body)
			if hex.EncodeToString(sum[:]) == springFaviconMD5 {
				res.Signals = append(res.Signals, "Spring 默认 favicon")
			}
		}
	}

	// 信号二：访问不存在的路径，观察错误页特征
	probe := fmt.Sprintf("__ssp_probe_%d.jsp", rand.Intn(1000000))
	if _, body, err := client.Do(ctx, t.Client, http.MethodGet, t.URL+probe, nil, ""); err == nil {
		page := string(body)
		switch {
		case strings.Contains(page, "Whitelabel Error Page"):
			res.Signals = append(res.Signals, "Whitelabel 错误页")
		case strings.Contains(page, `"timestamp"`) && strings.Contains(page, `"status"`):
			res.Signals = append(res.Signals, "Boot 标准 JSON 错误体")
		}
	}

	if len(res.Signals) == 0 {
		return res, nil
	}

	res.IsSpring = true
	for _, s := range res.Signals {
		if s == "Whitelabel 错误页" || strings.HasPrefix(s, "Spring 默认") {
			res.Confidence = "high"
			break
		}
	}
	if res.Confidence != "high" {
		res.Confidence = "medium"
	}
	return res, nil
}
