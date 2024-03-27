package common

import (
	"bufio"
	"fmt"
	"github.com/fatih/color"
	"math/rand"
	"os"
	"regexp"
	"strings"
)

func ReadUrlFromFile(filePath string) ([]string, error) {
	var urls []string

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		url = FormatURL(url)
		urls = append(urls, url)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

func FormatURL(url string) string {
	if !strings.Contains(url, "://") {
		if strings.Contains(url, ":443") {
			url = strings.Replace(url, ":443", "", 1)
			url = "https://" + url
		} else {
			url = "http://" + url
		}
	}

	if !strings.HasSuffix(url, "/") {
		url = url + "/"
	}
	return url
}

func GetRandomUserAgent() string {
	randomIndex := rand.Intn(len(userAgents))
	return userAgents[randomIndex]
}

func MergeHeaders(headerMaps ...map[string]string) map[string]string {
	merged := make(map[string]string)
	for _, headers := range headerMaps {
		for key, value := range headers {
			merged[key] = value
		}
	}
	return merged
}

func ExtractResult(input string, regex string) string {

	re := regexp.MustCompile(regex)

	matches := re.FindStringSubmatch(input)

	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func PrintVulnerabilityConfirmation(vulnerabilityName, targetURL, confirmationMessage string, id string) {
	color.Red("[+] %s已确认存在:\n", vulnerabilityName)
	color.Red("    - 目标: %s\n", targetURL)
	color.Red("    - Poc: %s\n", confirmationMessage)
	color.Red("    - 漏洞编号: %s\n", id)
	fmt.Println()
}

func ContainsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func WriteToFile(filename, content string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(content + "\n"); err != nil {
		return err
	}
	return nil
}
