package common

import (
	"flag"
	"fmt"
)

func interpolateColor(start, end, steps int) []string {
	var colors []string
	for i := 0; i < steps; i++ {

		r := int(float64(start>>16&0xFF)*(1-float64(i)/float64(steps)) + float64(end>>16&0xFF)*float64(i)/float64(steps))
		g := int(float64(start>>8&0xFF)*(1-float64(i)/float64(steps)) + float64(end>>8&0xFF)*float64(i)/float64(steps))
		b := int(float64(start&0xFF)*(1-float64(i)/float64(steps)) + float64(end&0xFF)*float64(i)/float64(steps))

		color := fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b)
		colors = append(colors, color)
	}
	return colors
}

func Banner() {
	lines := []string{
		"▄▄▀▀▀▀▄  ▄▀▀▀▀▄  ▄▀▀▄▀▀▀▄",
		"█ █   ▐ █ █   ▐ █   █   █",
		"  ▀▄      ▀▄   ▐  █▀▀▀▀  ",
		"▀▄   █  ▀▄   █     █      ",
		" █▀▀▀    █▀▀▀    ▄▀       ",
		" ▐       ▐      █         ",
		"                ▐          ",
		"Spring vulnerability scanner.",
		"--------------------------------------------",
		":  https://github.com/sspsec/Scan-Spring-GO :",
		":  Author: sspsec                           :",
		"--------------------------------------------",
	}

	startColor := 0x00FF00
	endColor := 0x006AAC
	steps := len(lines)

	colors := interpolateColor(startColor, endColor, steps)

	for i, line := range lines {
		color := colors[i]

		for _, char := range line {
			fmt.Print(color + string(char) + "\033[0m")
		}

		fmt.Println()
	}
}

var (
	UrlPtr     = flag.String("u", "", "对单一URL进行信息泄露扫描")
	UrlfilePtr = flag.String("uf", "", "读取目标TXT进行信息泄露扫描")
	VulPtr     = flag.String("v", "", "对单一URL进行漏洞利用")
	VulfilePtr = flag.String("vf", "", "读取目标TXT进行批量漏洞扫描")
	ProxyPtr   = flag.String("p", "", "使用HTTP代理，格式：http://<username>:<password>@<host>:<port>")
	DelayPtr   = flag.Int("delay", 0, "设置请求之间的延迟时间，单位秒")
)

func Flag() {
	Banner()
	flag.Parse()

	if *UrlPtr == "" && *UrlfilePtr == "" && *VulPtr == "" && *VulfilePtr == "" {
		flag.PrintDefaults()
	}
}
