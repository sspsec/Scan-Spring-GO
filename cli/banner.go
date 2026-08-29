package cli

import "fmt"

// Banner 渐变色横幅，与 v1 视觉保持一致。
func Banner() {
	lines := []string{
		"▄▄▀▀▀▀▄  ▄▀▀▀▀▄  ▄▀▀▄▀▀▀▄",
		"█ █   ▐ █ █   ▐ █   █   █",
		"  ▀▄      ▀▄   ▐  █▀▀▀▀  ",
		"▀▄   █  ▀▄   █     █      ",
		" █▀▀▀    █▀▀▀    ▄▀       ",
		" ▐       ▐      █         ",
		"                ▐          ",
		"Spring vulnerability scanner (v" + Version + ", MCP ready).",
		"--------------------------------------------",
		":  https://github.com/sspsec/Scan-Spring-GO :",
		":  Author: sspsec                           :",
		"--------------------------------------------",
	}

	start, end := 0x00FF00, 0x006AAC
	steps := len(lines)
	for i, line := range lines {
		f := float64(i) / float64(steps)
		r := int(float64(start>>16&0xFF)*(1-f) + float64(end>>16&0xFF)*f)
		g := int(float64(start>>8&0xFF)*(1-f) + float64(end>>8&0xFF)*f)
		b := int(float64(start&0xFF)*(1-f) + float64(end&0xFF)*f)
		color := fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b)
		fmt.Println(color + line + "\033[0m")
	}
	fmt.Println()
}
