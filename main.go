package main

import (
	"os"

	"github.com/sspsec/Scan-Spring-GO/cli"
	"github.com/sspsec/Scan-Spring-GO/internal/mcpserver"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "mcp" {
		os.Exit(mcpserver.Main(os.Args[2:]))
	}
	os.Exit(cli.Run())
}
