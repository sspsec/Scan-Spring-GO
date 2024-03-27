package common

import "flag"

func Banner() {
	banner := `______________________ 
__  ___/_  ___/__  __ \
_(__  )_(__  )__  /_/ /
/____/ /____/ _  .___/ 
              /_/
              version:` + version + `

`
	print(banner)
}

var (
	UrlPtr     = flag.String("u", "", "对单一URL进行信息泄露扫描")
	UrlfilePtr = flag.String("uf", "", "读取目标TXT进行信息泄露扫描")
	VulPtr     = flag.String("v", "", "对单一URL进行漏洞利用")
	VulfilePtr = flag.String("vf", "", "读取目标TXT进行批量漏洞扫描")
	//proxyPtr   = flag.String("p", "", "使用HTTP代理")
	//fofaPtr    = flag.String("f", "", "使用Fofa导出Spring框架资产")
)

func Flag() {
	Banner()
	flag.Parse()
}
