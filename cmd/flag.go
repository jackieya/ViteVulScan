package cmd

import (
	"flag"
)

var (
	CVE      string
	NeedFofa bool
	Url      string
	FileName string
	Exploit  bool
)

func init() {
	flag.StringVar(&CVE, "cve", "cve-2025-30208", "使用哪个cve漏洞进行检测。支持CVE_2025_30208和CVE_2025_31125。")
	flag.BoolVar(&NeedFofa, "fofa", false, "确认是否需要fofa")
	flag.StringVar(&Url, "url", "", "检测存在漏洞的url")
	flag.StringVar(&Url, "u", "", "检测存在漏洞的url")
	flag.StringVar(&FileName, "filename", "", "批量检测文件")
	flag.StringVar(&FileName, "f", "", "批量检测文件")
	flag.BoolVar(&Exploit, "e", false, "是否深度利用漏洞(谨慎使用)")
	flag.Parse()
}
