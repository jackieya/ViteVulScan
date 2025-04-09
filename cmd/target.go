package cmd

import (
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
var client = &http.Client{
	Transport: tr,
	Timeout:   10 * time.Second,
}

type Target struct {
	HOST       string
	IP         string
	Port       string
	Protocol   string
	Url        string
	StatusCode int
	Platform   string
	RootPath   string
}

func (target *Target) CheckAlive() {
	if !strings.Contains(target.HOST, "://") {
		target.Url = fmt.Sprintf("%s://%s", target.Protocol, target.HOST)
	} else {
		target.Url = target.HOST
	}
	if target.Port == "80" || target.Port == "443" {
		target.Url = fmt.Sprintf("%s:%s", target.Url, target.Port)
	}
	htp, err := Request(target.Url)
	if err != nil {
		target.StatusCode = 0
		return
	}
	defer htp.Body.Close()
	SUCCESS("[+] %s存活!\n", target.Url)
	target.StatusCode = htp.StatusCode
}

func Request(url string) (*http.Response, error) {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		ERROR("[-] 访问%s发生错误!\n", url)
		return nil, err
	}
	request.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	htp, err := client.Do(request)
	if err != nil {
		ERROR("[-] 访问%s发生错误!\n", url)
		return nil, err
	}
	return htp, nil
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
					Protocol:   u.Scheme,
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
			Protocol:   u2.Scheme,
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
		Protocol:   u.Scheme,
		Url:        targetUrl,
		StatusCode: request.StatusCode,
	}, true
}

func SaveResult(successList []Target) {
	fileName := path.Join(ResultDir, fmt.Sprintf("%d", time.Now().Unix())+".csv")
	dir := filepath.Dir(fileName)
	err := os.MkdirAll(dir, 0777)
	if err != nil {
		ERROR("[-] 创建目录 %s 失败", dir)
		os.Exit(1)
	}
	file, err := os.Create(fileName)
	if err != nil {
		ERROR("[-] 未能成功将结果输出到文件中！")
		os.Exit(1)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	writer.Write([]string{"IP", "PORT", "URL", "Protocal", "Platform", "RootPath"})
	for _, result := range successList {
		writer.Write([]string{result.IP, result.Port, result.Url, result.Protocol, result.Platform, result.RootPath})
	}
	SUCCESS("[+] 成功将结果写入到%s文件中", fileName)
}

func (target *Target) CheckAndExploit() bool {
	platform, vul, sep := "", false, ""
	if CVE == "cve-2025-30208" {
		platform, vul = target.check_CVE_2025_30208(sep)

	} else if CVE == "cve-2025-31125" {
		platform, vul = target.check_CVE_2025_31125(sep)
		if !vul {
			sep = "/@fs"
			platform, vul = target.check_CVE_2025_31125(sep)
		}
	} else {
		platform, vul = target.check_CVE_2025_31486(sep)
		if !vul {
			sep = "/@fs"
			platform, vul = target.check_CVE_2025_31486(sep)
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
				SUCCESS("[+] 利用成功!所有扫描的敏感文件已存放在%s目录下\n", path.Join(ResultDir, target.HOST))
			} else if CVE == "cve-2025-31125" {
				ok, err := target.exploit_CVE_2025_31125(sep)
				if !ok {
					ERROR("[-]利用漏洞%s失败！%s\n", CVE, err)
					return vul
				}
				SUCCESS("[+] 利用成功!所有扫描的敏感文件已存放在%s目录下\n", path.Join(ResultDir, target.HOST))
			} else {
				ok, err := target.exploit_CVE_2025_31486(sep)
				if !ok {
					ERROR("[-]利用漏洞%s失败！%s\n", CVE, err)
					return vul
				}
				SUCCESS("[+] 利用成功!所有扫描的敏感文件已存放在%s目录下\n", path.Join(ResultDir, target.HOST))
			}
		}
	} else {
		ERROR("[-] %s貌似不存在%s漏洞！\n", target.Url, CVE)
	}
	return vul
}
