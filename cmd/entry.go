package cmd

import (
	"bufio"
	"flag"
	"os"
	"path"
	"strings"
	"sync"
)

var assets = make(chan Target, 100)
var lock sync.Mutex
var RootDir, _ = os.Getwd()
var ResultDir = path.Join(RootDir, "result")
var DictDir = path.Join(RootDir, "dict")
var ConfigDir = path.Join(RootDir, "config")

func Run() {
	if Url == "" && NeedFofa == false && FileName == "" {
		ERROR("[-] 请至少输入-u/-url|-fofa|-filename/-f等参数\n")
		flag.Usage()
		os.Exit(1)
	}
	CVE = strings.ToLower(CVE)
	cveOptions := map[string]struct{}{
		"cve-2025-30208": {},
		"cve-2025-31125": {},
		"cve-2025-31486": {},
	}
	if _, ok := cveOptions[CVE]; !ok {
		ERROR("[-] 对于CVE参数，请输入cve-2025-30208、cve-2025-31125或者cve-2025-31486\n")
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
			file, err := os.Open(path.Join(RootDir, FileName))
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
				wg.Add(1)
				go func() {
					defer wg.Done()
					target, ok := NormalizeUrl(Url)
					if !ok {
						ERROR("[-] 请检查url：%s是否正确！\n", Url)
						return
					}
					vul := target.CheckAndExploit()
					if vul {
						lock.Lock()
						successList = append(successList, target)
						lock.Unlock()
					}
				}()
			}
			wg.Wait()
			if len(successList) != 0 {
				SaveResult(successList)
			}
		}
	} else {
		// 联动fofa进行检测， 先从fofa中取出相应的目标资产，然后检测存活度、去重，最终利用相应的cve进行批量检测

		err := GetFofaAssets()
		if err != nil {
			ERROR("[-] 出现了错误: %s\n", err.Error())
			os.Exit(1)
		}
		var successList []Target
		for asset := range assets {
			wg.Add(1)
			go func(asset Target) {
				defer wg.Done()
				vul := asset.CheckAndExploit()
				if vul {
					lock.Lock()
					successList = append(successList, asset)
					lock.Unlock()
				}
			}(asset)
		}
		wg.Wait()
		if len(successList) != 0 {
			SaveResult(successList)
		}
	}
}
