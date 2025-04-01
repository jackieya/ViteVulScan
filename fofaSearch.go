package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gookit/color"
	"gopkg.in/ini.v1"
	"io"
	"net/http"
	"sync"
	"time"
)

var INFO = color.Bluef
var SUCCESS = color.Greenf
var WARNING = color.Yellowf
var ERROR = color.Redf
var cfgFile = "app.ini"

type FofaRespJson struct {
	Error           bool       `json:"error"`
	ConsumedFpoint  int        `json:"consumed_fpoint"`
	RequiredFpoints int        `json:"required_fpoints"`
	Size            int        `json:"size"`
	Page            int        `json:"page"`
	Mode            string     `json:"mode"`
	Query           string     `json:"query"`
	Results         [][]string `json:"results"`
	Errmsg          string     `json:"errmsg"`
}

type Target struct {
	HOST       string
	IP         string
	Port       string
	Protocal   string
	Url        string
	StatusCode int
	Platform   string
}

var wg sync.WaitGroup
var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
var client = &http.Client{
	Transport: tr,
	Timeout:   10 * time.Second,
}

// 封装一个简单的get请求
func Request(url string) (*http.Response, error) {

	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		ERROR("[-] 连接%s错误!\n", url)
		return nil, err
	}
	request.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	htp, err := client.Do(request)
	if err != nil {
		ERROR("[-] 连接%s错误!\n", url)
		return nil, err
	}
	return htp, nil
}

func (target *Target) CheckAlive() {
	target.Url = fmt.Sprintf("%s://%s", target.Protocal, target.HOST)
	if target.Port == "80" || target.Port == "443" {
		target.Url = fmt.Sprintf("%s:%s", target.Url, target.Port)
	}
	htp, err := Request(target.Url)
	defer htp.Body.Close()
	if err != nil {
		target.StatusCode = 0
		return
	}
	SUCCESS("[+] %s存活!\n", target.Url)
	target.StatusCode = htp.StatusCode
}
func GetFofaAssets() ([]Target, error) {
	cfg, err := ini.Load(cfgFile)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("请检查配置文件%s!退出~", cfgFile))
	}
	fofaSec := cfg.Section("fofa")
	FofaKey := fofaSec.Key("fofaKey").String()
	if FofaKey == "" {
		return nil, errors.New("未配置fofakey字段!")
	}
	FofaQuery := fofaSec.Key("fofaQuery").String()
	qbase64 := base64.StdEncoding.EncodeToString([]byte(FofaQuery))
	num, err := fofaSec.Key("num").Int()
	if err != nil {
		return nil, errors.New("请检查配置文件中num字段信息!")
	}
	size := 100
	MAXPAGE := num / 100
	fields := "host,ip,port,protocal"
	AliveList := []Target{}
	for page := 1; page <= MAXPAGE; page++ {
		FofaUrl := fmt.Sprintf("https://fofa.info/api/v1/search/all?key=%s&qbase64=%s&page=%v&size=%v&fields=%v", FofaKey, qbase64, page, size, fields)
		resp, err := http.Get(FofaUrl)
		if err != nil {
			return nil, errors.New("请检查网络问题!")
		}
		defer resp.Body.Close()
		jsonStr, err := io.ReadAll(resp.Body)
		RespJson := FofaRespJson{}
		err = json.Unmarshal(jsonStr, &RespJson)
		if err != nil {
			return nil, errors.New("fofa请求出错")
		}
		if RespJson.Error == true {
			return nil, errors.New(RespJson.Errmsg)
		}
		wg.Add(len(RespJson.Results))
		for _, target := range RespJson.Results {
			newTarget := Target{HOST: target[0], IP: target[1], Port: target[2], Protocal: target[3]}
			go func(target *Target) {
				defer wg.Done()
				target.CheckAlive()
				if target.StatusCode != 0 {
					AliveList = append(AliveList, *target)
				}
			}(&newTarget)
		}
		wg.Wait()
	}
	return AliveList, nil
}
