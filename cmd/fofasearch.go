package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/ini.v1"
	"io"
	"net/http"
	"path"
	"sync"
	"time"
)

var wg sync.WaitGroup

var CfgFile = path.Join(ConfigDir, "app.ini")
var sendWg sync.WaitGroup

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

// 封装一个简单的get请求

func GetFofaAssets() error {
	cfg, err := ini.Load(CfgFile)
	if err != nil {
		return errors.New(fmt.Sprintf("请检查配置文件%s!退出~", CfgFile))
	}
	fofaSec := cfg.Section("fofa")
	FofaKey := fofaSec.Key("fofaKey").String()
	if FofaKey == "" {
		return errors.New("未配置fofakey字段!")
	}
	FofaQuery := fofaSec.Key("fofaQuery").String()
	qbase64 := base64.StdEncoding.EncodeToString([]byte(FofaQuery))
	num, err := fofaSec.Key("num").Int()
	if err != nil {
		return errors.New("请检查配置文件中num字段信息!")
	}
	size := 100
	MAXPAGE := num / size
	fields := "host,ip,port,protocol"
	for page := 1; page <= MAXPAGE; page++ {
		FofaUrl := fmt.Sprintf("https://fofa.info/api/v1/search/all?key=%s&qbase64=%s&page=%v&size=%v&fields=%v", FofaKey, qbase64, page, size, fields)
		resp, err := http.Get(FofaUrl)
		if err != nil {
			return errors.New("请检查网络问题!")
		}
		defer resp.Body.Close()
		jsonStr, err := io.ReadAll(resp.Body)
		RespJson := FofaRespJson{}
		err = json.Unmarshal(jsonStr, &RespJson)
		if err != nil {
			return errors.New("fofa请求出错")
		}
		if RespJson.Error == true {
			return errors.New(RespJson.Errmsg)
		}
		hostMap := map[string]struct{}{} // 用来去重
		for _, target := range RespJson.Results {
			if _, ok := hostMap[target[0]]; ok {
				continue
			}
			hostMap[target[0]] = struct{}{}
			newTarget := Target{HOST: target[0], IP: target[1], Port: target[2], Protocol: target[3]}
			sendWg.Add(1)
			wg.Add(1)
			go func(target *Target) {
				defer sendWg.Done()
				defer wg.Done()
				target.CheckAlive()
				if target.StatusCode != 0 {
					assets <- *target
				}
			}(&newTarget)
		}
		time.Sleep(time.Second * 2)
	}
	go func() {
		sendWg.Wait()
		close(assets)
	}()
	return nil
}
