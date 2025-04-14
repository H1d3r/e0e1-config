package help

import "fmt"

func ShowHelp() {
	helpText := `
        ___       _                        __ _       
   ___ / _ \  ___/ |       ___ ___  _ __  / _(_) __ _ 
  / _ \ | | |/ _ \ |_____ / __/ _ \| '_ \| |_| |/ _  |
 |  __/ |_| |  __/ |_____| (_| (_) | | | |  _| | (_| |
  \___|\___/ \___|_|      \___\___/|_| |_|_| |_|\__, |
		e0e1-config - 配置扫描利用工具 - version: 1.20
     github: https://github.com/eeeeeeeeee-code/e0e1-config

用法:
  e0e1-config [选项]

选项:
	记事本:
  		-notepad                获取Windows11记事本和Notepad++的保存与未保存内容
	远程:  
		-sunlogin               获取向日葵的连接ID和密码(需要向日葵进程)
  		-todesk                 获取ToDesk的连接ID和密码(需要ToDesk进程)
	navicat:
  		-navicat-reg            读取系统注册表获取保存的Navicat连接信息
		-navicat-ncx string     对导出的Navicat-ncx文件进行解密
  		-navicat-version int    指定Navicat版本(11/12以及更高版本)，默认12
 	dbeaver:
		-dbeaver                获取DBeaver的数据库连接信息(找默认路径,不存在需要自定义指定)
		-dbeaver-config string  自定义指定DBeaver的credentials-config.json文件路径
		-dbeaver-sources string 自定义指定DBeaver的data-sources.json文件路径
	finalshell:  
		-finalshell             获取FinalShell的连接信息(找默认路径,不存在需要自定义指定)
		-finalshell-path string 自定义指定FinalShell的conn文件夹路径
	xshell:
		-xshell                 获取Xshell的连接信息(找默认路径,不存在需要自定义指定)
		-xshell-path string     自定义指定Xshell的Sessions文件夹路径
 	xftp:
		-xftp                   获取Xftp的连接信息(找默认路径,不存在需要自定义指定)
		-xftp-path string       自定义指定Xftp的Sessions文件夹路径
	filezilla:  
		-filezilla              获取FileZilla的连接信息(找默认路径,不存在需要自定义指定)
		-filezilla-path string  自定义指定FileZilla的配置文件夹路径
	winscp:
		-winscp                 获取WinSCP的连接信息(1.注册表获取 2.寻找默认配置文件)
		-winscp-path string     自定义指定WinSCP的配置文件路径
	浏览器:
		-bromium				指定要扫描的浏览器内核类型 (all, chromium, firefox)
		-browser-name			QQ等，需要联结browser-path参数
		-browser-path			指定浏览器数据路径，需要联结browser-name参数
		-browser-format			指定输出格式 (csv 或 json)，为空只输出到控制台
		-browser-outdir			指定浏览器数据保存目录，默认out目录，需要-browser-format为csv或者json时输出
		-browers-limit			指定读取的数据行数，默认2000行数据，避免数据过多
	search:
		-search					搜索敏感配置信息
		-search-path 			指定搜索路径(默认当前目录)
		-search-regex			自定义正则表达式，多个表达式用逗号分隔
		-search-user-only		仅使用用户提供的正则表达式
		-search-file-types		自定义文件类型列表
		-search-exten-only		仅搜索指定扩展名的文件
		-search-size-limit		文件大小限制(默认10*1024*1024字节)
		-search-char-limit 		匹配行字符数限制(默认当前目录)
  	基础功能:
		-all                    执行所有功能
  		-output string          输出结果到指定文件
  		-help                   显示帮助信息

示例:
  e0e1-config -winscp
  e0e1-config -winscp -winscp-path "C:\path\winscp.ini"
  e0e1-config -all
  e0e1-config -all -output "result.txt"
  e0e1-config -bromium all -output "result.txt"
  e0e1-config -all -browser-format csv -output "result.txt" 
`
	fmt.Println(helpText)
}
