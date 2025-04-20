# e0e1-config

## 功能简介
  该工具主要用于后渗透方面，包含：
  1. firefox、ie和chromium内核浏览器，提取浏览记录、下载记录、书签、cookie、用户密码
  2. Windows记事本和Notepad++ 保存与未保存内容提取
  3. 向日葵（支持最新版本）  获取id、密码、配置信息
  4. ToDesk  获取id、密码、配置信息
  5. Navicat  获取数据库连接信息
  6. DBeaver  获取数据库连接信息
  7. FinalShell  获取连接信息
  8. Xshell和Xftp  获取连接信息
  9. FileZilla  获取连接信息
  10. winscp  获取连接信息
  11. 敏感信息文件搜索

## 版本更新
2025.4.20-1.30版本更新内容
  1. 首先将go版本从1.2.13回退到1.2.0，不然就不支持windows低版本了，这个是测试ie浏览器的时候发现的问题
     
  2. ie浏览器内容解密
    获取ie浏览器 登录凭据、书签、浏览记录

  3. 他是默认是直接输出到控制台的，但是测试的时候没注意将output填入了默认。
     

2025.4.14-1.20版本更新内容
  1. firefox浏览器内容解密

      获取firef5ox浏览器 浏览记录、下载记录、书签、cookie、用户密码
  2. chromium内核浏览器内容解密

      获取chromium内核浏览器 浏览记录、下载记录、书签、cookie、用户密码
    默认检测Chrome、Chrome Beta、Chromium、Edge、360 Speed、360 Speed X、Brave、QQ、Opera、OperaGX、Vivaldi、CocCoc、Yandex、DCBrowser、Old Sogou、New Sogou等多种浏览器

## 工具使用示例
> 编译
> 
> go build -ldflags "-w -s" ./
> 

> 参数示例
> 
>   e0e1-config -winscp   #获取winscp连接信息，通过默认配置文件和注册表
> 
>   e0e1-config -winscp -winscp-path "C:\path\winscp.ini"  #自定义配置文件路径
> 
>   e0e1-config -all      #执行所有功能
> 
>   e0e1-config -all -output "result.txt"   #执行所有功能，并将输出 输入到result.txt文件中
>
>   e0e1-config -bromium all -output "result.txt"
>
>  e0e1-config -all -browser-format csv -output "result.txt"
> 

## 微步沙盒分析
因为添加了浏览器方面的东西，所以会有一些敏感的东西，会有一点检出，不过效果还好。
![image](https://github.com/user-attachments/assets/a4bd2ec1-f436-4236-ab04-166de63844ec)

## 赞赏码
开源维护不易，有钱的大哥，可以请我喝一杯咖啡努努力ᕙ(• ॒ ູ•)ᕘ
![image](https://github.com/user-attachments/assets/fa9176a9-5247-4d0c-bd09-82f40125589e)


## 效果展示
浏览器信息获取
![image](https://github.com/user-attachments/assets/5969b2df-cd24-45fa-9971-f71a629d70b1)
![image](https://github.com/user-attachments/assets/ef190458-1cd6-4265-93dc-dce40571f018)


敏感信息文件搜集功能
![QQ_1744284336027](https://github.com/user-attachments/assets/5f87126e-6ec6-428d-9c85-f158edee5f5a)

notepad功能
![image](https://github.com/user-attachments/assets/905ca861-904f-4f80-ad27-eb799b7262d3)

向日葵功能（支持最新版本）
![image](https://github.com/user-attachments/assets/feae53bd-ce29-4c6b-8b72-1ca79d380379)

todesk功能
![image](https://github.com/user-attachments/assets/facf1d4e-6032-4d02-ad00-ca76d8f2c15c)

navicat功能
![QQ_1744283637007](https://github.com/user-attachments/assets/eed76767-f08a-4ec9-b1f7-28f7d36f48e5)

dbeaver功能
![QQ_1744283684310](https://github.com/user-attachments/assets/ec2f6a10-3cf2-43bb-8be1-2d0ea10d748a)

finalshell功能
![QQ_1744283820508](https://github.com/user-attachments/assets/6f8cb22b-7f79-4905-aed2-c12a89a7854c)

xshell功能
![QQ_1744283871974](https://github.com/user-attachments/assets/3fcbef27-78c5-4709-89d4-a9d9b7b8b1b0)

xftp功能
![QQ_1744283915688](https://github.com/user-attachments/assets/55e0c2af-0591-4336-a06f-18389e35fb11)

filezilla功能
![QQ_1744283962054](https://github.com/user-attachments/assets/4ea52413-2df7-4709-85a4-0c35a73513ef)

winscp功能
![QQ_1744284044686](https://github.com/user-attachments/assets/8812ca9e-5064-4fed-aad1-88f76c3b570c)


## 工具参考
>  感谢下面各位的开源精神
> 
>  https://github.com/doki-byte/read_sun_todesk
> 
>  https://github.com/lele8/SharpDBeaver
> 
>  https://github.com/AabyssZG/NavicatPwn
>
>  https://github.com/RowTeam/SharpDecryptPwd
> 
>  https://github.com/sf197/GetPwd
> 
>  https://github.com/ShuYeJang/ToDeskSunDump
> 
>  https://github.com/Naturehi666/searchall
>
>  https://github.com/StarfireLab/SharpWeb
>
>  https://github.com/moonD4rk/HackBrowserData
