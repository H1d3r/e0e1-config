# e0e1-config

## 功能简介
  该工具主要用于后渗透方面，包含：
  1. Windows记事本和Notepad++ 保存与未保存内容提取
  2. 向日葵（支持最新版本）  获取id、密码、配置信息
  3. ToDesk  获取id、密码、配置信息
  4. Navicat  获取数据库连接信息
  5. DBeaver  获取数据库连接信息
  6. FinalShell  获取连接信息
  7. Xshell和Xftp  获取连接信息
  8. FileZilla  获取连接信息
  9. winscp  获取连接信息
  10. 敏感信息文件搜索

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

## 微步沙盒分析
![QQ_1744285073224](https://github.com/user-attachments/assets/25b167aa-193b-417b-b393-7887806114f1)


## 效果展示

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
