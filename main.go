package main

import (
	"e0e1-config/pkg/browers"
	"e0e1-config/pkg/dbeaver"
	"e0e1-config/pkg/filezilla"
	"e0e1-config/pkg/finalshell"
	"e0e1-config/pkg/help"
	"e0e1-config/pkg/navicat"
	"e0e1-config/pkg/notepad"
	"e0e1-config/pkg/remotecontrol"
	"e0e1-config/pkg/search"
	"e0e1-config/pkg/winscp"
	"e0e1-config/pkg/xshell"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	os.Setenv("LANG", "zh_CN.UTF-8")

	notepadFlag := flag.Bool("notepad", false, "获取Windows11记事本和Notepad++的保存与未保存内容")
	sunloginFlag := flag.Bool("sunlogin", false, "获取向日葵的连接ID和密码")
	todeskFlag := flag.Bool("todesk", false, "获取ToDesk的连接ID和密码")
	navicatReg := flag.Bool("navicat-reg", false, "读取系统注册表获取保存的Navicat连接")
	navicatNcxFile := flag.String("navicat-ncx", "", "对导出的Navicat-ncx文件进行解密")
	navicatVersion := flag.Int("navicat-version", 12, "指定Navicat版本(11/12以及更高版本)，默认12")
	dbeaverFlag := flag.Bool("dbeaver", false, "获取DBeaver的数据库连接信息")
	dbeaverConfig := flag.String("dbeaver-config", "", "指定DBeaver的credentials-config.json文件路径")
	dbeaverSources := flag.String("dbeaver-sources", "", "指定DBeaver的data-sources.json文件路径")
	finalshellFlag := flag.Bool("finalshell", false, "获取FinalShell的连接信息")
	finalshellPath := flag.String("finalshell-path", "", "指定FinalShell的conn文件夹路径")
	xshellFlag := flag.Bool("xshell", false, "获取Xshell的连接信息")
	xshellPath := flag.String("xshell-path", "", "自定义指定Xshell的Sessions文件夹路径")
	xftpFlag := flag.Bool("xftp", false, "获取Xftp的连接信息")
	xftpPath := flag.String("xftp-path", "", "自定义指定Xftp的Sessions文件夹路径")
	filezillaFlag := flag.Bool("filezilla", false, "获取FileZilla的连接信息")
	filezillaPath := flag.String("filezilla-path", "", "自定义指定XFileZilla的配置文件夹路径")
	winscpFlag := flag.Bool("winscp", false, "获取WinSCP的连接信息")
	winscpPath := flag.String("winscp-path", "", "自定义指定WinSCP的配置文件路径")

	bromiumFlag := flag.String("bromium", "", "指定要扫描的浏览器内核类型 (all, chromium, firefox,ie)")
	browersName := flag.String("browser-name", "", "指定浏览器名称")
	browersPath := flag.String("browser-path", "", "指定浏览器数据路径")
	browersFormat := flag.String("browser-format", "", "输出格式 (csv 或 json)，默认只输出到控制台")
	browersOutDir := flag.String("browser-outdir", "out", "指定浏览器数据保存目录")
	browserFileLimit := flag.String("browers-limit", "2000", "指定读取的数据行数，默认2000个数据")

	searchFlag := flag.Bool("search", false, "搜索敏感配置信息")
	searchPath := flag.String("search-path", ".", "指定搜索路径")
	searchRegex := flag.String("search-regex", "", "自定义正则表达式，多个表达式用逗号分隔")
	searchUserOnly := flag.Bool("search-user-only", false, "仅使用用户提供的正则表达式")
	searchFileTypes := flag.String("search-file-types", "", "自定义文件类型列表")
	searchExtenOnly := flag.Bool("search-exten-only", false, "仅搜索指定扩展名的文件")
	searchSizeLimit := flag.Int64("search-size-limit", 10*1024*1024, "文件大小限制(字节)")
	searchCharLimit := flag.Int("search-char-limit", 1000, "匹配行字符数限制")

	allFlag := flag.Bool("all", false, "执行所有功能")
	outputFile := flag.String("output", "", "输出结果到指定文件")
	helpFlag := flag.Bool("help", false, "显示帮助信息")
	flag.Parse()

	if *helpFlag || (!*notepadFlag && !*sunloginFlag && !*todeskFlag && !*dbeaverFlag && !*finalshellFlag &&
		!*navicatReg && *navicatNcxFile == "" && !*xshellFlag && !*xftpFlag && !*filezillaFlag && !*winscpFlag &&
		!*searchFlag && !*allFlag && *dbeaverConfig == "" && *dbeaverSources == "" &&
		*finalshellPath == "" && *xshellPath == "" && *xftpPath == "" && *filezillaPath == "" && *winscpPath == "" &&
		*bromiumFlag == "" && *browersName == "" && *browersPath == "") {
		help.ShowHelp()
		return
	}

	var resultBuilder strings.Builder

	if *notepadFlag || *allFlag {
		notepadResult := notepad.GetNotepadContent()
		if notepadResult != "" {
			resultBuilder.WriteString("===== 记事本内容 =====\n")
			resultBuilder.WriteString(notepadResult)
			resultBuilder.WriteString("\n\n")
		}
	}

	if *todeskFlag || *allFlag {
		fmt.Println("正在扫描ToDesk...")
		todeskResult, err := remotecontrol.ScanRemoteControl("todesk")
		if err != nil {
			fmt.Printf("ToDesk扫描失败: %v\n", err)
		} else if todeskResult != "" {
			resultBuilder.WriteString(todeskResult)
			resultBuilder.WriteString("\n")
		}
	}

	if *sunloginFlag || *allFlag {
		fmt.Println("正在扫描向日葵...")
		sunloginResult, err := remotecontrol.ScanRemoteControl("sunlogin")
		if err != nil {
			fmt.Printf("向日葵扫描失败: %v\n", err)
		} else if sunloginResult != "" {
			resultBuilder.WriteString(sunloginResult)
			resultBuilder.WriteString("\n")
		}
	}

	if *dbeaverFlag || *allFlag || (*dbeaverConfig != "" || *dbeaverSources != "") {
		fmt.Println("正在扫描DBeaver...")
		dbeaverResult, err := dbeaver.ScanDBeaver(*dbeaverConfig, *dbeaverSources)
		if err != nil {
			fmt.Printf("DBeaver扫描失败: %v\n", err)
		} else if dbeaverResult != "" {
			resultBuilder.WriteString("===== DBeaver信息 =====\n")
			resultBuilder.WriteString(dbeaverResult)
			resultBuilder.WriteString("\n")
		}
	}

	if *finalshellFlag || *allFlag {
		fmt.Println("正在扫描FinalShell...")
		finalshellResult, err := finalshell.ScanFinalShell(*finalshellPath)
		if err != nil {
			fmt.Printf("FinalShell扫描失败: %v\n", err)
		} else if finalshellResult != "" {
			resultBuilder.WriteString("===== FinalShell信息 =====\n")
			resultBuilder.WriteString(finalshellResult)
			resultBuilder.WriteString("\n")
		}
	}

	if *xshellFlag || *allFlag {
		xshellResult, err := xshell.ScanXshell(*xshellPath)
		if err != nil {
			fmt.Printf("Xshell扫描失败: %v\n", err)
		} else if xshellResult != "" {
			resultBuilder.WriteString("===== Xshell信息 =====\n")
			resultBuilder.WriteString(xshellResult)
			resultBuilder.WriteString("\n")
		}
	}

	if *xftpFlag || *allFlag {
		xftpResult, err := xshell.ScanXftp(*xftpPath)
		if err != nil {
			fmt.Printf("Xftp扫描失败: %v\n", err)
		} else if xftpResult != "" {
			resultBuilder.WriteString("===== Xftp信息 =====\n")
			resultBuilder.WriteString(xftpResult)
			resultBuilder.WriteString("\n")
		}
	}

	if *filezillaFlag || *allFlag {
		fmt.Println("正在扫描FileZilla...")
		filezillaResult, err := filezilla.ScanFileZilla(*filezillaPath)
		if err != nil {
			fmt.Printf("FileZilla扫描失败: %v\n", err)
		} else if filezillaResult != "" {
			resultBuilder.WriteString("===== FileZilla信息 =====\n")
			resultBuilder.WriteString(filezillaResult)
			resultBuilder.WriteString("\n")
		}
	}

	if *navicatReg || *navicatNcxFile != "" || *allFlag {
		fmt.Println("正在处理Navicat信息...")
		navicatResult, err := navicat.ScanNavicat(*navicatNcxFile, *navicatReg || *allFlag, *navicatVersion)
		if err != nil {
			fmt.Printf("Navicat处理失败: %v\n", err)
		} else if navicatResult != "" {
			resultBuilder.WriteString("===== Navicat信息 =====\n")
			resultBuilder.WriteString(navicatResult)
			resultBuilder.WriteString("\n")
		}
	}

	if *winscpFlag || *allFlag {
		fmt.Println("正在扫描WinSCP...")
		winscpResult, err := winscp.ScanWinSCP(*winscpPath)
		if err != nil {
			fmt.Printf("WinSCP扫描失败: %v\n", err)
		} else if winscpResult != "" {
			resultBuilder.WriteString("===== WinSCP信息 =====\n")
			resultBuilder.WriteString(winscpResult)
			resultBuilder.WriteString("\n")
		}
	}

	if *searchFlag || *allFlag {
		fmt.Println("正在执行敏感配置信息搜索...")

		var userRegexList []string
		if *searchRegex != "" {
			userRegexList = strings.Split(*searchRegex, ",")
		}

		options := search.SearchOptions{
			Path:               *searchPath,
			UserRegexList:      userRegexList,
			UserOnlyFlag:       *searchUserOnly,
			CustomFileTypeList: *searchFileTypes,
			ExtenOnlyFlag:      *searchExtenOnly,
			SizeLimit:          *searchSizeLimit,
			CharLimit:          *searchCharLimit,
		}

		searchResult, err := search.Search(options)
		if err != nil {
			fmt.Printf("搜索失败: %v\n", err)
		} else if searchResult != "" {
			resultBuilder.WriteString("===== 敏感配置信息搜索结果 =====\n")
			resultBuilder.WriteString(fmt.Sprintf("搜索路径: %s\n", *searchPath))
			resultBuilder.WriteString(searchResult)
			resultBuilder.WriteString("\n")
		}
	}

	// 添加Chromium处理逻辑
	if (*bromiumFlag == "all" || *bromiumFlag == "chromium" || *bromiumFlag == "firefox") || *allFlag || (*browersName != "" && *browersPath != "") {
		browers.SetFormat(*browersFormat)
		browers.SetOutputDir(*browersOutDir)
		browers.SetLimit(*browserFileLimit)

		if *allFlag {
			*bromiumFlag = "all"
		}
		var chromiumResult string
		var chromiumOutput string
		var FireOutput string
		var IEOutput string

		if *browersName != "" && *browersPath != "" {
			chromiumOutput, err := browers.SpecifyPath(*browersName, *browersPath)
			if err != nil {
				fmt.Printf("Chromium浏览器扫描失败: %v\n", err)
			} else {
				chromiumResult = chromiumOutput
				if *browersFormat != "" {
					chromiumResult += fmt.Sprintf("已处理 %s 浏览器数据，结果保存在 %s 目录\n", *browersName, *browersOutDir)
				}
			}
		} else {
			switch *bromiumFlag {
			case "all":
				chromiumOutput = browers.ChromiumKernel()
				FireOutput, _ = browers.GetFirefox()
				IEOutput, _ = browers.GetIE()
				if *browersFormat != "" {
					chromiumOutput += fmt.Sprintf("已处理所有支持的浏览器数据，结果保存在 %s 目录\n", *browersOutDir)
				}
			case "chromium":
				chromiumOutput = browers.ChromiumKernel()
				if *browersFormat != "" {
					chromiumOutput += fmt.Sprintf("已处理所有Chromium内核浏览器数据，结果保存在 %s 目录\n", *browersOutDir)
				}
			case "firefox":
				FireOutput, _ = browers.GetFirefox()
				if *browersFormat != "" {
					FireOutput += fmt.Sprintf("已处理所有Firefox浏览器数据，结果保存在 %s 目录\n", *browersOutDir)
				}
			case "ie":
				IEOutput, _ = browers.GetIE()
				if *browersFormat != "" {
					IEOutput += fmt.Sprintf("已处理所有IE浏览器数据，结果保存在 %s 目录\n", *browersOutDir)
				}
			}
			chromiumResult = chromiumOutput
		}

		if chromiumResult != "" && *browersFormat == "" && *outputFile != "" {
			resultBuilder.WriteString("===== Chromium浏览器信息 =====\n")
			resultBuilder.WriteString(chromiumResult)
			resultBuilder.WriteString("\n")
		}

		if FireOutput != "" && *browersFormat == "" && *outputFile != "" {
			resultBuilder.WriteString("===== Firefox浏览器信息 =====\n")
			resultBuilder.WriteString(chromiumResult)
			resultBuilder.WriteString("\n")
		}
		if FireOutput != "" && *browersFormat == "" && *outputFile != "" {
			resultBuilder.WriteString("===== IE浏览器信息 =====\n")
			resultBuilder.WriteString(chromiumResult)
			resultBuilder.WriteString("\n")
		}
	}

	// 删除重复的搜索功能执行代码块

	result := resultBuilder.String()

	if *outputFile != "" {
		file, err := os.Create(*outputFile)
		if err != nil {
			fmt.Printf("创建输出文件失败: %v\n", err)
		} else {
			defer file.Close()
			_, err = file.Write([]byte{0xEF, 0xBB, 0xBF})
			if err != nil {
				fmt.Printf("写入UTF-8 BOM标记失败: %v\n", err)
			} else {
				_, err = file.WriteString(result)
				if err != nil {
					fmt.Printf("写入输出文件内容失败: %v\n", err)
				} else {
					fmt.Printf("结果已使用UTF-8编码保存到: %s\n", *outputFile)
				}
			}
		}
	} else {
		fmt.Println(result)
	}
}
