package remotecontrol

import (
	"fmt"
	"strings"
)

func ScanRemoteControl(softwareType string) (string, error) {
	var (
		name           string
		keyword        string
		processKeyword string
		appKeyword     string
		result         strings.Builder
	)

	switch softwareType {
	case "todesk":
		name = ToDeskName
		keyword = KeywordsToDesk
		processKeyword = ProcessKeywordsToDesk
		appKeyword = AppKeywordsToDesk
	case "sunlogin":
		name = SunName
		keyword = KeywordsSun
		processKeyword = ProcessKeywordsSun
		appKeyword = AppKeywordsSun
	default:
		return "", fmt.Errorf("不支持的远程控制软件类型: %s", softwareType)
	}

	if !IsInstalled(appKeyword) {
		return "", fmt.Errorf("%s 未安装", name)
	}

	result.WriteString(fmt.Sprintf("===== %s 信息 =====\n", name))

	registryInfo := ReadRegistryInfo(appKeyword, keyword)
	if registryInfo != nil && len(registryInfo) > 0 {
		result.WriteString("--- 注册表信息 ---\n")
		for k, v := range registryInfo {
			result.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
		result.WriteString("\n")
	}

	if registryInfo != nil {
		if configPath, ok := registryInfo["配置文件路径"]; ok {
			configInfo := ReadConfigFile(configPath, keyword)
			if configInfo != nil && len(configInfo) > 0 {
				result.WriteString("--- 配置文件信息 ---\n")
				for k, v := range configInfo {
					result.WriteString(fmt.Sprintf("%s: %s\n", k, v))
				}
				result.WriteString("\n")
			}
		}
	}

	if IsRunning(processKeyword) {
		result.WriteString("--- 运行状态 ---\n")
		result.WriteString("状态: 正在运行\n\n")

		memoryInfo := ReadMemoryInfo(keyword, processKeyword)
		if memoryInfo != nil && len(memoryInfo) > 0 {
			result.WriteString("--- 内存信息 ---\n")
			for k, v := range memoryInfo {
				result.WriteString(fmt.Sprintf("%s: %s\n", k, v))
			}
		}
	} else {
		result.WriteString("--- 运行状态 ---\n")
		result.WriteString("状态: 未运行\n")
	}

	return result.String(), nil
}