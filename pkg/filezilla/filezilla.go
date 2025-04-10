package filezilla

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type Server struct {
	Host     string `xml:"Host"`
	Port     string `xml:"Port"`
	User     string `xml:"User"`
	Pass     string `xml:"Pass"`
	Protocol string `xml:"Protocol"`
	Name     string `xml:"Name"`
}

type RecentServers struct {
	XMLName xml.Name `xml:"RecentServers"`
	Servers []Server `xml:"Server"`
}

type FileZilla3 struct {
	XMLName xml.Name `xml:"FileZilla3"`
	Servers struct {
		Servers []Server `xml:"Server"`
	} `xml:"Servers"`
}

func ScanFileZilla(customPath string) (string, error) {
	var fzPath string
	var result strings.Builder

	if customPath == "" {

		appData, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("获取用户配置目录失败: %v", err)
		}
		fzPath = filepath.Join(appData, "FileZilla")
	} else {
		fzPath = customPath
	}

	if _, err := os.Stat(fzPath); os.IsNotExist(err) {
		return "", fmt.Errorf("FileZilla 目录不存在: %s", fzPath)
	}

	xmlFiles, err := findXMLFiles(fzPath)
	if err != nil {
		return "", fmt.Errorf("查找 XML 文件失败: %v", err)
	}

	foundServers := false

	for _, xmlFile := range xmlFiles {
		servers, err := parseFileZillaXML(xmlFile)
		if err != nil {
			continue
		}

		if len(servers) > 0 {
			foundServers = true
			result.WriteString(fmt.Sprintf("从文件解析: %s\n", xmlFile))

			for _, server := range servers {
				if server.Host != "" && server.Port != "" && server.User != "" && server.Pass != "" {
					if server.Name != "" {
						result.WriteString(fmt.Sprintf("名称: %s\n", server.Name))
					}
					result.WriteString(fmt.Sprintf("主机: %s\n", server.Host))
					result.WriteString(fmt.Sprintf("端口: %s\n", server.Port))
					result.WriteString(fmt.Sprintf("用户: %s\n", server.User))
					result.WriteString(fmt.Sprintf("密码: %s\n", server.Pass))
					if server.Protocol != "" {
						protocol := "FTP"
						if server.Protocol == "1" {
							protocol = "SFTP"
						}
						result.WriteString(fmt.Sprintf("协议: %s\n", protocol))
					}
					result.WriteString("\n")
				}
			}
		}
	}

	if !foundServers {
		return "", fmt.Errorf("未找到有效的 FileZilla 服务器配置")
	}

	return result.String(), nil
}

func findXMLFiles(dir string) ([]string, error) {
	var xmlFiles []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.ToLower(filepath.Ext(path)) == ".xml" {
			xmlFiles = append(xmlFiles, path)
		}
		return nil
	})

	return xmlFiles, err
}

func parseFileZillaXML(filePath string) ([]Server, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var fileZilla3 FileZilla3
	err1 := xml.Unmarshal(data, &fileZilla3)
	if err1 == nil && len(fileZilla3.Servers.Servers) > 0 {

		for i := range fileZilla3.Servers.Servers {
			if fileZilla3.Servers.Servers[i].Pass != "" {

				if strings.Contains(string(data), `encoding="base64"`) {
					decodedPass, err := base64.StdEncoding.DecodeString(fileZilla3.Servers.Servers[i].Pass)
					if err == nil {
						fileZilla3.Servers.Servers[i].Pass = string(decodedPass)
					}
				}
			}
		}
		return fileZilla3.Servers.Servers, nil
	}

	var recentServers RecentServers
	err2 := xml.Unmarshal(data, &recentServers)
	if err2 == nil && len(recentServers.Servers) > 0 {

		for i := range recentServers.Servers {
			if recentServers.Servers[i].Pass != "" {

				if strings.Contains(string(data), `encoding="base64"`) {
					decodedPass, err := base64.StdEncoding.DecodeString(recentServers.Servers[i].Pass)
					if err == nil {
						recentServers.Servers[i].Pass = string(decodedPass)
					}
				}
			}
		}
		return recentServers.Servers, nil
	}

	return nil, fmt.Errorf("无法解析 XML 文件: %v 或 %v", err1, err2)
}
