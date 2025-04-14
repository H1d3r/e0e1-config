package browers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BrowserName 存储当前浏览器名称
var BrowserName string

// browlimit 读取数据行数
var browerlimit string

// SystemKey 存储系统密钥
var SystemKey []byte

// Format 存储输出格式
var Format string

var PrintOut = true

// OutputDir 存储输出目录
var OutputDir = "out"

// SetFormat 设置输出格式
func SetFormat(format string) {
	Format = format
	if Format != "" {
		PrintOut = false
	}
}

// SetOutputDir 设置输出目录
func SetOutputDir(dir string) {
	OutputDir = dir
}

func SetLimit(limit string) {
	browerlimit = limit
}

// TimeEpoch 将Chrome时间戳转换为时间
func TimeEpoch(timestamp int64) time.Time {
	// Chrome时间戳是从1601年1月1日开始的微秒数
	// 需要转换为Unix时间戳（从1970年1月1日开始的秒数）
	// 差值为11644473600秒
	windowsEpochOffset := int64(11644473600 * 1000000)
	unixMicro := timestamp - windowsEpochOffset
	if unixMicro < 0 {
		return time.Time{}
	}
	return time.Unix(0, unixMicro*1000)
}

// CreateTmpFile 创建临时文件
func CreateTmpFile(srcPath string) (string, error) {
	tmpFile, err := ioutil.TempFile("", "brower_*")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	data, err := ioutil.ReadFile(srcPath)
	if err != nil {
		return "", err
	}

	if _, err := tmpFile.Write(data); err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}

func RemoveFile(strPath string) error {
	if _, err := os.Stat(strPath); os.IsNotExist(err) {
		return nil // 文件不存在就无需删除
	}
	return os.Remove(strPath)
}

// FileExists 检查文件是否存在
// 返回存在的文件路径列表
func FileExists(paths []string) []string {
	existingPaths := []string{}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			existingPaths = append(existingPaths, path)
		}
	}
	return existingPaths
}

// PathExists 检查单个路径是否存在
func PathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// WriteCSV 写入CSV文件
func WriteCSV(header []string, data [][]string, fileName string) error {
	// 确保输出目录存在
	outDir := filepath.Dir(fileName)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	file, err := os.Create(fileName + ".csv")
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write(header); err != nil {
		return err
	}

	for _, record := range data {
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// WriteJSON 写入JSON文件
func WriteJSON(header []string, data [][]string, fileName string) error {
	// 确保输出目录存在
	outDir := filepath.Dir(fileName)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	jsonData := make([]map[string]string, 0, len(data))
	for _, row := range data {
		item := make(map[string]string)
		for i, key := range header {
			if i < len(row) {
				item[key] = row[i]
			}
		}
		jsonData = append(jsonData, item)
	}

	jsonBytes, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(fileName+".json", jsonBytes, 0644)
}

// 打印函数
func PrintNormal(message string) {
	if PrintOut {
		fmt.Println(message)
	}
}

func PrintSuccess(message string, indent int) {
	if PrintOut {
		indentStr := strings.Repeat("  ", indent)
		fmt.Printf("%s[+] %s\n", indentStr, message)
	}
}

func PrintFail(message string, indent int) {
	if PrintOut {
		indentStr := strings.Repeat("  ", indent)
		fmt.Printf("%s[-] %s\n", indentStr, message)
	}
}

func PrintVerbose(message string) {
	fmt.Printf("[*] %s\n", message)
}

// IsTrueFalse 布尔值转换
func IsTrueFalse(value string) string {
	if value == "1" {
		return "true"
	}
	return "false"
}

// TryParseSameSite 解析SameSite值
func TryParseSameSite(value string) string {
	switch value {
	case "0":
		return "no_restriction"
	case "1":
		return "lax"
	case "2":
		return "strict"
	default:
		return "no_restriction"
	}
}

// IsHighIntegrity 检查是否有管理员权限
func IsHighIntegrity() bool {
	// 在Go中检查管理员权限的简化实现
	file, err := os.Open(`C:\Windows\System32\config\system`)

	if err == nil {
		err := file.Close()
		if err != nil {
			return true
		}
		return true
	}
	return false
}

// CopyFile 复制文件
func CopyFile(src, dst string) error {
	sourceFile, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dst, sourceFile, 0644)
}
