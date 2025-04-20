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

var BrowserName string

var browerlimit string

var SystemKey []byte

var Format string

var PrintOut = true

var OutputDir = "out"

func SetFormat(format string) {
	Format = format
	if Format != "" {
		PrintOut = false
	}
}

func SetOutputDir(dir string) {
	OutputDir = dir
}

func SetLimit(limit string) {
	browerlimit = limit
}

func TimeEpoch(timestamp int64) time.Time {

	windowsEpochOffset := int64(11644473600 * 1000000)
	unixMicro := timestamp - windowsEpochOffset
	if unixMicro < 0 {
		return time.Time{}
	}
	return time.Unix(0, unixMicro*1000)
}

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
		return nil
	}
	return os.Remove(strPath)
}

func FileExists(paths []string) []string {
	existingPaths := []string{}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			existingPaths = append(existingPaths, path)
		}
	}
	return existingPaths
}

func PathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func WriteCSV(header []string, data [][]string, fileName string) error {

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

func WriteJSON(header []string, data [][]string, fileName string) error {

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

func IsTrueFalse(value string) string {
	if value == "1" {
		return "true"
	}
	return "false"
}

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

func IsHighIntegrity() bool {

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

func CopyFile(src, dst string) error {
	sourceFile, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dst, sourceFile, 0644)
}
