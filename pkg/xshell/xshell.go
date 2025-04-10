package xshell

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"
)

type Xsh struct {
	Host      string
	Port      string
	UserName  string
	Password  string
	EncryptPw string
	Version   string
}

type UserSID struct {
	Name string
	SID  string
}

var enableMasterPasswd bool = false
var hashMasterPasswd string = ""

func ScanXshell(customPath string) (string, error) {
	var resultBuilder strings.Builder

	fmt.Println("正在扫描Xshell...")

	var userDataPaths []string
	var err error

	if customPath != "" {
		userDataPaths = []string{customPath}
	} else {
		userDataPaths, err = getUserDataPath()
		if err != nil {
			return "", fmt.Errorf("获取Xshell用户数据路径失败: %v", err)
		}
	}

	if len(userDataPaths) == 0 {
		return "", fmt.Errorf("未找到Xshell用户数据路径")
	}

	userSID, err := getUserSID()
	if err != nil {
		return "", fmt.Errorf("获取用户SID失败: %v", err)
	}

	for _, userDataPath := range userDataPaths {
		err = checkMasterPw(userDataPath)
		if err != nil {
			fmt.Printf("检查主密码失败: %v\n", err)
			continue
		}

		xshPathList, err := enumXshPath(userDataPath)
		if err != nil {
			fmt.Printf("枚举XSH文件失败: %v\n", err)
			continue
		}

		for _, xshPath := range xshPathList {
			xsh, err := xshParser(xshPath)
			if err != nil {
				fmt.Printf("解析XSH文件失败: %v\n", err)
				continue
			}
			if xsh.EncryptPw != "" {
				resultBuilder.WriteString(fmt.Sprintf("  XSH路径: %s\n", xshPath))
				password, err := xdecrypt(xsh, userSID)
				if err != nil {
					fmt.Printf("解密密码失败: %v\n", err)
					continue
				}
				xsh.Password = password
				resultBuilder.WriteString(fmt.Sprintf("  主机: %s\n", xsh.Host))
				resultBuilder.WriteString(fmt.Sprintf("  Port: %s\n", xsh.Port))
				resultBuilder.WriteString(fmt.Sprintf("  用户名: %s\n", xsh.UserName))
				resultBuilder.WriteString(fmt.Sprintf("  密码: %s\n", xsh.Password))
				resultBuilder.WriteString(fmt.Sprintf("  版本: %s\n", xsh.Version))
				resultBuilder.WriteString("\n")
			}
		}
	}

	return resultBuilder.String(), nil
}

func getUserSID() (UserSID, error) {
	var userSID UserSID

	username := os.Getenv("USERNAME")
	if username == "" {
		return userSID, fmt.Errorf("无法获取当前用户名")
	}
	userSID.Name = username

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return userSID, fmt.Errorf("打开注册表失败: %v", err)
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return userSID, fmt.Errorf("读取子键失败: %v", err)
	}

	for _, subkey := range subkeys {
		if strings.HasPrefix(subkey, "S-1-5-21") {
			profileKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+subkey, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			defer profileKey.Close()

			profilePath, _, err := profileKey.GetStringValue("ProfileImagePath")
			if err != nil {
				continue
			}

			if strings.Contains(profilePath, username) {
				userSID.SID = subkey
				break
			}
		}
	}

	if userSID.SID == "" {
		return userSID, fmt.Errorf("无法获取用户SID")
	}

	return userSID, nil
}

func getUserDataPath() ([]string, error) {
	fmt.Println("[*] 开始获取用户路径....")
	var userDataPaths []string

	strRegPath := `Software\NetSarang\Common`
	key, err := registry.OpenKey(registry.CURRENT_USER, strRegPath, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("打开注册表失败: %v", err)
	}
	defer key.Close()

	versions, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("读取子键失败: %v", err)
	}

	for _, version := range versions {
		if strings.HasPrefix(version, "5") || strings.HasPrefix(version, "6") || strings.HasPrefix(version, "7") {
			strUserDataRegPath := strRegPath + `\` + version + `\UserData`
			subKey, err := registry.OpenKey(registry.CURRENT_USER, strUserDataRegPath, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			defer subKey.Close()

			userDataPath, _, err := subKey.GetStringValue("UserDataPath")
			if err != nil {
				continue
			}

			fmt.Printf("  用户路径: %s\n", userDataPath)
			userDataPaths = append(userDataPaths, userDataPath)
		}
	}

	fmt.Println("[*] 获取用户路径成功!")
	fmt.Println()

	return userDataPaths, nil
}

func enumXshPath(userDataPath string) ([]string, error) {
	var xshPathList []string
	var sessionsPath string

	if strings.HasSuffix(userDataPath, "8") || strings.HasSuffix(userDataPath, "7") || strings.HasSuffix(userDataPath, "6") || strings.HasSuffix(userDataPath, "5") {
		sessionsPath = filepath.Join(userDataPath, "Xshell", "Sessions")
	} else {
		sessionsPath = userDataPath
	}

	if _, err := os.Stat(sessionsPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("会话目录不存在: %s", sessionsPath)
	}

	err := filepath.Walk(sessionsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".xsh") {
			xshPathList = append(xshPathList, path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("遍历目录失败: %v", err)
	}

	return xshPathList, nil
}

func xshParser(xshPath string) (Xsh, error) {
	var xsh Xsh

	content, err := os.ReadFile(xshPath)
	if err != nil {
		return xsh, fmt.Errorf("读取文件失败: %v", err)
	}

	isUTF16 := false
	if len(content) >= 2 && content[0] == 0xFF && content[1] == 0xFE {

		isUTF16 = true
		content = content[2:]
	} else if len(content) >= 4 && content[0] == 0 && content[2] == 0 && content[1] != 0 && content[3] != 0 {

		isUTF16 = true
	}

	var fileContent string
	if isUTF16 {

		utf16Chars := make([]uint16, len(content)/2)
		for i := 0; i < len(content); i += 2 {
			if i+1 < len(content) {
				utf16Chars[i/2] = uint16(content[i]) | (uint16(content[i+1]) << 8)
			}
		}
		fileContent = string(utf16.Decode(utf16Chars))
	} else {
		fileContent = string(content)
	}

	lines := strings.Split(fileContent, "\n")

	for _, line := range lines {

		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Host=") {
			xsh.Host = strings.TrimPrefix(line, "Host=")
		} else if strings.HasPrefix(line, "Password=") {
			rawPass := strings.TrimPrefix(line, "Password=")
			if rawPass != "" {
				xsh.EncryptPw = rawPass
			}
		} else if strings.HasPrefix(line, "UserName=") {
			xsh.UserName = strings.TrimPrefix(line, "UserName=")
		} else if strings.HasPrefix(line, "Version=") {
			xsh.Version = strings.TrimPrefix(line, "Version=")
		} else if strings.HasPrefix(line, "Port=") {
			xsh.Port = strings.TrimPrefix(line, "Port=")
		}
	}

	if xsh.Version == "" {
		xsh.Version = "7.0"
	}

	return xsh, nil
}

func checkMasterPw(userDataPath string) error {
	masterPwPath := filepath.Join(userDataPath, "common", "MasterPassword.mpw")

	if _, err := os.Stat(masterPwPath); os.IsNotExist(err) {

		enableMasterPasswd = false
		hashMasterPasswd = ""
		return nil
	}

	content, err := os.ReadFile(masterPwPath)
	if err != nil {
		return fmt.Errorf("读取主密码文件失败: %v", err)
	}

	isUTF16 := false
	if len(content) >= 2 && content[0] == 0xFF && content[1] == 0xFE {

		isUTF16 = true
		content = content[2:]
	} else if len(content) >= 4 && content[0] == 0 && content[2] == 0 && content[1] != 0 && content[3] != 0 {

		isUTF16 = true
	}

	var fileContent string
	if isUTF16 {

		utf16Chars := make([]uint16, len(content)/2)
		for i := 0; i < len(content); i += 2 {
			if i+1 < len(content) {
				utf16Chars[i/2] = uint16(content[i]) | (uint16(content[i+1]) << 8)
			}
		}
		fileContent = string(utf16.Decode(utf16Chars))
	} else {
		fileContent = string(content)
	}

	lines := strings.Split(fileContent, "\n")

	for _, line := range lines {

		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "EnblMasterPasswd=") {
			rawPass := strings.TrimPrefix(line, "EnblMasterPasswd=")
			if rawPass == "1" {
				enableMasterPasswd = true
			} else {
				enableMasterPasswd = false
			}
		} else if strings.HasPrefix(line, "HashMasterPasswd=") {
			rawPass := strings.TrimPrefix(line, "HashMasterPasswd=")
			if len(rawPass) > 1 {
				hashMasterPasswd = rawPass
			} else {
				hashMasterPasswd = ""
			}
		}
	}

	return nil
}

func xdecrypt(xsh Xsh, userSID UserSID) (string, error) {
	if enableMasterPasswd {
		return "", fmt.Errorf("主密码已启用，暂不支持解密")
	}

	data, err := base64.StdEncoding.DecodeString(xsh.EncryptPw)
	if err != nil {
		return "", fmt.Errorf("Base64解码失败: %v", err)
	}

	if len(data) <= 0x20 {
		return "", fmt.Errorf("加密数据长度不足")
	}

	passData := data[:len(data)-0x20]

	if strings.HasPrefix(xsh.Version, "5.0") || strings.HasPrefix(xsh.Version, "4") || strings.HasPrefix(xsh.Version, "3") || strings.HasPrefix(xsh.Version, "2") {
		key := md5.Sum([]byte("!X@s#h$e%l^l&"))
		decrypted, err := rc4Decrypt(key[:], passData)
		if err != nil {
			return "", err
		}
		return string(decrypted), nil
	} else if strings.HasPrefix(xsh.Version, "5.1") || strings.HasPrefix(xsh.Version, "5.2") {
		h := sha256.New()
		h.Write([]byte(userSID.SID))
		key := h.Sum(nil)
		decrypted, err := rc4Decrypt(key, passData)
		if err != nil {
			return "", err
		}
		return string(decrypted), nil
	} else if strings.HasPrefix(xsh.Version, "5") || strings.HasPrefix(xsh.Version, "6") || strings.HasPrefix(xsh.Version, "7.0") {
		h := sha256.New()
		h.Write([]byte(userSID.Name + userSID.SID))
		key := h.Sum(nil)
		decrypted, err := rc4Decrypt(key, passData)
		if err != nil {
			return "", err
		}
		return string(decrypted), nil
	} else if strings.HasPrefix(xsh.Version, "7") {

		reversedName := reverseString(userSID.Name)
		strkey1 := reversedName + userSID.SID
		strkey2 := reverseString(strkey1)

		h := sha256.New()
		h.Write([]byte(strkey2))
		key := h.Sum(nil)
		decrypted, err := rc4Decrypt(key, passData)
		if err != nil {
			return "", err
		}
		return string(decrypted), nil
	} else if strings.HasPrefix(xsh.Version, "8") {

		reversedName := reverseString(userSID.Name)
		strkey1 := reversedName + userSID.SID
		strkey2 := reverseString(strkey1)

		h := sha256.New()
		h.Write([]byte(strkey2))
		key := h.Sum(nil)
		decrypted, err := rc4Decrypt(key, passData)
		if err != nil {
			return "", err
		}
		return string(decrypted), nil
	}

	return "", fmt.Errorf("不支持的Xshell版本: %s", xsh.Version)
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func ScanXftp(customPath string) (string, error) {
	var resultBuilder strings.Builder

	fmt.Println("正在扫描Xftp...")

	var userDataPaths []string
	var err error

	if customPath != "" {
		userDataPaths = []string{customPath}
	} else {
		userDataPaths, err = getUserDataPath()
		if err != nil {
			return "", fmt.Errorf("获取Xftp用户数据路径失败: %v", err)
		}
	}

	if len(userDataPaths) == 0 {
		return "", fmt.Errorf("未找到Xftp用户数据路径")
	}

	userSID, err := getUserSID()
	if err != nil {
		return "", fmt.Errorf("获取用户SID失败: %v", err)
	}

	for _, userDataPath := range userDataPaths {
		err = checkMasterPw(userDataPath)
		if err != nil {
			fmt.Printf("检查主密码失败: %v\n", err)
			continue
		}

		xfpPathList, err := enumXfpPath(userDataPath)
		if err != nil {
			fmt.Printf("枚举XFP文件失败: %v\n", err)
			continue
		}

		for _, xfpPath := range xfpPathList {
			xfp, err := xfpParser(xfpPath)
			if err != nil {
				fmt.Printf("解析XFP文件失败: %v\n", err)
				continue
			}
			if xfp.EncryptPw != "" {
				resultBuilder.WriteString(fmt.Sprintf("  XFP路径: %s\n", xfpPath))
				password, err := xdecrypt(xfp, userSID)
				if err != nil {
					fmt.Printf("解密密码失败: %v\n", err)
					continue
				}
				xfp.Password = password
				resultBuilder.WriteString(fmt.Sprintf("  主机: %s\n", xfp.Host))
				resultBuilder.WriteString(fmt.Sprintf("  Port: %s\n", xfp.Port))
				resultBuilder.WriteString(fmt.Sprintf("  用户名: %s\n", xfp.UserName))
				resultBuilder.WriteString(fmt.Sprintf("  密码: %s\n", xfp.Password))
				resultBuilder.WriteString(fmt.Sprintf("  版本: %s\n", xfp.Version))
				resultBuilder.WriteString("\n")
			}
		}
	}

	return resultBuilder.String(), nil
}

func enumXfpPath(userDataPath string) ([]string, error) {
	var xfpPathList []string
	var sessionsPath string

	if strings.HasSuffix(userDataPath, "8") || strings.HasSuffix(userDataPath, "7") || strings.HasSuffix(userDataPath, "6") || strings.HasSuffix(userDataPath, "5") {
		sessionsPath = filepath.Join(userDataPath, "Xftp", "Sessions")
	} else {
		sessionsPath = userDataPath
	}

	if _, err := os.Stat(sessionsPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("会话目录不存在: %s", sessionsPath)
	}

	err := filepath.Walk(sessionsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".xfp") {
			xfpPathList = append(xfpPathList, path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("遍历目录失败: %v", err)
	}

	return xfpPathList, nil
}

func xfpParser(xfpPath string) (Xsh, error) {
	var xfp Xsh

	content, err := os.ReadFile(xfpPath)
	if err != nil {
		return xfp, fmt.Errorf("读取文件失败: %v", err)
	}

	isUTF16 := false
	if len(content) >= 2 && content[0] == 0xFF && content[1] == 0xFE {

		isUTF16 = true
		content = content[2:]
	} else if len(content) >= 4 && content[0] == 0 && content[2] == 0 && content[1] != 0 && content[3] != 0 {

		isUTF16 = true
	}

	var fileContent string
	if isUTF16 {

		utf16Chars := make([]uint16, len(content)/2)
		for i := 0; i < len(content); i += 2 {
			if i+1 < len(content) {
				utf16Chars[i/2] = uint16(content[i]) | (uint16(content[i+1]) << 8)
			}
		}
		fileContent = string(utf16.Decode(utf16Chars))
	} else {
		fileContent = string(content)
	}

	lines := strings.Split(fileContent, "\n")

	for _, line := range lines {

		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Host=") {
			xfp.Host = strings.TrimPrefix(line, "Host=")
		} else if strings.HasPrefix(line, "Password=") {
			rawPass := strings.TrimPrefix(line, "Password=")
			if rawPass != "" {
				xfp.EncryptPw = rawPass
			}
		} else if strings.HasPrefix(line, "UserName=") {
			xfp.UserName = strings.TrimPrefix(line, "UserName=")
		} else if strings.HasPrefix(line, "Version=") {
			xfp.Version = strings.TrimPrefix(line, "Version=")
		} else if strings.HasPrefix(line, "Port=") {
			xfp.Port = strings.TrimPrefix(line, "Port=")
		}
	}

	if xfp.Version == "" {
		xfp.Version = "7.0"
	}

	return xfp, nil
}

func rc4Decrypt(key, data []byte) ([]byte, error) {

	s := make([]byte, 256)
	for i := 0; i < 256; i++ {
		s[i] = byte(i)
	}

	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) % 256
		s[i], s[j] = s[j], s[i]
	}

	result := make([]byte, len(data))
	i, j := 0, 0
	for k := 0; k < len(data); k++ {
		i = (i + 1) % 256
		j = (j + int(s[i])) % 256
		s[i], s[j] = s[j], s[i]
		t := (int(s[i]) + int(s[j])) % 256
		result[k] = data[k] ^ s[t]
	}

	return result, nil
}
