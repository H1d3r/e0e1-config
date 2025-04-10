package winscp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	PW_MAGIC = 0xA3
	PW_FLAG  = 0xFF
)

func DecryptNextCharacterWinSCP(passwd string) (flag rune, remainingPass string) {
	bases := "0123456789ABCDEF"

	firstval := strings.IndexByte(bases, passwd[0]) * 16
	secondval := strings.IndexByte(bases, passwd[1])
	added := firstval + secondval
	flag = rune((((^(added ^ PW_MAGIC) % 256) + 256) % 256))
	remainingPass = passwd[2:]
	return flag, remainingPass
}

func DecryptWinSCPPassword(host, userName, passWord string) string {
	var clearpwd strings.Builder
	var length rune
	unicodeKey := userName + host
	flag, remainingPass := DecryptNextCharacterWinSCP(passWord)

	storedFlag := flag

	if storedFlag == PW_FLAG {
		flag, remainingPass = DecryptNextCharacterWinSCP(remainingPass)
		flag, remainingPass = DecryptNextCharacterWinSCP(remainingPass)
		length = flag
	} else {
		length = flag
	}

	flag, remainingPass = DecryptNextCharacterWinSCP(remainingPass)
	remainingPass = remainingPass[int(flag)*2:]

	for i := 0; i < int(length); i++ {
		flag, remainingPass = DecryptNextCharacterWinSCP(remainingPass)
		clearpwd.WriteRune(flag)
	}

	if storedFlag == PW_FLAG {
		if len(clearpwd.String()) >= len(unicodeKey) && clearpwd.String()[:len(unicodeKey)] == unicodeKey {
			return clearpwd.String()[len(unicodeKey):]
		}
		return ""
	}
	return clearpwd.String()
}

func ScanWinSCP(configPath string) (string, error) {
	var result strings.Builder
	var foundData bool

	registryPath := `Software\Martin Prikryl\WinSCP 2\Sessions`
	key, err := registry.OpenKey(registry.CURRENT_USER, registryPath, registry.READ)
	if err == nil {
		defer key.Close()

		result.WriteString("=== WinSCP 注册表信息 ===\n")
		result.WriteString(fmt.Sprintf("注册表位置: HKEY_CURRENT_USER\\%s\n\n", registryPath))

		subKeys, err := key.ReadSubKeyNames(0)
		if err == nil {
			for _, subKeyName := range subKeys {
				subKey, err := registry.OpenKey(registry.CURRENT_USER, registryPath+"\\"+subKeyName, registry.READ)
				if err == nil {
					defer subKey.Close()

					hostname, _, err := subKey.GetStringValue("HostName")
					if err == nil && hostname != "" {
						username, _, _ := subKey.GetStringValue("UserName")
						password, _, err := subKey.GetStringValue("Password")
						portNumer, _, _ := subKey.GetIntegerValue("PortNumber")
						if err == nil {
							foundData = true
							result.WriteString(fmt.Sprintf("会话名称: %s\n", subKeyName))
							result.WriteString(fmt.Sprintf("主机名: %s\n", hostname))
							result.WriteString(fmt.Sprintf("Port: %v\n", portNumer))
							result.WriteString(fmt.Sprintf("用户名: %s\n", username))
							result.WriteString(fmt.Sprintf("加密密码: %s\n", password))
							result.WriteString(fmt.Sprintf("解密密码: %s\n\n", DecryptWinSCPPassword(hostname, username, password)))
						}
					}
				}
			}
		}
	} else {
		result.WriteString(fmt.Sprintf("未找到 WinSCP 注册表位置: HKEY_CURRENT_USER\\%s\n", registryPath))
	}

	if configPath == "" {

		appDataPath := os.Getenv("APPDATA")
		configPath = filepath.Join(appDataPath, "winscp.ini")
	}

	if _, err := os.Stat(configPath); err == nil {

		result.WriteString("=== WinSCP 配置文件信息 ===\n")
		result.WriteString(fmt.Sprintf("配置文件位置: %s\n", configPath))
		result.WriteString("配置文件解析功能待实现\n")
		foundData = true
	}

	if !foundData {
		return "", fmt.Errorf("未找到 WinSCP 连接信息")
	}

	return result.String(), nil
}
