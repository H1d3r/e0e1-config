package dbeaver

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	DefaultKeyHex = "babb4a9f774ab853c96c2d653dfe544a"
	DefaultIVHex  = "00000000000000000000000000000000"
)

func GetAppDataFolderPath() string {
	return os.Getenv("APPDATA")
}

func GetDefaultConfigPaths() (string, string) {
	appDataPath := GetAppDataFolderPath()
	credentialsPath := filepath.Join(appDataPath, "DBeaverData", "workspace6", "General", ".dbeaver", "credentials-config.json")
	sourcesPath := filepath.Join(appDataPath, "DBeaverData", "workspace6", "General", ".dbeaver", "data-sources.json")
	return credentialsPath, sourcesPath
}

func Decrypt(filePath, keyHex, ivHex string) (string, error) {
	encryptedBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("读取文件失败: %v", err)
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("解析密钥失败: %v", err)
	}

	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return "", fmt.Errorf("解析IV失败: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建AES加密器失败: %v", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(encryptedBytes))
	mode.CryptBlocks(decrypted, encryptedBytes)

	padding := int(decrypted[len(decrypted)-1])
	if padding > 0 && padding <= aes.BlockSize {
		decrypted = decrypted[:len(decrypted)-padding]
	}

	return string(decrypted), nil
}

func MatchDataSource(json, jdbcKey string) string {
	pattern := fmt.Sprintf(`"%s":\s*{[^}]+?"url":\s*"([^"]+)"[^}]+?}`, regexp.QuoteMeta(jdbcKey))
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(json)
	if len(match) > 1 {
		return fmt.Sprintf("host: %s", match[1])
	}
	return fmt.Sprintf("未找到匹配的连接: %s", jdbcKey)
}

func ConnectionInfo(config, sources string) (string, error) {
	sourcesContent, err := ioutil.ReadFile(sources)
	if err != nil {
		return "", fmt.Errorf("读取数据源文件失败: %v", err)
	}

	pattern := `"(?P<key>[^"]+)"\s*:\s*{\s*"#connection"\s*:\s*{\s*"user"\s*:\s*"(?P<user>[^"]+)"\s*,\s*"password"\s*:\s*"(?P<password>[^"]+)"\s*}\s*}`
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(config, -1)

	var result strings.Builder
	for _, match := range matches {
		if len(match) >= 4 {
			key := match[1]
			user := match[2]
			password := match[3]

			hostInfo := MatchDataSource(string(sourcesContent), key)
			result.WriteString(hostInfo + "\n")
			result.WriteString(fmt.Sprintf("username: %s\n", user))
			result.WriteString(fmt.Sprintf("password: %s\n\n", password))
		}
	}

	return result.String(), nil
}

func ScanDBeaver(configPath, sourcesPath string) (string, error) {

	if configPath == "" || sourcesPath == "" {
		defaultConfigPath, defaultSourcesPath := GetDefaultConfigPaths()

		if configPath == "" {
			configPath = defaultConfigPath
		}

		if sourcesPath == "" {
			sourcesPath = defaultSourcesPath
		}
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return "", fmt.Errorf("配置文件不存在: %s", configPath)
	}

	if _, err := os.Stat(sourcesPath); os.IsNotExist(err) {
		return "", fmt.Errorf("数据源文件不存在: %s", sourcesPath)
	}

	decryptedConfig, err := Decrypt(configPath, DefaultKeyHex, DefaultIVHex)
	if err != nil {
		return "", fmt.Errorf("解密配置文件失败: %v", err)
	}

	connectionInfo, err := ConnectionInfo(decryptedConfig, sourcesPath)
	if err != nil {
		return "", fmt.Errorf("解析连接信息失败: %v", err)
	}

	return connectionInfo, nil
}
