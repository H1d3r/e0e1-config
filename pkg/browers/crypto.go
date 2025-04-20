package browers

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"syscall"
	"unsafe"
)

type AesGcm struct{}

func (a *AesGcm) Decrypt(key, iv, aad, cipherText, authTag []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("invalid key size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(iv) != 12 {
		return nil, errors.New("invalid IV size, expected 12 bytes")
	}

	combinedData := make([]byte, len(cipherText)+len(authTag))
	copy(combinedData, cipherText)
	copy(combinedData[len(cipherText):], authTag)

	plaintext, err := aesGCM.Open(nil, iv, combinedData, aad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func GetMasterKey(filePath string) ([]byte, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, errors.New("file does not exist")
	}

	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	patterns := []string{
		`"encrypted_key":"(.*?)"`,
		`"encrypted_key"\s*:\s*"([^"]+)"`,
		`"os_crypt"[\s\S]*?"encrypted_key"\s*:\s*"([^"]+)"`,
	}

	var masterKey []byte
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(string(fileContent))
		if len(matches) > 1 {
			masterKey, err = base64.StdEncoding.DecodeString(matches[1])
			if err == nil && len(masterKey) > 5 {

				masterKey = masterKey[5:]

				decryptedKey, err := decryptDPAPI(masterKey)
				if err == nil {
					return decryptedKey, nil
				}
			}
		}
	}

	return nil, errors.New("encrypted key not found in state file")
}

const (
	CRYPTPROTECT_UI_FORBIDDEN  = 0x1
	CRYPTPROTECT_LOCAL_MACHINE = 0x4
)

func DecryptWithSystemDPAPI(stateFilePath string) ([]byte, error) {

	stateData, err := ioutil.ReadFile(stateFilePath)
	if err != nil {
		return nil, err
	}

	patterns := []string{
		`"os_crypt"[\s\S]*?"encrypted_key"\s*:\s*"([^"]+)"`,
		`"encrypted_key":"([^"]+)"`,
		`"encrypted_key"\s*:\s*"([^"]+)"`,
	}

	appBoundPatterns := []string{
		`"os_crypt"[\s\S]*?"app_bound_encrypted_key"\s*:\s*"([^"]+)"`,
		`"app_bound_encrypted_key":"([^"]+)"`,
		`"app_bound_encrypted_key"\s*:\s*"([^"]+)"`,
	}

	for _, pattern := range appBoundPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(string(stateData))
		if len(matches) > 1 {
			encryptedKey, err := base64.StdEncoding.DecodeString(matches[1])
			if err == nil && len(encryptedKey) > 4 {

				if encryptedKey[0] == 'A' && encryptedKey[1] == 'P' && encryptedKey[2] == 'P' && encryptedKey[3] == 'B' {
					encryptedKey = encryptedKey[4:]

					decryptedKey, err := decryptDPAPIWithFlags(encryptedKey, CRYPTPROTECT_UI_FORBIDDEN|CRYPTPROTECT_LOCAL_MACHINE)
					if err == nil {
						return decryptedKey, nil
					}
				}
			}
		}
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(string(stateData))
		if len(matches) > 1 {
			encryptedKey, err := base64.StdEncoding.DecodeString(matches[1])
			if err == nil && len(encryptedKey) > 5 {

				if encryptedKey[0] == 'D' && encryptedKey[1] == 'P' && encryptedKey[2] == 'A' && encryptedKey[3] == 'P' && encryptedKey[4] == 'I' {
					encryptedKey = encryptedKey[5:]

					decryptedKey, err := decryptDPAPI(encryptedKey)
					if err == nil {
						return decryptedKey, nil
					}
				}
			}
		}
	}

	return nil, errors.New("无法从状态文件中获取加密密钥")
}

func DecryptWithUserDPAPI(systemKey []byte, stateFilePath string) ([]byte, error) {
	if systemKey == nil {
		var err error
		systemKey, err = DecryptWithSystemDPAPI(stateFilePath)
		if err != nil {
			return nil, err
		}
	}

	decryptedKey, err := decryptDPAPI(systemKey)
	if err != nil {
		return nil, err
	}

	if strings.Contains(stateFilePath, "Google") || strings.Contains(stateFilePath, "Chrome") {

		if len(decryptedKey) >= 61 {
			key := decryptedKey[len(decryptedKey)-61:]

			if len(key) > 1 && key[0] == 1 {

				iv := key[1:13]
				ciphertext := key[13:45]
				tag := key[45:61]

				aesKeyBase64 := "sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c="
				aesKey, err := base64.StdEncoding.DecodeString(aesKeyBase64)
				if err != nil {
					return nil, err
				}

				aesGcm := &AesGcm{}
				decryptedData, err := aesGcm.Decrypt(aesKey, iv, nil, ciphertext, tag)
				if err != nil {
					return nil, err
				}

				return decryptedData, nil
			}
		}
	}

	if len(decryptedKey) >= 32 {
		key := make([]byte, 32)
		copy(key, decryptedKey[len(decryptedKey)-32:])
		return key, nil
	}

	return decryptedKey, nil
}

func DecryptData(encryptedData []byte, masterKey []byte) (string, error) {
	if masterKey == nil {
		return "", errors.New("master key is nil")
	}

	if len(encryptedData) < 3 {
		return "", errors.New("buffer too short")
	}

	bufferString := string(encryptedData)

	if strings.HasPrefix(bufferString, "v10") || strings.HasPrefix(bufferString, "v11") {
		iv := encryptedData[3:15]
		cipherText := encryptedData[15:]

		var tag []byte
		var data []byte

		if len(cipherText) < 16 {
			return "", errors.New("ciphertext too short")
		}

		if strings.HasPrefix(bufferString, "v10") {
			data = cipherText
			tag = nil
		} else {

			tag = cipherText[len(cipherText)-16:]
			data = cipherText[:len(cipherText)-16]
		}

		aesGcm := &AesGcm{}
		decryptedData, err := aesGcm.Decrypt(masterKey, iv, nil, data, tag)
		if err != nil {
			return "", err
		}

		return string(decryptedData), nil
	} else if strings.HasPrefix(bufferString, "v20") {

		iv := encryptedData[3:15]
		cipherText := encryptedData[15:]

		if len(cipherText) < 16 {
			return "", errors.New("ciphertext too short")
		}

		tag := cipherText[len(cipherText)-16:]
		data := cipherText[:len(cipherText)-16]

		aesGcm := &AesGcm{}
		decryptedData, err := aesGcm.Decrypt(masterKey, iv, nil, data, tag)
		if err != nil {
			return "", err
		}

		if len(decryptedData) <= 32 {
			return "", errors.New("decrypted data too short")
		}

		return string(decryptedData[32:]), nil
	} else {

		decryptedData, err := decryptDPAPI(encryptedData)
		if err != nil {
			return "", err
		}

		return string(decryptedData), nil
	}
}

func decryptDPAPI(encryptedData []byte) ([]byte, error) {
	return decryptDPAPIWithFlags(encryptedData, 0)
}

func decryptDPAPIWithFlags(encryptedData []byte, flags uint32) ([]byte, error) {
	var outBlob dataBlob
	var inBlob dataBlob

	inBlob.cbData = uint32(len(encryptedData))
	if len(encryptedData) == 0 {
		return nil, errors.New("empty encrypted data")
	}

	inBlob.pbData = uintptr(unsafe.Pointer(&encryptedData[0]))

	procDecryptData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0,
		0,
		0,
		0,
		uintptr(flags),
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if outBlob.cbData == 0 {
		return nil, errors.New("decryption failed")
	}

	decryptedData := make([]byte, outBlob.cbData)
	copyMemory(decryptedData, outBlob.pbData, outBlob.cbData)

	localFree.Call(outBlob.pbData)

	return decryptedData, nil
}

type dataBlob struct {
	cbData uint32
	pbData uintptr
}

var (
	dllCrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllKernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procDecryptData = dllCrypt32.NewProc("CryptUnprotectData")
	procEncryptData = dllCrypt32.NewProc("CryptProtectData")
	localFree       = dllKernel32.NewProc("LocalFree")
)

func copyMemory(dest []byte, src uintptr, length uint32) {
	for i := uint32(0); i < length; i++ {
		dest[i] = *(*byte)(unsafe.Pointer(src + uintptr(i)))
	}
}

var ErrCiphertextLengthIsInvalid = errors.New("ciphertext length is invalid")

func AES128CBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("AES128CBCDecrypt: ciphertext too short")
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("AES128CBCDecrypt: ciphertext is not a multiple of the block size")
	}

	decryptedData := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decryptedData, ciphertext)

	decryptedData, err = pkcs5UnPadding(decryptedData)
	if err != nil {
		return nil, fmt.Errorf("AES128CBCDecrypt: %w", err)
	}

	return decryptedData, nil
}

func AES128CBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("AES128CBCEncrypt: iv length is invalid, must equal block size")
	}

	plaintext = pkcs5Padding(plaintext, block.BlockSize())
	encryptedData := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptedData, plaintext)

	return encryptedData, nil
}

func DES3Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < des.BlockSize {
		return nil, errors.New("DES3Decrypt: ciphertext too short")
	}
	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("DES3Decrypt: ciphertext is not a multiple of the block size")
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	sq := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(sq, ciphertext)

	return pkcs5UnPadding(sq)
}

func DES3Encrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = pkcs5Padding(plaintext, block.BlockSize())
	dst := make([]byte, len(plaintext))
	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(dst, plaintext)

	return dst, nil
}

func pkcs5UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, errors.New("pkcs5UnPadding: src should not be empty")
	}
	padding := int(src[length-1])
	if padding < 1 || padding > aes.BlockSize {
		return nil, errors.New("pkcs5UnPadding: invalid padding size")
	}
	return src[:length-padding], nil
}

func pkcs5Padding(src []byte, blocksize int) []byte {
	padding := blocksize - (len(src) % blocksize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func PBKDF2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {

		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		t := dk[len(dk)-hashLen:]
		copy(u, t)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = u[:0]
			u = prf.Sum(u)
			for x := range u {
				t[x] ^= u[x]
			}
		}
	}
	return dk[:keyLen]
}

type ASN1PBE interface {
	Decrypt(globalSalt []byte) ([]byte, error)
	Encrypt(globalSalt, plaintext []byte) ([]byte, error)
}

func NewASN1PBE(b []byte) (pbe ASN1PBE, err error) {
	var (
		nss   nssPBE
		meta  metaPBE
		login loginPBE
	)
	if _, err := asn1.Unmarshal(b, &nss); err == nil {
		return nss, nil
	}
	if _, err := asn1.Unmarshal(b, &meta); err == nil {
		return meta, nil
	}
	if _, err := asn1.Unmarshal(b, &login); err == nil {
		return login, nil
	}
	return nil, ErrDecodeASN1Failed
}

var ErrDecodeASN1Failed = errors.New("decode ASN1 data failed")

//
//	OBJECT IDENTIFIER
//	SEQUENCE (2 elem)
//	  OCTET STRING (20 byte)
//	  INTEGER 1
//

type nssPBE struct {
	AlgoAttr struct {
		asn1.ObjectIdentifier
		SaltAttr struct {
			EntrySalt []byte
			Len       int
		}
	}
	Encrypted []byte
}

func (n nssPBE) Decrypt(globalSalt []byte) ([]byte, error) {
	key, iv := n.deriveKeyAndIV(globalSalt)
	return DES3Decrypt(key, iv, n.Encrypted)
}

func (n nssPBE) Encrypt(globalSalt, plaintext []byte) ([]byte, error) {
	key, iv := n.deriveKeyAndIV(globalSalt)
	return DES3Encrypt(key, iv, plaintext)
}

func (n nssPBE) deriveKeyAndIV(globalSalt []byte) ([]byte, []byte) {
	salt := n.AlgoAttr.SaltAttr.EntrySalt
	hashPrefix := sha1.Sum(globalSalt)
	compositeHash := sha1.Sum(append(hashPrefix[:], salt...))
	paddedEntrySalt := paddingZero(salt, 20)

	hmacProcessor := hmac.New(sha1.New, compositeHash[:])
	hmacProcessor.Write(paddedEntrySalt)

	paddedEntrySalt = append(paddedEntrySalt, salt...)
	keyComponent1 := hmac.New(sha1.New, compositeHash[:])
	keyComponent1.Write(paddedEntrySalt)

	hmacWithSalt := append(hmacProcessor.Sum(nil), salt...)
	keyComponent2 := hmac.New(sha1.New, compositeHash[:])
	keyComponent2.Write(hmacWithSalt)

	key := append(keyComponent1.Sum(nil), keyComponent2.Sum(nil)...)
	iv := key[len(key)-8:]
	return key[:24], iv
}

func paddingZero(src []byte, length int) []byte {
	if len(src) >= length {
		return src
	}
	dst := make([]byte, length)
	copy(dst, src)
	return dst
}

//
//	OBJECT IDENTIFIER
//	SEQUENCE (2 elem)
//	SEQUENCE (2 elem)
//	  OBJECT IDENTIFIER
//	  SEQUENCE (4 elem)
//	  OCTET STRING (32 byte)
//	    INTEGER 1
//	    INTEGER 32
//	    SEQUENCE (1 elem)
//	      OBJECT IDENTIFIER
//	SEQUENCE (2 elem)
//	  OBJECT IDENTIFIER
//	  OCTET STRING (14 byte)
//

type metaPBE struct {
	AlgoAttr  algoAttr
	Encrypted []byte
}

type algoAttr struct {
	asn1.ObjectIdentifier
	Data struct {
		Data struct {
			asn1.ObjectIdentifier
			SlatAttr slatAttr
		}
		IVData ivAttr
	}
}

type ivAttr struct {
	asn1.ObjectIdentifier
	IV []byte
}

type slatAttr struct {
	EntrySalt      []byte
	IterationCount int
	KeySize        int
	Algorithm      struct {
		asn1.ObjectIdentifier
	}
}

func (m metaPBE) Decrypt(globalSalt []byte) ([]byte, error) {
	key, iv := m.deriveKeyAndIV(globalSalt)
	return AES128CBCDecrypt(key, iv, m.Encrypted)
}

func (m metaPBE) Encrypt(globalSalt, plaintext []byte) ([]byte, error) {
	key, iv := m.deriveKeyAndIV(globalSalt)
	return AES128CBCEncrypt(key, iv, plaintext)
}

func (m metaPBE) deriveKeyAndIV(globalSalt []byte) ([]byte, []byte) {
	password := sha1.Sum(globalSalt)

	salt := m.AlgoAttr.Data.Data.SlatAttr.EntrySalt
	iter := m.AlgoAttr.Data.Data.SlatAttr.IterationCount
	keyLen := m.AlgoAttr.Data.Data.SlatAttr.KeySize

	key := PBKDF2Key(password[:], salt, iter, keyLen, sha256.New)
	iv := append([]byte{4, 14}, m.AlgoAttr.Data.IVData.IV...)
	return key, iv
}

//
//	OBJECT IDENTIFIER
//	OCTET STRING (8 byte)
//

type loginPBE struct {
	CipherText []byte
	Data       struct {
		asn1.ObjectIdentifier
		IV []byte
	}
	Encrypted []byte
}

func (l loginPBE) Decrypt(globalSalt []byte) ([]byte, error) {
	key, iv := l.deriveKeyAndIV(globalSalt)
	return DES3Decrypt(key, iv, l.Encrypted)
}

func (l loginPBE) Encrypt(globalSalt, plaintext []byte) ([]byte, error) {
	key, iv := l.deriveKeyAndIV(globalSalt)
	return DES3Encrypt(key, iv, plaintext)
}

func (l loginPBE) deriveKeyAndIV(globalSalt []byte) ([]byte, []byte) {
	return globalSalt, l.Data.IV
}
