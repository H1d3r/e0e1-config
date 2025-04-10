package finalshell

import (
	"crypto/des"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Random struct {
	seed int64
}

func NewRandom(seed int64) *Random {
	if seed == 0 {
		seed = 1
	}
	return &Random{
		seed: (seed ^ 0x5DEECE66D) & ((1 << 48) - 1),
	}
}

func (r *Random) Next(bits int) int64 {
	r.seed = (r.seed*0x5DEECE66D + 0xB) & ((1 << 48) - 1)
	value := r.seed >> (48 - bits)
	if value < (1 << (bits - 1)) {
		return value
	}
	return value - (1 << bits)
}

func (r *Random) NextInt() int32 {
	return int32(r.Next(32))
}

func (r *Random) NextLong() int64 {
	return (r.Next(32) << 32) + r.Next(32)
}

func RemoveNonPrintableChars(input string) string {
	re := regexp.MustCompile(`[\x00-\x1F\x7F-\x9F]`)
	return re.ReplaceAllString(input, "")
}

func RandomKey(head []byte) []byte {
	ilist := []int{24, 54, 89, 120, 19, 49, 85, 115, 14, 44, 80, 110, 9, 40, 75, 106, 43, 73, 109, 12, 38, 68, 104, 7, 33, 64,
		99, 3, 28, 59, 94, 125, 112, 16, 51, 82, 107, 11, 46, 77, 103, 6, 41, 72, 98, 1, 37, 67, 4, 35, 70, 101, 0,
		30, 65, 96, 122, 25, 61, 91, 117, 20, 56, 86, 74, 104, 13, 43, 69, 99, 8, 38, 64, 95, 3, 34, 59, 90, 125,
		29, 93, 123, 32, 62, 88, 119, 27, 58, 83, 114, 22, 53, 79, 109, 17, 48, 35, 66, 101, 5, 31, 61, 96, 0, 26,
		56, 92, 122, 21, 51, 87, 117, 55, 85, 120, 24, 50, 80, 116, 19, 45, 75, 111, 14, 40, 71, 106, 10, 50, 81,
		116, 20, 45, 76, 111, 15, 41, 71, 106, 10, 36, 66, 102, 5, 69, 100, 8, 39, 65, 95, 3, 34, 60, 90, 126, 29,
		55, 85, 121, 24, 12, 42, 78, 108, 7, 37, 73, 103, 2, 33, 68, 99, 124, 28, 63, 94, 31, 61, 97, 0, 26, 57,
		92, 123, 21, 52, 87, 118, 17, 47, 82, 113, 100, 4, 39, 70, 96, 126, 34, 65, 91, 121, 30, 60, 86, 116, 25,
		55, 120, 23, 58, 89, 115, 18, 54, 84, 110, 13, 49, 79, 105, 9, 44, 75, 62, 92, 1, 31, 57, 88, 123, 27, 52,
		83, 118, 22, 48, 78, 113, 17, 81, 112, 20, 51, 76, 107, 15, 46, 72, 102, 10, 41, 67, 97, 6, 36}

	i := ilist[head[5]]
	ks := int64(3680984568597093857) / int64(i)
	random := NewRandom(ks)
	t := int(head[0])
	for i := 0; i < t; i++ {
		random.NextLong()
	}
	n := random.NextLong()
	r2 := NewRandom(n)
	ld := []int64{int64(head[4]), r2.NextLong(), int64(head[7]), int64(head[3]), r2.NextLong(), int64(head[1]), random.NextLong(), int64(head[2])}

	var byteStream []byte
	for _, l := range ld {
		buf := make([]byte, 8)

		binary.BigEndian.PutUint64(buf, uint64(l)&0xFFFFFFFFFFFFFFFF)
		byteStream = append(byteStream, buf...)
	}

	hash := md5.Sum(byteStream)
	return hash[:8]
}

func DecodePass(data string) (string, error) {
	if data == "" {
		return "", fmt.Errorf("empty password data")
	}

	buf, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	if len(buf) < 8 {
		return "", fmt.Errorf("invalid password data length")
	}

	head := buf[:8]
	d := buf[8:]

	key := RandomKey(head)
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(d)%des.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	decrypted := make([]byte, len(d))
	for bs, be := 0, des.BlockSize; bs < len(d); bs, be = bs+des.BlockSize, be+des.BlockSize {
		block.Decrypt(decrypted[bs:be], d[bs:be])
	}

	rs := string(decrypted)
	rs = RemoveNonPrintableChars(rs)
	return rs, nil
}

type Connection struct {
	Host     string `json:"host"`
	Username string `json:"user_name"`
	Password string `json:"password"`
}

func ScanFinalShell(customPath string) (string, error) {
	var connPath string
	if customPath != "" {

		connPath = customPath

		if !strings.HasSuffix(strings.ToLower(connPath), "conn") {
			connPath = filepath.Join(connPath, "conn")
		}
	} else {

		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("获取用户目录失败: %v", err)
		}
		connPath = filepath.Join(home, "AppData", "Local", "finalshell", "conn")
	}

	if _, err := os.Stat(connPath); os.IsNotExist(err) {
		return "", fmt.Errorf("FinalShell连接目录不存在: %s", connPath)
	}

	fmt.Printf("正在扫描FinalShell连接目录: %s\n", connPath)

	var results []string
	err := filepath.Walk(connPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".json") {

			data, err := ioutil.ReadFile(path)
			if err != nil {
				return nil
			}

			var conn Connection
			if err := json.Unmarshal(data, &conn); err != nil {
				return nil
			}

			if conn.Host != "" && conn.Username != "" && conn.Password != "" {

				password, err := DecodePass(conn.Password)
				if err == nil {
					results = append(results, fmt.Sprintf("主机: %s, 用户名: %s, 密码: %s", conn.Host, conn.Username, password))
				}
			}
		}
		return nil
	})

	if err != nil {
		return "", err
	}

	if len(results) == 0 {
		return "未找到FinalShell连接信息", nil
	}

	return strings.Join(results, "\n"), nil
}
