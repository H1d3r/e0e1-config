package guolv

import (
	"bytes"
)

func ContainsAny(line []byte, blacklist [][]byte) bool {
	for _, blackItem := range blacklist {
		if bytes.Contains(bytes.ToLower(line), bytes.ToLower(blackItem)) {
			return true
		}
	}
	return false
}
