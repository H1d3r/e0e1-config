package jiexi

import (
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/unicode"
)

func DetectEncoding(content []byte) (encoding.Encoding, error) {

	if len(content) >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF {
		return unicode.UTF8, nil
	}

	if len(content) >= 2 && content[0] == 0xFF && content[1] == 0xFE {
		return unicode.UTF16(unicode.LittleEndian, unicode.UseBOM), nil
	}

	if len(content) >= 2 && content[0] == 0xFE && content[1] == 0xFF {
		return unicode.UTF16(unicode.BigEndian, unicode.UseBOM), nil
	}

	if isGBK(content) {
		return simplifiedchinese.GB18030, nil
	}

	return unicode.UTF8, nil
}

func isGBK(data []byte) bool {
	length := len(data)
	var i int = 0
	for i < length {
		if data[i] <= 0x7f {

			i++
			continue
		} else {

			if i+1 < length {

				if data[i] >= 0x81 && data[i] <= 0xFE && data[i+1] >= 0x40 && data[i+1] <= 0xFE {
					i += 2
					continue
				}
			}
			return false
		}
	}
	return true
}
