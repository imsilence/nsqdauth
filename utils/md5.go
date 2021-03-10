package utils

import (
	"crypto/md5"
	"fmt"
)

// Md5 MD5工具
func Md5(txt string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(txt)))
}
