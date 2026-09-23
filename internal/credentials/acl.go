// This file defines the Windows ACL argument contract used to protect .env files.
// 本文件定义保护 .env 文件时使用的 Windows ACL 参数契约。
package credentials

import (
	"errors"
	"strings"
	"unicode"
)

// windowsACLCommands builds the ordered icacls argument vectors without shell interpolation.
// windowsACLCommands 构造不经过 shell 插值且按顺序执行的 icacls 参数向量。
func windowsACLCommands(path string, principal string) ([][]string, error) {
	if path == "" || principal == "" || strings.TrimSpace(principal) != principal {
		return nil, errors.New("Windows ACL inputs are invalid")
	}
	for _, char := range principal {
		if unicode.IsControl(char) || char == '/' || char == '"' {
			return nil, errors.New("Windows ACL principal is invalid")
		}
	}
	return [][]string{
		{path, "/reset"},
		{path, "/inheritance:r"},
		{path, "/grant:r", principal + ":(F)", "SYSTEM:(F)"},
	}, nil
}
