//go:build !windows

// Package fetch contains non-Windows staging path checks.
// fetch 包包含非 Windows 平台的暂存路径检查。
// The helper rejects symbolic links while rooted operations constrain later access to the staging directory.
// 该辅助函数拒绝符号链接，后续根目录句柄操作则将访问约束在暂存目录内。
package fetch

import "os"

// pathIsReparsePoint reports whether a non-Windows path is a symbolic link.
// pathIsReparsePoint 报告非 Windows 路径是否为符号链接。
func pathIsReparsePoint(_ string, info os.FileInfo) (bool, error) {
	return info.Mode()&os.ModeSymlink != 0, nil
}
