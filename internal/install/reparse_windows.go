//go:build windows

// Package install contains Windows path guards for VMM installation transactions.
// install 包含 VMM 安装事务在 Windows 平台上的路径安全检查。
package install

import (
	"os"
	"syscall"
)

// isUnsafePathEntry rejects symbolic links and every Windows reparse point, including junctions.
// isUnsafePathEntry 拒绝符号链接以及包括目录联接在内的所有 Windows 重解析点。
func isUnsafePathEntry(path string, info os.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attributes, err := syscall.GetFileAttributes(name)
	if err != nil {
		return true
	}
	return attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
