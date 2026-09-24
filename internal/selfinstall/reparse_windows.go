// Package selfinstall contains the Windows reparse-point guard for self-installation paths.
// selfinstall 包含 Windows 自安装路径的重解析点保护。
package selfinstall

import "syscall"

// hasReparsePoint rejects junctions, symbolic links, and other Windows reparse points.
// hasReparsePoint 拒绝连接点、符号链接和其他 Windows 重解析点。
func hasReparsePoint(path string) bool {
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
