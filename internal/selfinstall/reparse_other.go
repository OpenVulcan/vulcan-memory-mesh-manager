//go:build !windows

// Package selfinstall contains the non-Windows reparse-point guard for self-installation paths.
// selfinstall 包含非 Windows 自安装路径的重解析点保护。
package selfinstall

// hasReparsePoint reports no Windows-specific reparse metadata on POSIX targets.
// hasReparsePoint 在 POSIX 目标上报告不存在 Windows 专属重解析元数据。
func hasReparsePoint(path string) bool {
	return false
}
