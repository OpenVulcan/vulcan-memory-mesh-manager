//go:build !windows

// Package install contains POSIX path guards for VMM installation transactions.
// install 包含 VMM 安装事务在 POSIX 平台上的路径安全检查。
package install

import "os"

// isUnsafePathEntry reports symbolic links and other non-directory redirects visible on POSIX.
// isUnsafePathEntry 报告 POSIX 平台可见的符号链接及其他不安全路径重定向。
func isUnsafePathEntry(_ string, info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}
