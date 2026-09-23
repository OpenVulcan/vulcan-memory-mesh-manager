//go:build windows

// This file reuses the protected Windows directory ACL for manager control state.
// 本文件复用受保护的 Windows 目录 ACL 来保存管理器控制状态。
package install

// ensureInstallControlRoot prepares a private state and lock directory on Windows.
// ensureInstallControlRoot 在 Windows 上准备私有状态与锁目录。
func ensureInstallControlRoot(path string) error {
	return ensureInstallDataRoot(path)
}
