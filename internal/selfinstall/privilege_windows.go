//go:build windows

// This file leaves Windows manager ownership to the existing protected ACL path.
// 本文件在 Windows 上由现有受保护 ACL 路径管理程序所有权。
package selfinstall

import "errors"

// validatePrivilegedManagerRoot has no Unix UID contract on Windows.
// validatePrivilegedManagerRoot 在 Windows 上没有 Unix UID 契约。
func validatePrivilegedManagerRoot(_ string) error { return nil }

// VerifyPrivilegedExecutable is unavailable because Windows elevation uses a separate boundary.
// VerifyPrivilegedExecutable 在 Windows 上不可用，因为提权使用独立边界。
func VerifyPrivilegedExecutable(_ string) error {
	return errors.New("Unix privileged executable verification is unavailable on Windows")
}
