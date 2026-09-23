//go:build windows

// This file leaves Windows installation ownership to the protected ACL adapters.
// 本文件在 Windows 上由现有受保护 ACL 适配器管理安装目录权限。
package install

import "errors"

// validateServiceOwnership is a no-op because Windows uses ACLs instead of Unix UIDs.
// validateServiceOwnership 在 Windows 上不执行 Unix UID 检查。
func validateServiceOwnership(_ Request) error { return nil }

// prepareServiceOwnership keeps Windows directory preparation in existing transaction code.
// prepareServiceOwnership 在 Windows 上沿用现有事务目录准备逻辑。
func prepareServiceOwnership(_ Request) error { return nil }

// assignServiceConfigOwnership keeps Windows file ACL handling in existing adapters.
// assignServiceConfigOwnership 在 Windows 上沿用现有文件 ACL 处理逻辑。
func assignServiceConfigOwnership(_ Request, _ []string) error { return nil }

// PrepareServiceConfigRoot rejects Unix account ownership on Windows.
// PrepareServiceConfigRoot 在 Windows 上拒绝 Unix 账户所有权操作。
func PrepareServiceConfigRoot(_ string, _ string) (uint32, uint32, error) {
	return 0, 0, errors.New("Unix service account ownership is unavailable on Windows")
}
