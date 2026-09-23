// data_root_other.go prepares the persistent installation root on non-Windows systems.
// data_root_other.go 负责在非 Windows 系统上准备持久化安装数据根目录。
// It belongs to the installation transaction layer and keeps Unix creation semantics aligned with VMM.
// 它属于安装事务层，并保持与 VMM 一致的 Unix 创建语义。
//go:build !windows

package install

import (
	"fmt"
	"os"
)

// ensureInstallDataRoot creates missing data-root components with private Unix permissions.
// ensureInstallDataRoot 使用私有 Unix 权限创建缺失的数据根目录组件。
// Existing directories are left unchanged so the installer never silently repairs user ownership or mode.
// 已有目录保持不变，安装器不会静默修改用户所有权或权限。
func ensureInstallDataRoot(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private data root %q: %w", path, err)
	}
	return nil
}
