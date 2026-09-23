//go:build !windows

// This file enforces private POSIX permissions for persisted path records.
// 本文件为持久化路径记录强制执行私有 POSIX 权限。
package pathctl

import (
	"errors"
	"os"
)

// validateRecordPermissions rejects group or world-readable path records.
// validateRecordPermissions 拒绝组用户或其他用户可读的路径记录。
func validateRecordPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("record file permissions must be private (0600 or stricter)")
	}
	return nil
}
