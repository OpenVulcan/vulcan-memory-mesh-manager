//go:build !windows

// This file protects the Unix state and lock root from service-account writes.
// 本文件保护 Unix 状态与锁目录，避免服务账户写入。
package install

import (
	"errors"
	"os"
	"syscall"
)

// ensureInstallControlRoot creates a private owner-only root without repairing existing paths.
// ensureInstallControlRoot 创建仅所有者可访问的私有目录，不静默修复已有路径。
func ensureInstallControlRoot(path string) error {
	if err := validateDirectoryPath("control root", path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := validateDirectoryPath("control root", path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("control root must be an owner-only real directory")
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != uint32(os.Geteuid()) {
		return errors.New("control root owner does not match manager identity")
	}
	return nil
}
