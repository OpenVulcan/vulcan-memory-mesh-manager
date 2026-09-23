//go:build !windows

// This file validates root-owned manager paths before installation or sudo re-entry.
// 本文件在安装或 sudo 重新进入前校验 root 持有的管理器路径。
package selfinstall

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// validatePrivilegedManagerRoot protects the full path when root manages a system installation.
// validatePrivilegedManagerRoot 在 root 管理系统安装时保护整条目录链。
func validatePrivilegedManagerRoot(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return verifyRootPathChain(path, true)
}

// VerifyPrivilegedExecutable validates a fixed root-owned manager before an ordinary user may sudo it.
// VerifyPrivilegedExecutable 验证固定 root 所有的管理器，供普通用户安全 sudo 启动。
func VerifyPrivilegedExecutable(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("privileged manager executable must be absolute")
	}
	if err := verifyRootPathChain(filepath.Dir(path), false); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o001 == 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("privileged manager executable is unsafe")
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 {
		return errors.New("privileged manager executable is not root-owned")
	}
	return nil
}

// verifyRootPathChain checks every existing component and forbids service-writable ancestors.
// verifyRootPathChain 检查每个现有目录组件并拒绝服务可写的祖先。
func verifyRootPathChain(path string, allowMissing bool) error {
	if !filepath.IsAbs(path) {
		return errors.New("privileged manager root must be absolute")
	}
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && allowMissing {
			// Root creates only the absent suffix after its existing ancestors are checked.
			// root 仅在校验现有祖先后创建缺失的路径后缀。
		} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o005 != 0o005 {
			return errors.New("privileged manager directory is unsafe")
		} else {
			metadata, ok := info.Sys().(*syscall.Stat_t)
			if !ok || metadata.Uid != 0 {
				return errors.New("privileged manager directory is not root-owned")
			}
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}
