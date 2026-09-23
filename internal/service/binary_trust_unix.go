//go:build !windows

// This file checks the full Unix program tree before root executes VMM service commands.
// 本文件在 root 执行 VMM 服务命令前校验完整 Unix 程序树。
package service

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// validateServiceBinaryTrust rejects writable ancestors, package entries, and symlink redirects.
// validateServiceBinaryTrust 拒绝可写祖先、可写程序包条目及符号链接重定向。
func validateServiceBinaryTrust(binaryPath string) error {
	if !filepath.IsAbs(binaryPath) || filepath.Base(filepath.Dir(binaryPath)) != "bin" {
		return errors.New("VMM service executable is outside its packaged bin directory")
	}
	programRoot := filepath.Dir(filepath.Dir(binaryPath))
	for current := programRoot; ; current = filepath.Dir(current) {
		if err := validateTrustedEntry(current, true); err != nil {
			return err
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return filepath.WalkDir(programRoot, func(path string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		return validateTrustedEntry(path, false)
	})
}

// validateTrustedEntry requires root ownership and permissions safe for service traversal.
// validateTrustedEntry 要求 root 所有权以及服务账户可遍历且不可修改的权限。
func validateTrustedEntry(path string, ancestor bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !(info.IsDir() || info.Mode().IsRegular()) {
		return errors.New("VMM service program path is unsafe")
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("VMM service program path is not root-owned and protected")
	}
	if info.IsDir() && info.Mode().Perm()&0o005 != 0o005 {
		return errors.New("VMM service program directory is not traversable")
	}
	if ancestor && !info.IsDir() {
		return errors.New("VMM service program ancestor is not a directory")
	}
	return nil
}
