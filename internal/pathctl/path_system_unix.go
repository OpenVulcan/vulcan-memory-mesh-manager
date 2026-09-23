//go:build !windows

// This file constrains the optional machine-wide Unix vmmm command link.
// 本文件约束可选的 Unix 机器级 vmmm 命令链接。
package pathctl

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/selfinstall"
)

// validateSystemCommandTarget requires a trusted manager binary before exposing it system-wide.
// validateSystemCommandTarget 要求目标管理器可信，才允许将其暴露为机器级命令。
func validateSystemCommandTarget(path string) error {
	if os.Geteuid() != 0 {
		return errors.New("system command integration requires a root manager")
	}
	return selfinstall.VerifyPrivilegedExecutable(path)
}

// validateSystemCommandLinkParent checks the fixed command directory and every ancestor.
// validateSystemCommandLinkParent 检查固定命令目录及其全部祖先。
func validateSystemCommandLinkParent(path string) error {
	if os.Geteuid() != 0 || filepath.Clean(path) != "/usr/local/bin" {
		return errors.New("system command link parent is invalid")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o005 != 0o005 {
			return errors.New("system command directory is unsafe")
		}
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || metadata.Uid != 0 {
			return errors.New("system command directory is not root-owned")
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}
