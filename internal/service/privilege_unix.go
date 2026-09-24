//go:build linux || darwin

// This file applies the Unix privilege boundary used by VMMM service-management writes.
// 本文件实现 VMMM 服务管理写操作使用的 Unix 提权边界。
// It belongs to the service adapter and is called only after controller ownership checks.
// 它属于服务适配层，仅在 controller 完成账户归属检查后调用。
package service

import (
	"fmt"
	"os"
	"syscall"
)

const (
	// secureSudoExecutable fixes sudo to the trusted system location and prevents PATH hijacking.
	// secureSudoExecutable 将 sudo 固定到可信系统路径，防止 PATH 劫持。
	secureSudoExecutable = "/usr/bin/sudo"
)

var (
	// effectiveUID is replaceable by package tests so the non-root branch is deterministic.
	// effectiveUID 可由包测试替换，以便确定性覆盖非 root 分支。
	effectiveUID = os.Geteuid

	// resolveSudoExecutable is replaceable by package tests while production always validates the fixed path.
	// resolveSudoExecutable 可由包测试替换，生产环境始终校验固定路径。
	resolveSudoExecutable = resolveSecureSudoExecutable
)

// preparePrivilegedCommand selects a trusted non-interactive sudo vector for Unix service writes.
// preparePrivilegedCommand 为 Unix 服务写操作选择可信的非交互 sudo 参数数组。
func preparePrivilegedCommand(binaryPath string, args []string, privileged bool) (string, []string, bool, error) {
	if !privileged || effectiveUID() == 0 {
		return binaryPath, args, false, nil
	}
	sudoPath, err := resolveSudoExecutable()
	if err != nil {
		return "", nil, true, err
	}
	return sudoPath, sudoCommandArguments(binaryPath, args), true, nil
}

// resolveSecureSudoExecutable accepts only the fixed root-owned, executable, non-writable sudo binary.
// resolveSecureSudoExecutable 只接受固定路径下 root 所有、可执行且不可写的 sudo 二进制文件。
func resolveSecureSudoExecutable() (string, error) {
	info, err := os.Lstat(secureSudoExecutable)
	if err != nil {
		return "", fmt.Errorf("%w: fixed path cannot be inspected", ErrSecureSudoUnavailable)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: fixed path is not a regular non-symlink file", ErrSecureSudoUnavailable)
	}
	if info.Mode().Perm()&0022 != 0 {
		return "", fmt.Errorf("%w: fixed path is group/other writable", ErrSecureSudoUnavailable)
	}
	if info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("%w: fixed path is not executable", ErrSecureSudoUnavailable)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Uid) != 0 {
		return "", fmt.Errorf("%w: fixed path is not root-owned", ErrSecureSudoUnavailable)
	}
	return secureSudoExecutable, nil
}
