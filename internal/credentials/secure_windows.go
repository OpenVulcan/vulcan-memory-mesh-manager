//go:build windows

// This file applies a restricted current-user and SYSTEM ACL on Windows.
// 本文件在 Windows 上应用仅当前用户和 SYSTEM 的受限 ACL。
package credentials

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
)

// secureFile uses the system icacls binary to leave only the current user and SYSTEM.
// secureFile 使用系统 icacls，仅保留当前用户和 SYSTEM 的访问控制项。
func secureFile(path string) error {
	current, err := user.Current()
	if err != nil || current.Username == "" {
		return errors.New("cannot identify the current Windows user for dotenv ACL")
	}
	commands, err := windowsACLCommands(path, current.Username)
	if err != nil {
		return err
	}
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = os.Getenv("windir")
	}
	if !filepath.IsAbs(systemRoot) {
		return errors.New("cannot locate the trusted Windows ACL utility")
	}
	icacls := filepath.Join(systemRoot, "System32", "icacls.exe")
	info, err := os.Stat(icacls)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("trusted Windows ACL utility is unavailable")
	}
	// exec.Command passes each argument directly to CreateProcess; no shell parses user input.
	// exec.Command 将每个参数直接传给 CreateProcess，不经过 shell 解析用户输入。
	for _, args := range commands {
		if err := exec.Command(icacls, args...).Run(); err != nil {
			return errors.New("could not restrict dotenv ACL")
		}
	}
	return nil
}

// atomicReplace uses MoveFileExW with replace and write-through flags on one volume.
// atomicReplace 在同一卷上使用带替换和写穿标志的 MoveFileExW。
func atomicReplace(source string, target string) error {
	return moveFileReplace(source, target)
}

// syncDirectory is intentionally a no-op because Windows does not expose POSIX directory fsync.
// syncDirectory 在 Windows 上有意为空操作，因为 Windows 没有 POSIX 目录 fsync。
func syncDirectory(string) error {
	return nil
}
