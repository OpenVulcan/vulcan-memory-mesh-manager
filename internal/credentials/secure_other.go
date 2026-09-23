//go:build !windows

// This file applies owner-only permissions and atomic replacement on Unix-like systems.
// 本文件在类 Unix 系统上应用所有者权限并执行原子替换。
package credentials

import (
	"errors"
	"os"
)

// secureFile enforces Unix owner-only read/write permissions for the secret file.
// secureFile 为 Unix 密钥文件强制设置仅所有者可读写权限。
func secureFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return errors.New("could not restrict dotenv permissions")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		return errors.New("dotenv permissions are not restricted")
	}
	return nil
}

// atomicReplace uses os.Rename on Unix, which replaces a same-filesystem target atomically.
// atomicReplace 在 Unix 上使用 os.Rename，在同一文件系统内原子替换目标。
func atomicReplace(source string, target string) error {
	if err := os.Rename(source, target); err != nil {
		return errors.New("could not atomically replace dotenv file")
	}
	return nil
}

// syncDirectory requests directory metadata durability where the filesystem supports it.
// syncDirectory 在文件系统支持时请求目录元数据持久化。
func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
