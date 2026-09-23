// This file implements same-directory atomic persistence for credential documents.
// 本文件实现凭据文档的同目录原子持久化。
package credentials

import (
	"errors"
	"os"
	"path/filepath"
)

// writeAtomic creates a same-directory temporary file, secures it, and replaces the target.
// writeAtomic 在同目录创建临时文件、收紧权限并替换目标文件。
func writeAtomic(path string, data []byte) error {
	return writeAtomicWith(path, data, secureFile, atomicReplace)
}

// writeAtomicWith keeps security and replacement seams injectable for failure-path tests.
// writeAtomicWith 保留可注入的安全设置与替换边界，用于失败路径测试。
func writeAtomicWith(path string, data []byte, secure func(string) error, replace func(string, string) error) error {
	if err := validatePath(path); err != nil {
		return err
	}
	if secure == nil || replace == nil {
		return errors.New("dotenv atomic writer requires security and replacement handlers")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".vmmm-env-*")
	if err != nil {
		return errors.New("could not create temporary dotenv file")
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.New("could not restrict temporary dotenv permissions")
	}
	// Apply the final ACL before the first secret byte is written to the temporary file.
	// 在向临时文件写入第一个密钥字节前应用最终 ACL。
	if err := secure(temporaryPath); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return errors.New("could not write temporary dotenv file")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("could not flush temporary dotenv file")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("could not close temporary dotenv file")
	}
	if err := replace(temporaryPath, path); err != nil {
		return err
	}
	removeTemporary = false
	// Directory synchronization is best effort because some supported filesystems do not
	// expose fsync for directories; replacement itself remains same-directory and atomic.
	// 目录同步是尽力而为的，因为部分支持的文件系统不提供目录 fsync；替换本身仍在同目录原子完成。
	_ = syncDirectory(directory)
	return nil
}
