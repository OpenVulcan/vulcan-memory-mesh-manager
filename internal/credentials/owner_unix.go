//go:build !windows

// This file protects service-owned credential updates made by a privileged Unix manager.
// 本文件保护 Unix 特权管理器写入服务账户凭据时的所有权边界。
package credentials

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// validateOwnerTarget verifies the service-owned directory and existing secret file.
// validateOwnerTarget 校验服务账户持有的目录与已存在的密钥文件。
func validateOwnerTarget(path string, owner Owner) error {
	if os.Geteuid() != 0 {
		return ErrOwnerConflict
	}
	if err := validatePath(path); err != nil {
		return err
	}
	directory := filepath.Dir(path)
	for current := directory; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrOwnerConflict
		}
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrOwnerConflict
		}
		if current == directory {
			if metadata.Uid != owner.UID || info.Mode().Perm()&0o700 != 0o700 || info.Mode().Perm()&0o077 != 0 {
				return ErrOwnerConflict
			}
		} else if metadata.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return ErrOwnerConflict
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o600 != 0o600 {
		return ErrOwnerConflict
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != owner.UID || metadata.Gid != owner.GID {
		return ErrOwnerConflict
	}
	return nil
}

// writeAtomicForOwner sets the final owner before writing any credential bytes.
// writeAtomicForOwner 在写入任何凭据字节之前设置最终所有者。
func writeAtomicForOwner(path string, data []byte, owner *Owner) error {
	if owner == nil {
		return writeAtomic(path, data)
	}
	if err := validateOwnerTarget(path, *owner); err != nil {
		return err
	}
	directory := filepath.Dir(path)
	root, err := os.OpenRoot(directory)
	if err != nil {
		return ErrOwnerConflict
	}
	defer root.Close()
	temporaryName := ".vmmm-env-" + rand.Text()
	temporary, err := root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrOwnerConflict
	}
	defer func() {
		_ = temporary.Close()
		_ = root.Remove(temporaryName)
	}()
	// Ownership is assigned to the opened inode before the first secret byte is written.
	// 在写入第一个密钥字节前，对已打开的 inode 设置目标所有权。
	if err := temporary.Chown(int(owner.UID), int(owner.GID)); err != nil {
		return ErrOwnerConflict
	}
	if err := temporary.Chmod(0o600); err != nil {
		return ErrOwnerConflict
	}
	if err := validateOwnerTemp(temporary, *owner); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return errors.New("could not write temporary dotenv file")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("could not flush temporary dotenv file")
	}
	if err := validateOwnerTarget(path, *owner); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return errors.New("could not close temporary dotenv file")
	}
	if err := root.Rename(temporaryName, ".env"); err != nil {
		return err
	}
	_ = syncDirectory(directory)
	return nil
}

// validateOwnerTemp confirms the opened temporary inode has the intended ownership.
// validateOwnerTemp 确认已打开的临时 inode 具有目标所有权。
func validateOwnerTemp(file *os.File, owner Owner) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return ErrOwnerConflict
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != owner.UID || metadata.Gid != owner.GID {
		return ErrOwnerConflict
	}
	return nil
}
