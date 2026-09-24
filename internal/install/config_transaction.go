// This file confines configuration promotion and recovery to pinned directory handles.
// 本文件将配置推广与恢复限制在已固定的目录句柄内，防止服务账户并发替换目录造成越界。
package install

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// configFileChange owns one configuration replacement and its same-volume private backup.
// configFileChange 持有一项配置替换及其同卷私有备份，所有操作均使用固定的父目录句柄。
type configFileChange struct {
	// parent and backup pin the original directories even if their names are replaced.
	// parent 与 backup 固定原始目录，即使对应路径名称被替换也不会改指其他目录。
	parent *os.Root
	backup *os.Root
	// target, temporary, and backupName are single components relative to parent.
	// target、temporary 与 backupName 均为相对于 parent 的单个路径组件。
	target, temporary, backupName string
	// digest and size identify the promoted bytes before a rollback may remove them.
	// digest 与 size 标识推广后的内容，回滚只能删除仍然匹配的文件。
	digest string
	size   int64
	// backedUp and promoted record completed mutations for recovery after partial failure.
	// backedUp 与 promoted 记录已完成的修改，便于部分失败后恢复。
	backedUp, promoted bool
	// closed keeps repeated deferred cleanup idempotent.
	// closed 保证重复执行的延迟清理保持幂等。
	closed bool
}

// replaceConfigFile publishes one validated overlay below its bounded configuration root.
// replaceConfigFile 在受限配置根内推广一个已校验覆盖文件；参数为源文件、配置根、相对路径与文件权限。
// It returns an error before any operation can follow a swapped parent outside that root.
// 如果目录被替换并指向根外，则返回错误，任何操作都不会跟随该路径越界。
func (transaction *fileTransaction) replaceConfigFile(source, configRoot, relative string, mode os.FileMode) error {
	if _, err := safeConfigPath(configRoot, relative); err != nil {
		return err
	}
	root, err := os.OpenRoot(configRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	parentName := filepath.Dir(filepath.FromSlash(relative))
	if err := root.MkdirAll(parentName, 0o700); err != nil {
		return err
	}
	parent, err := root.OpenRoot(parentName)
	if err != nil {
		return err
	}
	change := &configFileChange{parent: parent, target: filepath.Base(filepath.FromSlash(relative))}
	transaction.configChanges = append(transaction.configChanges, change)
	change.digest, change.size, err = digestFile(source)
	if err != nil {
		return err
	}
	// Stage and chmod through the file descriptor before publication; never chmod a mutable target name.
	// 发布前通过文件句柄暂存并设置权限，绝不对可被并发替换的目标名称执行 chmod。
	change.temporary = ".vmmm-config-" + rand.Text()
	file, err := parent.OpenFile(change.temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := copyConfigCandidate(source, file, change.digest, change.size, mode); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if info, err := parent.Lstat(change.target); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("configuration target is not a regular file")
		}
		change.backupName = ".vmmm-backup-" + rand.Text()
		if err := parent.Mkdir(change.backupName, 0o700); err != nil {
			return err
		}
		change.backup, err = parent.OpenRoot(change.backupName)
		if err != nil {
			return err
		}
		if err := parent.Rename(change.target, filepath.Join(change.backupName, "original")); err != nil {
			return err
		}
		change.backedUp = true
		original, err := change.backup.Lstat("original")
		if err != nil || !original.Mode().IsRegular() || !os.SameFile(info, original) {
			return errors.New("configuration target changed while being backed up")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := parent.Rename(change.temporary, change.target); err != nil {
		return err
	}
	change.temporary = ""
	change.promoted = true
	return nil
}

// copyConfigCandidate copies and verifies source bytes into an open private file, then sets mode and syncs.
// copyConfigCandidate 将源内容复制并校验到已打开的私有文件，随后设置权限并同步；返回任一阶段的错误。
func copyConfigCandidate(source string, output *os.File, digest string, size int64, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(output, hash), input)
	if err != nil {
		return err
	}
	if written != size || hex.EncodeToString(hash.Sum(nil)) != digest {
		return errors.New("configuration candidate changed during copy")
	}
	if err := output.Chmod((mode & 0o777) | 0o600); err != nil {
		return err
	}
	return output.Sync()
}

// removePromoted removes only unchanged transaction bytes through the pinned parent.
// removePromoted 仅通过固定父目录删除仍与事务摘要匹配的内容；修改过的文件会保留并返回错误。
func (change *configFileChange) removePromoted() error {
	info, err := change.parent.Lstat(change.target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("configuration target changed type before rollback")
	}
	file, err := change.parent.Open(change.target)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("configuration target changed before rollback")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, change.size+1))
	if err != nil {
		return err
	}
	if size != change.size || hex.EncodeToString(hash.Sum(nil)) != change.digest {
		return errors.New("configuration target content changed before rollback")
	}
	return change.parent.Remove(change.target)
}

// verifyBackupName checks that the backup entry still names the directory originally opened.
// verifyBackupName 检查备份名称仍指向最初打开的目录，返回目录替换或访问错误。
func (change *configFileChange) verifyBackupName() error {
	info, err := change.parent.Lstat(change.backupName)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("configuration backup directory changed")
	}
	original, err := change.backup.Stat(".")
	if err != nil || !os.SameFile(info, original) {
		return errors.New("configuration backup directory identity changed")
	}
	return nil
}

// rollback restores the original configuration in its pinned parent, preserving concurrent user edits.
// rollback 在固定父目录内恢复原配置，遇到并发用户修改时保留内容并返回错误。
func (change *configFileChange) rollback() error {
	if !change.promoted && !change.backedUp {
		return nil
	}
	if change.promoted {
		if err := change.removePromoted(); err != nil {
			return err
		}
		change.promoted = false
	}
	if change.backedUp {
		if err := change.verifyBackupName(); err != nil {
			return err
		}
		if _, err := change.parent.Lstat(change.target); !errors.Is(err, os.ErrNotExist) {
			return errors.New("configuration rollback target is occupied")
		}
		if err := change.parent.Rename(filepath.Join(change.backupName, "original"), change.target); err != nil {
			return err
		}
		change.backedUp = false
	}
	return nil
}

// cleanup deletes only known temporary entries; it never recursively removes a mutable directory name.
// cleanup 只删除已知临时项，绝不递归删除可被替换的目录名称；失败时返回错误并保留可恢复内容。
func (change *configFileChange) cleanup() error {
	if change.closed {
		return nil
	}
	if change.temporary != "" {
		if err := change.parent.Remove(change.temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if change.backup != nil {
		if err := change.verifyBackupName(); err != nil {
			return err
		}
		if err := change.backup.Remove("original"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := change.backup.Close(); err != nil {
			return err
		}
		change.backup = nil
	}
	if change.backupName != "" {
		if err := change.parent.Remove(change.backupName); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove empty configuration backup: %w", err)
		}
		change.backupName = ""
	}
	return nil
}

// close releases pinned directory handles without removing files needed for manual recovery.
// close 释放固定目录句柄，不删除可能用于人工恢复的文件。
func (change *configFileChange) close() {
	if change.closed {
		return
	}
	if change.backup != nil {
		_ = change.backup.Close()
	}
	_ = change.parent.Close()
	change.closed = true
}
