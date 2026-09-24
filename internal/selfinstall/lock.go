// Package selfinstall contains the portable lock handle used to serialize one installation root.
// selfinstall 包含用于串行化单个安装根目录的可移植锁句柄。
package selfinstall

import (
	"errors"
	"fmt"
	"os"
)

// processLock owns an operating-system lock held on the installation anchor file.
// processLock 持有安装锚定文件上的操作系统锁。
type processLock struct {
	file *os.File
}

// acquireProcessLock opens the persistent anchor and blocks until this process owns it.
// acquireProcessLock 打开持久化锚定文件，并阻塞至当前进程获得独占锁。
func acquireProcessLock(path string) (*processLock, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || hasReparsePoint(path) {
			return nil, fmt.Errorf("%w: lock path is not a regular file", ErrUnsafePath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect installation lock: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open installation lock: %w", err)
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !openedInfo.Mode().IsRegular() {
		_ = file.Close()
		if statErr != nil {
			return nil, fmt.Errorf("inspect opened installation lock: %w", statErr)
		}
		return nil, fmt.Errorf("%w: opened installation lock is not a regular file", ErrUnsafePath)
	}
	finalInfo, finalErr := os.Lstat(path)
	if finalErr != nil || finalInfo.Mode()&os.ModeSymlink != 0 || !finalInfo.Mode().IsRegular() {
		_ = file.Close()
		if finalErr != nil {
			return nil, fmt.Errorf("%w: installation lock changed while opening: %v", ErrUnsafePath, finalErr)
		}
		return nil, fmt.Errorf("%w: installation lock became a non-regular file", ErrUnsafePath)
	}
	if !os.SameFile(finalInfo, openedInfo) {
		_ = file.Close()
		return nil, fmt.Errorf("%w: installation lock changed while opening", ErrUnsafePath)
	}
	if hasReparsePoint(path) {
		_ = file.Close()
		return nil, fmt.Errorf("%w: installation lock is a reparse point", ErrUnsafePath)
	}
	if err := lockPlatformFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("acquire installation lock: %w", err)
	}
	return &processLock{file: file}, nil
}

// close releases the operating-system lock and closes its anchor without deleting the anchor.
// close 释放操作系统锁并关闭锚定文件，但不删除锚定文件。
func (lock *processLock) close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := unlockPlatformFile(lock.file)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
