//go:build windows

// This file provides cancellable byte-range locking for Windows install transactions.
// 本文件为 Windows 安装事务提供可取消的字节范围锁。
package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// installLock holds the Windows lock file descriptor until Close is called.
// installLock 持有 Windows 锁文件描述符，直到调用 Close 释放。
type installLock struct {
	// file is the open lock file descriptor.
	// file 是打开的锁文件描述符。
	file *os.File
	// overlapped is retained for the matching unlock call.
	// overlapped 用于匹配 Windows 解锁调用。
	overlapped windows.Overlapped
}

// acquireInstallLock waits for exclusive access without allowing concurrent state transactions.
// acquireInstallLock 等待独占访问，阻止并发状态事务交错执行。
func acquireInstallLock(ctx context.Context, path string) (*installLock, error) {
	if err := validateInstallLockPath(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, errors.New("installation lock could not be opened")
	}
	if err := verifyOpenedInstallLock(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	lock := &installLock{file: file}
	for {
		err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock.overlapped)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_IO_PENDING) {
			_ = file.Close()
			return nil, fmt.Errorf("installation lock could not be acquired: %w", err)
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			_ = file.Close()
			return nil, ctx.Err()
		}
	}
}

// Close releases the Windows byte-range lock and descriptor.
// Close 释放 Windows 字节范围锁和文件描述符。
func (lock *installLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := windows.UnlockFileEx(windows.Handle(lock.file.Fd()), 0, 1, 0, &lock.overlapped)
	closeErr := lock.file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
