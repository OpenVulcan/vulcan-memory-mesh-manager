//go:build windows

// This file implements cancellable byte-range locking for Windows state files.
// 此文件实现 Windows 状态文件的可取消字节范围锁。
package processctl

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// stateLock holds a Windows byte-range lock until Close is called.
// stateLock 持有 Windows 字节范围锁，直到调用 Close 才释放。
type stateLock struct {
	// file is the open lock file descriptor.
	// file 是打开的锁文件描述符。
	file *os.File
	// overlapped is retained for the matching unlock call.
	// overlapped 为匹配解锁调用而保留。
	overlapped windows.Overlapped
}

// acquireStateLock waits for an exclusive Windows byte-range lock.
// acquireStateLock 等待独占 Windows 字节范围锁。
func acquireStateLock(ctx context.Context, path string) (*stateLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("VMM process state lock could not be opened")
	}
	lock := &stateLock{file: file}
	for {
		err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock.overlapped)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_IO_PENDING) {
			_ = file.Close()
			return nil, errors.New("VMM process state lock could not be acquired")
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

// Close releases the Windows byte-range lock and its file descriptor.
// Close 释放 Windows 字节范围锁及其文件描述符。
func (lock *stateLock) Close() error {
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
