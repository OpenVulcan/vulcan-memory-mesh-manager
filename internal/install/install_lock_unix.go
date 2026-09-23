//go:build !windows

// This file provides cancellable advisory locking for install transactions on Unix-like systems.
// 本文件为 Unix 类系统的安装事务提供可取消的建议锁。
package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// installLock holds the installation lock file descriptor until Close is called.
// installLock 持有安装锁文件描述符，直到调用 Close 释放。
type installLock struct {
	// file is the open lock file descriptor.
	// file 是打开的锁文件描述符。
	file *os.File
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
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return lock, nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
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

// Close releases the Unix advisory lock and descriptor.
// Close 释放 Unix 建议锁和文件描述符。
func (lock *installLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
