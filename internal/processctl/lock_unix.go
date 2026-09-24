//go:build !windows

// This file implements cancellable advisory locking for Unix state files.
// 此文件实现 Unix 状态文件的可取消建议式锁。
package processctl

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

// stateLock holds an advisory Unix file lock until Close is called.
// stateLock 持有 Unix 建议式文件锁，直到调用 Close 才释放。
type stateLock struct {
	// file is the open lock file descriptor.
	// file 是打开的锁文件描述符。
	file *os.File
}

// acquireStateLock waits for an exclusive advisory lock without busy spinning.
// acquireStateLock 等待独占建议式锁，且不会忙等消耗 CPU。
func acquireStateLock(ctx context.Context, path string) (*stateLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("VMM process state lock could not be opened")
	}
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &stateLock{file: file}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
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

// Close releases the advisory lock and its file descriptor.
// Close 释放建议式锁及其文件描述符。
func (lock *stateLock) Close() error {
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
