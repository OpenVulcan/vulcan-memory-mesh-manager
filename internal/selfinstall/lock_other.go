//go:build !windows

// POSIX locking uses flock so the kernel releases the lock if the process exits.
// POSIX 锁使用 flock，使进程退出时由内核自动释放锁。
package selfinstall

import (
	"os"
	"syscall"
)

// lockPlatformFile acquires an exclusive advisory lock and waits for other processes.
// lockPlatformFile 获取独占建议锁，并等待其他进程释放。
func lockPlatformFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
}

// unlockPlatformFile releases the exclusive advisory lock.
// unlockPlatformFile 释放独占建议锁。
func unlockPlatformFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
