//go:build windows

// Windows locking uses LockFileEx so the kernel releases the lock if the process exits.
// Windows 锁使用 LockFileEx，使进程退出时由内核自动释放锁。
package selfinstall

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	// lockFileExclusive asks Windows for one exclusive byte-range lock.
	// lockFileExclusive 请求 Windows 创建一个独占字节范围锁。
	lockFileExclusive = 0x00000002
)

var (
	// lockFileExProc resolves the kernel lock operation without external dependencies.
	// lockFileExProc 解析内核锁操作，且不引入外部依赖。
	lockFileExProc   = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")
	// unlockFileExProc resolves the matching kernel unlock operation.
	// unlockFileExProc 解析对应的内核解锁操作。
	unlockFileExProc = syscall.NewLazyDLL("kernel32.dll").NewProc("UnlockFileEx")
)

// lockPlatformFile acquires one exclusive byte-range lock and waits for other processes.
// lockPlatformFile 获取一个独占字节范围锁，并等待其他进程释放。
func lockPlatformFile(file *os.File) error {
	var overlapped syscall.Overlapped
	result, _, callErr := lockFileExProc.Call(
		uintptr(file.Fd()),
		uintptr(lockFileExclusive),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if result == 0 {
		return callErr
	}
	return nil
}

// unlockPlatformFile releases the byte-range lock before the handle closes.
// unlockPlatformFile 在关闭句柄前释放字节范围锁。
func unlockPlatformFile(file *os.File) error {
	var overlapped syscall.Overlapped
	result, _, callErr := unlockFileExProc.Call(
		uintptr(file.Fd()),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if result == 0 {
		return callErr
	}
	return nil
}
