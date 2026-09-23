//go:build windows

// This file supplies the Windows atomic replacement used by state persistence.
// 本文件提供状态持久化使用的 Windows 原子替换实现。
package state

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	// moveFileReplaceExisting allows replacing an existing registration file.
	// moveFileReplaceExisting 允许替换已经存在的登记文件。
	moveFileReplaceExisting uint32 = 0x00000001

	// moveFileWriteThrough requests that the replacement is flushed before returning.
	// moveFileWriteThrough 请求在返回前刷新替换操作。
	moveFileWriteThrough uint32 = 0x00000008
)

var moveFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

// atomicReplace uses MoveFileExW because os.Rename cannot replace an existing file on Windows.
// atomicReplace 使用 MoveFileExW，因为 Windows 上 os.Rename 不能替换已存在文件。
func atomicReplace(temporaryPath string, destinationPath string) error {
	temporaryUTF16, err := syscall.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return fmt.Errorf("encode temporary path: %w", err)
	}
	destinationUTF16, err := syscall.UTF16PtrFromString(destinationPath)
	if err != nil {
		return fmt.Errorf("encode destination path: %w", err)
	}
	result, _, callErr := moveFileEx.Call(
		uintptr(unsafe.Pointer(temporaryUTF16)),
		uintptr(unsafe.Pointer(destinationUTF16)),
		uintptr(moveFileReplaceExisting|moveFileWriteThrough),
	)
	if result != 0 {
		return nil
	}
	if callErr == nil {
		callErr = syscall.GetLastError()
	}
	if callErr == nil {
		callErr = errors.New("MoveFileExW failed without an operating-system error")
	}
	return fmt.Errorf("MoveFileExW: %w", callErr)
}
