//go:build windows

// This file provides Windows atomic path-record replacement through MoveFileExW.
// 本文件通过 MoveFileExW 为 Windows 提供路径记录原子替换。
package pathctl

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	// replaceExistingFile permits replacing the previous path record atomically.
	// replaceExistingFile 允许原子替换之前的路径记录。
	replaceExistingFile uint32 = 0x00000001

	// writeThroughFile requests that the replacement is flushed before returning.
	// writeThroughFile 请求在返回前刷新替换操作。
	writeThroughFile uint32 = 0x00000008
)

// replaceRecordProc resolves MoveFileExW lazily for atomic Windows record replacement.
// replaceRecordProc 延迟解析 MoveFileExW，用于 Windows 记录原子替换。
var replaceRecordProc = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

// replaceRecord uses MoveFileExW because os.Rename cannot replace an existing Windows file.
// replaceRecord 使用 MoveFileExW，因为 os.Rename 无法替换已有 Windows 文件。
func replaceRecord(temporaryPath string, destinationPath string) error {
	temporaryUTF16, err := syscall.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return fmt.Errorf("encode temporary path: %w", err)
	}
	destinationUTF16, err := syscall.UTF16PtrFromString(destinationPath)
	if err != nil {
		return fmt.Errorf("encode destination path: %w", err)
	}
	result, _, callErr := replaceRecordProc.Call(
		uintptr(unsafe.Pointer(temporaryUTF16)),
		uintptr(unsafe.Pointer(destinationUTF16)),
		uintptr(replaceExistingFile|writeThroughFile),
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
