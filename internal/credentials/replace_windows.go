//go:build windows

// This file provides the Windows same-volume atomic replacement primitive.
// 本文件提供 Windows 同卷原子替换原语。
package credentials

import (
	"errors"
	"syscall"
	"unsafe"
)

const (
	// moveFileReplaceExisting replaces the destination as one filesystem operation.
	// moveFileReplaceExisting 让目标在同一文件系统操作中被替换。
	moveFileReplaceExisting uint32 = 0x00000001

	// moveFileWriteThrough asks Windows to flush the move metadata before returning.
	// moveFileWriteThrough 请求 Windows 在返回前刷新移动元数据。
	moveFileWriteThrough uint32 = 0x00000008
)

var moveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

// moveFileReplace invokes MoveFileExW without shell or command parsing.
// moveFileReplace 调用 MoveFileExW，不经过 shell 或命令解析。
func moveFileReplace(source string, target string) error {
	sourcePointer, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return errors.New("source path cannot be encoded")
	}
	targetPointer, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return errors.New("target path cannot be encoded")
	}
	result, _, callErr := moveFileExW.Call(
		uintptr(unsafe.Pointer(sourcePointer)),
		uintptr(unsafe.Pointer(targetPointer)),
		uintptr(moveFileReplaceExisting|moveFileWriteThrough),
	)
	if result == 0 {
		_ = callErr
		return errors.New("could not atomically replace dotenv file")
	}
	return nil
}
