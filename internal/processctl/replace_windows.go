//go:build windows

// This file provides Windows write-through replacement for process state.
// 此文件提供 Windows 进程状态的写穿替换。
package processctl

import (
	"syscall"
	"unsafe"
)

var (
	// kernel32MoveFileExW is the native atomic replacement entry point.
	// kernel32MoveFileExW 是原生原子替换入口。
	kernel32MoveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")
)

const (
	// moveFileReplaceExisting asks MoveFileExW to replace only the state destination.
	// moveFileReplaceExisting 要求 MoveFileExW 仅替换状态目标文件。
	moveFileReplaceExisting = 0x1
	// moveFileWriteThrough requests durable metadata for the replacement.
	// moveFileWriteThrough 要求替换元数据写穿到持久存储。
	moveFileWriteThrough = 0x8
)

// atomicReplaceFile replaces a state file without exposing a partially written JSON document.
// atomicReplaceFile 替换状态文件时不会暴露部分写入的 JSON 文档。
func atomicReplaceFile(source string, destination string) error {
	sourcePointer, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationPointer, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	result, _, callErr := kernel32MoveFileExW.Call(
		uintptr(unsafe.Pointer(sourcePointer)),
		uintptr(unsafe.Pointer(destinationPointer)),
		moveFileReplaceExisting|moveFileWriteThrough,
	)
	if result == 0 {
		return callErr
	}
	return nil
}
