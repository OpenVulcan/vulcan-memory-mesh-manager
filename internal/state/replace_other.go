//go:build !windows

// This file supplies the POSIX atomic replacement used by state persistence.
// 本文件提供状态持久化使用的 POSIX 原子替换实现。
package state

import "os"

// atomicReplace atomically replaces the destination on POSIX-like platforms.
// atomicReplace 在类 POSIX 平台上原子替换目标文件。
func atomicReplace(temporaryPath string, destinationPath string) error {
	return os.Rename(temporaryPath, destinationPath)
}
