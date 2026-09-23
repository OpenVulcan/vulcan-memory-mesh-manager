//go:build !windows

// This file provides atomic path-record replacement for POSIX-like systems.
// 本文件为 POSIX 类系统提供路径记录原子替换。
package pathctl

import "os"

// replaceRecord atomically replaces a same-directory record on POSIX filesystems.
// replaceRecord 在 POSIX 文件系统上原子替换同目录记录。
func replaceRecord(temporaryPath string, destinationPath string) error {
	return os.Rename(temporaryPath, destinationPath)
}
