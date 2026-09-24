//go:build windows

// This file identifies native Windows protection of open test directories.
// 本文件识别 Windows 对已打开测试目录施加的原生重命名保护。
package testpath

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// PinnedDirectoryRenameBlocked reports access or sharing denial caused by a pinned directory handle.
// PinnedDirectoryRenameBlocked 判断固定目录句柄导致的访问拒绝或共享冲突；其他错误返回 false。
func PinnedDirectoryRenameBlocked(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
