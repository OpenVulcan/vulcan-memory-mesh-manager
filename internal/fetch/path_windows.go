//go:build windows

// Package fetch contains Windows-specific staging path checks.
// fetch 包包含 Windows 平台专用的暂存路径检查。
// The helper rejects every reparse point, including directory junctions, before file publication.
// 该辅助函数会在发布文件前拒绝所有重解析点，包括目录联接。
package fetch

import (
	"fmt"
	"os"
	"syscall"
)

// pathIsReparsePoint reports whether a Windows path uses a reparse point.
// pathIsReparsePoint 报告 Windows 路径是否使用重解析点。
func pathIsReparsePoint(path string, info os.FileInfo) (bool, error) {
	if info.Mode()&os.ModeSymlink != 0 {
		return true, nil
	}
	pathPointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false, fmt.Errorf("encode Windows path: %w", err)
	}
	attributes, err := syscall.GetFileAttributes(pathPointer)
	if err != nil {
		return false, fmt.Errorf("read Windows file attributes: %w", err)
	}
	return attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}
