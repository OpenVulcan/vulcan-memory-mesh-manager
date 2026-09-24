//go:build !windows

// This file keeps Unix directory replacement tests strict because open directories may be renamed.
// 本文件让 Unix 目录替换测试保持严格，因为该平台允许重命名已打开的目录。
package testpath

// PinnedDirectoryRenameBlocked returns false on platforms that permit renaming an open directory.
// PinnedDirectoryRenameBlocked 在允许重命名已打开目录的平台返回 false。
func PinnedDirectoryRenameBlocked(error) bool { return false }
