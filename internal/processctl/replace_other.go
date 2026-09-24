//go:build !windows

// This file provides durable same-volume state replacement on Unix.
// 此文件提供 Unix 上同卷持久化状态替换。
package processctl

import (
	"os"
	"path/filepath"
)

// atomicReplaceFile renames a same-directory temporary file into place on Unix.
// atomicReplaceFile 在 Unix 上将同目录临时文件重命名为目标文件。
func atomicReplaceFile(source string, destination string) error {
	if err := os.Rename(source, destination); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return nil
	}
	defer directory.Close()
	_ = directory.Sync()
	return nil
}
