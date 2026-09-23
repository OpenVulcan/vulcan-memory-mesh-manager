// This file reads credential snapshots through bounded directory handles.
// 本文件通过受限目录句柄读取凭据快照，避免检查后的符号链接替换泄露根外内容。
package credentials

import (
	"errors"
	"os"
	"path/filepath"
)

// ReadSnapshot returns bounded dotenv bytes, existence, and original mode for recovery.
// ReadSnapshot 返回有界 dotenv 内容、是否存在及原权限，供失败恢复使用；路径必须为绝对 .env 文件路径。
func ReadSnapshot(path string) ([]byte, bool, os.FileMode, error) {
	if err := validatePath(path); err != nil {
		return nil, false, 0, err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, 0o600, nil
	}
	if err != nil {
		return nil, false, 0, errors.New("could not open dotenv directory")
	}
	defer root.Close()
	return readSnapshot(root)
}

// readSnapshot binds inspection and reading to one parent and verifies the opened inode before reading secrets.
// readSnapshot 将检查和读取绑定到同一父目录，并在读取密钥前确认打开的文件与检查对象一致。
func readSnapshot(root *os.Root) ([]byte, bool, os.FileMode, error) {
	info, err := root.Lstat(".env")
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, 0o600, nil
	}
	if err != nil {
		return nil, false, 0, errors.New("could not inspect dotenv file")
	}
	if !info.Mode().IsRegular() {
		return nil, false, 0, errors.New("dotenv path must be a regular file")
	}
	file, err := root.Open(".env")
	if err != nil {
		return nil, false, 0, errors.New("could not open dotenv file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, false, 0, errors.New("dotenv file changed before reading")
	}
	data, err := readBounded(file)
	if err != nil {
		return nil, false, 0, err
	}
	return data, true, opened.Mode().Perm(), nil
}
