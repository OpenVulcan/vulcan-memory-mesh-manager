//go:build !windows

// This file owns the macOS system path_helper entry without changing shared command-directory permissions.
// 本文件管理 macOS 系统 path_helper 条目，不更改共享命令目录权限，属于平台 PATH 适配层。
package pathctl

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/selfinstall"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
)

// openDarwinPathsRoot pins the canonical, root-owned path directory after checking every ancestor.
// openDarwinPathsRoot 检查全部祖先后固定规范且由 root 持有的路径目录，返回目录句柄或错误。
func openDarwinPathsRoot() (*os.Root, error) {
	if runtime.GOOS != "darwin" || os.Geteuid() != 0 {
		return nil, errors.New("macOS system PATH integration requires a root manager on macOS")
	}
	directory := filepath.Dir(DarwinPathsFile)
	for current := directory; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o005 != 0o005 {
			return nil, errors.New("macOS system path directory is unsafe")
		}
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || metadata.Uid != 0 {
			return nil, errors.New("macOS system path directory is not root-owned")
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return os.OpenRoot(directory)
}

// readDarwinPathsEntry rejects links and foreign ownership and bounds file reads before comparing a removal receipt.
// readDarwinPathsEntry 拒绝链接和外部归属，并在比较撤销收据前限制文件读取，返回内容或错误。
func readDarwinPathsEntry(root *os.Root) ([]byte, error) {
	info, err := root.Lstat("vmmm")
	if err != nil {
		return nil, err
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || metadata.Uid != 0 || metadata.Nlink != 1 || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o004 == 0 {
		return nil, errors.New("macOS path entry is not a private root-owned regular file")
	}
	file, err := root.OpenFile("vmmm", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("macOS path entry changed during inspection")
	}
	content, err := io.ReadAll(io.LimitReader(file, 32769))
	if err != nil || len(content) > 32768 {
		return nil, errors.New("macOS path entry is unreadable or oversized")
	}
	return content, nil
}

// installDarwinPaths creates one exclusive root-owned file; an identical pre-existing file remains externally owned.
// installDarwinPaths 独占创建单个 root 文件；既有相同文件仍属于外部，返回可撤销登记或错误。
func (c *Controller) installDarwinPaths(options Options) (Record, error) {
	if err := selfinstall.VerifyPrivilegedExecutable(filepath.Join(options.Directory, "vmmm")); err != nil {
		return Record{}, err
	}
	content, err := darwinPathContent(options.Directory)
	if err != nil {
		return Record{}, err
	}
	root, err := openDarwinPathsRoot()
	if err != nil {
		return Record{}, err
	}
	defer root.Close()
	owner := state.PATHOwnerManager
	existing, err := readDarwinPathsEntry(root)
	if err == nil {
		if !bytes.Equal(existing, content) {
			return Record{}, ErrConflict
		}
		owner = state.PATHOwnerExternal
	} else if !errors.Is(err, os.ErrNotExist) {
		return Record{}, err
	} else {
		file, err := root.OpenFile("vmmm", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return Record{}, err
		}
		_, writeErr := file.Write(content)
		// The login shell reads this non-secret path as an ordinary user, regardless of the invoking root umask.
		// 普通用户登录 shell 需要读取此非秘密路径，权限不应受调用 root 的 umask 影响。
		modeErr := file.Chmod(0o644)
		syncErr := file.Sync()
		closeErr := file.Close()
		if err := errors.Join(writeErr, modeErr, syncErr, closeErr); err != nil {
			_ = root.Remove("vmmm")
			return Record{}, err
		}
	}
	return Record{Version: RecordVersion, Path: state.PATHState{Owner: owner, Scope: state.PATHScopeSystem, Entries: []string{filepath.Clean(options.Directory)}}, Method: MethodDarwinPathsD, Directory: filepath.Clean(options.Directory), ProfilePath: DarwinPathsFile, AfterSHA256: digest(content)}, nil
}

// removeDarwinPaths removes only the exact root-owned file whose content still matches the manager's receipt.
// removeDarwinPaths 仅移除内容仍与管理器收据一致的 root 文件，返回冲突或系统错误，不删除外部文件。
func (c *Controller) removeDarwinPaths(record Record) error {
	root, err := openDarwinPathsRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	content, err := readDarwinPathsEntry(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	expected, err := darwinPathContent(record.Directory)
	if err != nil || !bytes.Equal(content, expected) || digest(content) != record.AfterSHA256 {
		return ErrChanged
	}
	return root.Remove("vmmm")
}
