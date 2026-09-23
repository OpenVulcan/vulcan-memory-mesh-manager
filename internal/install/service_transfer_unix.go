//go:build linux || darwin

// This file transfers registered private roots to a selected Unix service account with reversible descriptor-based ownership changes.
// 本文件通过可回退的文件句柄归属调整，将受管私有根目录交给所选 Unix 服务账户。
package install

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
)

// ownershipRecord identifies one changed inode and its previous owner for rollback.
// ownershipRecord 记录已变更文件的身份及原归属，以便回退。
type ownershipRecord struct {
	root *os.Root
	path string
	info os.FileInfo
	uid  uint32
	gid  uint32
}

// TransferServiceRoots changes only the explicit configuration and data roots after the caller stops VMM; finalize commits or rolls back.
// TransferServiceRoots 在调用方停止 VMM 后仅调整明确的配置及数据根；返回的 finalize 用于提交或回退。
func TransferServiceRoots(paths state.InstallPaths, account string) (finalize func(bool) error, returnErr error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("service ownership transfer requires root")
	}
	for _, directory := range []string{paths.ProgramRoot, paths.ConfigRoot, paths.DataRoot} {
		if err := validateDirectoryPath("service transfer root", directory); err != nil {
			return nil, err
		}
		if filepath.Clean(directory) == filepath.Dir(filepath.Clean(directory)) {
			return nil, errors.New("service transfer cannot own a filesystem root")
		}
	}
	if pathsOverlap(paths.ConfigRoot, paths.DataRoot) || pathsOverlap(paths.ProgramRoot, paths.ConfigRoot) || pathsOverlap(paths.ProgramRoot, paths.DataRoot) {
		return nil, errors.New("service transfer roots must be disjoint")
	}
	identity, err := resolveUnixServiceIdentity(account)
	if err != nil {
		return nil, err
	}
	roots := make([]*os.Root, 0, 2)
	changes := make([]ownershipRecord, 0)
	finished := false
	finalize = func(commit bool) error {
		if finished {
			return nil
		}
		finished = true
		var result error
		if !commit {
			for index := len(changes) - 1; index >= 0; index-- {
				record := changes[index]
				file, err := openOwnershipFile(record.root, record.path, record.info.IsDir())
				if err != nil {
					result = errors.Join(result, err)
					continue
				}
				info, err := file.Stat()
				if err == nil && os.SameFile(info, record.info) {
					err = file.Chown(int(record.uid), int(record.gid))
				} else if err == nil {
					err = errors.New("ownership rollback found a replaced file")
				}
				result = errors.Join(result, err, file.Close())
			}
		}
		for _, root := range roots {
			result = errors.Join(result, root.Close())
		}
		return result
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, finalize(false))
		}
	}()
	for _, directory := range []string{paths.ConfigRoot, paths.DataRoot} {
		if err := validateRootOwnedChain(filepath.Dir(directory)); err != nil {
			return finalize, err
		}
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return finalize, err
		}
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			return finalize, errors.New("service transfer requires private real directories")
		}
		original, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return finalize, errors.New("service root identity is unavailable")
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			return finalize, err
		}
		roots = append(roots, root)
		opened, err := root.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			return finalize, errors.New("service root changed during transfer")
		}
		err = fs.WalkDir(root.FS(), ".", func(relative string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() && !entry.Type().IsRegular() {
				return errors.New("service transfer rejects links and special files")
			}
			file, err := openOwnershipFile(root, relative, entry.IsDir())
			if err != nil {
				return err
			}
			defer file.Close()
			current, err := file.Stat()
			if err != nil {
				return err
			}
			metadata, ok := current.Sys().(*syscall.Stat_t)
			if !ok || (!current.IsDir() && (!current.Mode().IsRegular() || metadata.Nlink != 1)) || (metadata.Uid != 0 && metadata.Uid != original.Uid) || current.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
				return errors.New("service transfer found an unsafe file owner or type")
			}
			if metadata.Uid == identity.uid && metadata.Gid == identity.gid {
				return nil
			}
			if err := file.Chown(int(identity.uid), int(identity.gid)); err != nil {
				return err
			}
			changes = append(changes, ownershipRecord{root: root, path: relative, info: current, uid: metadata.Uid, gid: metadata.Gid})
			return nil
		})
		if err != nil {
			return finalize, err
		}
	}
	return finalize, nil
}

// openOwnershipFile prevents symlink following and avoids blocking on a concurrently replaced special file.
// openOwnershipFile 禁止跟随符号链接，并避免特殊文件被并发替换后阻塞打开操作。
func openOwnershipFile(root *os.Root, relative string, directory bool) (*os.File, error) {
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if directory {
		flags |= syscall.O_DIRECTORY
	}
	return root.OpenFile(relative, flags, 0)
}
