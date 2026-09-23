//go:build linux || darwin

// This file transfers registered private roots to a selected Unix service account with reversible descriptor-based ownership changes.
// 本文件通过可回退的文件句柄归属调整，将受管私有根目录交给所选 Unix 服务账户。
package install

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
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
	// credentialDigest authenticates the byte-identical .env replacement made by credential rollback.
	// credentialDigest 验证凭据回退产生的字节完全相同的 .env 替换文件。
	credentialDigest string
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
				matches := err == nil && os.SameFile(info, record.info)
				// Credential restoration deliberately replaces the inode; accept only identical bounded bytes in a regular single-link file.
				// 凭据恢复会明确替换 inode；仅接受普通单链接文件中完全相同的有界字节。
				if err == nil && !matches && record.credentialDigest != "" {
					metadata, ok := info.Sys().(*syscall.Stat_t)
					if ok && info.Mode().IsRegular() && metadata.Nlink == 1 {
						digest, digestErr := ownershipCredentialDigest(file)
						matches = digestErr == nil && digest == record.credentialDigest
					}
				}
				if err == nil && matches {
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
			record := ownershipRecord{root: root, path: relative, info: current, uid: metadata.Uid, gid: metadata.Gid}
			if directory == paths.ConfigRoot && relative == ".env" {
				record.credentialDigest, err = ownershipCredentialDigest(file)
				if err != nil {
					return err
				}
			}
			if err := file.Chown(int(identity.uid), int(identity.gid)); err != nil {
				return err
			}
			changes = append(changes, record)
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

// ownershipCredentialDigest hashes the bounded credential snapshot without storing or reporting secret bytes.
// ownershipCredentialDigest 为有界凭据快照计算摘要，不保存或报告秘密字节。
func ownershipCredentialDigest(file *os.File) (string, error) {
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, maxConfigFileBytes+1))
	if err != nil || size > maxConfigFileBytes {
		return "", errors.New("credential snapshot exceeds ownership rollback limits")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
