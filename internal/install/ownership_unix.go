//go:build !windows

// This file separates Unix administrator code/state from service-owned configuration/data.
// 本文件将 Unix 管理员程序与状态同服务账户的配置和数据隔离。
package install

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// unixServiceIdentity is the resolved numeric account used only for controlled ownership changes.
// unixServiceIdentity 是用于受控所有权变更的已解析数字账户。
type unixServiceIdentity struct {
	uid uint32
	gid uint32
}

// resolveUnixServiceIdentity rejects ambiguous or unavailable local service accounts.
// resolveUnixServiceIdentity 拒绝含糊或不存在的本机服务账户。
func resolveUnixServiceIdentity(name string) (unixServiceIdentity, error) {
	account, err := user.Lookup(name)
	if err != nil || account.Username != name {
		return unixServiceIdentity{}, errors.New("selected service account is unavailable")
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil {
		return unixServiceIdentity{}, errors.New("selected service account identity is invalid")
	}
	return unixServiceIdentity{uid: uint32(uid), gid: uint32(gid)}, nil
}

// validateServiceOwnership checks all paths from which root will execute or persist state.
// validateServiceOwnership 检查 root 执行程序或持久化状态所经过的全部路径。
func validateServiceOwnership(request Request) error {
	if request.Service.Name == "" {
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("system service installation requires a root manager")
	}
	identity, err := resolveUnixServiceIdentity(request.Service.User)
	if err != nil {
		return err
	}
	if err := validateUnixControlStateLocation(request.StatePath, request.ManagerRoot, request.Paths); err != nil {
		return err
	}
	for _, root := range []string{request.ManagerRoot, request.Paths.ProgramRoot, filepath.Dir(request.StatePath)} {
		if err := validateRootOwnedChain(root); err != nil {
			return err
		}
	}
	if err := validateProgramTree(request.Paths.ProgramRoot); err != nil {
		return err
	}
	for _, root := range []string{request.Paths.ConfigRoot, request.Paths.DataRoot} {
		if err := validateRootOwnedChain(filepath.Dir(root)); err != nil {
			return err
		}
		if err := validateExistingServiceRoot(root, identity); err != nil {
			return err
		}
	}
	return validateExistingRootState(request.StatePath)
}

// validateRootOwnedChain rejects symlinks and every service-writable ancestor of a root path.
// validateRootOwnedChain 拒绝根路径整条祖先链上的符号链接与服务可写目录。
func validateRootOwnedChain(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("privileged path is not absolute")
	}
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			// A missing suffix will be created by root; its nearest existing ancestor is checked below.
			// 缺失的路径后缀将由 root 创建；继续校验其最近的现有祖先。
		} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("privileged path contains an unsafe ancestor")
		} else {
			metadata, ok := info.Sys().(*syscall.Stat_t)
			if !ok || metadata.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
				return errors.New("privileged path ancestor is not root-owned and protected")
			}
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}

// validateProgramTree rejects existing package entries writable by the service account.
// validateProgramTree 拒绝现有程序包中可由服务账户修改的目录或文件。
func validateProgramTree(root string) error {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() {
		return errors.New("program root is unsafe")
	}
	return filepath.WalkDir(root, func(path string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entry, err := os.Lstat(path)
		if err != nil || entry.Mode()&os.ModeSymlink != 0 || !(entry.IsDir() || entry.Mode().IsRegular()) {
			return fmt.Errorf("program path %q is unsafe", path)
		}
		metadata, ok := entry.Sys().(*syscall.Stat_t)
		if !ok || metadata.Uid != 0 || entry.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("program path %q is not root-owned and protected", path)
		}
		return nil
	})
}

// validateExistingServiceRoot accepts a missing leaf or an exact private service-owned directory.
// validateExistingServiceRoot 仅接受尚未创建的目录或精确由服务账户私有持有的目录。
func validateExistingServiceRoot(path string, identity unixServiceIdentity) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("service config or data root is unsafe")
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != identity.uid || metadata.Gid != identity.gid {
		return errors.New("service config or data root has a different owner")
	}
	return nil
}

// validateExistingRootState checks the root-owned registration when it already exists.
// validateExistingRootState 校验已存在登记文件的 root 所有权。
func validateExistingRootState(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("manager registration is unsafe")
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 {
		return errors.New("manager registration is not root-owned")
	}
	return nil
}

// prepareServiceOwnership creates only missing config/data leaf directories for one service account.
// prepareServiceOwnership 只为目标账户创建缺失的配置与数据叶目录。
func prepareServiceOwnership(request Request) error {
	if request.Service.Name == "" {
		return nil
	}
	if err := validateServiceOwnership(request); err != nil {
		return err
	}
	identity, err := resolveUnixServiceIdentity(request.Service.User)
	if err != nil {
		return err
	}
	for _, root := range []string{request.Paths.ConfigRoot, request.Paths.DataRoot} {
		if err := prepareServiceDirectory(root, identity); err != nil {
			return err
		}
	}
	return nil
}

// PrepareServiceConfigRoot safely creates a private leaf directory for a selected Unix account.
// PrepareServiceConfigRoot 为选定 Unix 账户安全创建私有配置叶目录。
func PrepareServiceConfigRoot(path string, account string) (uint32, uint32, error) {
	if os.Geteuid() != 0 {
		return 0, 0, errors.New("service configuration requires a root manager")
	}
	identity, err := resolveUnixServiceIdentity(account)
	if err != nil {
		return 0, 0, err
	}
	if err := prepareServiceDirectory(path, identity); err != nil {
		return 0, 0, err
	}
	return identity.uid, identity.gid, nil
}

// prepareServiceDirectory changes ownership only for a newly created final directory.
// prepareServiceDirectory 仅对本次新建的最终目录变更所有权。
func prepareServiceDirectory(path string, identity unixServiceIdentity) error {
	parent := filepath.Dir(path)
	if err := validateRootOwnedChain(parent); err != nil {
		return err
	}
	_, statErr := os.Lstat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return err
		}
		if err := validateRootOwnedChain(parent); err != nil {
			return err
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		if err := os.Chown(path, int(identity.uid), int(identity.gid)); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	} else if statErr != nil {
		return statErr
	}
	return validateExistingServiceRoot(path, identity)
}

// assignServiceConfigOwnership gives promoted overlay files to the selected service account.
// assignServiceConfigOwnership 将已推广的覆盖文件归属选定服务账户。
func assignServiceConfigOwnership(request Request, files []string) error {
	if request.Service.Name == "" {
		return nil
	}
	identity, err := resolveUnixServiceIdentity(request.Service.User)
	if err != nil {
		return err
	}
	configHandle, err := os.OpenRoot(request.Paths.ConfigRoot)
	if err != nil {
		return err
	}
	defer configHandle.Close()
	for _, relative := range files {
		if _, err := safeConfigPath(request.Paths.ConfigRoot, relative); err != nil {
			return err
		}
		if err := assignServiceConfigDirectoryOwnership(configHandle, filepath.Dir(filepath.FromSlash(relative)), identity); err != nil {
			return err
		}
		// Resolve all ancestors inside the pinned configuration root before changing descriptor ownership.
		// 先将所有上级目录解析限制在固定配置根内，再通过文件句柄变更所有权。
		file, err := configHandle.OpenFile(filepath.FromSlash(relative), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		info, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			return statErr
		}
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || metadata.Nlink != 1 || (metadata.Uid != 0 && metadata.Uid != identity.uid) || info.Mode().Perm()&0o077 != 0 {
			_ = file.Close()
			return errors.New("promoted configuration file is unsafe")
		}
		if err := file.Chown(int(identity.uid), int(identity.gid)); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	return nil
}

// assignServiceConfigDirectoryOwnership grants the selected account access only to parents of files promoted in this transaction.
// assignServiceConfigDirectoryOwnership 仅把本次推广文件的父目录访问权交给选定账户。
func assignServiceConfigDirectoryOwnership(root *os.Root, relative string, identity unixServiceIdentity) error {
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("configuration parent escapes the service root")
	}
	current := "."
	if relative == "." {
		return nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		directory, err := root.OpenFile(current, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("open service config directory %q: %w", current, err)
		}
		info, statErr := directory.Stat()
		if statErr != nil {
			_ = directory.Close()
			return statErr
		}
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || (metadata.Uid != 0 && metadata.Uid != identity.uid) || info.Mode().Perm()&0o077 != 0 {
			_ = directory.Close()
			return fmt.Errorf("service config directory %q has unsafe ownership or permissions", current)
		}
		if err := directory.Chown(int(identity.uid), int(identity.gid)); err != nil {
			_ = directory.Close()
			return err
		}
		if err := directory.Chmod(0o700); err != nil {
			_ = directory.Close()
			return err
		}
		if err := directory.Close(); err != nil {
			return err
		}
	}
	return nil
}
