//go:build !windows

// Package controller contains Unix service-account and access checks.
// controller 包含 Unix 服务账户与路径可访问性检查。
//
// The checks run immediately before service registration so a root-launched manager cannot
// create files that the selected account cannot read after VMM starts.
// 这些检查在注册服务前执行，避免 root 启动的管理器创建服务账户无法读取的文件。
package controller

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// validateServiceUserForInstall validates legacy root-only callers using writable directory checks.
// validateServiceUserForInstall 为旧的根目录调用方执行可写目录检查。
func validateServiceUserForInstall(serviceUser string, roots []string) error {
	checks := make([]servicePathCheck, 0, len(roots))
	for _, root := range roots {
		checks = append(checks, servicePathCheck{path: root, writable: true})
	}
	return validateServiceUserAccess(serviceUser, checks)
}

// validateServiceUserAccess verifies the account and every path selected by the install plan.
// validateServiceUserAccess 校验账户，并检查安装计划选定的每一条路径。
//
// Existing roots and files must be owned by the account or explicitly accessible through
// their other permission bits. Missing targets are checked through their existing ancestors;
// the final post-commit call catches files created by the manager with the wrong owner.
// 已存在的根目录和文件必须由该账户拥有，或通过 other 权限明确可访问；缺失目标沿现有祖先
// 检查，提交后的再次检查会捕获管理器以错误所有者创建的文件。
func validateServiceUserAccess(serviceUser string, checks []servicePathCheck) error {
	if !validServiceUserToken(serviceUser) {
		return errors.New("service user is invalid")
	}
	account, err := user.Lookup(serviceUser)
	if err != nil {
		return errors.New("service user is not a local account")
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 64)
	if err != nil {
		return errors.New("service user identity is invalid")
	}
	// Service registration changes the system manager and therefore require an explicit
	// root-launched controller. The selected account is validated independently and owns
	// configuration/data paths; the controller must never recursively chown existing paths.
	// 服务注册会修改系统服务管理器，因此要求管理器明确由 root 启动。选定账户单独校验并
	// 拥有配置/数据路径；管理器绝不递归 chown 既有路径。
	if os.Geteuid() != 0 {
		return errors.New("service mode requires root controller")
	}
	seen := make(map[string]struct{}, len(checks))
	for _, check := range checks {
		path := filepath.Clean(check.path)
		if path == "." || path == "" {
			return errors.New("service path is invalid")
		}
		if _, exists := seen[path]; exists {
			continue
		}
		seen[path] = struct{}{}
		if err := validateServicePathAccess(path, uid, check.writable, check.rootOwned); err != nil {
			return errors.New("service user cannot access the configuration, data, or program path")
		}
	}
	return nil
}

// validServiceUserToken mirrors the VMM service adapter's portable account grammar.
// validServiceUserToken 与 VMM 服务适配器的跨平台账户语法保持一致。
func validServiceUserToken(value string) bool {
	if len(value) == 0 || len(value) > 128 || value != strings.TrimSpace(value) {
		return false
	}
	if !isASCIIAccountStart(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !isASCIIAccountPart(value[index]) {
			return false
		}
	}
	return true
}

// isASCIIAccountStart accepts the first byte allowed by the VMM service user contract.
// isASCIIAccountStart 接受 VMM 服务账户契约允许的首字节。
func isASCIIAccountStart(value byte) bool {
	return isASCIIAlphaNumeric(value) || value == '_'
}

// isASCIIAlphaNumeric accepts ASCII letters and digits used by the VMM account contract.
// isASCIIAlphaNumeric 接受 VMM 账户契约使用的 ASCII 字母和数字。
func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

// isASCIIAccountPart accepts subsequent account bytes allowed by the VMM service contract.
// isASCIIAccountPart 接受 VMM 服务账户契约允许的后续字节。
func isASCIIAccountPart(value byte) bool {
	return isASCIIAccountStart(value) || value == '.' || value == '-'
}

// validateServicePathAccess checks symlink-free ancestors, ownership, and Unix mode bits.
// validateServicePathAccess 检查无符号链接的祖先链、所有者以及 Unix 权限位。
func validateServicePathAccess(path string, uid uint64, writable bool, rootOwned bool) error {
	if err := validateAbsolutePath(path); err != nil {
		return err
	}
	cleaned := filepath.Clean(path)
	nearest, nearestInfo, err := nearestExistingPath(cleaned)
	if err != nil {
		return err
	}
	if nearestInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("service path contains a symlink")
	}

	// The nearest existing object is the strongest ownership boundary. A missing target
	// is allowed to be created later, but its current parent must still be traversable.
	// 最近的现有对象是最强的所有权边界。目标缺失时允许稍后创建，但当前父路径仍须可遍历。
	if nearest == cleaned {
		if err := checkServiceObject(nearestInfo, uid, writable, rootOwned); err != nil {
			return err
		}
	} else if !nearestInfo.IsDir() {
		return errors.New("service path ancestor is not a directory")
	}

	// Check every directory from the nearest object to the filesystem root. This catches
	// a private ancestor such as /root even when the leaf directory is owned by the service user.
	// 检查最近对象到文件系统根的每一级目录，避免 /root 等私有祖先掩盖叶目录的归属。
	current := nearest
	if !nearestInfo.IsDir() {
		current = filepath.Dir(nearest)
	}
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("service path ancestor is not a real directory")
		}
		if err := checkServiceDirectoryAncestor(info, uid, current == nearest, writable && current == nearest); err != nil {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}

// nearestExistingPath returns the nearest non-symlink object or directory ancestor.
// nearestExistingPath 返回最近的非符号链接现有对象或目录祖先。
func nearestExistingPath(path string) (string, os.FileInfo, error) {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err == nil {
			return current, info, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", nil, err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", nil, errors.New("service path has no existing ancestor")
		}
		current = parent
	}
}

// checkServiceObject validates a concrete directory or file at the requested path.
// checkServiceObject 校验请求路径处的具体目录或文件。
func checkServiceObject(info os.FileInfo, uid uint64, writable bool, rootOwned bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("service path is a symlink")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("service path ownership is unavailable")
	}
	mode := info.Mode().Perm()
	if rootOwned {
		if uint64(stat.Uid) != 0 {
			return errors.New("program path must be root-owned")
		}
		if info.IsDir() {
			if mode&0005 != 0005 || mode&0022 != 0 {
				return errors.New("program directory permissions are unsafe")
			}
			return nil
		}
		if !info.Mode().IsRegular() || mode&0005 != 0005 || mode&0022 != 0 {
			return errors.New("program file permissions are unsafe")
		}
		return nil
	}
	if uint64(stat.Uid) != uid {
		return errors.New("service path owner differs from service user")
	}
	if info.IsDir() {
		if mode&0500 != 0500 || writable && mode&0200 == 0 {
			return errors.New("service directory permissions are insufficient")
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return errors.New("service path is not a regular file or directory")
	}
	if mode&0400 == 0 || writable && mode&0200 == 0 {
		return errors.New("service file permissions are insufficient")
	}
	return nil
}

// checkServiceDirectoryAncestor checks traversal permissions without assuming group membership.
// checkServiceDirectoryAncestor 检查祖先遍历权限，避免猜测服务账户的组成员关系。
func checkServiceDirectoryAncestor(info os.FileInfo, uid uint64, leaf bool, writable bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("service ancestor ownership is unavailable")
	}
	mode := info.Mode().Perm()
	if uint64(stat.Uid) == uid {
		if mode&0500 != 0500 {
			return errors.New("service ancestor permissions are insufficient")
		}
		if leaf && writable && mode&0200 == 0 {
			return errors.New("service directory is not writable")
		}
		return nil
	}
	// For an unknown group membership, only explicit other permissions are safe to rely on.
	// 对未知组成员关系，只能安全依赖明确的 other 权限位。
	if mode&0005 != 0005 {
		return errors.New("service ancestor is not traversable by service user")
	}
	if leaf && writable && mode&0002 == 0 {
		return errors.New("service directory is not writable by service user")
	}
	return nil
}
