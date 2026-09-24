// data_root_windows.go creates and verifies the protected Windows installation data root.
// data_root_windows.go 负责创建并校验受保护的 Windows 安装数据根目录。
// It belongs to the installation transaction layer and mirrors VMM local-storage DACL rules.
// 它属于安装事务层，并镜像 VMM 本地存储目录的 DACL 规则。
//go:build windows

package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// installDirectoryDeleteChildAccess is the directory-specific delete-child bit omitted by x/sys constants.
// installDirectoryDeleteChildAccess 是 x/sys 常量未导出的目录专用删除子项权限位。
const installDirectoryDeleteChildAccess windows.ACCESS_MASK = 0x00000040

// installDirectoryRequiredAccess covers database read/write, child creation, traversal, and cleanup rights.
// installDirectoryRequiredAccess 覆盖数据库读写、创建子项、遍历和清理所需的权限。
const installDirectoryRequiredAccess windows.ACCESS_MASK = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.FILE_TRAVERSE | windows.DELETE | installDirectoryDeleteChildAccess

// ensureInstallDataRoot creates missing components with a protected DACL and validates an existing root read-only.
// ensureInstallDataRoot 使用受保护 DACL 创建缺失组件，并只读校验已有数据根目录。
// The Windows API receives the security descriptor during CreateDirectoryW, preventing inherited broad access.
// Windows API 在 CreateDirectoryW 时直接接收安全描述符，避免继承宽泛访问权限。
func ensureInstallDataRoot(path string) error {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("resolve data root %q: %w", path, err)
	}
	ancestor := absolute
	var missing []string
	for {
		if _, statErr := os.Lstat(ancestor); statErr == nil {
			if err := validateInstallStorageDirectory(ancestor); err != nil {
				return fmt.Errorf("validate data-root ancestor %q: %w", ancestor, err)
			}
			break
		} else if !os.IsNotExist(statErr) {
			return fmt.Errorf("inspect data-root ancestor %q: %w", ancestor, statErr)
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return fmt.Errorf("data root %q has no existing ancestor", absolute)
		}
		missing = append(missing, filepath.Base(ancestor))
		ancestor = parent
	}
	if len(missing) == 0 {
		return validateInstallPrivateDirectory(absolute)
	}

	securityDescriptor, err := newInstallPrivateDirectorySecurityDescriptor()
	if err != nil {
		return err
	}
	securityAttributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: securityDescriptor,
	}
	for index := len(missing) - 1; index >= 0; index-- {
		if err := validateInstallStorageDirectory(ancestor); err != nil {
			return fmt.Errorf("validate data-root parent %q: %w", ancestor, err)
		}
		child := filepath.Join(ancestor, missing[index])
		name, err := windows.UTF16PtrFromString(child)
		if err != nil {
			return fmt.Errorf("encode data-root directory %q: %w", child, err)
		}
		createErr := windows.CreateDirectory(name, securityAttributes)
		if createErr != nil && !errors.Is(createErr, windows.ERROR_ALREADY_EXISTS) {
			return fmt.Errorf("create protected data-root directory %q: %w", child, createErr)
		}
		if err := validateInstallPrivateDirectory(child); err != nil {
			return fmt.Errorf("validate protected data-root directory %q: %w", child, err)
		}
		ancestor = child
	}
	return nil
}

// validateInstallPrivateDirectory verifies an existing root without changing its DACL.
// validateInstallPrivateDirectory 只读校验已有数据根目录，不修改其 DACL。
func validateInstallPrivateDirectory(path string) error {
	if err := validateInstallStorageDirectory(path); err != nil {
		return err
	}
	if err := validateInstallPrivateDirectoryACL(path); err != nil {
		return fmt.Errorf("validate data-root DACL for %q: %w", path, err)
	}
	return nil
}

// validateInstallStorageDirectory rejects links, reparse points, and non-directories before ACL access.
// validateInstallStorageDirectory 在读取 ACL 前拒绝链接、重解析点和非目录。
func validateInstallStorageDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat data root %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("data root %q is not a directory", path)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode data root %q: %w", path, err)
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil {
		return fmt.Errorf("read data-root attributes %q: %w", path, err)
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("data root %q is a reparse point", path)
	}
	return nil
}

// validateInstallPrivateDirectoryACL rejects unapproved trustees and missing current-user write access.
// validateInstallPrivateDirectoryACL 拒绝未批准主体，并拒绝当前用户缺少写权限的目录。
func validateInstallPrivateDirectoryACL(path string) error {
	securityDescriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read directory DACL: %w", err)
	}
	if securityDescriptor == nil {
		return errors.New("directory security descriptor is empty")
	}
	dacl, _, err := securityDescriptor.DACL()
	if err != nil || dacl == nil {
		if err != nil {
			return fmt.Errorf("read directory DACL entries: %w", err)
		}
		return errors.New("directory has no DACL")
	}
	if dacl.AceCount == 0 {
		return errors.New("directory DACL has no entries")
	}
	control, _, err := securityDescriptor.Control()
	if err != nil {
		return fmt.Errorf("read directory DACL protection: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("directory DACL is inheritable")
	}
	currentSID, err := currentInstallWindowsUserSID()
	if err != nil {
		return err
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("create SYSTEM SID: %w", err)
	}
	administratorsSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("create Administrators SID: %w", err)
	}
	currentGranted := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("read directory DACL entry %d: %w", index, err)
		}
		if ace == nil {
			return fmt.Errorf("directory DACL entry %d is empty", index)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			return fmt.Errorf("directory DACL entry %d uses unsupported ACE type %d", index, ace.Header.AceType)
		}
		entrySID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !entrySID.IsValid() {
			return fmt.Errorf("directory DACL entry %d contains an invalid SID", index)
		}
		if !entrySID.Equals(currentSID) && !entrySID.Equals(systemSID) && !entrySID.Equals(administratorsSID) {
			return fmt.Errorf("directory DACL entry %d grants or denies an unapproved SID %s", index, entrySID.String())
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			if ace.Mask&installDirectoryRequiredAccess != 0 {
				return fmt.Errorf("directory DACL entry %d denies required access for %s", index, entrySID.String())
			}
			continue
		}
		if !entrySID.Equals(currentSID) || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Mask&installDirectoryRequiredAccess != installDirectoryRequiredAccess {
			return errors.New("directory DACL grants insufficient access for current user")
		}
		currentGranted = true
	}
	if !currentGranted && !currentSID.Equals(systemSID) && !currentSID.Equals(administratorsSID) {
		return errors.New("directory DACL does not contain the current user")
	}
	return nil
}

// currentInstallWindowsUserSID returns the SID attached to the current process token.
// currentInstallWindowsUserSID 返回当前进程令牌绑定的用户 SID。
func currentInstallWindowsUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read current Windows user SID: %w", err)
	}
	if user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, errors.New("current Windows user SID is invalid")
	}
	return user.User.Sid, nil
}

// newInstallPrivateDirectorySecurityDescriptor builds the protected allow-list used for new data directories.
// newInstallPrivateDirectorySecurityDescriptor 构造新数据目录使用的受保护允许列表。
func newInstallPrivateDirectorySecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	currentSID, err := currentInstallWindowsUserSID()
	if err != nil {
		return nil, err
	}
	sddl := fmt.Sprintf("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", currentSID.String())
	securityDescriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build protected data-root security descriptor: %w", err)
	}
	return securityDescriptor, nil
}
