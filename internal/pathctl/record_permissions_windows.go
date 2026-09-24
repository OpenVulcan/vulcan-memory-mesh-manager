//go:build windows

// Windows ACLs do not map to POSIX mode bits; the installer root owns ACL policy.
// Windows ACL 不映射到 POSIX 模式位；安装器根目录负责 ACL 策略。
package pathctl

// validateRecordPermissions leaves ACL enforcement to the secured manager root on Windows.
// validateRecordPermissions 在 Windows 将 ACL 强制交给受保护的管理器根目录。
func validateRecordPermissions(path string) error {
	return nil
}
