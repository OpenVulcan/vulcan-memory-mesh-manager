//go:build windows

// privilege_windows.go checks the Windows service-control privilege before changing an installation.
// privilege_windows.go 在改动安装内容前检查 Windows 服务控制所需的权限。
package controller

import (
	"errors"

	"golang.org/x/sys/windows"
)

// requireNativeServicePrivileges gives a clear preflight error before the installer stops or replaces a runtime.
// requireNativeServicePrivileges 在安装器停止或替换运行实例前返回明确的权限预检错误。
func requireNativeServicePrivileges() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("Windows service management requires an elevated Administrator terminal; reopen vmmm as Administrator")
	}
	return nil
}
