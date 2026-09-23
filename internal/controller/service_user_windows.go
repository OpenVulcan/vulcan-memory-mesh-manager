//go:build windows

// Package controller contains the Windows service-account boundary for VMMM installation.
// controller 包含 VMMM 安装在 Windows 上的服务账户边界。
//
// Windows SCM keeps its account policy outside the VMM service command's stable status contract.
// Windows SCM 的账户策略由系统服务管理器维护，不属于 VMM 稳定状态协议。
package controller

// validateServiceUserForInstall accepts no Unix account requirement on Windows.
// validateServiceUserForInstall 在 Windows 上不要求 Unix 服务账户。
func validateServiceUserForInstall(string, []string) error {
	return nil
}

// validateServiceUserAccess keeps Windows account policy in the native service manager.
// validateServiceUserAccess 将 Windows 账户策略交给原生服务管理器处理。
func validateServiceUserAccess(string, []servicePathCheck) error {
	return nil
}
