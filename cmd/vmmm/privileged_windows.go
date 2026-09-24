//go:build windows

// This file keeps Windows TUI startup on its existing account boundary.
// 本文件让 Windows TUI 沿用现有账户边界启动。
package main

// relaunchPrivilegedInteractive is unnecessary on Windows.
// relaunchPrivilegedInteractive 在 Windows 上无需重新提权启动。
func relaunchPrivilegedInteractive(_ []string, _ commandEnvironment, _ commandOptions) (bool, int) {
	return false, 0
}
