//go:build windows

// This file leaves Windows service binary trust to the protected install ACL boundary.
// 本文件在 Windows 上由受保护的安装 ACL 边界检查服务程序。
package service

// validateServiceBinaryTrust has no Unix owner checks on Windows.
// validateServiceBinaryTrust 在 Windows 上不执行 Unix 所有权检查。
func validateServiceBinaryTrust(_ string) error { return nil }
