//go:build !windows && !linux && !darwin

// This file makes unsupported Unix identity layouts fail closed.
// 此文件让不支持的 Unix 身份布局安全失败。
package processctl

import "errors"

// inspectProcess fails closed on unsupported Unix process-inspection layouts.
// inspectProcess 在不支持的 Unix 进程检查布局上安全失败。
func inspectProcess(pid int) (processSnapshot, error) {
	return processSnapshot{}, errors.Join(ErrIdentityUnverified, errors.New("unsupported Unix process identity layout"))
}

// verifyProcessOwner fails closed when the platform cannot expose ownership.
// verifyProcessOwner 在平台无法暴露拥有者时安全失败。
func verifyProcessOwner(snapshot processSnapshot) error {
	return ErrIdentityUnverified
}
