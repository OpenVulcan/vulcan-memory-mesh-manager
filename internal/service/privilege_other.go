//go:build !windows && !linux && !darwin

// This file fails closed for unsupported targets instead of guessing a privilege mechanism.
// 本文件在不支持的目标平台上关闭提权路径，不猜测平台机制。
// It keeps package compilation explicit while VMMM supports Windows, Linux, and macOS service control.
// 它让包的编译边界保持明确，因为 VMMM 当前支持 Windows、Linux 和 macOS 服务控制。
package service

import "errors"

// preparePrivilegedCommand fails closed because no trusted privilege boundary is defined for unsupported targets.
// preparePrivilegedCommand 在不支持的平台上安全失败，因为未定义可信的提权边界。
func preparePrivilegedCommand(_ string, _ []string, _ bool) (string, []string, bool, error) {
	return "", nil, false, errors.New("service privilege boundary is unsupported on this platform")
}
