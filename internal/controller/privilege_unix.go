//go:build !windows

// privilege_unix.go requires the root-owned manager for native system-service changes.
// privilege_unix.go 要求由 root 持有的管理器执行原生系统服务变更。
package controller

import (
	"errors"
	"os"
)

// requireNativeServicePrivileges rejects service mutations outside the administrator process.
// requireNativeServicePrivileges 拒绝管理员进程之外的服务变更。
func requireNativeServicePrivileges() error {
	if os.Geteuid() != 0 {
		return errors.New("system service management requires a root manager")
	}
	return nil
}
