//go:build !windows

// This file safely reopens a root-owned installed manager from an ordinary Unix shell.
// 本文件让普通 Unix shell 安全地通过 root 持有的管理器重新进入安装界面。
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/selfinstall"
)

// relaunchPrivilegedInteractive invokes sudo only for a verified permanent root-owned binary.
// relaunchPrivilegedInteractive 只对已验证的 root 永久程序调用 sudo。
func relaunchPrivilegedInteractive(args []string, environment commandEnvironment, options commandOptions) (bool, int) {
	if os.Geteuid() == 0 || !environment.allowPrivilegeEscalation {
		return false, 0
	}
	managerRoot := options.ManagerRoot
	if managerRoot == "" {
		var err error
		managerRoot, err = defaultManagerRoot()
		if err != nil {
			writeError(environment.stderr, err)
			return true, 1
		}
	}
	permanentPath := filepath.Join(managerRoot, "vmmm")
	if err := selfinstall.VerifyPrivilegedExecutable(permanentPath); err != nil {
		writeError(environment.stderr, fmt.Errorf("trusted installed manager is unavailable; run the verified bootstrap with sudo: %w", err))
		return true, 1
	}
	if err := selfinstall.VerifyPrivilegedExecutable("/usr/bin/sudo"); err != nil {
		writeError(environment.stderr, fmt.Errorf("trusted sudo is unavailable: %w", err))
		return true, 1
	}
	commandArgs := append([]string{"--", permanentPath}, args...)
	command := exec.Command("/usr/bin/sudo", commandArgs...)
	command.Stdin = environment.stdin
	command.Stdout = environment.stdout
	command.Stderr = environment.stderr
	if err := command.Run(); err != nil {
		writeError(environment.stderr, fmt.Errorf("privileged manager did not complete: %w", err))
		return true, 1
	}
	return true, 0
}
