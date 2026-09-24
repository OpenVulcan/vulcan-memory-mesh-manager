//go:build !windows

// This file owns Unix process groups, signals, and command-line normalization.
// 此文件负责 Unix 进程组、信号和命令行规范化。
package processctl

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// prepareBackgroundCommand creates a private Unix process group for VMM.
// prepareBackgroundCommand 为 VMM 创建独立的 Unix 进程组。
func prepareBackgroundCommand(command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

// terminateProcessByRecord signals the verified Unix process group only.
// terminateProcessByRecord 只向已验证的 Unix 进程组发送信号。
func terminateProcessByRecord(record processRecord) error {
	if record.PID <= 0 || record.ProcessGroupID <= 0 || record.ProcessGroupID != record.PID {
		return ErrIdentityUnverified
	}
	if err := syscall.Kill(-record.ProcessGroupID, syscall.SIGTERM); err != nil {
		if err == syscall.ESRCH {
			return ErrNotRunning
		}
		return ErrIdentityUnverified
	}
	return nil
}

// forceTerminateProcessByRecord kills the verified Unix process group after a timeout.
// forceTerminateProcessByRecord 超时后终止已验证的 Unix 进程组。
func forceTerminateProcessByRecord(record processRecord) error {
	if record.PID <= 0 || record.ProcessGroupID <= 0 || record.ProcessGroupID != record.PID {
		return ErrIdentityUnverified
	}
	if err := syscall.Kill(-record.ProcessGroupID, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return ErrIdentityUnverified
	}
	return nil
}

// abortStartedProcess kills a just-created child only after fresh identity evidence.
// abortStartedProcess 只有在取得最新身份凭据后才终止刚创建的子进程。
func abortStartedProcess(pid int, executable string, args []string, expectedStartToken string) error {
	snapshot, err := inspectProcess(pid)
	if err != nil || snapshot.StartToken != expectedStartToken || !sameExecutablePath(snapshot.ExecutablePath, executable) || snapshot.CommandLineDigest != commandLineDigest(executable, args) || verifyProcessOwner(snapshot) != nil || snapshot.ProcessGroupID != pid {
		return ErrIdentityUnverified
	}
	if err := syscall.Kill(-snapshot.ProcessGroupID, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return ErrIdentityUnverified
	}
	return nil
}

// executablePathsEqual compares Unix paths after cleaning their lexical form.
// executablePathsEqual 清理 Unix 路径后比较其词法形式。
func executablePathsEqual(left, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}

// platformCommandLine joins Unix argv exactly as procfs and sysctl expose it.
// platformCommandLine 按 procfs 和 sysctl 暴露的形式连接 Unix argv。
func platformCommandLine(executable string, args []string) string {
	values := make([]string, 0, len(args)+1)
	values = append(values, executable)
	values = append(values, args...)
	return strings.Join(values, "\x00")
}

// verifyProcessOwner requires the child to belong to the current Unix user.
// verifyProcessOwner 要求子进程属于当前 Unix 用户。
func verifyProcessOwner(snapshot processSnapshot) error {
	if snapshot.Owner != strconv.Itoa(os.Getuid()) {
		return ErrIdentityMismatch
	}
	return nil
}

// attachProcessJob is a no-op on Unix because the private process group owns descendants.
// attachProcessJob 在 Unix 上为空操作，因为独立进程组负责收拢子进程。
func attachProcessJob(pid int, statePath string) (string, error) {
	return "", nil
}
