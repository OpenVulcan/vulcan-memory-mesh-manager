//go:build darwin

// This file reads Darwin sysctl identity and exact process arguments.
// 此文件读取 Darwin sysctl 身份和精确进程参数。
package processctl

import (
	"encoding/binary"
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// inspectProcess reads Darwin sysctl process identity and exact argv data.
// inspectProcess 读取 Darwin sysctl 进程身份和精确 argv 数据。
func inspectProcess(pid int) (processSnapshot, error) {
	if pid <= 0 {
		return processSnapshot{}, ErrIdentityMismatch
	}
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return processSnapshot{}, ErrNotRunning
		}
		return processSnapshot{}, ErrIdentityUnverified
	}
	arguments, err := darwinArguments(pid)
	if err != nil {
		return processSnapshot{}, ErrIdentityUnverified
	}
	if len(arguments) == 0 {
		return processSnapshot{}, ErrIdentityUnverified
	}
	start := info.Proc.P_starttime
	startToken := "darwin:" + strconv.FormatInt(start.Sec, 10) + ":" + strconv.FormatInt(int64(start.Usec), 10)
	return processSnapshot{
		PID:               pid,
		ProcessGroupID:    int(info.Eproc.Pgid),
		ExecutablePath:    filepath.Clean(arguments[0]),
		Arguments:         arguments,
		CommandLineDigest: commandLineDigest(arguments[0], arguments[1:]),
		Owner:             strconv.FormatUint(uint64(info.Eproc.Ucred.Uid), 10),
		StartToken:        startToken,
	}, nil
}

// darwinArguments parses KERN_PROCARGS2 and keeps exactly argc plus executable.
// darwinArguments 解析 KERN_PROCARGS2，并只保留 argc 加可执行文件。
func darwinArguments(pid int) ([]string, error) {
	data, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(data) < 4 {
		return nil, errors.New("Darwin process arguments are unavailable")
	}
	argc := int(int32(binary.LittleEndian.Uint32(data[:4])))
	if argc < 0 || argc > 256 {
		return nil, errors.New("Darwin process argument count is invalid")
	}
	rest := data[4:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	parts := make([]string, 0, argc+1)
	for len(parts) < argc+1 {
		index := strings.IndexByte(string(rest), 0)
		if index < 0 {
			if len(rest) == 0 {
				return nil, errors.New("Darwin process arguments are truncated")
			}
			parts = append(parts, string(rest))
			break
		}
		parts = append(parts, string(rest[:index]))
		rest = rest[index+1:]
	}
	if len(parts) != argc+1 || parts[0] == "" {
		return nil, errors.New("Darwin process arguments are malformed")
	}
	return parts, nil
}
