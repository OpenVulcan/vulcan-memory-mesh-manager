//go:build darwin

// This file reads Darwin sysctl identity and exact process arguments.
// 此文件读取 Darwin sysctl 身份和精确进程参数。
package processctl

import (
	"bytes"
	"encoding/binary"
	"errors"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// inspectProcess reads Darwin sysctl process identity and exact argv data.
// inspectProcess 读取 Darwin sysctl 进程身份和精确 argv 数据。
func inspectProcess(pid int) (processSnapshot, error) {
	if pid <= 0 {
		return processSnapshot{}, ErrIdentityMismatch
	}
	// The single-record helper maps an empty kernel result to EIO; the slice helper preserves an empty result.
	// 单记录辅助函数把内核空结果转换为 EIO；切片辅助函数保留可判定的空结果。
	infos, err := unix.SysctlKinfoProcSlice("kern.proc.pid", pid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return processSnapshot{}, ErrNotRunning
		}
		return processSnapshot{}, ErrIdentityUnverified
	}
	if len(infos) == 0 {
		return processSnapshot{}, ErrNotRunning
	}
	if len(infos) != 1 || int(infos[0].Proc.P_pid) != pid {
		return processSnapshot{}, ErrIdentityUnverified
	}
	info := infos[0]
	// XNU reports SZOMB as 5 while the parent still owns the exited process; argv is no longer available then.
	// XNU 在父进程尚未回收已退出进程时用状态值 5 表示 SZOMB，此时 argv 已不可读取。
	if info.Proc.P_stat == 5 {
		return processSnapshot{}, ErrNotRunning
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

// darwinArguments reads the kernel argv vector from KERN_PROCARGS2.
// darwinArguments 从 KERN_PROCARGS2 读取内核 argv 向量。
func darwinArguments(pid int) ([]string, error) {
	data, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil, errors.New("Darwin process arguments are unavailable")
	}
	return parseDarwinArguments(data)
}

// parseDarwinArguments skips the separate executable path and alignment padding before reading argc arguments.
// parseDarwinArguments 跳过独立的可执行文件路径及对齐填充，再读取 argc 个参数。
func parseDarwinArguments(data []byte) ([]string, error) {
	if len(data) < 4 {
		return nil, errors.New("Darwin process arguments are unavailable")
	}
	argc := int(int32(binary.LittleEndian.Uint32(data[:4])))
	if argc < 1 || argc > 256 {
		return nil, errors.New("Darwin process argument count is invalid")
	}
	rest := data[4:]
	// The kernel stores the executable path before argv and pads it with NUL bytes.
	// 内核先存储可执行文件路径，再用 NUL 字节填充，随后才是 argv。
	executableEnd := bytes.IndexByte(rest, 0)
	if executableEnd <= 0 {
		return nil, errors.New("Darwin executable path is missing")
	}
	rest = rest[executableEnd+1:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	parts := make([]string, 0, argc)
	for len(parts) < argc {
		index := bytes.IndexByte(rest, 0)
		if index < 0 {
			return nil, errors.New("Darwin process arguments are truncated")
		}
		parts = append(parts, string(rest[:index]))
		rest = rest[index+1:]
	}
	if parts[0] == "" {
		return nil, errors.New("Darwin process arguments are malformed")
	}
	return parts, nil
}
