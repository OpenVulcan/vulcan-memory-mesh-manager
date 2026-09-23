//go:build linux

// This file reads Linux procfs identity evidence without invoking a shell.
// 此文件直接读取 Linux procfs 身份凭据，不调用 shell。
package processctl

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// inspectProcess reads Linux procfs evidence for one process without using a shell.
// inspectProcess 直接读取 Linux procfs 证据，不经由 shell。
func inspectProcess(pid int) (processSnapshot, error) {
	if pid <= 0 {
		return processSnapshot{}, ErrIdentityMismatch
	}
	root := filepath.Join("/proc", strconv.Itoa(pid))
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return processSnapshot{}, ErrNotRunning
	} else if err != nil {
		return processSnapshot{}, ErrIdentityUnverified
	}
	executable, err := os.Readlink(filepath.Join(root, "exe"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return processSnapshot{}, ErrNotRunning
		}
		return processSnapshot{}, ErrIdentityUnverified
	}
	arguments, err := readProcArguments(filepath.Join(root, "cmdline"))
	if err != nil {
		return processSnapshot{}, ErrIdentityUnverified
	}
	owner, err := readProcOwner(filepath.Join(root, "status"))
	if err != nil {
		return processSnapshot{}, ErrIdentityUnverified
	}
	stat, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return processSnapshot{}, ErrNotRunning
		}
		return processSnapshot{}, ErrIdentityUnverified
	}
	groupID, startToken, err := parseProcStat(string(stat))
	if err != nil {
		return processSnapshot{}, ErrIdentityUnverified
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return processSnapshot{}, ErrIdentityUnverified
	}
	return processSnapshot{
		PID:               pid,
		ProcessGroupID:    groupID,
		ExecutablePath:    filepath.Clean(executable),
		Arguments:         arguments,
		CommandLineDigest: commandLineDigest(executable, arguments[1:]),
		Owner:             owner,
		StartToken:        "linux:" + strings.TrimSpace(string(bootID)) + ":" + startToken,
	}, nil
}

// readProcArguments converts NUL-separated procfs argv into a strict vector.
// readProcArguments 将 procfs 的 NUL 分隔 argv 转换为严格数组。
func readProcArguments(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(string(data), "\x00")
	if len(parts) == 0 || parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) < 1 || parts[0] == "" {
		return nil, errors.New("Linux process argv is empty")
	}
	return parts, nil
}

// readProcOwner extracts the effective UID from procfs status.
// readProcOwner 从 procfs status 提取有效 UID。
func readProcOwner(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) == 0 {
			return "", errors.New("Linux process UID is empty")
		}
		if _, err := strconv.ParseUint(fields[0], 10, 32); err != nil {
			return "", err
		}
		return fields[0], nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("Linux process UID is unavailable")
}

// parseProcStat reads process-group ID and kernel start ticks from /proc/PID/stat.
// parseProcStat 从 /proc/PID/stat 读取进程组 ID 与内核启动时钟。
func parseProcStat(value string) (int, string, error) {
	closeParen := strings.LastIndex(value, ")")
	if closeParen < 0 || closeParen+2 > len(value) {
		return 0, "", errors.New("Linux process stat is malformed")
	}
	fields := strings.Fields(value[closeParen+2:])
	if len(fields) <= 19 {
		return 0, "", errors.New("Linux process stat is incomplete")
	}
	groupID, err := strconv.Atoi(fields[2])
	if err != nil || groupID <= 0 {
		return 0, "", errors.New("Linux process group is invalid")
	}
	start := fields[19]
	if _, err := strconv.ParseUint(start, 10, 64); err != nil || start == "" {
		return 0, "", errors.New("Linux process start token is invalid")
	}
	return groupID, start, nil
}
