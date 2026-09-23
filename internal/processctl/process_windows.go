//go:build windows

// This file owns Windows process handles, identity queries, and safe termination.
// 此文件负责 Windows 进程句柄、身份查询和安全终止。
package processctl

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	// kernel32CreateJobObjectW creates a fresh named job and exposes already-existing names.
	// kernel32CreateJobObjectW 创建全新的命名作业，并暴露名称已存在的情况。
	kernel32CreateJobObjectW = windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateJobObjectW")
	// kernel32OpenJobObjectW opens the manager-owned named job during Stop.
	// kernel32OpenJobObjectW 在 Stop 期间打开管理器拥有的命名作业。
	kernel32OpenJobObjectW = windows.NewLazySystemDLL("kernel32.dll").NewProc("OpenJobObjectW")
)

const (
	// jobObjectTerminate grants only the native operation needed for Stop.
	// jobObjectTerminate 只授予 Stop 所需的原生操作。
	jobObjectTerminate = 0x0008
	// jobObjectAssignProcess grants attaching the just-created VMM process.
	// jobObjectAssignProcess 授予附加刚创建 VMM 进程的权限。
	jobObjectAssignProcess = 0x0001
)

// prepareBackgroundCommand creates a distinct Windows process group.
// prepareBackgroundCommand 创建独立的 Windows 进程组。
func prepareBackgroundCommand(command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	return nil
}

// terminateProcessByRecord opens the verified process and terminates its native handle.
// terminateProcessByRecord 打开已验证进程并通过原生句柄终止它。
func terminateProcessByRecord(record processRecord) error {
	if record.PID <= 0 {
		return ErrIdentityUnverified
	}
	process, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(record.PID))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return ErrNotRunning
	}
	if err != nil {
		return ErrIdentityUnverified
	}
	defer windows.CloseHandle(process)
	snapshot, err := inspectWindowsProcessHandle(process, record.PID)
	if err != nil {
		return err
	}
	if err := verifySnapshot(record, snapshot); err != nil {
		return err
	}
	if record.JobName != "" {
		job, openErr := openNamedJob(record.JobName)
		if openErr == nil {
			if err := windows.TerminateJobObject(job, 1); err == nil {
				windows.CloseHandle(job)
				return nil
			} else if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
				windows.CloseHandle(job)
				return ErrNotRunning
			}
			windows.CloseHandle(job)
		}
	}
	if err := windows.TerminateProcess(process, 1); err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return ErrNotRunning
		}
		return ErrIdentityUnverified
	}
	return nil
}

// attachProcessJob places the verified child in a named native Windows job.
// attachProcessJob 将已验证子进程加入命名的 Windows 原生作业。
func attachProcessJob(pid int, statePath string) (string, error) {
	jobName := processJobName(statePath)
	name, err := windows.UTF16PtrFromString(jobName)
	if err != nil {
		return "", ErrIdentityUnverified
	}
	jobResult, _, createErr := kernel32CreateJobObjectW.Call(0, uintptr(unsafe.Pointer(name)))
	if jobResult == 0 {
		if createErr == windows.ERROR_ACCESS_DENIED || createErr == windows.ERROR_PRIVILEGE_NOT_HELD || createErr == windows.ERROR_NOT_SUPPORTED {
			return "", nil
		}
		return "", ErrIdentityUnverified
	}
	if createErr == windows.ERROR_ALREADY_EXISTS {
		windows.CloseHandle(windows.Handle(jobResult))
		return "", ErrIdentityUnverified
	}
	job := windows.Handle(jobResult)
	defer windows.CloseHandle(job)
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return "", ErrIdentityUnverified
	}
	defer windows.CloseHandle(process)
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
			return "", nil
		}
		return "", ErrIdentityUnverified
	}
	return jobName, nil
}

// openNamedJob opens only the manager's terminate-capable job object.
// openNamedJob 只打开管理器拥有且具备终止权限的作业对象。
func openNamedJob(name string) (windows.Handle, error) {
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	result, _, callErr := kernel32OpenJobObjectW.Call(jobObjectTerminate, 0, uintptr(unsafe.Pointer(namePointer)))
	if result == 0 {
		return 0, callErr
	}
	return windows.Handle(result), nil
}

// processJobName derives a stable local namespace name from the explicit state path.
// processJobName 根据明确状态路径生成稳定的本地命名空间名称。
func processJobName(statePath string) string {
	digest := sha256.Sum256([]byte(filepath.Clean(statePath)))
	return "Local\\vmmm-process-" + hex.EncodeToString(digest[:16])
}

// forceTerminateProcessByRecord uses the same verified native handle after a timeout.
// forceTerminateProcessByRecord 超时后仍使用相同的已验证原生句柄。
func forceTerminateProcessByRecord(record processRecord) error {
	return terminateProcessByRecord(record)
}

// abortStartedProcess opens and verifies the just-created child before termination.
// abortStartedProcess 在终止刚创建的子进程前打开并验证它。
func abortStartedProcess(pid int, executable string, args []string, expectedStartToken string) error {
	process, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return ErrIdentityUnverified
	}
	defer windows.CloseHandle(process)
	snapshot, err := inspectWindowsProcessHandle(process, pid)
	if err != nil || snapshot.StartToken != expectedStartToken || !sameExecutablePath(snapshot.ExecutablePath, executable) || snapshot.CommandLineDigest != commandLineDigest(executable, args) || verifyProcessOwner(snapshot) != nil {
		return ErrIdentityUnverified
	}
	if err := windows.TerminateProcess(process, 1); err != nil {
		return ErrIdentityUnverified
	}
	return nil
}

// executablePathsEqual compares Windows paths case-insensitively after cleaning.
// executablePathsEqual 清理 Windows 路径后按不区分大小写规则比较。
func executablePathsEqual(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

// platformCommandLine uses the Windows quoting rules used by CreateProcess.
// platformCommandLine 使用 CreateProcess 所采用的 Windows 引号规则。
func platformCommandLine(executable string, args []string) string {
	values := make([]string, 0, len(args)+1)
	values = append(values, executable)
	values = append(values, args...)
	return windows.ComposeCommandLine(values)
}

// inspectProcess obtains a process handle and reads owner, image, creation time, and command line.
// inspectProcess 获取进程句柄并读取拥有者、镜像、创建时间和命令行。
func inspectProcess(pid int) (processSnapshot, error) {
	if pid <= 0 {
		return processSnapshot{}, ErrIdentityMismatch
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return processSnapshot{}, ErrNotRunning
	}
	if err != nil {
		return processSnapshot{}, ErrIdentityUnverified
	}
	defer windows.CloseHandle(process)
	return inspectWindowsProcessHandle(process, pid)
}

// inspectWindowsProcessHandle reads all identity evidence through one process handle.
// inspectWindowsProcessHandle 通过同一个进程句柄读取全部身份凭据。
func inspectWindowsProcessHandle(process windows.Handle, pid int) (processSnapshot, error) {
	executable, err := queryExecutablePath(process)
	if err != nil {
		return processSnapshot{}, ErrIdentityUnverified
	}
	owner, err := queryProcessOwner(process)
	if err != nil {
		return processSnapshot{}, ErrIdentityUnverified
	}
	startToken, err := queryCreationToken(process)
	if err != nil {
		return processSnapshot{}, ErrIdentityUnverified
	}
	commandLine, err := queryCommandLine(process)
	if err != nil {
		return processSnapshot{}, ErrIdentityUnverified
	}
	return processSnapshot{
		PID:               pid,
		ExecutablePath:    filepath.Clean(executable),
		CommandLineDigest: digestString(commandLine),
		Owner:             owner,
		StartToken:        startToken,
	}, nil
}

// queryExecutablePath asks Windows for the process image path through its handle.
// queryExecutablePath 通过进程句柄向 Windows 查询进程镜像路径。
func queryExecutablePath(process windows.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for len(buffer) <= 32768 {
		size := uint32(len(buffer))
		err := windows.QueryFullProcessImageName(process, 0, &buffer[0], &size)
		if err == nil {
			return windows.UTF16ToString(buffer[:size]), nil
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return "", err
		}
		buffer = make([]uint16, len(buffer)*2)
	}
	return "", errors.New("Windows image path is too long")
}

// queryProcessOwner obtains the target process token SID and compares it later with the caller.
// queryProcessOwner 获取目标进程令牌 SID，之后与调用方 SID 比较。
func queryProcessOwner(process windows.Handle) (string, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return "", errors.New("Windows process owner is unavailable")
	}
	return user.User.Sid.String(), nil
}

// queryCreationToken reads the immutable process creation FILETIME.
// queryCreationToken 读取不可变的进程创建 FILETIME。
func queryCreationToken(process windows.Handle) (string, error) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(process, &creation, &exit, &kernel, &user); err != nil {
		return "", err
	}
	return "windows:" + strconvUint64(uint64(creation.HighDateTime)<<32|uint64(creation.LowDateTime)), nil
}

// queryCommandLine reads RTL_USER_PROCESS_PARAMETERS from the target PEB.
// queryCommandLine 从目标 PEB 读取 RTL_USER_PROCESS_PARAMETERS 的命令行。
func queryCommandLine(process windows.Handle) (string, error) {
	var basic windows.PROCESS_BASIC_INFORMATION
	var returned uint32
	status := windows.NtQueryInformationProcess(process, windows.ProcessBasicInformation, unsafe.Pointer(&basic), uint32(unsafe.Sizeof(basic)), &returned)
	if status != nil || basic.PebBaseAddress == nil {
		return "", errors.New("Windows process PEB is unavailable")
	}
	var peb windows.PEB
	if err := readProcessMemory(process, uintptr(unsafe.Pointer(basic.PebBaseAddress)), unsafe.Pointer(&peb), unsafe.Sizeof(peb)); err != nil || peb.ProcessParameters == nil {
		return "", errors.New("Windows process parameters are unavailable")
	}
	var parameters windows.RTL_USER_PROCESS_PARAMETERS
	if err := readProcessMemory(process, uintptr(unsafe.Pointer(peb.ProcessParameters)), unsafe.Pointer(&parameters), unsafe.Sizeof(parameters)); err != nil {
		return "", errors.New("Windows process command line is unavailable")
	}
	if parameters.CommandLine.Buffer == nil || parameters.CommandLine.Length == 0 || parameters.CommandLine.Length%2 != 0 {
		return "", errors.New("Windows process command line is empty")
	}
	characters := make([]uint16, parameters.CommandLine.Length/2)
	if err := readProcessMemory(process, uintptr(unsafe.Pointer(parameters.CommandLine.Buffer)), unsafe.Pointer(&characters[0]), uintptr(parameters.CommandLine.Length)); err != nil {
		return "", errors.New("Windows process command line could not be read")
	}
	return windows.UTF16ToString(characters), nil
}

// readProcessMemory reads exactly one remote process buffer.
// readProcessMemory 精确读取一个远程进程缓冲区。
func readProcessMemory(process windows.Handle, address uintptr, destination unsafe.Pointer, size uintptr) error {
	if size == 0 {
		return nil
	}
	read := uintptr(0)
	err := windows.ReadProcessMemory(process, address, (*byte)(destination), size, &read)
	if err != nil || read != size {
		return errors.New("Windows remote memory read was incomplete")
	}
	return nil
}

// verifySnapshot compares a fresh Windows snapshot to a persisted record.
// verifySnapshot 将最新 Windows 快照与持久化登记比较。
func verifySnapshot(record processRecord, snapshot processSnapshot) error {
	if snapshot.PID != record.PID || !sameExecutablePath(snapshot.ExecutablePath, record.ExecutablePath) || snapshot.CommandLineDigest != record.CommandLineDigest || snapshot.Owner != record.Owner || snapshot.StartToken != record.StartToken {
		return ErrIdentityMismatch
	}
	return verifyProcessOwner(snapshot)
}

// verifyProcessOwner requires the target process token to match the caller token.
// verifyProcessOwner 要求目标进程令牌与调用方令牌一致。
func verifyProcessOwner(snapshot processSnapshot) error {
	currentOwner, err := currentWindowsOwner()
	if err != nil {
		return ErrIdentityUnverified
	}
	if currentOwner != snapshot.Owner {
		return ErrIdentityMismatch
	}
	return nil
}

// currentWindowsOwner returns the caller's stable token SID.
// currentWindowsOwner 返回调用方稳定的令牌 SID。
func currentWindowsOwner() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return "", errors.New("Windows current owner is unavailable")
	}
	return user.User.Sid.String(), nil
}

// digestString hashes a raw Windows command line without persisting its contents.
// digestString 对 Windows 原始命令行计算摘要，不持久化其内容。
func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// strconvUint64 avoids exposing platform identity values in errors.
// strconvUint64 避免在错误信息中暴露平台身份值。
func strconvUint64(value uint64) string {
	const digits = "0123456789abcdef"
	if value == 0 {
		return "0"
	}
	var buffer [16]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = digits[value&0xf]
		value >>= 4
	}
	return string(buffer[index:])
}
