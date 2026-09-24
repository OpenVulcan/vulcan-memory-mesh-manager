// Package processctl owns the non-service lifecycle of one installed VMM process.
// processctl 负责单个已安装 VMM 进程的非服务生命周期管理。
//
// It starts the exact executable selected by the installer, persists a strictly
// bound process identity, and refuses to act when that identity cannot be proved.
// 它只启动安装器选定的确切可执行文件，持久化严格绑定的进程身份，并在无法证明身份时拒绝操作。
package processctl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// protocolVersion identifies the on-disk process registration format.
	// protocolVersion 标识磁盘进程登记文件的格式版本。
	protocolVersion = 1

	// defaultOperationTimeout bounds lifecycle operations that wait for a process.
	// defaultOperationTimeout 限制需要等待进程的生命周期操作时长。
	defaultOperationTimeout = 30 * time.Second

	// startupGracePeriod catches immediate executable failures before Start succeeds.
	// startupGracePeriod 用于在 Start 返回成功前捕获立即退出的可执行文件。
	startupGracePeriod = 250 * time.Millisecond

	// processPollInterval bounds the delay while waiting for a verified process exit.
	// processPollInterval 限制等待已验证进程退出时的轮询间隔。
	processPollInterval = 40 * time.Millisecond
)

var (
	// ErrNotRunning indicates that no managed VMM process is currently running.
	// ErrNotRunning 表示当前没有受管理的 VMM 进程运行。
	ErrNotRunning = errors.New("managed VMM process is not running")

	// ErrAlreadyRunning indicates that a verified managed process already exists.
	// ErrAlreadyRunning 表示已经存在一个身份验证通过的受管理进程。
	ErrAlreadyRunning = errors.New("managed VMM process is already running")

	// ErrIdentityUnverified indicates that platform evidence was unavailable.
	// ErrIdentityUnverified 表示平台没有提供足够的身份验证证据。
	ErrIdentityUnverified = errors.New("managed VMM process identity cannot be verified")

	// ErrIdentityMismatch indicates that the PID belongs to a different process.
	// ErrIdentityMismatch 表示该 PID 当前属于另一个进程。
	ErrIdentityMismatch = errors.New("managed VMM process identity does not match")

	// ErrStateCorrupt indicates that the registration cannot be trusted.
	// ErrStateCorrupt 表示进程登记文件不可信或已损坏。
	ErrStateCorrupt = errors.New("managed VMM process state is corrupt")

	// ErrInvalidOptions indicates that a caller supplied an unsafe lifecycle root.
	// ErrInvalidOptions 表示调用方提供了不安全的生命周期路径。
	ErrInvalidOptions = errors.New("invalid process controller options")
)

// State describes the observable non-service process state.
// State 描述非服务进程的可观测状态。
type State string

const (
	// StateStopped means no verified process is running.
	// StateStopped 表示没有验证通过的进程运行。
	StateStopped State = "stopped"

	// StateRunning means the persisted process identity is currently verified.
	// StateRunning 表示磁盘登记的进程身份当前验证通过。
	StateRunning State = "running"

	// StateUnknown means a registration exists but its identity cannot be proved.
	// StateUnknown 表示存在登记，但无法证明进程身份。
	StateUnknown State = "unknown"
)

// Options binds a controller to one executable, one configuration root, and one state file.
// Options 将控制器绑定到一个可执行文件、一个配置根目录和一个状态文件。
type Options struct {
	// BinaryPath is the absolute installed VMM executable path.
	// BinaryPath 是已安装 VMM 可执行文件的绝对路径。
	BinaryPath string

	// ConfigRoot is the absolute VMM configuration root passed after -config.
	// ConfigRoot 是传给 -config 的 VMM 配置根目录绝对路径。
	ConfigRoot string

	// StatePath is the absolute manager-owned process registration path.
	// StatePath 是管理器拥有的进程登记文件绝对路径。
	StatePath string

	// OperationTimeout optionally overrides the bounded lifecycle wait duration.
	// OperationTimeout 可选覆盖有界生命周期等待时长。
	OperationTimeout time.Duration

	// Stdout and Stderr override foreground output; nil uses the current terminal.
	// Stdout 和 Stderr 覆盖前台输出；为空时使用当前终端。
	Stdout io.Writer
	// Stderr receives foreground diagnostics; it never receives manager state.
	// Stderr 接收前台诊断；不会接收管理器状态内容。
	Stderr io.Writer
}

// Status is a safe snapshot suitable for TUI or command-line display.
// Status 是适合 TUI 或命令行展示的安全快照。
type Status struct {
	// State is stopped, running, or unknown.
	// State 是 stopped、running 或 unknown。
	State State

	// PID is populated only when a registration contains a process identifier.
	// PID 仅在登记文件包含进程标识时填充。
	PID int

	// ExecutablePath is the verified executable path, without command output.
	// ExecutablePath 是验证过的可执行文件路径，不包含子进程输出。
	ExecutablePath string

	// ConfigRoot is the configured root path, never the configuration contents.
	// ConfigRoot 是配置根路径，绝不会包含配置内容。
	ConfigRoot string

	// StartedAt records the manager observation time for this process.
	// StartedAt 记录管理器观察到该进程启动的时间。
	StartedAt time.Time
}

// Client controls a single non-service VMM process.
// Client 控制一个非服务模式的 VMM 进程。
type Client struct {
	// options contains normalized immutable caller choices.
	// options 保存已规范化且不可变的调用方选项。
	options Options

	// timeout bounds start, stop, and restart waits.
	// timeout 限制启动、停止和重启等待时长。
	timeout time.Duration

	// mu serializes operations from one in-process caller.
	// mu 串行化同一进程内的生命周期操作。
	mu sync.Mutex
}

// processRecord is the strict state required before any background signal is sent.
// processRecord 是发送后台信号前必须严格验证的状态。
type processRecord struct {
	// ProtocolVersion identifies this record format.
	// ProtocolVersion 标识该登记格式。
	ProtocolVersion int `json:"protocol_version"`
	// PID is the platform process identifier.
	// PID 是平台进程标识。
	PID int `json:"pid"`
	// ProcessGroupID is the Unix process-group leader identifier.
	// ProcessGroupID 是 Unix 进程组领导者标识。
	ProcessGroupID int `json:"process_group_id"`
	// ExecutablePath is the canonical executable identity.
	// ExecutablePath 是规范化的可执行文件身份。
	ExecutablePath string `json:"executable_path"`
	// Arguments contains the exact non-secret argument vector.
	// Arguments 保存确切且不含秘密的参数数组。
	Arguments []string `json:"arguments"`
	// CommandLineDigest authenticates the observed command line.
	// CommandLineDigest 认证已观察到的命令行摘要。
	CommandLineDigest string `json:"command_line_digest"`
	// Owner identifies the current OS user owning the process.
	// Owner 标识拥有该进程的当前操作系统用户。
	Owner string `json:"owner"`
	// StartToken is the OS-provided process creation token.
	// StartToken 是操作系统提供的进程创建令牌。
	StartToken string `json:"start_token"`
	// StartedAtUnixNano is a diagnostic timestamp from the manager.
	// StartedAtUnixNano 是管理器记录的诊断时间戳。
	StartedAtUnixNano int64 `json:"started_at_unix_nano"`
	// JobName identifies the Windows job used to contain child processes.
	// JobName 标识用于收拢 Windows 子进程的作业对象。
	JobName string `json:"job_name"`
}

// processSnapshot contains fresh platform evidence for one PID.
// processSnapshot 保存某个 PID 的最新平台身份证据。
type processSnapshot struct {
	// PID is the inspected process identifier.
	// PID 是被检查的进程标识。
	PID int
	// ProcessGroupID is the verified Unix process group, or zero on Windows.
	// ProcessGroupID 是验证过的 Unix 进程组，Windows 上为零。
	ProcessGroupID int
	// ExecutablePath is the platform-reported executable path.
	// ExecutablePath 是平台报告的可执行文件路径。
	ExecutablePath string
	// Arguments are the platform-reported argv values on Unix.
	// Arguments 是 Unix 平台报告的 argv 值。
	Arguments []string
	// CommandLineDigest is the exact platform command-line digest.
	// CommandLineDigest 是确切的平台命令行摘要。
	CommandLineDigest string
	// Owner is the platform process owner identifier.
	// Owner 是平台进程拥有者标识。
	Owner string
	// StartToken is the platform process creation token.
	// StartToken 是平台进程创建令牌。
	StartToken string
}

// New validates explicit paths and creates a process controller.
// New 校验明确路径并创建进程控制器。
func New(options Options) (*Client, error) {
	normalized, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	return &Client{options: normalized, timeout: normalized.OperationTimeout}, nil
}

// RunForeground binds the VMM process directly to the caller's terminal.
// RunForeground 将 VMM 进程直接绑定到调用方终端。
func (c *Client) RunForeground(ctx context.Context) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if c == nil {
		return ErrInvalidOptions
	}
	command := exec.Command(c.options.BinaryPath, "-config", c.options.ConfigRoot)
	command.Stdin = os.Stdin
	command.Stdout = c.options.Stdout
	if command.Stdout == nil {
		command.Stdout = os.Stdout
	}
	command.Stderr = c.options.Stderr
	if command.Stderr == nil {
		command.Stderr = os.Stderr
	}
	if err := command.Start(); err != nil {
		return errors.New("VMM foreground process could not start")
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	select {
	case err := <-wait:
		if err != nil {
			return errors.New("VMM foreground process exited with an error")
		}
		return nil
	case <-ctx.Done():
		_ = command.Process.Kill()
		<-wait
		return ctx.Err()
	}
}

// Start launches the exact VMM executable as a verified background process.
// Start 将确切的 VMM 可执行文件作为已验证后台进程启动。
func (c *Client) Start(ctx context.Context) (Status, error) {
	if err := validateContext(ctx); err != nil {
		return Status{}, err
	}
	if c == nil {
		return Status{}, ErrInvalidOptions
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var result Status
	err := c.withStateLock(ctx, true, func() error {
		var err error
		result, err = c.startLocked(ctx)
		return err
	})
	return result, err
}

// Stop terminates only a process whose owner, executable, command line, and start token match.
// Stop 只终止拥有者、可执行文件、命令行和启动令牌全部匹配的进程。
func (c *Client) Stop(ctx context.Context) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if c == nil {
		return ErrInvalidOptions
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.withStateLock(ctx, true, func() error { return c.stopLocked(ctx) })
}

// Restart stops the verified process and starts a fresh verified instance.
// Restart 停止已验证进程并启动新的已验证实例。
func (c *Client) Restart(ctx context.Context) (Status, error) {
	if err := validateContext(ctx); err != nil {
		return Status{}, err
	}
	if c == nil {
		return Status{}, ErrInvalidOptions
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var result Status
	err := c.withStateLock(ctx, true, func() error {
		if err := c.stopLocked(ctx); err != nil && !errors.Is(err, ErrNotRunning) {
			return err
		}
		var err error
		result, err = c.startLocked(ctx)
		return err
	})
	return result, err
}

// Status verifies the persisted identity and removes only proven stale registrations.
// Status 验证磁盘身份，并且只清理已证明失效的登记。
func (c *Client) Status(ctx context.Context) (Status, error) {
	if err := validateContext(ctx); err != nil {
		return Status{}, err
	}
	if c == nil {
		return Status{}, ErrInvalidOptions
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.statusLocked(ctx)
}

// startLocked starts a process while the cross-process state lock is held.
// startLocked 在持有跨进程状态锁时启动进程。
func (c *Client) startLocked(ctx context.Context) (Status, error) {
	current, found, err := loadRecord(c.options.StatePath)
	if err != nil {
		return Status{}, err
	}
	if found {
		if _, err := verifyRecord(current); err == nil {
			return Status{}, ErrAlreadyRunning
		} else if !errors.Is(err, ErrNotRunning) && !errors.Is(err, ErrIdentityMismatch) {
			return Status{}, err
		}
		if err := removeRecord(c.options.StatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return Status{}, errors.New("stale VMM process state could not be removed")
		}
	}

	command := exec.Command(c.options.BinaryPath, "-config", c.options.ConfigRoot)
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	if err := prepareBackgroundCommand(command); err != nil {
		return Status{}, err
	}
	if err := command.Start(); err != nil {
		return Status{}, errors.New("VMM background process could not start")
	}
	snapshot, err := captureProcessSnapshot(command.Process.Pid, c.options.BinaryPath, command.Args[1:])
	if err != nil {
		if snapshot.StartToken != "" {
			_ = abortStartedProcess(command.Process.Pid, c.options.BinaryPath, command.Args[1:], snapshot.StartToken)
		}
		waitForCommandExit(command, nil)
		return Status{}, err
	}
	if err := ctx.Err(); err != nil {
		_ = abortStartedProcess(command.Process.Pid, c.options.BinaryPath, command.Args[1:], snapshot.StartToken)
		waitForCommandExit(command, nil)
		return Status{}, err
	}
	record := processRecord{
		ProtocolVersion:   protocolVersion,
		PID:               snapshot.PID,
		ProcessGroupID:    snapshot.ProcessGroupID,
		ExecutablePath:    snapshot.ExecutablePath,
		Arguments:         append([]string(nil), command.Args[1:]...),
		CommandLineDigest: snapshot.CommandLineDigest,
		Owner:             snapshot.Owner,
		StartToken:        snapshot.StartToken,
		StartedAtUnixNano: time.Now().UnixNano(),
	}
	record.JobName, err = attachProcessJob(record.PID, c.options.StatePath)
	if err != nil {
		_ = abortStartedProcess(command.Process.Pid, c.options.BinaryPath, command.Args[1:], snapshot.StartToken)
		waitForCommandExit(command, nil)
		return Status{}, err
	}
	if err := saveRecord(c.options.StatePath, record); err != nil {
		_ = terminateProcessByRecord(record)
		waitForCommandExit(command, &record)
		return Status{}, errors.New("VMM process state could not be saved")
	}
	go c.reapProcess(command, record)
	result := statusFromRecord(record)
	result.State = StateRunning
	return result, nil
}

// waitForCommandExit drains a failed child without sending an unverified PID signal.
// waitForCommandExit 回收失败子进程，但不会向未验证 PID 发送信号。
func waitForCommandExit(command *exec.Cmd, record *processRecord) {
	if command == nil || command.Process == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = command.Process.Wait()
		close(done)
	}()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
	}
	if record != nil {
		if _, err := verifyRecord(*record); err == nil {
			_ = forceTerminateProcessByRecord(*record)
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
	}
}

// stopLocked verifies and terminates a process while the state lock is held.
// stopLocked 在持有状态锁时验证并终止进程。
func (c *Client) stopLocked(ctx context.Context) error {
	record, found, err := loadRecord(c.options.StatePath)
	if err != nil {
		return err
	}
	if !found {
		return ErrNotRunning
	}
	if _, err := verifyRecord(record); err != nil {
		if errors.Is(err, ErrNotRunning) || errors.Is(err, ErrIdentityMismatch) {
			if removeErr := removeRecord(c.options.StatePath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return errors.New("stale VMM process state could not be removed")
			}
			return ErrNotRunning
		}
		return err
	}
	if err := terminateProcessByRecord(record); err != nil {
		if errors.Is(err, ErrNotRunning) {
			_ = removeRecord(c.options.StatePath)
			return ErrNotRunning
		}
		return err
	}
	deadline := time.Now().Add(c.timeout)
	for {
		if _, err := verifyRecord(record); err != nil {
			if errors.Is(err, ErrNotRunning) || errors.Is(err, ErrIdentityMismatch) {
				if removeErr := removeRecord(c.options.StatePath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
					return errors.New("VMM process state could not be removed")
				}
				return nil
			}
		}
		if time.Now().After(deadline) {
			if _, verifyErr := verifyRecord(record); verifyErr != nil {
				if errors.Is(verifyErr, ErrNotRunning) || errors.Is(verifyErr, ErrIdentityMismatch) {
					_ = removeRecord(c.options.StatePath)
					return nil
				}
				return ErrIdentityUnverified
			}
			_ = forceTerminateProcessByRecord(record)
			forceDeadline := time.Now().Add(time.Second)
			for time.Now().Before(forceDeadline) {
				if _, forceErr := verifyRecord(record); errors.Is(forceErr, ErrNotRunning) || errors.Is(forceErr, ErrIdentityMismatch) {
					_ = removeRecord(c.options.StatePath)
					return nil
				}
				_ = sleepContext(ctx, processPollInterval)
			}
			return errors.New("VMM background process did not stop before the timeout")
		}
		if err := sleepContext(ctx, processPollInterval); err != nil {
			return err
		}
	}
}

// statusLocked reads status and safely cleans up a process that is demonstrably gone.
// statusLocked 读取状态，并安全清理已明确消失的进程。
func (c *Client) statusLocked(ctx context.Context) (Status, error) {
	var result Status
	if _, err := os.Stat(c.options.StatePath); errors.Is(err, os.ErrNotExist) {
		return Status{State: StateStopped}, nil
	} else if err != nil {
		return Status{}, ErrStateCorrupt
	}
	err := c.withStateLock(ctx, false, func() error {
		record, found, err := loadRecord(c.options.StatePath)
		if err != nil {
			return err
		}
		if !found {
			result = Status{State: StateStopped}
			return nil
		}
		if _, err := verifyRecord(record); err != nil {
			if errors.Is(err, ErrNotRunning) || errors.Is(err, ErrIdentityMismatch) {
				if removeErr := removeRecord(c.options.StatePath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
					return errors.New("stale VMM process state could not be removed")
				}
				result = statusFromRecord(record)
				result.State = StateStopped
				return nil
			}
			result = statusFromRecord(record)
			result.State = StateUnknown
			return err
		}
		result = statusFromRecord(record)
		result.State = StateRunning
		return nil
	})
	return result, err
}

// reapProcess removes a registration only after proving that the exiting process owns it.
// reapProcess 只有在证明退出进程确实拥有登记后才移除登记。
func (c *Client) reapProcess(command *exec.Cmd, record processRecord) {
	if command == nil || command.Process == nil {
		return
	}
	_, _ = command.Process.Wait()
	_ = c.withStateLock(context.Background(), true, func() error {
		current, found, loadErr := loadRecord(c.options.StatePath)
		if loadErr != nil || !found || !sameRecord(current, record) {
			return loadErr
		}
		return removeRecord(c.options.StatePath)
	})
}

// verifyRecord compares fresh platform evidence with every persisted identity component.
// verifyRecord 将最新平台证据与持久化身份的每个组成部分进行比较。
func verifyRecord(record processRecord) (processSnapshot, error) {
	if err := validateRecord(record); err != nil {
		return processSnapshot{}, err
	}
	snapshot, err := inspectProcess(record.PID)
	if err != nil {
		return processSnapshot{}, err
	}
	if err := verifyProcessOwner(snapshot); err != nil {
		return processSnapshot{}, err
	}
	if snapshot.PID != record.PID || snapshot.ProcessGroupID != record.ProcessGroupID ||
		!sameExecutablePath(snapshot.ExecutablePath, record.ExecutablePath) ||
		snapshot.CommandLineDigest != record.CommandLineDigest || snapshot.Owner != record.Owner ||
		snapshot.StartToken != record.StartToken {
		return processSnapshot{}, ErrIdentityMismatch
	}
	return snapshot, nil
}

// captureProcessSnapshot obtains retryable startup evidence for a new child.
// captureProcessSnapshot 获取新子进程的可重试启动证据。
func captureProcessSnapshot(pid int, executable string, args []string) (processSnapshot, error) {
	deadline := time.Now().Add(startupGracePeriod)
	var last error
	for {
		snapshot, err := inspectProcess(pid)
		if err == nil {
			if !sameExecutablePath(snapshot.ExecutablePath, executable) {
				return snapshot, ErrIdentityMismatch
			}
			if snapshot.CommandLineDigest != commandLineDigest(executable, args) {
				return snapshot, ErrIdentityMismatch
			}
			return snapshot, nil
		}
		last = err
		if errors.Is(err, ErrNotRunning) || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if last == nil {
		last = ErrIdentityUnverified
	}
	return processSnapshot{}, last
}

// withStateLock serializes state reads and writes across manager processes.
// withStateLock 在不同管理器进程之间串行化状态读写。
func (c *Client) withStateLock(ctx context.Context, createParent bool, action func() error) error {
	if createParent {
		if err := os.MkdirAll(filepath.Dir(c.options.StatePath), 0700); err != nil {
			return errors.New("VMM process state directory could not be prepared")
		}
	}
	lock, err := acquireStateLock(ctx, c.options.StatePath+".lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	return action()
}

// normalizeOptions validates paths without echoing user configuration contents.
// normalizeOptions 校验路径，但不会回显用户配置内容。
func normalizeOptions(options Options) (Options, error) {
	if err := validateAbsolutePath(options.BinaryPath); err != nil {
		return Options{}, err
	}
	info, err := os.Stat(options.BinaryPath)
	if err != nil || !info.Mode().IsRegular() {
		return Options{}, ErrInvalidOptions
	}
	if err := rejectReparsePath(options.BinaryPath); err != nil {
		return Options{}, err
	}
	if err := validateAbsolutePath(options.ConfigRoot); err != nil {
		return Options{}, err
	}
	if err := validateAbsolutePath(options.StatePath); err != nil {
		return Options{}, err
	}
	if err := rejectReparsePath(options.StatePath); err != nil {
		return Options{}, err
	}
	options.BinaryPath = filepath.Clean(options.BinaryPath)
	options.ConfigRoot = filepath.Clean(options.ConfigRoot)
	options.StatePath = filepath.Clean(options.StatePath)
	if options.OperationTimeout <= 0 {
		options.OperationTimeout = defaultOperationTimeout
	}
	return options, nil
}

// validateAbsolutePath rejects relative, empty, and control-containing lifecycle paths.
// validateAbsolutePath 拒绝相对、空值及含控制字符的生命周期路径。
func validateAbsolutePath(value string) error {
	if strings.TrimSpace(value) == "" || !filepath.IsAbs(value) || filepath.Clean(value) == "." {
		return ErrInvalidOptions
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return ErrInvalidOptions
		}
	}
	return nil
}

// containsControl reports whether a persisted field contains a control character.
// containsControl 判断持久化字段是否含有控制字符。
func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

// rejectReparsePath prevents existing state or executable links from redirecting ownership.
// rejectReparsePath 防止已有状态或可执行文件链接重定向所有权。
func rejectReparsePath(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalidOptions
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrInvalidOptions
	}
	parent := filepath.Dir(path)
	if _, err := os.Stat(parent); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return ErrInvalidOptions
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || !sameExecutablePath(resolved, parent) {
		return ErrInvalidOptions
	}
	return nil
}

// validateContext rejects nil contexts and already-canceled operations.
// validateContext 拒绝空上下文和已经取消的操作。
func validateContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("process controller context is required")
	}
	return ctx.Err()
}

// validateRecord validates persisted fields before any platform lookup occurs.
// validateRecord 在任何平台查询前校验磁盘登记字段。
func validateRecord(record processRecord) error {
	if record.ProtocolVersion != protocolVersion || record.PID <= 0 || record.ProcessGroupID < 0 ||
		record.StartedAtUnixNano <= 0 || record.ExecutablePath == "" || record.Owner == "" || record.StartToken == "" ||
		record.CommandLineDigest == "" || len(record.Arguments) != 2 || record.Arguments[0] != "-config" || record.Arguments[1] == "" {
		return ErrStateCorrupt
	}
	if err := validateAbsolutePath(record.ExecutablePath); err != nil {
		return ErrStateCorrupt
	}
	if err := validateAbsolutePath(record.Arguments[1]); err != nil {
		return ErrStateCorrupt
	}
	if strings.TrimSpace(record.JobName) != record.JobName || containsControl(record.JobName) {
		return ErrStateCorrupt
	}
	return nil
}

// statusFromRecord converts a validated record into a non-secret public snapshot.
// statusFromRecord 将已验证登记转换为不含秘密的公开快照。
func statusFromRecord(record processRecord) Status {
	return Status{PID: record.PID, ExecutablePath: record.ExecutablePath, ConfigRoot: record.Arguments[1], StartedAt: time.Unix(0, record.StartedAtUnixNano)}
}

// sameRecord prevents an old reaper from deleting a newer registration.
// sameRecord 防止旧进程回收器删除新登记。
func sameRecord(left, right processRecord) bool {
	if left.ProtocolVersion != right.ProtocolVersion || left.PID != right.PID || left.ProcessGroupID != right.ProcessGroupID || left.ExecutablePath != right.ExecutablePath || left.CommandLineDigest != right.CommandLineDigest || left.Owner != right.Owner || left.StartToken != right.StartToken || left.StartedAtUnixNano != right.StartedAtUnixNano || left.JobName != right.JobName || len(left.Arguments) != len(right.Arguments) {
		return false
	}
	for index := range left.Arguments {
		if left.Arguments[index] != right.Arguments[index] {
			return false
		}
	}
	return true
}

// sameExecutablePath compares platform paths with the platform's case rules.
// sameExecutablePath 按平台路径规则比较可执行文件路径。
func sameExecutablePath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	return executablePathsEqual(left, right)
}

// commandLineDigest hashes the exact platform command line without storing it in state.
// commandLineDigest 对确切平台命令行计算摘要，而不把命令行明文写入状态。
func commandLineDigest(executable string, args []string) string {
	payload := platformCommandLine(executable, args)
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:])
}

// sleepContext waits briefly without blocking cancellation indefinitely.
// sleepContext 短暂等待，同时不会无限期阻塞取消。
func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
