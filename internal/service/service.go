// Package service invokes the installed VMM service-management CLI without a shell.
// service 包通过无 shell 子进程调用已安装的 VMM 服务管理 CLI。
// It belongs to the manager integration layer and exposes only the lifecycle actions needed by the TUI.
// 它属于管理器集成层，只开放 TUI 所需的服务生命周期操作。
package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// defaultTimeout bounds service-control processes while allowing native service managers time to settle.
	// defaultTimeout 为服务控制子进程设置上限，同时为原生服务管理器留出完成操作的时间。
	defaultTimeout = 45 * time.Second

	// statusOutputLimit caps captured machine-readable output while the writer continues draining excess bytes.
	// statusOutputLimit 限制机器可读状态输出的缓存大小，同时继续排空超出部分以避免子进程阻塞。
	statusOutputLimit = 8 * 1024

	// maximumServiceNameLength matches the VMM CLI's cross-platform service-name contract.
	// maximumServiceNameLength 与 VMM CLI 的跨平台服务名契约保持一致。
	maximumServiceNameLength = 128
)

var (
	// ErrTimeout reports a VMM service command that exceeded its context deadline.
	// ErrTimeout 表示 VMM 服务命令超过了上下文截止时间。
	ErrTimeout = errors.New("VMM service command timed out")

	// ErrCanceled reports a VMM service command canceled by its caller.
	// ErrCanceled 表示 VMM 服务命令被调用方取消。
	ErrCanceled = errors.New("VMM service command canceled")

	// ErrOutputLimit reports machine-readable output larger than the safe capture bound.
	// ErrOutputLimit 表示机器可读输出超过了安全缓存上限。
	ErrOutputLimit = errors.New("VMM service status output exceeded the limit")

	// ErrInvalidStatus reports a malformed or unsupported key-value service-status document.
	// ErrInvalidStatus 表示服务状态键值文档格式错误或包含不支持的字段。
	ErrInvalidStatus = errors.New("VMM service status output is invalid")

	// ErrSecureSudoUnavailable reports that the fixed Unix sudo helper failed its trust checks.
	// ErrSecureSudoUnavailable 表示固定 Unix sudo 辅助程序未通过信任检查。
	ErrSecureSudoUnavailable = errors.New("secure sudo executable is unavailable at /usr/bin/sudo")
)

// commandRunner is the narrow process seam used to test the final executable path and argument vector.
// commandRunner 是用于测试最终可执行路径和参数数组的最小进程边界。
type commandRunner func(context.Context, string, []string, bool) (string, error)

// Client is bound to one absolute VMM executable path and exposes a fixed set of service actions.
// Client 绑定到一个绝对 VMM 可执行文件路径，并只公开固定的服务操作集合。
// The private command runner prevents callers from injecting arbitrary subcommands or shell syntax.
// 私有子进程执行器可避免调用方注入任意子命令或 shell 语法。
type Client struct {
	// binaryPath is the absolute path to the installed VMM executable.
	// binaryPath 是已安装 VMM 可执行文件的绝对路径。
	binaryPath string

	// timeout is the upper bound for each service command and can be shortened by package tests.
	// timeout 是单次服务命令的时限上限，包内测试可缩短此值。
	timeout time.Duration

	// outputLimit caps only status output, which is the sole command response parsed by this adapter.
	// outputLimit 仅限制 status 输出，因为该适配器只解析这一命令的响应。
	outputLimit int

	// runner replaces the OS process launch only in package tests; production uses exec.CommandContext.
	// runner 仅在包测试中替换操作系统进程启动；生产环境使用 exec.CommandContext。
	runner commandRunner

	// testUnprivileged executes the fake service binary directly in package tests only.
	// testUnprivileged 仅在包测试中直接执行伪服务程序。
	testUnprivileged bool
}

// Status contains the stable key-value fields emitted by VMM's cross-platform service CLI.
// Status 保存 VMM 跨平台服务 CLI 输出的稳定键值字段。
// Substate is populated by Linux systemd, while StartType is populated by Windows SCM.
// Linux systemd 会提供 Substate，Windows SCM 会提供 StartType。
type Status struct {
	// State describes whether the service is running or stopped.
	// State 狏述服务正在运行或已经停止。
	State string

	// AutoStart records whether the service manager will start this service automatically.
	// AutoStart 记录服务管理器是否会在系统启动时自动启动该服务。
	AutoStart string

	// Substate preserves the systemd substate when the current platform is Linux.
	// Substate 在当前平台为 Linux 时保存 systemd 子状态。
	Substate string

	// StartType distinguishes automatic, manual, and disabled Windows SCM policies.
	// StartType 用于区分 Windows SCM 的自动、手动和禁用启动策略。
	StartType string

	// User identifies the account recorded by the Unix service manager.
	// User 标识 Unix 服务管理器记录的运行账户。
	// Windows SCM does not expose this field through the stable VMM status protocol.
	// Windows SCM 不通过稳定的 VMM 状态协议暴露此字段。
	User string
}

// New creates a service client for an absolute, existing regular VMM executable.
// New 为绝对路径下已存在的普通 VMM 可执行文件创建服务客户端。
// It rejects relative paths and directories so service actions cannot fall back to PATH lookup.
// 它拒绝相对路径和目录，确保服务操作不会退回到 PATH 搜索。
func New(binaryPath string) (*Client, error) {
	if strings.TrimSpace(binaryPath) == "" || !filepath.IsAbs(binaryPath) || hasControlCharacter(binaryPath) {
		return nil, errors.New("VMM executable path must be an absolute path")
	}
	cleaned := filepath.Clean(binaryPath)
	info, err := os.Stat(cleaned)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("VMM executable path must name an existing regular file")
	}
	return &Client{binaryPath: cleaned, timeout: defaultTimeout, outputLimit: statusOutputLimit}, nil
}

// Install registers the named VMM service with a persistent absolute directory or YAML configuration path.
// Install 使用持久化的绝对目录或 YAML 配置路径注册指定的 VMM 服务。
// serviceUser is the explicit Unix service account; Windows SCM intentionally receives no account flag.
// serviceUser 是明确的 Unix 服务账户；Windows SCM 不接收账户参数。
// The argument vector explicitly carries the requested boot-start policy and never passes through a shell.
// 参数数组会显式携带开机自启策略，且不会经过 shell。
func (c *Client) Install(ctx context.Context, name string, configPath string, serviceUser string, autoStart bool) error {
	if err := validateServiceName(name); err != nil {
		return err
	}
	cleanedConfig, err := validateConfigPath(configPath)
	if err != nil {
		return err
	}
	if err := validateServiceUserForPlatform(serviceUser, runtime.GOOS); err != nil {
		return err
	}
	_, err = c.runPrivileged(ctx, "install", installArgumentsForPlatform(name, cleanedConfig, serviceUser, autoStart, runtime.GOOS), false)
	return err
}

// installArgumentsForPlatform builds the fixed VMM install vector for one target platform.
// installArgumentsForPlatform 为指定目标平台构造固定的 VMM 安装参数数组。
// Unix targets carry the requested service account; Windows SCM uses its native account policy.
// Unix 目标会携带指定服务账户；Windows SCM 使用其原生账户策略。
func installArgumentsForPlatform(name string, configPath string, serviceUser string, autoStart bool, platform string) []string {
	autoStartArg := "-auto-start=false"
	if autoStart {
		autoStartArg = "-auto-start=true"
	}
	args := []string{"service", "install", name, "-config", configPath}
	switch platform {
	case "linux", "darwin":
		args = append(args, "-user", serviceUser)
	}
	return append(args, autoStartArg)
}

// validateServiceUserForPlatform requires an explicit safe account on Unix and ignores it on Windows.
// validateServiceUserForPlatform 在 Unix 上要求明确且安全的账户，在 Windows 上忽略该参数。
// Windows SCM intentionally has no -user argument in the VMM command contract.
// Windows SCM 的 VMM 命令契约明确不包含 -user 参数。
func validateServiceUserForPlatform(serviceUser string, platform string) error {
	switch platform {
	case "windows":
		return nil
	case "linux", "darwin":
		if !validServiceUserValue(serviceUser) {
			return errors.New("VMM service user must be a non-empty account without whitespace or control characters")
		}
		return nil
	default:
		return errors.New("VMM service user is unsupported on this platform")
	}
}

// validServiceUserValue accepts one printable account token that can be passed without shell interpretation.
// validServiceUserValue 接受一个可在无 shell 解释下传递的可打印账户令牌。
func validServiceUserValue(value string) bool {
	if len(value) == 0 || len(value) > 128 || value != strings.TrimSpace(value) {
		return false
	}
	if !isASCIIAlphaNumeric(value[0]) && value[0] != '_' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !isASCIIAlphaNumeric(character) && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

// Uninstall removes the named service registration from the native service manager.
// Uninstall 从原生服务管理器中移除指定服务注册。
func (c *Client) Uninstall(ctx context.Context, name string) error {
	return c.lifecycle(ctx, "uninstall", name)
}

// Start starts the named installed service.
// Start 启动指定的已安装服务。
func (c *Client) Start(ctx context.Context, name string) error {
	return c.lifecycle(ctx, "start", name)
}

// Stop stops the named running service.
// Stop 停止指定的运行中服务。
func (c *Client) Stop(ctx context.Context, name string) error {
	return c.lifecycle(ctx, "stop", name)
}

// Restart restarts the named installed service.
// Restart 重启指定的已安装服务。
func (c *Client) Restart(ctx context.Context, name string) error {
	return c.lifecycle(ctx, "restart", name)
}

// Enable configures the named service to start automatically when its service manager starts.
// Enable 将指定服务设置为随服务管理器启动时自动运行。
func (c *Client) Enable(ctx context.Context, name string) error {
	return c.lifecycle(ctx, "enable", name)
}

// Disable prevents the named service from starting automatically while preserving manual start capability.
// Disable 禁止指定服务自动启动，同时保留手动启动能力。
func (c *Client) Disable(ctx context.Context, name string) error {
	return c.lifecycle(ctx, "disable", name)
}

// GetStatus reads and validates the stable key-value status document for the named service.
// GetStatus 读取并校验指定服务的稳定键值状态文档。
// It discards all non-status output and never returns raw process diagnostics that could expose configuration data.
// 它会丢弃非状态输出，且不会返回可能泄露配置数据的原始进程诊断信息。
func (c *Client) GetStatus(ctx context.Context, name string) (Status, error) {
	if err := validateServiceName(name); err != nil {
		return Status{}, err
	}
	output, err := c.run(ctx, "status", []string{"service", "status", name}, true)
	if err != nil {
		return Status{}, err
	}
	return parseStatusOutput(output)
}

// lifecycle validates the service name and invokes one compile-time-selected lifecycle action.
// lifecycle 校验服务名，并调用一个在编译期已确定的生命周期操作。
func (c *Client) lifecycle(ctx context.Context, action string, name string) error {
	if err := validateServiceName(name); err != nil {
		return err
	}
	switch action {
	case "uninstall", "start", "stop", "restart", "enable", "disable":
		_, err := c.runPrivileged(ctx, action, []string{"service", action, name}, false)
		return err
	default:
		return errors.New("unsupported VMM service action")
	}
}

// run executes a fixed argument vector with bounded time and safe output handling.
// run 使用固定参数数组执行子进程，并限制运行时间和输出处理。
// Stderr and non-status stdout are discarded so secret-bearing diagnostics never enter manager errors or logs.
// stderr 和非 status 的 stdout 会被丢弃，避免含密钥的诊断进入管理器错误或日志。
func (c *Client) run(ctx context.Context, action string, args []string, captureStatus bool) (string, error) {
	return c.runWithPrivilege(ctx, action, args, captureStatus, false)
}

// runPrivileged executes a service-management write through the native privilege boundary on Unix.
// runPrivileged 在 Unix 上通过原生提权边界执行服务管理写操作。
// Status is intentionally excluded because it is a read-only operation available to the service user.
// status 特意不经过提权，因为它是服务用户可以执行的只读操作。
func (c *Client) runPrivileged(ctx context.Context, action string, args []string, captureStatus bool) (string, error) {
	return c.runWithPrivilege(ctx, action, args, captureStatus, true)
}

// runWithPrivilege executes a fixed argument vector with bounded time and an optional Unix sudo boundary.
// runWithPrivilege 在有界时间内执行固定参数数组，并按需经过 Unix sudo 边界。
func (c *Client) runWithPrivilege(ctx context.Context, action string, args []string, captureStatus bool, privileged bool) (string, error) {
	if c == nil || c.binaryPath == "" {
		return "", errors.New("VMM service client is not initialized")
	}
	if ctx == nil {
		return "", errors.New("VMM service context is required")
	}
	if c.timeout <= 0 {
		return "", errors.New("VMM service timeout must be positive")
	}
	if c.runner == nil && !c.testUnprivileged {
		if err := validateServiceBinaryTrust(c.binaryPath); err != nil {
			return "", commandFailure(action, err, privileged)
		}
	}
	commandContext, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var commandPath string
	var commandArgs []string
	var usedSudo bool
	var prepareErr error
	if c.testUnprivileged {
		commandPath, commandArgs = c.binaryPath, args
	} else {
		commandPath, commandArgs, usedSudo, prepareErr = preparePrivilegedCommand(c.binaryPath, args, privileged)
	}
	if prepareErr != nil {
		return "", commandFailure(action, prepareErr, privileged || usedSudo)
	}
	if c.runner != nil {
		output, err := c.runner(commandContext, commandPath, commandArgs, captureStatus)
		if err != nil {
			return "", commandFailure(action, err, usedSudo)
		}
		return output, nil
	}
	command := exec.CommandContext(commandContext, commandPath, commandArgs...)
	command.Stdin = nil
	command.Stderr = io.Discard
	var statusOutput cappedBuffer
	if captureStatus {
		statusOutput.limit = c.outputLimit
		command.Stdout = &statusOutput
	} else {
		command.Stdout = io.Discard
	}
	err := command.Run()
	if captureStatus && statusOutput.exceeded {
		return "", ErrOutputLimit
	}
	if err != nil {
		if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
			return "", commandFailure(action, ErrTimeout, usedSudo)
		}
		if errors.Is(commandContext.Err(), context.Canceled) {
			return "", commandFailure(action, ErrCanceled, usedSudo)
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return "", commandFailure(action, fmt.Errorf("VMM service %s failed with exit code %d", action, exitError.ExitCode()), usedSudo)
		}
		return "", commandFailure(action, fmt.Errorf("VMM service %s process failed", action), usedSudo)
	}
	if captureStatus {
		return statusOutput.buffer.String(), nil
	}
	return "", nil
}

// commandFailure adds the actionable sudo hint only when the command actually crossed the Unix privilege boundary.
// commandFailure 仅在命令确实经过 Unix 提权边界时补充可执行的 sudo 提示。
func commandFailure(action string, cause error, usedSudo bool) error {
	if !usedSudo {
		return fmt.Errorf("%s: %w", action, cause)
	}
	return fmt.Errorf("%s: %w; run `sudo -v` before retrying the privileged VMM service operation", action, cause)
}

// sudoCommandArguments prepends the non-interactive sudo policy without invoking a shell.
// sudoCommandArguments 在不调用 shell 的前提下，为命令添加非交互 sudo 策略。
func sudoCommandArguments(binaryPath string, args []string) []string {
	wrapped := make([]string, 0, len(args)+2)
	wrapped = append(wrapped, "-n", binaryPath)
	return append(wrapped, args...)
}

// cappedBuffer stores at most limit bytes while reporting the full write as consumed to keep child pipes draining.
// cappedBuffer 最多保存 limit 字节，但将超出内容也视为已消费，以持续排空子进程管道。
type cappedBuffer struct {
	// buffer contains the bounded prefix needed for status parsing.
	// buffer 保存供状态解析使用的有限长度前缀。
	buffer bytes.Buffer

	// limit is the maximum number of bytes retained in memory.
	// limit 是内存中最多保留的字节数。
	limit int

	// exceeded records that the child emitted more bytes than the protocol allows.
	// exceeded 记录子进程输出是否超过协议允许的字节数。
	exceeded bool
}

// Write retains only the remaining capacity and always drains the supplied slice.
// Write 仅保存剩余容量内的数据，并始终消费调用方提供的整段内容。
func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.limit < 0 {
		return 0, ErrOutputLimit
	}
	remaining := b.limit - b.buffer.Len()
	if remaining < len(p) {
		b.exceeded = true
		if remaining > 0 {
			_, _ = b.buffer.Write(p[:remaining])
		}
		return len(p), nil
	}
	_, _ = b.buffer.Write(p)
	return len(p), nil
}

// validateServiceName matches the portable identifier accepted by VMM on Windows, Linux, and macOS.
// validateServiceName 校验服务名是否符合 VMM 在 Windows、Linux 和 macOS 上接受的可移植标识符规则。
func validateServiceName(name string) error {
	if len(name) == 0 || len(name) > maximumServiceNameLength || !isASCIIAlphaNumeric(name[0]) {
		return errors.New("service name must contain 1-128 portable characters and start with a letter or digit")
	}
	for index := 1; index < len(name); index++ {
		character := name[index]
		if !isASCIIAlphaNumeric(character) && character != '.' && character != '_' && character != '-' {
			return errors.New("service name must contain only letters, numbers, dot, underscore, or hyphen")
		}
	}
	return nil
}

// validateConfigPath requires an absolute existing directory or an absolute YAML file path.
// validateConfigPath 要求配置路径为绝对的现有目录或绝对 YAML 文件路径。
// A not-yet-created directory or YAML file is accepted because VMM's installer contract permits registration before first creation.
// VMM 安装契约允许先注册再创建目录或 YAML 文件，因此尚未创建的路径也会被接受。
func validateConfigPath(configPath string) (string, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" || !filepath.IsAbs(configPath) || hasControlCharacter(configPath) {
		return "", errors.New("VMM configuration path must be absolute and contain no control characters")
	}
	cleaned := filepath.Clean(configPath)
	info, err := os.Stat(cleaned)
	if err == nil {
		if info.IsDir() {
			return cleaned, nil
		}
		if info.Mode().IsRegular() && isYAMLPath(cleaned) {
			return cleaned, nil
		}
		return "", errors.New("VMM configuration path must be a directory or a .yaml/.yml file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("VMM configuration path must be an existing directory or a valid future configuration path")
	}
	if filepath.Ext(cleaned) != "" && !isYAMLPath(cleaned) {
		return "", errors.New("VMM configuration path must be an existing directory or a .yaml/.yml file path")
	}
	return cleaned, nil
}

// isYAMLPath reports whether a path has one of the two VMM-supported YAML extensions.
// isYAMLPath 判断路径是否使用 VMM 支持的两种 YAML 扩展名之一。
func isYAMLPath(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	return extension == ".yaml" || extension == ".yml"
}

// hasControlCharacter reports control bytes that could corrupt service-manager arguments or status rendering.
// hasControlCharacter 用于检测可能破坏服务管理参数或状态显示的控制字符。
func hasControlCharacter(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f {
			return true
		}
	}
	return false
}

// isASCIIAlphaNumeric reports whether a byte is an ASCII letter or digit.
// isASCIIAlphaNumeric 判断字节是否为 ASCII 字母或数字。
func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

// parseStatusOutput strictly decodes one platform-specific set of stable key-value status fields.
// parseStatusOutput 严格解析一组平台特定的稳定键值状态字段。
// It rejects unknown, repeated, malformed, or control-bearing fields instead of guessing which line is authoritative.
// 它会拒绝未知、重复、格式错误或含控制字符的字段，不会猜测哪一行才是权威状态。
func parseStatusOutput(output string) (Status, error) {
	return parseStatusOutputForPlatform(output, runtime.GOOS)
}

// parseStatusOutputForPlatform decodes the exact status schema emitted by one supported VMM platform.
// parseStatusOutputForPlatform 按指定支持平台解码 VMM 发出的精确状态模式。
// Keeping the platform explicit lets one fixture suite verify all cross-platform contracts.
// 显式传入平台可以让同一组 fixture 覆盖所有跨平台协议。
func parseStatusOutputForPlatform(output string, platform string) (Status, error) {
	controlCheck := strings.ReplaceAll(output, "\r\n", "")
	controlCheck = strings.ReplaceAll(controlCheck, "\n", "")
	if output == "" || len(output) > statusOutputLimit || hasControlCharacter(controlCheck) {
		return Status{}, ErrInvalidStatus
	}
	trimmed := strings.TrimSuffix(output, "\n")
	lines := strings.Split(trimmed, "\n")
	values := make(map[string]string, 4)
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		key, value, found := strings.Cut(line, "=")
		if !found || !validStatusKey(key) || !validStatusValueForKey(key, value) {
			return Status{}, ErrInvalidStatus
		}
		if _, duplicate := values[key]; duplicate {
			return Status{}, ErrInvalidStatus
		}
		values[key] = value
	}
	if values["state"] == "" || values["auto_start"] == "" {
		return Status{}, ErrInvalidStatus
	}
	// Absence has no account or native start-type fields; accept only the exact shared two-field contract.
	// 服务不存在时没有账户或系统启动类型字段；只接受精确的双字段跨平台契约。
	if values["state"] == "not-installed" {
		if platform != "windows" && platform != "linux" && platform != "darwin" {
			return Status{}, ErrInvalidStatus
		}
		if len(values) != 2 || values["auto_start"] != "false" {
			return Status{}, ErrInvalidStatus
		}
		return Status{State: "not-installed", AutoStart: "false"}, nil
	}
	if values["state"] != "running" && values["state"] != "stopped" {
		return Status{}, ErrInvalidStatus
	}
	switch platform {
	case "windows":
		if len(values) != 3 || values["start_type"] == "" || values["substate"] != "" || values["user"] != "" {
			return Status{}, ErrInvalidStatus
		}
	case "linux":
		if len(values) != 4 || values["substate"] == "" || values["user"] == "" || values["start_type"] != "" {
			return Status{}, ErrInvalidStatus
		}
	case "darwin":
		if len(values) != 3 || values["user"] == "" || values["substate"] != "" || values["start_type"] != "" {
			return Status{}, ErrInvalidStatus
		}
	default:
		return Status{}, ErrInvalidStatus
	}
	return Status{State: values["state"], AutoStart: values["auto_start"], Substate: values["substate"], StartType: values["start_type"], User: values["user"]}, nil
}

// validStatusKey restricts status fields to the contract documented by VMM's service CLI.
// validStatusKey 将状态字段限制在 VMM 服务 CLI 文档约定的范围内。
func validStatusKey(key string) bool {
	switch key {
	case "state", "auto_start", "substate", "start_type":
		return true
	case "user":
		return true
	default:
		return false
	}
}

// validStatusValue accepts only short printable ASCII tokens so status cannot inject terminal control sequences.
// validStatusValue 仅接受短 ASCII 可见字符令牌，防止状态内容注入终端控制序列。
func validStatusValue(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !isASCIIAlphaNumeric(character) && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

// validStatusValueForKey applies the narrow token grammar to ordinary fields and the account grammar to user.
// validStatusValueForKey 对普通字段应用严格令牌语法，对 user 应用账户语法。
func validStatusValueForKey(key string, value string) bool {
	if key == "user" {
		return validServiceUserValue(value)
	}
	return validStatusValue(value)
}
