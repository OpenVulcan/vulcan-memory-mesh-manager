// Package main provides the standalone vmmm command-line entry point and TUI launcher.
// main 包提供独立 vmmm 命令行入口以及 TUI 启动边界。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbletea/v2"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configedit"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/controller"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/download"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/fetch"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/i18n"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/install"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/manifest"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/platform"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/release"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/selfinstall"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/trust"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

var (
	// version is replaced by the release workflow with the signed manager version.
	// version 由发行工作流替换为带签名清单对应的管理器版本。
	version = "dev"
)

const (
	// defaultServiceName matches the controller's platform service identity.
	// defaultServiceName 与 controller 使用的平台服务身份保持一致。
	defaultServiceName = "VulcanMemoryMesh"

	// defaultOperationTimeout bounds non-interactive lifecycle commands.
	// defaultOperationTimeout 限制非交互生命周期命令的最长执行时间。
	defaultOperationTimeout = 2 * time.Minute
)

// commandEnvironment contains process I/O and the TUI hook so command dispatch stays testable.
// commandEnvironment 保存进程 I/O 与 TUI 启动钩子，使命令分派可以进行确定性测试。
type commandEnvironment struct {
	// stdin is the input stream used by the TUI and terminal detection.
	// stdin 是 TUI 与终端检测使用的输入流。
	stdin io.Reader
	// stdout receives user-visible command results.
	// stdout 接收用户可见的命令结果。
	stdout io.Writer
	// stderr receives diagnostics and progress messages.
	// stderr 接收诊断与进度消息。
	stderr io.Writer
	// isTerminal reports whether interactive terminal input and output are available.
	// isTerminal 报告是否同时具备交互式终端输入与输出。
	isTerminal func() bool
	// launchTUI starts the real TUI after the runtime has been constructed.
	// launchTUI 在运行时构造完成后启动真实 TUI。
	launchTUI func(context.Context, *runtimeContext, commandOptions, io.Reader, io.Writer) error
	// allowPrivilegeEscalation permits the production CLI to reopen its trusted system installation through sudo.
	// allowPrivilegeEscalation 允许正式 CLI 通过 sudo 重新打开受信任的系统安装。
	allowPrivilegeEscalation bool
}

// commandOptions contains global command-line settings shared by every subcommand.
// commandOptions 保存所有子命令共享的全局命令行设置。
type commandOptions struct {
	// EntryAction preserves the explicit interactive subcommand for TUI routing.
	// EntryAction 保留明确的交互子命令，供 TUI 选择入口。
	EntryAction string
	// StatePath is the explicit VMMM registration path.
	// StatePath 是明确的 VMMM 安装登记路径。
	StatePath string
	// ManagerRoot is the permanent root containing the manager executable.
	// ManagerRoot 是包含管理器可执行文件的永久根目录。
	ManagerRoot string
	// CacheRoot is the manager-owned download and extraction cache.
	// CacheRoot 是管理器拥有的下载与解包缓存目录。
	CacheRoot string
	// ProgramRoot, ConfigRoot, and DataRoot override first-install defaults.
	// ProgramRoot、ConfigRoot 与 DataRoot 覆盖首次安装默认路径。
	ProgramRoot string
	ConfigRoot  string
	DataRoot    string
	// ServiceName overrides the platform service name.
	// ServiceName 覆盖平台服务名称。
	ServiceName string
	// Language selects the TUI catalog.
	// Language 选择 TUI 语言目录。
	Language string
	// JSON requests machine-readable output for non-interactive commands.
	// JSON 请求非交互命令输出机器可读 JSON。
	JSON bool
}

// runtimeContext holds one real controller and the state-derived presentation snapshot.
// runtimeContext 保存一个真实 controller 以及由安装状态推导出的界面快照。
type runtimeContext struct {
	// controller owns network, installation, service, and PATH operations.
	// controller 负责网络、安装、服务与 PATH 操作。
	controller *controller.Controller
	// identity is the exact supported runtime platform mapping.
	// identity 是当前平台的精确受支持运行时映射。
	identity platform.Identity
	// options are the validated command settings used to construct the controller.
	// options 是构造 controller 时使用的已校验命令设置。
	options commandOptions
	// state is the durable VMM registration when one exists.
	// state 是存在时读取到的持久化 VMM 安装登记。
	state state.State
	// installed identifies whether state contains a valid VMM registration.
	// installed 标识 state 是否包含有效的 VMM 安装登记。
	installed bool
	// snapshot is the sanitized TUI and status summary.
	// snapshot 是脱敏后的 TUI 与状态摘要。
	snapshot tui.InstallationSnapshot
	// defaults contains first-install roots and baseline choices.
	// defaults 包含首次安装根目录与基础选择。
	defaults tui.InstallPlan
}

// defaultPaths describes platform-owned installation and control roots.
// defaultPaths 描述由平台管理的安装目录与控制目录。
type defaultPaths struct {
	// ProgramRoot contains the administrator-owned VMM package.
	// ProgramRoot 保存管理员持有的 VMM 程序包。
	ProgramRoot string
	// ConfigRoot and DataRoot become owned by the selected service account.
	// ConfigRoot 与 DataRoot 由选定的服务账户持有。
	ConfigRoot string
	DataRoot   string
	// StatePath is separate from service-writable data.
	// StatePath 与服务可写数据隔离。
	StatePath string
	// ManagerRoot and CacheRoot remain administrator-owned on Unix.
	// ManagerRoot 与 CacheRoot 在 Unix 上由管理员持有。
	ManagerRoot string
	CacheRoot   string
}

// main exits with the command dispatcher result.
// main 使用命令分派结果退出进程。
func main() {
	os.Exit(runCommand(os.Args[1:], productionEnvironment()))
}

// productionEnvironment binds the CLI to the process streams and real Bubble Tea launcher.
// productionEnvironment 将 CLI 绑定到进程流以及真实 Bubble Tea 启动器。
func productionEnvironment() commandEnvironment {
	return commandEnvironment{
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
		isTerminal: func() bool {
			return isCharacterDevice(os.Stdin) && isCharacterDevice(os.Stdout)
		},
		launchTUI:                launchTUI,
		allowPrivilegeEscalation: true,
	}
}

// isCharacterDevice detects the portable terminal signal exposed by os.File.Stat.
// isCharacterDevice 使用 os.File.Stat 暴露的可移植终端信号进行检测。
func isCharacterDevice(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// runCommand parses global options and dispatches one explicit command.
// runCommand 解析全局选项并分派一个明确的命令。
func runCommand(args []string, environment commandEnvironment) int {
	environment = normalizeEnvironment(environment)
	options, remaining, help, err := parseGlobalOptions(args, environment.stderr)
	if help {
		printUsage(environment.stdout)
		return 0
	}
	if err != nil {
		writeError(environment.stderr, err)
		return 2
	}
	if len(remaining) == 0 {
		if !environment.isTerminal() {
			printUsage(environment.stderr)
			writeError(environment.stderr, errors.New("interactive TUI requires a terminal; use an explicit non-interactive command"))
			return 2
		}
		return runInteractive(environment, options, args)
	}

	if remaining[0] == "version" {
		return runVersion(environment.stdout, options.JSON)
	}
	if remaining[0] == "help" || remaining[0] == "--help" || remaining[0] == "-h" {
		printUsage(environment.stdout)
		return 0
	}
	if remaining[0] == "install" || remaining[0] == "open" {
		if !environment.isTerminal() {
			writeError(environment.stderr, errors.New("install/open requires a terminal; pipe-free interactive configuration is intentional"))
			return 2
		}
		return runInteractive(environment, options, args)
	}

	if remaining[0] == "upgrade" || remaining[0] == "rollback" || (remaining[0] == "config" && len(remaining) > 1 && remaining[1] == "edit") {
		if !environment.isTerminal() {
			writeError(environment.stderr, errors.New("this command requires a terminal; use the TUI for package selection or configuration editing"))
			return 2
		}
		return runInteractive(environment, options, args)
	}
	// System registration and service actions share one administrator-owned state root.
	// 系统登记与服务操作共用一处管理员持有的状态根目录。
	switch remaining[0] {
	case "config", "doctor", "uninstall", "status", "start", "stop", "restart", "enable", "disable", "service", "path":
		if handled, code := relaunchPrivilegedInteractive(args, environment, options); handled {
			return code
		}
	}

	if remaining[0] == "config" {
		return runConfigCommand(remaining[1:], options, environment)
	}
	if remaining[0] == "doctor" {
		return runDoctor(options, environment)
	}
	if remaining[0] == "uninstall" {
		return runUninstall(remaining[1:], options, environment)
	}
	if remaining[0] == "status" || remaining[0] == "start" || remaining[0] == "stop" || remaining[0] == "restart" || remaining[0] == "enable" || remaining[0] == "disable" {
		return runLifecycleCommand(remaining[0], options, environment)
	}
	if remaining[0] == "service" {
		return runServiceCommand(remaining[1:], options, environment)
	}
	if remaining[0] == "path" {
		return runPathCommand(remaining[1:], options, environment)
	}

	writeError(environment.stderr, fmt.Errorf("unknown command %q", remaining[0]))
	printUsage(environment.stderr)
	return 2
}

// normalizeEnvironment fills nil test or embedding streams with safe process defaults.
// normalizeEnvironment 为测试或嵌入场景中的空流填充安全的进程默认值。
func normalizeEnvironment(environment commandEnvironment) commandEnvironment {
	if environment.stdin == nil {
		environment.stdin = os.Stdin
	}
	if environment.stdout == nil {
		environment.stdout = os.Stdout
	}
	if environment.stderr == nil {
		environment.stderr = os.Stderr
	}
	if environment.isTerminal == nil {
		environment.isTerminal = func() bool { return isCharacterDevice(os.Stdin) && isCharacterDevice(os.Stdout) }
	}
	if environment.launchTUI == nil {
		environment.launchTUI = launchTUI
	}
	return environment
}

// parseGlobalOptions consumes only options before the subcommand and returns help separately.
// parseGlobalOptions 只消费子命令前的选项，并单独返回帮助请求。
func parseGlobalOptions(args []string, output io.Writer) (commandOptions, []string, bool, error) {
	options := commandOptions{Language: string(i18n.SimplifiedChinese), ServiceName: defaultServiceName}
	flagSet := flag.NewFlagSet("vmmm", flag.ContinueOnError)
	flagSet.SetOutput(output)
	flagSet.StringVar(&options.StatePath, "state", "", "VMMM installation registration path")
	flagSet.StringVar(&options.ManagerRoot, "manager-root", "", "permanent VMMM manager root")
	flagSet.StringVar(&options.CacheRoot, "cache-root", "", "VMMM download cache root")
	flagSet.StringVar(&options.ProgramRoot, "program-root", "", "first-install VMM program root")
	flagSet.StringVar(&options.ConfigRoot, "config-root", "", "first-install VMM configuration root")
	flagSet.StringVar(&options.DataRoot, "data-root", "", "first-install VMM data root")
	flagSet.StringVar(&options.ServiceName, "service-name", defaultServiceName, "VMM service name")
	flagSet.StringVar(&options.Language, "language", string(i18n.SimplifiedChinese), "TUI language: zh or en")
	flagSet.BoolVar(&options.JSON, "json", false, "machine-readable output")
	if err := flagSet.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return options, nil, true, nil
		}
		return commandOptions{}, nil, false, err
	}
	if strings.TrimSpace(options.StatePath) == "" {
		options.StatePath = os.Getenv("VMMM_STATE_PATH")
	}
	return options, flagSet.Args(), false, nil
}

// runVersion writes the build identity without creating a controller or reading local state.
// runVersion 输出构建身份，不构造 controller，也不读取本地状态。
func runVersion(output io.Writer, machineReadable bool) int {
	if machineReadable {
		_ = json.NewEncoder(output).Encode(map[string]string{"product": "vmmm", "version": version})
		return 0
	}
	_, _ = fmt.Fprintf(output, "vmmm %s\n", version)
	return 0
}

// runInteractive constructs the real controller and enters the Bubble Tea model.
// runInteractive 构造真实 controller 并进入 Bubble Tea 模型。
func runInteractive(environment commandEnvironment, options commandOptions, args []string) int {
	if handled, code := relaunchPrivilegedInteractive(args, environment, options); handled {
		return code
	}
	managerRoot, err := ensurePermanentManager(options)
	if err != nil {
		writeError(environment.stderr, err)
		return 1
	}
	options.ManagerRoot = managerRoot
	if len(args) > 0 {
		options.EntryAction = args[0]
		if len(args) == 2 && args[0] == "config" && args[1] == "edit" {
			options.EntryAction = "edit"
		}
	}
	runtimeValue, err := newRuntime(options)
	if err != nil {
		writeError(environment.stderr, err)
		return 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := environment.launchTUI(ctx, runtimeValue, options, environment.stdin, environment.stdout); err != nil {
		writeError(environment.stderr, err)
		return 1
	}
	return 0
}

// launchTUI creates the localized model and binds it to the caller's terminal streams.
// launchTUI 创建本地化模型，并将其绑定到调用方终端流。
func launchTUI(ctx context.Context, runtimeValue *runtimeContext, options commandOptions, input io.Reader, output io.Writer) error {
	if runtimeValue == nil || runtimeValue.controller == nil {
		return errors.New("installation controller is unavailable")
	}
	language := i18n.Language(options.Language)
	if language != i18n.English && language != i18n.SimplifiedChinese {
		return fmt.Errorf("unsupported language %q; use zh or en", options.Language)
	}
	model := tui.NewModel(tui.ModelConfig{
		EntryAction: options.EntryAction,
		Controller:  runtimeValue.controller,
		Localizer:   tui.NewCatalogLocalizer(),
		Language:    tui.Language(language),
		Initial:     runtimeValue.snapshot,
		Defaults:    runtimeValue.defaults,
		Sources:     tui.DefaultSourceOptions(),
		Storage:     tui.DefaultStorageOptions(),
	})
	return tui.Run(model, tea.WithContext(ctx), tea.WithInput(input), tea.WithOutput(output))
}

// newRuntime resolves explicit roots, loads state, and constructs the fail-closed controller.
// newRuntime 解析明确根目录、读取状态，并构造失败即关闭的 controller。
func newRuntime(options commandOptions) (*runtimeContext, error) {
	identity, err := platform.Current()
	if err != nil {
		return nil, fmt.Errorf("current platform is unsupported: %w", err)
	}
	paths, err := platformDefaultPaths(runtime.GOOS)
	if err != nil {
		return nil, err
	}
	defaults := tui.InstallPlan{
		ProgramRoot: paths.ProgramRoot,
		ConfigRoot:  paths.ConfigRoot,
		DataRoot:    paths.DataRoot,
		ServiceMode: tui.ServiceModeForeground,
		AddToPath:   false,
	}
	// The current local account is a visible starting value; the TUI still requires explicit confirmation.
	// 当前本机账户仅作为可见初值；TUI 仍要求用户明确确认。
	if runtime.GOOS != "windows" {
		if current, lookupErr := user.Current(); lookupErr == nil {
			defaults.ServiceUser = current.Username
		}
		// sudo records the invoking local account; the TUI still requires confirmation.
		// sudo 记录发起提权的本机账户；TUI 仍要求明确确认。
		if runtime.GOOS != "windows" && os.Geteuid() == 0 {
			if invoking := strings.TrimSpace(os.Getenv("SUDO_USER")); invoking != "" {
				if selected, lookupErr := user.Lookup(invoking); lookupErr == nil {
					defaults.ServiceUser = selected.Username
				}
			}
		}
	}
	if options.ProgramRoot != "" {
		defaults.ProgramRoot = options.ProgramRoot
	}
	if options.ConfigRoot != "" {
		defaults.ConfigRoot = options.ConfigRoot
	}
	if options.DataRoot != "" {
		defaults.DataRoot = options.DataRoot
	}
	for name, value := range map[string]string{"program root": defaults.ProgramRoot, "config root": defaults.ConfigRoot, "data root": defaults.DataRoot} {
		absolute, err := filepath.Abs(value)
		if err != nil || !filepath.IsAbs(absolute) {
			return nil, fmt.Errorf("%s is invalid", name)
		}
		switch name {
		case "program root":
			defaults.ProgramRoot = filepath.Clean(absolute)
		case "config root":
			defaults.ConfigRoot = filepath.Clean(absolute)
		case "data root":
			defaults.DataRoot = filepath.Clean(absolute)
		}
	}
	statePath := options.StatePath
	if strings.TrimSpace(statePath) == "" {
		statePath = paths.StatePath
	}
	statePath, err = filepath.Abs(statePath)
	if err != nil || !filepath.IsAbs(statePath) {
		return nil, errors.New("state path is invalid")
	}
	statePath = filepath.Clean(statePath)
	managerRoot := options.ManagerRoot
	if managerRoot == "" {
		managerRoot, err = defaultManagerRoot()
		if err != nil {
			return nil, err
		}
	}
	managerRoot, err = filepath.Abs(managerRoot)
	if err != nil || !filepath.IsAbs(managerRoot) {
		return nil, errors.New("manager root is invalid")
	}
	cacheRoot := options.CacheRoot
	if cacheRoot == "" {
		cacheRoot = paths.CacheRoot
	}
	cacheRoot, err = filepath.Abs(cacheRoot)
	if err != nil || !filepath.IsAbs(cacheRoot) {
		return nil, errors.New("cache root is invalid")
	}

	loaded, installed, err := loadOptionalState(statePath)
	if err != nil {
		return nil, fmt.Errorf("installation could not be verified: registration is unreadable or invalid: %w", err)
	}
	if installed {
		defaults.ProgramRoot = loaded.Paths.ProgramRoot
		defaults.ConfigRoot = loaded.Paths.ConfigRoot
		defaults.DataRoot = loaded.Paths.DataRoot
		if loaded.Service.Name != "" {
			defaults.ServiceMode = tui.ServiceModeService
			defaults.AutoStart = loaded.Service.AutoStart
			if loaded.Service.User != "" {
				defaults.ServiceUser = loaded.Service.User
			}
		}
		defaults.AddToPath = loaded.PATH.Owner == state.PATHOwnerManager
	}
	controllerValue, err := controller.New(controller.Options{
		ManagerVersion: version,
		ManagerRoot:    managerRoot,
		StatePath:      statePath,
		CacheRoot:      cacheRoot,
		TrustKeys:      trust.VMMKeys(),
		ServiceName:    options.ServiceName,
		CredentialPath: filepath.Join(defaults.ConfigRoot, ".env"),
		Identity:       identity,
	})
	if err != nil {
		return nil, fmt.Errorf("create installation controller: %w", err)
	}
	snapshot := snapshotFromState(loaded, installed, identity, statePath)
	if !installed && install.HasProgramRemnants(defaults.ProgramRoot) {
		snapshot.Incomplete = true
		snapshot.IntegrityIssue = "unregistered-program-files"
		snapshot.ProgramRoot = defaults.ProgramRoot
		snapshot.ConfigRoot = defaults.ConfigRoot
		snapshot.DataRoot = defaults.DataRoot
	}
	if installed {
		ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
		liveSnapshot, snapshotErr := controllerValue.Snapshot(ctx)
		cancel()
		if snapshotErr != nil {
			return nil, fmt.Errorf("read installation snapshot: %w", snapshotErr)
		}
		snapshot = liveSnapshot
	}
	return &runtimeContext{controller: controllerValue, identity: identity, options: options, state: loaded, installed: installed, snapshot: snapshot, defaults: defaults}, nil
}

// defaultBaseRoot returns the Windows per-user root for the existing installation layout.
// defaultBaseRoot 返回 Windows 现有安装布局的用户根目录。
func defaultBaseRoot() (string, error) {
	configRoot, err := os.UserConfigDir()
	if err != nil {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return "", errors.New("user configuration root could not be resolved")
		}
		configRoot = filepath.Join(home, ".config")
	}
	return filepath.Join(configRoot, "VulcanMemoryMesh"), nil
}

// platformDefaultPaths keeps manager control state outside service-writable roots.
// platformDefaultPaths 将管理器控制状态与服务可写目录隔离。
func platformDefaultPaths(osName string) (defaultPaths, error) {
	switch osName {
	case "windows":
		baseRoot, err := defaultBaseRoot()
		if err != nil {
			return defaultPaths{}, err
		}
		return defaultPaths{
			ProgramRoot: filepath.Join(baseRoot, "vmm"),
			ConfigRoot:  filepath.Join(baseRoot, "config"),
			DataRoot:    filepath.Join(baseRoot, "data"),
			StatePath:   filepath.Join(baseRoot, "data", install.RegistrationFileName),
			ManagerRoot: filepath.Join(baseRoot, "manager"),
			CacheRoot:   filepath.Join(baseRoot, "cache"),
		}, nil
	case "linux":
		return defaultPaths{
			ProgramRoot: "/opt/vulcan-memory-mesh",
			ConfigRoot:  "/etc/vulcan-memory-mesh",
			DataRoot:    "/var/lib/vulcan-memory-mesh",
			StatePath:   "/var/lib/vmmm/installation.json",
			ManagerRoot: "/usr/local/lib/vmmm",
			CacheRoot:   "/var/cache/vmmm",
		}, nil
	case "darwin":
		return defaultPaths{
			ProgramRoot: "/Library/Application Support/VulcanMemoryMesh/program",
			ConfigRoot:  "/Library/Application Support/VulcanMemoryMesh/config",
			DataRoot:    "/Library/Application Support/VulcanMemoryMesh/data",
			StatePath:   "/Library/Application Support/VMMM/state/installation.json",
			ManagerRoot: "/Library/Application Support/VMMM/manager",
			CacheRoot:   "/Library/Caches/VMMM",
		}, nil
	default:
		return defaultPaths{}, fmt.Errorf("unsupported installation platform %q", osName)
	}
}

// defaultManagerRoot returns the trusted permanent directory for the manager executable.
// defaultManagerRoot 返回管理器可执行文件使用的可信永久目录。
func defaultManagerRoot() (string, error) {
	paths, err := platformDefaultPaths(runtime.GOOS)
	return paths.ManagerRoot, err
}

// ensurePermanentManager installs the authenticated manager before any TUI or PATH operation.
// ensurePermanentManager 在进入 TUI 或修改 PATH 前安装经过签名验证的管理器永久副本。
func ensurePermanentManager(options commandOptions) (string, error) {
	managerRoot := options.ManagerRoot
	if managerRoot == "" {
		var err error
		managerRoot, err = defaultManagerRoot()
		if err != nil {
			return "", err
		}
	}
	absoluteRoot, err := filepath.Abs(managerRoot)
	if err != nil || !filepath.IsAbs(absoluteRoot) {
		return "", errors.New("manager root is invalid")
	}
	managerRoot = filepath.Clean(absoluteRoot)

	currentExecutable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve current manager executable: %w", err)
	}
	currentExecutable, err = filepath.Abs(currentExecutable)
	if err != nil || !filepath.IsAbs(currentExecutable) {
		return "", errors.New("current manager executable path is invalid")
	}
	installer, err := selfinstall.New(selfinstall.Options{InstallRoot: managerRoot, CurrentExecutable: filepath.Clean(currentExecutable)})
	if err != nil {
		return "", fmt.Errorf("prepare permanent manager installation: %w", err)
	}
	existing, detectErr := installer.Detect()
	hasExisting := detectErr == nil
	if detectErr != nil && !errors.Is(detectErr, selfinstall.ErrNotInstalled) && !errors.Is(detectErr, selfinstall.ErrIncomplete) && !errors.Is(detectErr, selfinstall.ErrModified) {
		return "", fmt.Errorf("validate permanent manager installation: %w", detectErr)
	}
	if hasExisting && sameExecutablePath(currentExecutable, existing.ExecutablePath) {
		return managerRoot, nil
	}

	identity, err := platform.Current()
	if err != nil {
		return "", fmt.Errorf("current platform is unsupported: %w", err)
	}
	paths, err := platformDefaultPaths(runtime.GOOS)
	if err != nil {
		return "", err
	}
	cacheRoot := options.CacheRoot
	if cacheRoot == "" {
		cacheRoot = paths.CacheRoot
	}
	cacheRoot, err = filepath.Abs(cacheRoot)
	if err != nil || !filepath.IsAbs(cacheRoot) {
		return "", errors.New("cache root is invalid")
	}
	if err := os.MkdirAll(cacheRoot, 0o700); err != nil {
		return "", fmt.Errorf("prepare manager cache: %w", err)
	}

	source, err := managerBootstrapSource()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()
	releaseResult, err := release.Discover(ctx, release.Request{
		Product:   manifest.ProductVMMM,
		Selector:  release.Latest(),
		Source:    source,
		TrustKeys: trust.VMMMKeys(),
	})
	if err != nil {
		return "", fmt.Errorf("discover authenticated manager release: %w", err)
	}
	artifact, err := releaseResult.Manifest.FindArtifact(manifest.ProductVMMM, identity.PlatformID)
	if err != nil {
		return "", fmt.Errorf("select manager artifact: %w", err)
	}
	stageRoot, err := os.MkdirTemp(cacheRoot, ".vmmm-manager-")
	if err != nil {
		return "", fmt.Errorf("prepare manager staging directory: %w", err)
	}
	defer os.RemoveAll(stageRoot)
	stagingPath := filepath.Join(stageRoot, artifact.Filename)
	fetched, err := fetch.Fetch(ctx, fetch.Request{
		Source:      source,
		Manifest:    releaseResult.Manifest,
		Product:     manifest.ProductVMMM,
		Repository:  releaseResult.Repository,
		Platform:    identity.PlatformID,
		StagingPath: stagingPath,
	})
	if err != nil {
		return "", fmt.Errorf("download authenticated manager artifact: %w", err)
	}
	metadata := selfinstall.Release{
		Version:  releaseResult.Tag,
		Commit:   releaseResult.Commit,
		Platform: identity.PlatformID,
		Filename: artifact.Filename,
		SHA256:   artifact.SHA256,
		Size:     artifact.Bytes,
	}
	if hasExisting {
		comparison, err := compareManagerReleaseTags(metadata.Version, existing.Current.Version)
		if err != nil {
			return "", fmt.Errorf("compare manager release identities: %w", err)
		}
		if comparison < 0 {
			return "", fmt.Errorf("authenticated manager release %q is older than installed release %q", metadata.Version, existing.Current.Version)
		}
		if comparison == 0 {
			if !sameManagerRelease(existing.Current, metadata) {
				return "", errors.New("authenticated manager release has a conflicting identity for the installed version")
			}
			return managerRoot, nil
		}
		if sameExecutablePath(currentExecutable, existing.ExecutablePath) {
			return "", errors.New("manager update cannot replace the running permanent executable; restart from the bootstrap or installed manager")
		}
		if _, err := installer.Upgrade(fetched.Path, metadata); err != nil {
			return "", fmt.Errorf("upgrade permanent manager executable: %w", err)
		}
		return managerRoot, nil
	}
	if _, err := installer.Install(fetched.Path, metadata); err != nil {
		return "", fmt.Errorf("install permanent manager executable: %w", err)
	}
	return managerRoot, nil
}

// sameExecutablePath identifies the running image and managed image without trusting string casing alone.
// sameExecutablePath 通过文件身份确认运行中的映像与受管映像，避免仅依赖路径字符串大小写。
func sameExecutablePath(left string, right string) bool {
	if left == "" || right == "" {
		return false
	}
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	if leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo) {
		return true
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

// sameManagerRelease compares every authenticated field persisted by self-installation.
// sameManagerRelease 比较自安装记录持久化的全部已认证字段。
func sameManagerRelease(left selfinstall.Release, right selfinstall.Release) bool {
	return left.Version == right.Version && left.Commit == right.Commit && left.Platform == right.Platform && left.Filename == right.Filename && left.SHA256 == right.SHA256 && left.Size == right.Size
}

// compareManagerReleaseTags compares vMAJOR.MINOR.PATCH cores and rejects ambiguous tags.
// compareManagerReleaseTags 比较 vMAJOR.MINOR.PATCH 数字核心，并拒绝无法安全排序的标签。
func compareManagerReleaseTags(candidate string, installed string) (int, error) {
	parse := func(value string) ([3]int64, error) {
		var result [3]int64
		if !strings.HasPrefix(value, "v") {
			return result, fmt.Errorf("release tag %q is not semantic", value)
		}
		core := strings.TrimPrefix(value, "v")
		if separator := strings.IndexByte(core, '-'); separator >= 0 {
			core = core[:separator]
		}
		parts := strings.Split(core, ".")
		if len(parts) != len(result) {
			return result, fmt.Errorf("release tag %q is not semantic", value)
		}
		for index, part := range parts {
			if part == "" || (len(part) > 1 && part[0] == '0') {
				return result, fmt.Errorf("release tag %q is not semantic", value)
			}
			parsed, err := strconv.ParseInt(part, 10, 64)
			if err != nil || parsed < 0 {
				return result, fmt.Errorf("release tag %q is not semantic", value)
			}
			result[index] = parsed
		}
		return result, nil
	}
	candidateParts, err := parse(candidate)
	if err != nil {
		return 0, err
	}
	installedParts, err := parse(installed)
	if err != nil {
		return 0, err
	}
	for index := range candidateParts {
		if candidateParts[index] > installedParts[index] {
			return 1, nil
		}
		if candidateParts[index] < installedParts[index] {
			return -1, nil
		}
	}
	return 0, nil
}

// managerBootstrapSource maps the bootstrap source contract to the signed release source type.
// managerBootstrapSource 将引导脚本的来源契约映射为签名发布流程使用的来源类型。
func managerBootstrapSource() (download.Source, error) {
	selected := strings.TrimSpace(os.Getenv("VMMM_BOOTSTRAP_SOURCE"))
	prefix := strings.TrimSpace(os.Getenv("VMMM_BOOTSTRAP_PROXY_PREFIX"))
	if selected == "" {
		if prefix != "" {
			return download.Source{}, errors.New("bootstrap proxy prefix requires an explicit source")
		}
		return builtInDownloadSource(download.SourceIDGitHubOfficial)
	}
	if selected == "custom" {
		if prefix == "" {
			return download.Source{}, errors.New("custom bootstrap source requires VMMM_BOOTSTRAP_PROXY_PREFIX")
		}
		return download.NewCustomProxy(prefix)
	}
	if prefix != "" {
		return download.Source{}, errors.New("built-in bootstrap source cannot use a custom proxy prefix")
	}
	sourceID := map[string]download.SourceID{
		"official":     download.SourceIDGitHubOfficial,
		"ghproxy-net":  download.SourceIDGhproxyNet,
		"gh-proxy-org": download.SourceIDGhProxyOrg,
		"ghfast-top":   download.SourceIDGhfastTop,
	}[selected]
	if sourceID == "" {
		return download.Source{}, fmt.Errorf("unsupported bootstrap source %q", selected)
	}
	return builtInDownloadSource(sourceID)
}

// builtInDownloadSource resolves one source from the repository's explicit allowlist.
// builtInDownloadSource 从仓库明确维护的来源白名单中解析一个内置来源。
func builtInDownloadSource(id download.SourceID) (download.Source, error) {
	for _, source := range download.DefaultSources() {
		if source.ID == id {
			return source, nil
		}
	}
	return download.Source{}, fmt.Errorf("built-in download source %q is unavailable", id)
}

// loadOptionalState distinguishes a missing registration from a malformed one.
// loadOptionalState 区分缺失登记与损坏登记。
func loadOptionalState(path string) (state.State, bool, error) {
	loaded, err := state.Load(path)
	if err == nil {
		return loaded, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return state.State{}, false, nil
	}
	return state.State{}, false, fmt.Errorf("load VMM installation state: %w", err)
}

// snapshotFromState converts durable state into a secret-free TUI summary.
// snapshotFromState 将持久化状态转换为不含秘密的 TUI 摘要。
func snapshotFromState(loaded state.State, installed bool, identity platform.Identity, _ string) tui.InstallationSnapshot {
	if !installed {
		return tui.InstallationSnapshot{ServiceMode: tui.ServiceModeForeground}
	}
	snapshot := tui.InstallationSnapshot{
		Installed:      true,
		ManagerVersion: loaded.ManagerVersion,
		VMMVersion:     loaded.VMM.Tag,
		SourceID:       loaded.DownloadSource.ID,
		SourcePrefix:   loaded.DownloadSource.CustomPrefix,
		ProgramRoot:    loaded.Paths.ProgramRoot,
		ConfigRoot:     loaded.Paths.ConfigRoot,
		DataRoot:       loaded.Paths.DataRoot,
		ServiceMode:    tui.ServiceModeForeground,
		AutoStart:      loaded.Service.AutoStart,
		PathEnabled:    loaded.PATH.Owner == state.PATHOwnerManager,
		LastValidation: loaded.ConfigValidatedAt,
	}
	if loaded.Service.Name != "" {
		snapshot.ServiceMode = tui.ServiceModeService
		snapshot.ServiceState = loaded.Service.Name
	}
	configPath := loaded.Paths.ConfigRoot
	if info, err := os.Stat(configPath); err == nil && info.IsDir() {
		configPath = filepath.Join(configPath, install.UserConfigFileName)
	}
	if data, err := os.ReadFile(configPath); err == nil {
		if draft, parseErr := configedit.Parse(data); parseErr == nil {
			if value, getErr := draft.Get("storage.mode"); getErr == nil {
				snapshot.Storage = tui.StorageMode(value.Value)
			}
		}
	}
	if identity.VMMExecutablePath == "" {
		snapshot.ServiceState = "installed"
	}
	return snapshot
}

// runLifecycleCommand maps one top-level lifecycle action to the controller contract.
// runLifecycleCommand 将一个顶层生命周期动作映射到 controller 契约。
func runLifecycleCommand(action string, options commandOptions, environment commandEnvironment) int {
	runtimeValue, err := newRuntime(options)
	if err != nil {
		writeError(environment.stderr, err)
		return 1
	}
	if !runtimeValue.installed {
		writeError(environment.stderr, errors.New("VMM is not installed; run vmmm install in a terminal"))
		return 1
	}
	request := tui.OperationRequest{Kind: tui.OperationService, TargetMode: runtimeValue.snapshot.ServiceMode, ServiceAction: tui.ServiceActionStatus}
	switch action {
	case "status":
		request.Kind = tui.OperationRefresh
	case "start":
		request.ServiceAction = tui.ServiceActionStart
	case "stop":
		request.ServiceAction = tui.ServiceActionStop
	case "restart":
		request.ServiceAction = tui.ServiceActionRestart
	case "enable":
		request.ServiceAction = tui.ServiceActionEnable
	case "disable":
		request.ServiceAction = tui.ServiceActionDisable
	default:
		writeError(environment.stderr, fmt.Errorf("unsupported lifecycle action %q", action))
		return 2
	}
	return executeControllerOperation(request, options, runtimeValue, environment)
}

// runServiceCommand validates a service subcommand before dispatching lifecycle work.
// runServiceCommand 校验服务子命令后再分派生命周期操作。
func runServiceCommand(args []string, options commandOptions, environment commandEnvironment) int {
	if len(args) == 0 {
		writeError(environment.stderr, errors.New("service requires one of install, uninstall, start, stop, restart, enable, disable, status"))
		return 2
	}
	requestAction := map[string]string{"install": "install", "uninstall": "uninstall", "start": "start", "stop": "stop", "restart": "restart", "enable": "enable", "disable": "disable", "status": "status"}
	action, ok := requestAction[args[0]]
	if !ok {
		writeError(environment.stderr, fmt.Errorf("unknown service action %q", args[0]))
		return 2
	}
	serviceUser := ""
	if action == "install" {
		flags := flag.NewFlagSet("vmmm service install", flag.ContinueOnError)
		flags.SetOutput(environment.stderr)
		flags.StringVar(&serviceUser, "user", "", "explicit local account for Linux or macOS system service")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			writeError(environment.stderr, errors.New("service install accepts only --user <account>"))
			return 2
		}
		if runtime.GOOS == "windows" && serviceUser != "" {
			writeError(environment.stderr, errors.New("--user is supported only for Linux or macOS services"))
			return 2
		}
	} else if len(args) != 1 {
		writeError(environment.stderr, errors.New("this service action does not accept extra arguments"))
		return 2
	}
	runtimeValue, err := newRuntime(options)
	if err != nil {
		writeError(environment.stderr, err)
		return 1
	}
	if !runtimeValue.installed {
		writeError(environment.stderr, errors.New("VMM is not installed; service actions are unavailable"))
		return 1
	}
	request := tui.OperationRequest{Kind: tui.OperationService, TargetMode: tui.ServiceModeService, ServiceAction: tui.ServiceActionStatus}
	switch action {
	case "install":
		request.ServiceAction = tui.ServiceActionInstall
		request.Plan.AutoStart = runtimeValue.state.Service.AutoStart
		request.Plan.ServiceUser = serviceUser
		if runtime.GOOS != "windows" && request.Plan.ServiceUser == "" {
			request.Plan.ServiceUser = runtimeValue.state.Service.User
			if request.Plan.ServiceUser == "" {
				writeError(environment.stderr, errors.New("service install requires --user <account> on Linux or macOS"))
				return 2
			}
		}
	case "uninstall":
		request.ServiceAction = tui.ServiceActionUninstall
	case "start":
		request.ServiceAction = tui.ServiceActionStart
	case "stop":
		request.ServiceAction = tui.ServiceActionStop
	case "restart":
		request.ServiceAction = tui.ServiceActionRestart
	case "enable":
		request.ServiceAction = tui.ServiceActionEnable
	case "disable":
		request.ServiceAction = tui.ServiceActionDisable
	case "status":
		request.ServiceAction = tui.ServiceActionStatus
	}
	return executeControllerOperation(request, options, runtimeValue, environment)
}

// runPathCommand applies one explicit manager PATH choice through the controller.
// runPathCommand 通过 controller 应用一个明确的管理器 PATH 选择。
func runPathCommand(args []string, options commandOptions, environment commandEnvironment) int {
	if len(args) != 1 || (args[0] != "enable" && args[0] != "disable") {
		writeError(environment.stderr, errors.New("path requires enable or disable"))
		return 2
	}
	runtimeValue, err := newRuntime(options)
	if err != nil {
		writeError(environment.stderr, err)
		return 1
	}
	if !runtimeValue.installed {
		writeError(environment.stderr, errors.New("VMM is not installed; PATH management is unavailable"))
		return 1
	}
	request := tui.OperationRequest{Kind: tui.OperationPath, AddToPath: args[0] == "enable"}
	return executeControllerOperation(request, options, runtimeValue, environment)
}

// runConfigCommand exposes schema, validation, and masked effective fields without writing secrets.
// runConfigCommand 提供 schema、校验与脱敏有效字段查询，并且不写入秘密。
func runConfigCommand(args []string, options commandOptions, environment commandEnvironment) int {
	if len(args) != 1 || (args[0] != "schema" && args[0] != "validate" && args[0] != "show-effective" && args[0] != "edit") {
		writeError(environment.stderr, errors.New("config requires schema, validate, show-effective, or edit"))
		return 2
	}
	if args[0] == "edit" {
		if !environment.isTerminal() {
			writeError(environment.stderr, errors.New("config edit requires a terminal"))
			return 2
		}
		return runInteractive(environment, options, []string{"config", "edit"})
	}
	runtimeValue, err := newRuntime(options)
	if err != nil {
		writeError(environment.stderr, err)
		return 1
	}
	if !runtimeValue.installed {
		writeError(environment.stderr, errors.New("VMM is not installed; configuration commands are unavailable"))
		return 1
	}
	if issue := install.FilesIntact(runtimeValue.state); issue != "" {
		writeError(environment.stderr, fmt.Errorf("VMM installation is incomplete (%s); reinstall before running configuration commands", issue))
		return 1
	}
	binaryPath := filepath.Join(runtimeValue.state.Paths.ProgramRoot, filepath.FromSlash(runtimeValue.identity.VMMExecutablePath))
	bridge, err := configbridge.New(binaryPath, runtimeValue.state.Paths.ConfigRoot)
	if err != nil {
		writeError(environment.stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()
	switch args[0] {
	case "schema":
		result, err := bridge.Schema(ctx)
		if err != nil {
			writeError(environment.stderr, err)
			return 1
		}
		if options.JSON {
			return encodeJSON(environment.stdout, result)
		}
		for _, field := range result.Fields {
			_, _ = fmt.Fprintf(environment.stdout, "%s\t%s\n", field.Path, field.Type)
		}
		return 0
	case "validate":
		result, err := runtimeValue.controller.ValidateInstalled(ctx)
		if err != nil {
			writeError(environment.stderr, err)
			return 1
		}
		if options.JSON {
			if code := encodeJSON(environment.stdout, result); code != 0 {
				return code
			}
		} else {
			if result.Valid {
				_, _ = fmt.Fprintln(environment.stdout, "valid")
			} else {
				_, _ = fmt.Fprintln(environment.stdout, "invalid")
				for _, item := range result.Errors {
					_, _ = fmt.Fprintf(environment.stdout, "%s: %s\n", item.Path, item.Message)
				}
			}
		}
		if !result.Valid {
			return 1
		}
		return 0
	case "show-effective":
		result, err := bridge.Effective(ctx)
		if err != nil {
			writeError(environment.stderr, err)
			return 1
		}
		if options.JSON {
			return encodeJSON(environment.stdout, result)
		}
		encoder := json.NewEncoder(environment.stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return 1
		}
		return 0
	}
	return 2
}

// runDoctor combines durable-state, lifecycle, and configuration checks into one safe report.
// runDoctor 将持久化状态、生命周期与配置检查组合成一个安全报告。
func runDoctor(options commandOptions, environment commandEnvironment) int {
	runtimeValue, err := newRuntime(options)
	if err != nil {
		writeError(environment.stderr, err)
		return 1
	}
	if !runtimeValue.installed {
		writeError(environment.stderr, errors.New("VMM is not installed"))
		return 1
	}
	result := struct {
		Installed  bool                          `json:"installed"`
		Snapshot   tui.InstallationSnapshot      `json:"snapshot"`
		Validation configbridge.ValidationResult `json:"validation"`
		Health     configbridge.HealthResult     `json:"health"`
	}{Installed: runtimeValue.snapshot.Installed, Snapshot: runtimeValue.snapshot}
	if runtimeValue.snapshot.Incomplete {
		if options.JSON {
			if code := encodeJSON(environment.stdout, result); code != 0 {
				return code
			}
		} else {
			_, _ = fmt.Fprintf(environment.stdout, "installed=false\nincomplete=true\nreason=%s\n", runtimeValue.snapshot.IntegrityIssue)
		}
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()
	validation := configbridge.ValidationResult{}
	binaryPath := filepath.Join(runtimeValue.state.Paths.ProgramRoot, filepath.FromSlash(runtimeValue.identity.VMMExecutablePath))
	bridge, err := configbridge.New(binaryPath, runtimeValue.state.Paths.ConfigRoot)
	if err == nil {
		validation, err = runtimeValue.controller.ValidateInstalled(ctx)
	}
	if err != nil {
		writeError(environment.stderr, err)
		return 1
	}
	result.Validation = validation
	result.Snapshot, err = runtimeValue.controller.Snapshot(ctx)
	if err != nil {
		writeError(environment.stderr, err)
		return 1
	}
	result.Installed = result.Snapshot.Installed
	result.Health, err = bridge.Health(ctx)
	if err != nil {
		writeError(environment.stderr, err)
		return 1
	}
	valid := result.Installed && result.Validation.Valid && result.Health.Class == "ok"
	if options.JSON {
		if code := encodeJSON(environment.stdout, result); code != 0 {
			return code
		}
		return boolExit(valid)
	}
	_, _ = fmt.Fprintf(environment.stdout, "installed=%t\n", result.Installed)
	_, _ = fmt.Fprintf(environment.stdout, "vmm=%s\n", result.Snapshot.VMMVersion)
	_, _ = fmt.Fprintf(environment.stdout, "config=%s\n", result.Snapshot.ConfigRoot)
	_, _ = fmt.Fprintf(environment.stdout, "valid=%t\n", result.Validation.Valid)
	_, _ = fmt.Fprintf(environment.stdout, "health=%s\n", result.Health.Class)
	return boolExit(valid)
}

// runUninstall executes a data-preserving uninstall unless explicit removal flags are supplied.
// runUninstall 默认执行保留配置与数据的卸载，只有显式参数才删除它们。
func runUninstall(args []string, options commandOptions, environment commandEnvironment) int {
	flagSet := flag.NewFlagSet("vmmm uninstall", flag.ContinueOnError)
	flagSet.SetOutput(environment.stderr)
	removeService := flagSet.Bool("remove-service", false, "remove the registered VMM service")
	removePath := flagSet.Bool("remove-path", false, "remove the manager-owned PATH entry")
	removeConfig := flagSet.Bool("remove-config", false, "remove the VMM configuration root")
	removeData := flagSet.Bool("remove-data", false, "remove the VMM data root")
	if err := flagSet.Parse(args); err != nil {
		return 2
	}
	if flagSet.NArg() != 0 {
		writeError(environment.stderr, errors.New("uninstall does not accept positional arguments"))
		return 2
	}
	runtimeValue, err := newRuntime(options)
	if err != nil {
		writeError(environment.stderr, err)
		return 1
	}
	if !runtimeValue.installed {
		writeError(environment.stderr, errors.New("VMM is not installed"))
		return 1
	}
	request := tui.OperationRequest{Kind: tui.OperationUninstall, Uninstall: tui.UninstallOptions{RemoveService: *removeService, KeepConfig: !*removeConfig, KeepData: !*removeData, RemovePath: *removePath}}
	return executeControllerOperation(request, options, runtimeValue, environment)
}

// executeControllerOperation drains the controller stream and returns a truthful process exit code.
// executeControllerOperation 消费 controller 事件流，并返回真实的进程退出码。
func executeControllerOperation(request tui.OperationRequest, options commandOptions, runtimeValue *runtimeContext, environment commandEnvironment) int {
	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()
	events, err := runtimeValue.controller.Start(ctx, request)
	if err != nil {
		writeError(environment.stderr, err)
		return 1
	}
	var last tui.OperationEvent
	var snapshot *tui.InstallationSnapshot
	terminal := false
	for event := range events {
		last = event
		if event.Snapshot != nil {
			snapshot = event.Snapshot
		}
		if !options.JSON && event.Progress.Message != "" {
			_, _ = fmt.Fprintln(environment.stderr, event.Progress.Message)
		}
		if event.Kind == tui.OperationEventCompleted || event.Kind == tui.OperationEventFailed || event.Kind == tui.OperationEventCancelled {
			terminal = true
		}
	}
	if !terminal {
		writeError(environment.stderr, errors.New("controller operation ended without a terminal result"))
		return 1
	}
	if last.Kind == tui.OperationEventFailed {
		writeError(environment.stderr, errors.New(nonEmpty(last.Message, "operation failed")))
		return 1
	}
	if last.Kind == tui.OperationEventCancelled {
		writeError(environment.stderr, errors.New("operation cancelled"))
		return 1
	}
	// The terminal event carries only the outcome; retain the snapshot delivered by the preceding progress event.
	// 结束事件只携带操作结果；保留此前进度事件携带的安装快照，供命令行报告完整状态。
	last.Snapshot = snapshot
	complete := snapshot == nil || !snapshot.Incomplete
	if options.JSON {
		if code := encodeJSON(environment.stdout, last); code != 0 {
			return code
		}
		return boolExit(complete)
	}
	if last.Snapshot != nil {
		_, _ = fmt.Fprintf(environment.stdout, "installed=%t\n", last.Snapshot.Installed)
		_, _ = fmt.Fprintf(environment.stdout, "running=%t\n", last.Snapshot.Running)
		_, _ = fmt.Fprintf(environment.stdout, "service_mode=%s\n", last.Snapshot.ServiceMode)
		if last.Snapshot.Incomplete {
			_, _ = fmt.Fprintf(environment.stdout, "incomplete=true\nreason=%s\n", last.Snapshot.IntegrityIssue)
		}
	} else {
		_, _ = fmt.Fprintln(environment.stdout, nonEmpty(last.Message, "operation completed"))
	}
	return boolExit(complete)
}

// encodeJSON writes one machine-readable value and reports output failures.
// encodeJSON 写出一个机器可读值，并报告输出失败。
func encodeJSON(output io.Writer, value any) int {
	if err := json.NewEncoder(output).Encode(value); err != nil {
		return 1
	}
	return 0
}

// boolExit converts a validation boolean into the conventional command exit code.
// boolExit 将校验布尔值转换为约定的命令退出码。
func boolExit(valid bool) int {
	if valid {
		return 0
	}
	return 1
}

// nonEmpty chooses a stable fallback for empty controller messages.
// nonEmpty 为为空的 controller 消息选择稳定的后备文本。
func nonEmpty(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

// writeError writes one normalized diagnostic line without exposing multiline child output.
// writeError 写出一行规范化诊断，避免暴露子进程多行原始输出。
func writeError(output io.Writer, err error) {
	if err == nil {
		return
	}
	message := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(err.Error())
	_, _ = fmt.Fprintf(output, "vmmm: %s\n", strings.TrimSpace(message))
}

// printUsage documents the stable non-interactive command surface and terminal boundary.
// printUsage 文档化稳定的非交互命令面与终端边界。
func printUsage(output io.Writer) {
	_, _ = fmt.Fprintln(output, `vmmm - Vulcan Memory Mesh manager

Usage:
  vmmm                         Open the TUI when stdin/stdout are terminals.
  vmmm install|open            Open the installation and configuration TUI.
  vmmm status                  Show installed VMM status.
  vmmm start|stop|restart      Control the configured foreground/service runtime.
  vmmm enable|disable          Enable or disable service auto-start.
  vmmm service <action>        install, uninstall, start, stop, restart, enable, disable, status
  vmmm service install --user ACCOUNT  Select a Linux/macOS system service account.
  vmmm config <action>         schema, validate, show-effective, edit
  vmmm path enable|disable     Manage the manager-owned PATH entry.
  vmmm doctor                  Validate state and the active VMM configuration.
  vmmm uninstall               Remove program files; keep config/data unless explicitly removed.
  vmmm upgrade|rollback        Open the TUI package selection flow.
  vmmm version                 Print the manager version.

Global options must appear before the subcommand:
  --state PATH --manager-root PATH --cache-root PATH
  --program-root PATH --config-root PATH --data-root PATH
  --service-name NAME --language zh|en --json`)
}

// compile-time assertion keeps the command's controller adapter aligned with tui.Controller.
// 编译期断言确保命令使用的 controller 适配器持续符合 tui.Controller。
var _ tui.Controller = (*controller.Controller)(nil)

// keep runtime referenced on every supported build while documenting the OS-dependent base choice.
// 保持 runtime 在所有受支持构建中被引用，并明确操作系统相关的基础路径选择。
