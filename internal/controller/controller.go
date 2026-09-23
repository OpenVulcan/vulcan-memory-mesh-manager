// Package controller coordinates the real VMMM download, configuration, and lifecycle operations.
// controller 包负责编排 VMMM 的真实下载、配置、安装以及运行生命周期操作。
//
// The package is the only system boundary used by the TUI; it never reports success
// until the delegated operation has completed and its durable state has been checked.
// 本包是 TUI 使用的唯一系统边界；只有委托操作完成并检查持久化状态后才会报告成功。
package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/archive"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configedit"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configflow"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/credentials"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/download"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/fetch"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/install"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/manifest"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/pathctl"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/platform"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/processctl"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/providerwizard"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/release"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/service"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
	"gopkg.in/yaml.v3"
)

const (
	// defaultServiceName is the stable name understood by VMM's service command.
	// defaultServiceName 是 VMM 服务命令理解的稳定服务名称。
	defaultServiceName = "VulcanMemoryMesh"

	// defaultConfigFileName is the user overlay written below an explicit config root.
	// defaultConfigFileName 是写入显式配置根目录的用户覆盖文件名。
	defaultConfigFileName = "config.yaml"

	// pathRecordFileName retains platform-specific PATH metadata that state.State cannot represent.
	// pathRecordFileName 保存 state.State 无法表达的平台 PATH 细节。
	pathRecordFileName = ".vmmm-path-record.json"

	// maxConfigBytes bounds the configuration read before YAML editing begins.
	// maxConfigBytes 限制进入 YAML 编辑器之前读取的配置大小。
	maxConfigBytes int64 = 64 << 20

	// maxDiagnosticBytes prevents untrusted runtime diagnostics from filling a TUI event.
	// maxDiagnosticBytes 防止不可信运行时诊断填满 TUI 事件。
	maxDiagnosticBytes = 512
)

var (
	// ErrDamagedServiceControl prevents executing damaged files to manage an existing native service.
	// ErrDamagedServiceControl 阻止使用损坏文件控制现有系统服务，要求先恢复已验证的程序包。
	ErrDamagedServiceControl = errors.New("restore the verified VMM package at its registered program root before repairing this service")
	// ErrRuntimeNotHealthy distinguishes readiness failure from successful process creation.
	// ErrRuntimeNotHealthy 将就绪失败与进程创建成功区分开。
	ErrRuntimeNotHealthy = errors.New("VMM runtime did not become healthy")
	// ErrNoStagedPackage means the user tried to install without completing package staging.
	// ErrNoStagedPackage 表示用户未完成安装包暂存就请求安装。
	ErrNoStagedPackage = errors.New("no verified VMM package is staged")

	// ErrProcessControlUnavailable means foreground lifecycle control was not configured.
	// ErrProcessControlUnavailable 表示没有配置前台进程生命周期控制器。
	ErrProcessControlUnavailable = errors.New("foreground process control is unavailable")

	// ErrPathRecordUnavailable means manager-owned PATH metadata cannot be safely recovered.
	// ErrPathRecordUnavailable 表示无法安全恢复管理器拥有的 PATH 元数据。
	ErrPathRecordUnavailable = errors.New("manager PATH record is unavailable")
)

// ServiceClient is the narrow service adapter used by the controller.
// ServiceClient 是 controller 使用的最小服务适配器接口。
type ServiceClient interface {
	// Install registers one VMM service with its explicit configuration and boot policy.
	// Install 使用显式配置路径和自动启动策略注册 VMM 服务。
	Install(context.Context, string, string, string, bool) error
	// Uninstall removes one existing VMM service registration.
	// Uninstall 删除一个已有的 VMM 服务注册。
	Uninstall(context.Context, string) error
	// Start starts one registered VMM service.
	// Start 启动一个已经注册的 VMM 服务。
	Start(context.Context, string) error
	// Stop stops one running VMM service.
	// Stop 停止一个正在运行的 VMM 服务。
	Stop(context.Context, string) error
	// Restart restarts one registered VMM service.
	// Restart 重启一个已经注册的 VMM 服务。
	Restart(context.Context, string) error
	// Enable enables automatic startup for one service.
	// Enable 开启一个服务的自动启动。
	Enable(context.Context, string) error
	// Disable disables automatic startup while retaining manual start.
	// Disable 关闭自动启动但保留手动启动能力。
	Disable(context.Context, string) error
	// GetStatus reads the service manager's bounded status protocol.
	// GetStatus 读取服务管理器的有界状态协议。
	GetStatus(context.Context, string) (service.Status, error)
}

// ProcessStatus is the bounded state returned by a foreground process adapter.
// ProcessStatus 是前台进程适配器返回的有界状态。
type ProcessStatus struct {
	// Running reports whether the tracked VMM process is alive.
	// Running 表示被跟踪的 VMM 进程是否仍然存活。
	Running bool
}

// ProcessController controls VMM when the user selects foreground mode.
// ProcessController 在用户选择前台模式时控制 VMM。
type ProcessController interface {
	// Start launches VMM with the explicit configuration root.
	// Start 使用显式配置根目录启动 VMM。
	Start(context.Context, string, string) error
	// Stop terminates the foreground VMM process.
	// Stop 终止前台 VMM 进程。
	Stop(context.Context, string) error
	// Restart replaces the foreground VMM process.
	// Restart 替换前台 VMM 进程。
	Restart(context.Context, string, string) error
	// Status returns the tracked foreground process state.
	// Status 返回被跟踪的前台进程状态。
	Status(context.Context, string) (ProcessStatus, error)
}

// processConfigBinder lets the verified default adapter recover a persisted process after a manager restart.
// processConfigBinder 让默认的已验证适配器在管理器重启后恢复持久化进程所需的配置根目录。
type processConfigBinder interface {
	Bind(string, string)
}

// PathClient applies and reverses manager-owned user PATH changes.
// PathClient 应用和撤销管理器拥有的用户 PATH 变更。
type PathClient interface {
	// Install adds one manager directory or command link and returns exact reversal metadata.
	// Install 添加管理器目录或命令链接并返回精确撤销元数据。
	Install(pathctl.Options) (pathctl.Record, error)
	// Remove reverses a previously returned record only when ownership checks pass.
	// Remove 仅在所有权检查通过时撤销之前返回的记录。
	Remove(pathctl.Record) error
}

// ServiceFactory constructs a service adapter for an absolute VMM executable.
// ServiceFactory 为绝对 VMM 可执行文件构造服务适配器。
type ServiceFactory func(string) (ServiceClient, error)

// PathFactory constructs the platform PATH adapter.
// PathFactory 构造平台 PATH 适配器。
type PathFactory func() PathClient

// servicePathCheck identifies one path that the selected service account must access.
// servicePathCheck 标识选定服务账户必须访问的一个路径。
//
// Directory paths are checked for write access because VMM may create or update its
// local database there; existing files are checked for read access by the Unix adapter.
// 目录路径检查写权限，因为 VMM 可能在其中创建或更新本地数据库；现有文件由 Unix
// 适配器检查读取权限。
type servicePathCheck struct {
	// path is an absolute configuration, data, database, or credential path.
	// path 是绝对配置、数据、数据库或凭据路径。
	path string
	// writable requests directory write access when the path already exists as a directory.
	// writable 要求路径已存在且为目录时具备写权限。
	writable bool
	// rootOwned requires a program path to be owned by root and kept unwritable by the service account.
	// rootOwned 要求程序路径由 root 拥有，且服务账户不得写入。
	rootOwned bool
}

// ProbeFunc is the injectable source health probe used by deterministic tests.
// ProbeFunc 是供确定性测试注入的下载源健康探测器。
type ProbeFunc func(context.Context, download.HTTPDoer, download.Source) download.ProbeResult

// DiscoverFunc is the injectable authenticated release discovery function.
// DiscoverFunc 是供确定性测试注入的已认证发行版本发现函数。
type DiscoverFunc func(context.Context, release.Request) (release.Result, error)

// FetchFunc is the injectable authenticated artifact downloader.
// FetchFunc 是供确定性测试注入的已认证资产下载器。
type FetchFunc func(context.Context, fetch.Request) (fetch.Result, error)

// ExtractFunc is the injectable archive verifier and extractor.
// ExtractFunc 是供确定性测试注入的压缩包校验解包器。
type ExtractFunc func(context.Context, string, string, archive.ExpectedRelease) (archive.Package, error)

// SchemaFunc retrieves the authoritative VMM configuration schema.
// SchemaFunc 获取权威 VMM 配置 schema。
type SchemaFunc func(context.Context, string, string) (configbridge.Schema, error)

// ValidateFunc validates one candidate VMM configuration root against one binary.
// ValidateFunc 使用一个 VMM 可执行文件校验一个候选配置根目录。
type ValidateFunc func(context.Context, string, string) (configbridge.ValidationResult, error)

// Options supplies explicit roots and trust material to New.
// Options 向 New 提供明确的根目录和信任材料。
type Options struct {
	// ManagerVersion identifies the manager build writing installation state.
	// ManagerVersion 标识写入安装状态的管理器版本。
	ManagerVersion string
	// ManagerRoot is the permanent root containing the running manager executable.
	// ManagerRoot 是包含正在运行的管理器可执行文件的永久根目录。
	ManagerRoot string
	// StatePath is the strict installation registration path.
	// StatePath 是严格安装登记文件的路径。
	StatePath string
	// CacheRoot is the manager-owned temporary root for downloads and extraction.
	// CacheRoot 是管理器拥有的下载和解包临时根目录。
	CacheRoot string
	// TrustKeys is the injected Ed25519 trust root for VMM release manifests.
	// TrustKeys 是注入的 VMM 发行清单 Ed25519 信任根。
	TrustKeys map[string]ed25519.PublicKey
	// Identity is the exact current platform identity; zero selects platform.Current.
	// Identity 是当前平台的精确身份；零值使用 platform.Current。
	Identity platform.Identity
	// ServiceName overrides the VMM service name; empty uses VulcanMemoryMesh.
	// ServiceName 覆盖 VMM 服务名；为空时使用 VulcanMemoryMesh。
	ServiceName string
	// CredentialPath optionally points to an explicit .env file checked for references.
	// CredentialPath 可选地指向用于检查引用的明确 .env 文件。
	CredentialPath string
	// HTTPClient is used by release discovery when non-nil.
	// HTTPClient 在非空时用于发行版本发现。
	HTTPClient *http.Client
	// ProbeClient is used by source probes when non-nil.
	// ProbeClient 在非空时用于下载源探测。
	ProbeClient download.HTTPDoer
	// ServiceFactory constructs service clients; nil selects service.New.
	// ServiceFactory 构造服务客户端；为空时使用 service.New。
	ServiceFactory ServiceFactory
	// ServicePrivilegeCheck checks native service permission before a runtime is stopped or files are committed.
	// ServicePrivilegeCheck 在停止运行实例或提交文件前检查原生服务权限。
	ServicePrivilegeCheck func() error
	// PathFactory constructs PATH clients; nil selects pathctl.New.
	// PathFactory 构造 PATH 客户端；为空时使用 pathctl.New。
	PathFactory PathFactory
	// Process supplies foreground process control; nil uses the local tracked process adapter.
	// Process 提供前台进程控制；为空时使用本地被跟踪的进程适配器。
	Process ProcessController
	// Probe, Discover, Fetch, and Extract replace package functions only in tests.
	// Probe、Discover、Fetch 和 Extract 仅用于测试时替换包函数。
	Probe    ProbeFunc
	Discover DiscoverFunc
	Fetch    FetchFunc
	Extract  ExtractFunc
	// Schema and Validate replace the VMM CLI bridge only in tests.
	// Schema 和 Validate 仅用于测试时替换 VMM CLI 桥接。
	Schema   SchemaFunc
	Validate ValidateFunc
	// Effective reads authoritative redacted values and sources; tests can inject an offline result.
	// Effective 读取权威脱敏值及来源；测试可以注入离线结果。
	Effective func(context.Context, string, string) (configbridge.EffectiveConfig, error)
	// TestProvider invokes paid diagnostics only after explicit consent; tests inject offline clients.
	// TestProvider 仅在明确确认后调用可能收费的诊断；测试注入离线客户端。
	TestProvider func(context.Context, string, string, string, int, bool) (configbridge.ProviderTestResult, error)
	// WaitHealthy checks runtime readiness after start; tests may supply a deterministic probe.
	// WaitHealthy 在启动后检查运行时就绪状态；测试可提供确定性探测。
	WaitHealthy func(context.Context, string, string) error
	// Clock supplies timestamps for deterministic status tests.
	// Clock 提供确定性状态测试所需的时间。
	Clock func() time.Time
}

// Controller implements tui.Controller with real download, installation, and lifecycle work.
// Controller 使用真实下载、安装和生命周期操作实现 tui.Controller。
type Controller struct {
	// options is immutable after construction and contains no secret values.
	// options 在构造后不可变，且不包含秘密值。
	options Options
	// identity is the closed platform mapping selected during construction.
	// identity 是构造时选择的封闭平台映射。
	identity platform.Identity
	// mu protects the staged package and foreground process from concurrent TUI commands.
	// mu 保护暂存包和前台进程，避免 TUI 命令并发访问。
	mu sync.Mutex
	// staged holds one verified package until the final confirmation is committed.
	// staged 保存一个已验证的安装包，直到最终确认提交。
	staged *stagedPackage
	// process is the foreground controller, shared by all lifecycle requests.
	// process 是所有生命周期请求共享的前台进程控制器。
	process ProcessController
}

// Compile-time checks keep the controller boundary aligned with the TUI contracts.
// 编译期断言确保 controller 边界持续匹配 TUI 契约。
var _ tui.Controller = (*Controller)(nil)
var _ tui.ProviderWizardController = (*Controller)(nil)

// stagedPackage is the controller-owned bridge between download and final confirmation.
// stagedPackage 是 controller 在下载和最终确认之间持有的桥接对象。
type stagedPackage struct {
	// release is the authenticated VMM release result.
	// release 是已认证的 VMM 发行结果。
	release release.Result
	// artifact is the downloaded and digest-checked archive.
	// artifact 是已下载并校验摘要的压缩包。
	artifact fetch.Result
	// packageData is the safely extracted package.
	// packageData 是已安全解包的安装包。
	packageData archive.Package
	// prepared is the install transaction's prevalidated handle.
	// prepared 是安装事务的预校验句柄。
	prepared install.PreparedPackage
	// expected binds the package to the outer manifest.
	// expected 将安装包绑定到外层发行清单。
	expected archive.ExpectedRelease
	// operation is install or upgrade semantics selected from durable state.
	// operation 是根据持久化状态选择的安装或升级语义。
	operation install.Operation
	// planKey prevents final confirmation from swapping roots or versions.
	// planKey 防止最终确认替换根目录或版本。
	planKey string
	// root owns the temporary download and extraction directory.
	// root 拥有下载和解包临时目录。
	root string
	// configRoot binds candidate validation to the exact configuration root selected before download.
	// configRoot 将候选校验绑定到下载前选定的确切配置根目录。
	configRoot string
}

// stoppedRuntime records the verified runtime that was paused before replacing its package.
// stoppedRuntime 记录替换程序包前已经验证并被暂停的运行实例。
//
// The transition keeps the old lifecycle handle until the new package has been committed and
// its service or foreground process has been started again.
// 该过渡对象会一直保留旧生命周期句柄，直到新程序包提交并重新启动服务或前台进程。
type stoppedRuntime struct {
	// process controls the old foreground runtime when serviceClient is nil.
	// process 在 serviceClient 为空时控制旧前台运行实例。
	process ProcessController

	// serviceClient controls the old service registration when the installed mode is a service.
	// serviceClient 在已安装模式为服务时控制旧服务注册。
	serviceClient ServiceClient

	// serviceName identifies the old service without copying user supplied diagnostics.
	// serviceName 标识旧服务，不复制用户提供的诊断文本。
	serviceName string

	// serviceConfigRoot is the old service configuration root used when a registration must be rebuilt.
	// serviceConfigRoot 是必须重建服务注册时使用的旧配置根目录。
	serviceConfigRoot string

	// serviceProgramRoot is the old program root used to decide whether registration recovery is coherent.
	// serviceProgramRoot 是用于判断服务注册恢复是否一致的旧程序根目录。
	serviceProgramRoot string

	// serviceAutoStart preserves the old boot policy during service registration recovery.
	// serviceAutoStart 在恢复服务注册时保留旧的开机启动策略。
	serviceAutoStart bool

	// serviceUser preserves the verified Unix service account during registration recovery.
	// serviceUser 在恢复服务注册时保留已验证的 Unix 服务账户。
	serviceUser string

	// serviceUninstalled records that package replacement removed the old registration.
	// serviceUninstalled 记录程序包替换是否移除了旧服务注册。
	serviceUninstalled bool

	// serviceWasRunning records whether the old service was active before the transition.
	// serviceWasRunning 记录过渡前旧服务是否处于运行状态。
	serviceWasRunning bool

	// binaryPath is the verified old executable path used for foreground restoration.
	// binaryPath 是用于恢复前台进程的已验证旧可执行文件路径。
	binaryPath string

	// configRoot is the verified old configuration root used for foreground restoration.
	// configRoot 是用于恢复前台进程的已验证旧配置根目录。
	configRoot string

	// foreground indicates that the stopped runtime was managed as a foreground process.
	// foreground 表示暂停的运行实例由前台进程控制器管理。
	foreground bool
}

// New constructs a fail-closed controller with explicit trust, state, and manager roots.
// New 使用明确的信任根、状态根和管理器根构造失败关闭的 controller。
func New(options Options) (*Controller, error) {
	if strings.TrimSpace(options.ManagerVersion) == "" {
		return nil, errors.New("manager version must not be empty")
	}
	if err := validateAbsolutePath(options.ManagerRoot); err != nil {
		return nil, errors.New("manager root is invalid")
	}
	if err := validateAbsolutePath(options.StatePath); err != nil {
		return nil, errors.New("state path is invalid")
	}
	if len(options.TrustKeys) == 0 {
		return nil, errors.New("VMM release trust keys must not be empty")
	}
	for keyID, key := range options.TrustKeys {
		if strings.TrimSpace(keyID) == "" || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("VMM release trust key is invalid")
		}
	}
	identity := options.Identity
	if identity.PlatformID == "" {
		var err error
		identity, err = platform.Current()
		if err != nil {
			return nil, errors.New("current platform is unsupported")
		}
	}
	if identity.PlatformID == "" || identity.VMMExecutablePath == "" || identity.ManagerExecutableName == "" {
		return nil, errors.New("platform identity is incomplete")
	}
	if options.CacheRoot == "" {
		options.CacheRoot = filepath.Join(os.TempDir(), "vmmm-cache")
	}
	if err := validateAbsolutePath(options.CacheRoot); err != nil {
		return nil, errors.New("cache root is invalid")
	}
	if options.ServiceName == "" {
		options.ServiceName = defaultServiceName
	}
	if options.ServiceFactory == nil {
		options.ServiceFactory = func(binaryPath string) (ServiceClient, error) {
			return service.New(binaryPath)
		}
	}
	if options.ServicePrivilegeCheck == nil {
		options.ServicePrivilegeCheck = requireNativeServicePrivileges
	}
	if options.PathFactory == nil {
		options.PathFactory = func() PathClient { return pathctl.New() }
	}
	if options.Probe == nil {
		options.Probe = download.Probe
	}
	if options.Discover == nil {
		options.Discover = release.Discover
	}
	if options.Fetch == nil {
		options.Fetch = fetch.Fetch
	}
	if options.Extract == nil {
		options.Extract = archive.Extract
	}
	if options.Schema == nil {
		options.Schema = func(ctx context.Context, binaryPath string, configRoot string) (configbridge.Schema, error) {
			client, err := configbridge.New(binaryPath, configRoot)
			if err != nil {
				return configbridge.Schema{}, err
			}
			return client.Schema(ctx)
		}
	}
	if options.Validate == nil {
		options.Validate = func(ctx context.Context, binaryPath string, configRoot string) (configbridge.ValidationResult, error) {
			client, err := configbridge.New(binaryPath, configRoot)
			if err != nil {
				return configbridge.ValidationResult{}, err
			}
			return client.Validate(ctx)
		}
	}
	if options.WaitHealthy == nil {
		options.WaitHealthy = func(ctx context.Context, binaryPath, configRoot string) error {
			client, err := configbridge.New(binaryPath, configRoot)
			if err != nil {
				return err
			}
			return client.WaitHealthy(ctx)
		}
	}
	if options.Effective == nil {
		options.Effective = func(ctx context.Context, binary, root string) (configbridge.EffectiveConfig, error) {
			client, err := configbridge.New(binary, root)
			if err != nil {
				return configbridge.EffectiveConfig{}, err
			}
			return client.Effective(ctx)
		}
	}
	if options.TestProvider == nil {
		options.TestProvider = func(ctx context.Context, binaryPath, configRoot, purpose string, route int, confirmed bool) (configbridge.ProviderTestResult, error) {
			client, err := configbridge.New(binaryPath, configRoot)
			if err != nil {
				return configbridge.ProviderTestResult{}, err
			}
			return client.TestProvider(ctx, purpose, route, confirmed)
		}
	}
	if options.Clock == nil {
		options.Clock = func() time.Time { return time.Now().UTC() }
	}
	options.TrustKeys = cloneTrustKeys(options.TrustKeys)
	controller := &Controller{options: options, identity: identity, process: options.Process}
	if controller.process == nil {
		controller.process = newProcessctlController(options.StatePath)
	}
	return controller, nil
}

// Start starts one cancellable operation and emits progress plus exactly one terminal event.
// Start 启动一个可取消操作，发出进度事件并且恰好发出一个终止事件。
func (c *Controller) Start(ctx context.Context, request tui.OperationRequest) (<-chan tui.OperationEvent, error) {
	if c == nil {
		return nil, errors.New("controller is nil")
	}
	if ctx == nil {
		return nil, errors.New("controller context must not be nil")
	}
	if request.Kind == "" {
		return nil, errors.New("controller operation must not be empty")
	}
	events := make(chan tui.OperationEvent, 16)
	go c.run(ctx, request, events)
	return events, nil
}

// OpenConfigFields opens a schema-backed editor snapshot without writing configuration.
// OpenConfigFields 打开 schema 驱动的编辑快照，但不会写入配置。
func (c *Controller) OpenConfigFields(ctx context.Context, request tui.ConfigFieldsRequest) (tui.ConfigFieldsResult, error) {
	if c == nil || ctx == nil {
		return tui.ConfigFieldsResult{}, errors.New("configuration controller is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return tui.ConfigFieldsResult{}, err
	}
	binaryPath, configRoot, err := c.activeConfigTarget()
	if err != nil {
		return tui.ConfigFieldsResult{}, errors.New("no staged or installed VMM configuration is available")
	}
	var cleanup func()
	if staged := c.stagedSnapshot(); staged != nil {
		verified, release, verifyErr := c.reverifyStagedPackage(ctx, staged)
		if verifyErr != nil {
			return tui.ConfigFieldsResult{}, errors.New("staged VMM package could not be reverified")
		}
		binaryPath = filepath.Join(verified.Root, filepath.FromSlash(c.identity.VMMExecutablePath))
		cleanup = release
	}
	if cleanup != nil {
		defer cleanup()
	}
	if request.Prefix == "@rules" {
		fields, err := readRuleAssets(filepath.Join(filepath.Dir(filepath.Dir(binaryPath)), "configs"), configRoot)
		if err != nil {
			return tui.ConfigFieldsResult{}, errors.New("VMM rule assets could not be read")
		}
		fields = overlayConfigFields(fields, request.Fields)
		return tui.ConfigFieldsResult{Fields: fields, Changed: configFieldsChanged(fields, request.Fields), Summary: "Rule assets loaded"}, nil
	}
	schema, err := c.options.Schema(ctx, binaryPath, configRoot)
	if err != nil {
		return tui.ConfigFieldsResult{}, errors.New("VMM configuration schema could not be loaded")
	}
	configBytes, err := readConfigBytes(configRoot)
	if err != nil {
		return tui.ConfigFieldsResult{}, errors.New("VMM configuration could not be read")
	}
	fields, err := displayFields(schema, configBytes, request.Prefix)
	if err != nil {
		return tui.ConfigFieldsResult{}, errors.New("VMM configuration fields could not be prepared")
	}
	fields = overlayConfigFields(fields, request.Fields)
	return tui.ConfigFieldsResult{Fields: fields, Changed: configFieldsChanged(fields, request.Fields), Summary: "Configuration fields loaded"}, nil
}

// Snapshot returns the current installation state without mutating files or services.
// Snapshot 返回当前安装状态，不修改文件或服务。
func (c *Controller) Snapshot(ctx context.Context) (tui.InstallationSnapshot, error) {
	if c == nil || ctx == nil {
		return tui.InstallationSnapshot{}, errors.New("controller context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return tui.InstallationSnapshot{}, err
	}
	return c.snapshot(ctx)
}

// ProviderCatalog returns the verified provider choices used by the quick setup flow.
// ProviderCatalog 返回快捷配置流程使用的已核实供应商选项。
func (c *Controller) ProviderCatalog(purpose providerwizard.Purpose) ([]providerwizard.ProviderMetadata, error) {
	if c == nil {
		return nil, errors.New("configuration controller is unavailable")
	}
	return providerwizard.ProviderCatalog(purpose)
}

// BuildProviderPatch validates typed provider input and emits a secret-free YAML patch.
// BuildProviderPatch 校验类型化供应商输入并输出不含密钥明文的 YAML 补丁。
func (c *Controller) BuildProviderPatch(configuration providerwizard.Configuration) ([]byte, error) {
	if c == nil {
		return nil, errors.New("configuration controller is unavailable")
	}
	return providerPatch(configuration)
}

// OpenProviderWizard returns the verified provider catalog and a value-free draft without writing files.
// OpenProviderWizard 返回已核实的供应商目录和不含值的草稿，不写入文件。
func (c *Controller) OpenProviderWizard(ctx context.Context, request tui.ProviderWizardRequest) (tui.ProviderWizardResult, error) {
	if c == nil || ctx == nil {
		return tui.ProviderWizardResult{}, errors.New("provider controller is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return tui.ProviderWizardResult{}, err
	}
	providers, err := providerwizard.ProviderCatalog(request.Purpose)
	if err != nil {
		return tui.ProviderWizardResult{}, errors.New("provider catalog is unavailable")
	}
	draft := request.Draft
	draft.Purpose = request.Purpose
	if draft.CredentialPath == "" {
		draft.CredentialPath = c.options.CredentialPath
	}
	if draft.Provider != "" {
		metadata, ok := providerwizard.LookupProvider(request.Purpose, draft.Provider)
		if !ok {
			return tui.ProviderWizardResult{}, errors.New("selected provider is not supported")
		}
		if draft.Endpoint == "" {
			draft.Endpoint = metadata.EndpointDefault
		}
		if draft.Model == "" {
			draft.Model = metadata.ModelDefault
		}
	}
	draft.CredentialConfigured = credentialDraftConfigured(draft.CredentialPath, draft.APIKeyEnvironmentNames)
	draft.APIKeyValue = ""
	return tui.ProviderWizardResult{
		Purpose:   request.Purpose,
		Providers: providers,
		Draft:     draft,
		Summary:   "Provider catalog loaded",
	}, nil
}

// run dispatches one request and converts every internal error into a safe terminal event.
// run 分发一个请求，并将所有内部错误转换为安全的终止事件。
func (c *Controller) run(ctx context.Context, request tui.OperationRequest, events chan<- tui.OperationEvent) {
	defer close(events)
	if err := ctx.Err(); err != nil {
		c.emit(events, tui.OperationEvent{Kind: tui.OperationEventCancelled, Message: "Operation cancelled"})
		return
	}
	var err error
	switch request.Kind {
	case tui.OperationProbeSource:
		err = c.probeSource(ctx, request.Source, events)
	case tui.OperationFetchVersions:
		err = c.fetchVersions(ctx, request.Source, request.Plan.Version.Tag, events)
	case tui.OperationStagePackage:
		err = c.stagePackage(ctx, request.Plan, events)
	case tui.OperationInstall:
		err = c.install(ctx, request.Plan, events)
	case tui.OperationValidate:
		err = c.validate(ctx, request.Plan, events, false)
	case tui.OperationValidateSaved:
		c.discardStaged()
		err = c.validateSaved(ctx, events)
	case tui.OperationEffective:
		if request.Plan.Version.Tag != "" {
			err = c.validate(ctx, request.Plan, events, true)
		} else {
			err = c.installedEffective(ctx, events)
		}
	case tui.OperationTestProvider:
		err = c.testProvider(ctx, request, events)
	case tui.OperationService:
		c.discardStaged()
		err = c.serviceAction(ctx, request, events)
	case tui.OperationPath:
		c.discardStaged()
		err = c.pathAction(ctx, request, events)
	case tui.OperationUninstall:
		c.discardStaged()
		err = c.uninstall(ctx, request.Uninstall, events)
	case tui.OperationRefresh:
		err = c.refresh(ctx, events)
	default:
		err = errors.New("unsupported controller operation")
	}
	if err == nil {
		c.emit(events, tui.OperationEvent{Kind: tui.OperationEventCompleted, Message: "Operation completed"})
		return
	}
	if request.Kind == tui.OperationInstall {
		// Refresh after install defers finish so an already-open TUI cannot keep displaying the pre-failure success state.
		// 安装的延迟收尾完成后刷新，使已经打开的界面不会继续显示失败前的成功状态。
		inspection, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		snapshot, snapshotErr := c.snapshot(inspection)
		cancel()
		if snapshotErr == nil {
			c.emit(events, tui.OperationEvent{Kind: tui.OperationEventProgress, Snapshot: &snapshot})
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
		c.emit(events, tui.OperationEvent{Kind: tui.OperationEventCancelled, Message: "Operation cancelled"})
		return
	}
	c.emit(events, tui.OperationEvent{Kind: tui.OperationEventFailed, Message: safeOperationError(err), Retryable: request.Kind != tui.OperationTestProvider})
}

// probeSource checks only the selected source and discovers its latest authenticated release.
// probeSource 只检查用户选定的源，并发现该源的最新已认证发行版本。
func (c *Controller) probeSource(ctx context.Context, option tui.SourceOption, events chan<- tui.OperationEvent) error {
	c.emitProgress(events, "probe-source", "Checking selected download source")
	result := c.options.Probe(ctx, c.options.ProbeClient, option.Source)
	if result.Status == download.ProbeStatusFailed || !result.Downloadable {
		return errors.New("selected download source failed its health check")
	}
	source := option
	source.Available = true
	source.ProbeMessage = "Source passed download checks"
	source.CheckedAt = result.CheckedAt
	c.emit(events, tui.OperationEvent{Kind: tui.OperationEventProgress, Sources: []tui.SourceOption{source}, Progress: tui.Progress{Stage: "probe-source", Message: source.ProbeMessage}})
	return c.fetchVersions(ctx, source, "", events)
}

// fetchVersions resolves exactly one selected source and returns its authenticated release choice.
// fetchVersions 仅使用一个选定源并返回其已认证发行版本选项。
func (c *Controller) fetchVersions(ctx context.Context, option tui.SourceOption, tag string, events chan<- tui.OperationEvent) error {
	c.emitProgress(events, "fetch-versions", "Resolving authenticated VMM release")
	selector := release.Latest()
	if strings.TrimSpace(tag) != "" {
		selector = release.ExactTag(tag)
	}
	result, err := c.options.Discover(ctx, release.Request{
		Product:    manifest.ProductVMM,
		Selector:   selector,
		Source:     option.Source,
		TrustKeys:  cloneTrustKeys(c.options.TrustKeys),
		HTTPClient: c.options.HTTPClient,
	})
	if err != nil {
		return errors.New("selected source did not provide a trusted VMM release")
	}
	version := tui.VersionOption{Tag: result.Tag, Commit: result.Commit, Available: true, PublishedAt: c.options.Clock()}
	c.emit(events, tui.OperationEvent{Kind: tui.OperationEventProgress, Versions: []tui.VersionOption{version}, Progress: tui.Progress{Stage: "fetch-versions", Message: "Authenticated VMM release is available"}})
	return nil
}

// stagePackage downloads, extracts, and prevalidates a complete VMM package before configuration.
// stagePackage 在配置前下载、解包并预校验完整 VMM 安装包。
func (c *Controller) stagePackage(ctx context.Context, plan tui.InstallPlan, events chan<- tui.OperationEvent) error {
	if err := validatePlanRoots(plan); err != nil {
		return err
	}
	if !plan.Source.Available {
		return errors.New("selected download source has not passed its health check")
	}
	if strings.TrimSpace(plan.Version.Tag) == "" {
		return errors.New("VMM release version must be selected")
	}
	// A replacement staging request must release this controller's previous lock before acquiring it again.
	// 替换暂存请求必须先释放当前控制器先前持有的锁，才能再次获取。
	c.discardStaged()
	identity := c.identity
	if err := os.MkdirAll(c.options.CacheRoot, 0o700); err != nil {
		return errors.New("could not prepare package cache")
	}
	selector := release.ExactTag(plan.Version.Tag)
	c.emitProgress(events, "discover-release", "Verifying selected VMM release")
	releaseResult, err := c.options.Discover(ctx, release.Request{
		Product:    manifest.ProductVMM,
		Selector:   selector,
		Source:     plan.Source.Source,
		TrustKeys:  cloneTrustKeys(c.options.TrustKeys),
		HTTPClient: c.options.HTTPClient,
	})
	if err != nil {
		return errors.New("selected VMM release could not be verified")
	}
	if releaseResult.Tag != plan.Version.Tag {
		return errors.New("selected VMM release changed during verification")
	}
	if plan.Version.Commit != "" && releaseResult.Commit != plan.Version.Commit {
		return errors.New("selected VMM release commit changed during verification")
	}
	artifact, err := releaseResult.Manifest.FindArtifact(manifest.ProductVMM, identity.PlatformID)
	if err != nil {
		return errors.New("selected VMM release has no artifact for this platform")
	}
	target, err := targetForPlatform(identity.PlatformID)
	if err != nil {
		return err
	}
	expected := archive.ExpectedRelease{Version: releaseResult.Tag, Commit: releaseResult.Commit, Platform: identity.PlatformID, Target: target, ArchiveBytes: artifact.Bytes, ArchiveSHA256: artifact.SHA256}
	root, err := os.MkdirTemp(c.options.CacheRoot, ".vmmm-stage-")
	if err != nil {
		return errors.New("could not create package staging directory")
	}
	keepRoot := false
	defer func() {
		if !keepRoot {
			_ = os.RemoveAll(root)
		}
	}()
	downDir := filepath.Join(root, "download")
	if err := os.MkdirAll(downDir, 0o700); err != nil {
		return errors.New("could not prepare package download directory")
	}
	archivePath := filepath.Join(downDir, artifact.Filename)
	c.emitProgress(events, "download", "Downloading and verifying VMM package")
	fetched, err := c.options.Fetch(ctx, fetch.Request{Source: plan.Source.Source, Manifest: releaseResult.Manifest, Product: manifest.ProductVMM, Repository: releaseResult.Repository, Platform: identity.PlatformID, StagingPath: archivePath})
	if err != nil {
		return errors.New("VMM package download or digest verification failed")
	}
	if fetched.Bytes != artifact.Bytes || fetched.SHA256 != artifact.SHA256 {
		return errors.New("downloaded VMM package does not match its signed artifact")
	}
	extractRoot := filepath.Join(root, "extracted")
	if err := os.MkdirAll(extractRoot, 0o700); err != nil {
		return errors.New("could not prepare package extraction directory")
	}
	c.emitProgress(events, "extract", "Verifying VMM package contents")
	packageData, err := c.options.Extract(ctx, fetched.Path, extractRoot, expected)
	if err != nil {
		return errors.New("VMM package contents failed verification")
	}
	operation := install.OperationInstall
	if existing, err := state.Load(c.options.StatePath); err == nil {
		if older, comparable := releaseTagOlderThan(releaseResult.Tag, existing.VMM.Tag); comparable && older && !plan.Rollback {
			return errors.New("selected VMM release is older than the installed release; rollback must be explicit")
		}
		operation = install.OperationUpgrade
		if plan.Rollback {
			operation = install.OperationRollback
		}
	} else if !isMissingState(err) {
		return errors.New("existing VMM installation state is invalid")
	}
	validate := c.validateFunc()
	prepared, err := install.StagePackage(ctx, install.Request{
		Repair:      plan.Repair,
		ManagerRoot: c.options.ManagerRoot, Operation: operation, ManagerVersion: c.options.ManagerVersion, Manifest: releaseResult.Manifest, Artifact: fetched, Package: packageData, Expected: expected,
		Paths: state.InstallPaths{ProgramRoot: plan.ProgramRoot, ConfigRoot: plan.ConfigRoot, DataRoot: plan.DataRoot}, StatePath: c.options.StatePath,
		Source: sourceState(plan.Source.Source), Service: serviceStateForPlan(plan, c.options.ServiceName), PATH: emptyPATHState(), ValidateConfig: validate,
	})
	if err != nil {
		return errors.New("VMM package cannot be staged for the selected installation roots")
	}
	c.mu.Lock()
	old := c.staged
	c.staged = &stagedPackage{release: releaseResult, artifact: fetched, packageData: packageData, prepared: prepared, expected: expected, operation: operation, planKey: planKey(plan, identity.PlatformID), root: root, configRoot: plan.ConfigRoot}
	c.mu.Unlock()
	if old != nil {
		old.prepared.Close()
		_ = os.RemoveAll(old.root)
	}
	keepRoot = true
	metadata := &tui.StagedPackage{Verified: true, Version: releaseResult.Tag, Platform: identity.PlatformID, ArtifactRoot: packageData.Root, StorageModes: storageModes(packageData.Receipt), CombinedFlavors: combinedFlavors(packageData.Receipt)}
	c.emit(events, tui.OperationEvent{Kind: tui.OperationEventProgress, Package: metadata, Progress: tui.Progress{Stage: "stage-package", Message: "VMM package is staged and verified"}})
	return nil
}

// pauseInstalledRuntime stops a verified running service or foreground process before package replacement.
// pauseInstalledRuntime 在替换程序包前停止已验证且正在运行的服务或前台进程。
//
// Replacing an executable while it is running has different failure modes across platforms: Windows
// may refuse the file replacement, while Unix can keep executing the old inode after the UI reports
// the new version. Pausing first gives the commit a single, explicit runtime boundary.
// 不同平台替换运行中的可执行文件会产生不同故障：Windows 可能拒绝替换，Unix 可能继续执行旧 inode，
// 即使界面已经显示新版本。先暂停可以让提交拥有单一且明确的运行边界。
func (c *Controller) pauseInstalledRuntime(ctx context.Context, installed state.State, exists bool, plan tui.InstallPlan, events chan<- tui.OperationEvent) (*stoppedRuntime, error) {
	if !exists {
		return nil, nil
	}
	if ctx == nil {
		return nil, errors.New("runtime transition context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	binaryPath := filepath.Join(installed.Paths.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
	if installed.Service.Name != "" {
		if install.FilesIntact(installed) != "" {
			return nil, c.confirmDamagedServiceAbsent(ctx, installed.Service.Name)
		}
		client, err := c.options.ServiceFactory(binaryPath)
		if err != nil {
			return nil, errors.New("existing VMM service control is unavailable")
		}
		status, err := client.GetStatus(ctx, installed.Service.Name)
		if err != nil {
			return nil, errors.New("existing VMM service status failed")
		}
		if status.State == "not-installed" {
			return nil, nil
		}
		serviceUser := installed.Service.User
		if status.User != "" {
			if serviceUser != "" && runtime.GOOS != "windows" && serviceUser != status.User {
				return nil, errors.New("registered VMM service account differs from its saved account")
			}
			serviceUser = status.User
		}
		if plan.ServiceMode == tui.ServiceModeService && runtime.GOOS != "windows" && serviceUser != plan.ServiceUser {
			return nil, errors.New("existing VMM service account differs from the selected account")
		}
		runtime := &stoppedRuntime{
			serviceClient:      client,
			serviceName:        installed.Service.Name,
			serviceConfigRoot:  installed.Paths.ConfigRoot,
			serviceProgramRoot: installed.Paths.ProgramRoot,
			serviceAutoStart:   installed.Service.AutoStart,
			serviceUser:        serviceUser,
			serviceWasRunning:  strings.EqualFold(status.State, "running"),
		}
		if runtime.serviceWasRunning {
			c.emitProgress(events, "stop-runtime", "Stopping the running VMM service before package replacement")
			if err := client.Stop(ctx, installed.Service.Name); err != nil {
				return nil, errors.New("existing VMM service could not be stopped")
			}
		}
		newBinaryPath := filepath.Join(plan.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
		if plan.ServiceMode == tui.ServiceModeService || filepath.Clean(newBinaryPath) != filepath.Clean(binaryPath) {
			c.emitProgress(events, "stop-runtime", "Removing the old VMM service registration before changing its executable path")
			if err := client.Uninstall(ctx, installed.Service.Name); err != nil {
				if runtime.serviceWasRunning {
					recoveryContext, cancel := context.WithTimeout(context.Background(), 45*time.Second)
					_ = runtime.restore(recoveryContext)
					cancel()
				}
				return nil, errors.New("existing VMM service registration could not be removed")
			}
			runtime.serviceUninstalled = true
		}
		return runtime, nil
	}
	if c.process == nil {
		return nil, ErrProcessControlUnavailable
	}
	if binder, ok := c.process.(processConfigBinder); ok {
		binder.Bind(binaryPath, installed.Paths.ConfigRoot)
	}
	status, err := c.process.Status(ctx, binaryPath)
	if err != nil {
		return nil, errors.New("existing VMM foreground status failed")
	}
	if !status.Running {
		return nil, nil
	}
	c.emitProgress(events, "stop-runtime", "Stopping the running VMM process before package replacement")
	if err := c.process.Stop(ctx, binaryPath); err != nil {
		return nil, errors.New("existing VMM foreground process could not be stopped")
	}
	return &stoppedRuntime{process: c.process, binaryPath: binaryPath, configRoot: installed.Paths.ConfigRoot, foreground: true}, nil
}

// confirmDamagedServiceAbsent uses a newly verified staged CLI only to prove no native service exists.
// confirmDamagedServiceAbsent 只用重新验证的暂存 CLI 证明系统服务不存在，绝不从暂存路径停止或修改已有服务。
// Existing registrations still require their exact executable identity and are rejected by this inspection.
// 已有服务登记仍要求精确的程序路径身份，本检查遇到已有登记时返回明确修复错误。
func (c *Controller) confirmDamagedServiceAbsent(ctx context.Context, name string) error {
	staged := c.stagedSnapshot()
	if staged == nil {
		return ErrDamagedServiceControl
	}
	verified, cleanup, err := c.reverifyStagedPackage(ctx, staged)
	if err != nil {
		return err
	}
	defer cleanup()
	client, err := c.options.ServiceFactory(filepath.Join(verified.Root, filepath.FromSlash(c.identity.VMMExecutablePath)))
	if err != nil {
		return ErrDamagedServiceControl
	}
	status, err := client.GetStatus(ctx, name)
	if err != nil || status.State != "not-installed" {
		return ErrDamagedServiceControl
	}
	return nil
}

// restore restarts the exact runtime that pauseInstalledRuntime stopped.
// restore 重新启动 pauseInstalledRuntime 停止的精确运行实例。
func (runtime *stoppedRuntime) restore(ctx context.Context) error {
	if runtime == nil {
		return nil
	}
	if runtime.serviceClient != nil {
		if runtime.serviceUninstalled {
			if err := runtime.serviceClient.Install(ctx, runtime.serviceName, runtime.serviceConfigRoot, runtime.serviceUser, runtime.serviceAutoStart); err != nil {
				return err
			}
		}
		if runtime.serviceWasRunning {
			return runtime.serviceClient.Start(ctx, runtime.serviceName)
		}
		return nil
	}
	if runtime.foreground && runtime.process != nil {
		if binder, ok := runtime.process.(processConfigBinder); ok {
			binder.Bind(runtime.binaryPath, runtime.configRoot)
		}
		return runtime.process.Start(ctx, runtime.binaryPath, runtime.configRoot)
	}
	return errors.New("previous VMM runtime handle is incomplete")
}

// wasRunning reports whether the transition must resume execution after a successful commit.
// wasRunning 判断成功提交后是否必须恢复运行状态。
func (runtime *stoppedRuntime) wasRunning() bool {
	if runtime == nil {
		return false
	}
	if runtime.serviceClient != nil {
		return runtime.serviceWasRunning
	}
	return runtime.foreground
}

// restoreStoppedRuntime performs bounded cleanup even when the user context was canceled.
// restoreStoppedRuntime 即使用户上下文已取消，也会执行有界的恢复清理。
func (c *Controller) restoreStoppedRuntime(runtime *stoppedRuntime, events chan<- tui.OperationEvent) error {
	if runtime == nil {
		return nil
	}
	c.emitProgress(events, "restore-runtime", "Restoring the previously running VMM runtime")
	recoveryContext, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := runtime.restore(recoveryContext); err != nil {
		return errors.New("previous VMM runtime could not be restored")
	}
	return nil
}

// startInstalledRuntime resumes the newly committed runtime when the previous runtime was active.
// startInstalledRuntime 当旧运行实例处于活动状态时启动刚刚提交的新运行实例。
func (c *Controller) startInstalledRuntime(ctx context.Context, plan tui.InstallPlan, installed state.State) error {
	binaryPath := filepath.Join(installed.Paths.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
	if plan.ServiceMode == tui.ServiceModeService {
		client, err := c.options.ServiceFactory(binaryPath)
		if err != nil {
			return errors.New("new VMM service control is unavailable")
		}
		if err := client.Start(ctx, installed.Service.Name); err != nil {
			return errors.New("new VMM service could not be started")
		}
		return c.checkRuntimeHealth(ctx, binaryPath, installed.Paths.ConfigRoot)
	}
	if c.process == nil {
		return ErrProcessControlUnavailable
	}
	if binder, ok := c.process.(processConfigBinder); ok {
		binder.Bind(binaryPath, installed.Paths.ConfigRoot)
	}
	if err := c.process.Start(ctx, binaryPath, installed.Paths.ConfigRoot); err != nil {
		return errors.New("new VMM foreground process could not be started")
	}
	return c.checkRuntimeHealth(ctx, binaryPath, installed.Paths.ConfigRoot)
}

// checkRuntimeHealth requires both a successful endpoint probe and the tracked runtime to remain running.
// checkRuntimeHealth 同时要求端点探测成功且被跟踪的运行实例仍在运行；返回固定脱敏错误。
func (c *Controller) checkRuntimeHealth(ctx context.Context, binaryPath, configRoot string) error {
	if err := c.options.WaitHealthy(ctx, binaryPath, configRoot); err != nil {
		return ErrRuntimeNotHealthy
	}
	snapshot, err := c.snapshot(ctx)
	if err != nil || !snapshot.Running {
		return ErrRuntimeNotHealthy
	}
	return nil
}

// install builds a candidate configuration, validates it with the staged binary, and commits after confirmation.
// install 使用暂存二进制构造候选配置，经真实校验后在确认阶段提交。
func (c *Controller) install(ctx context.Context, plan tui.InstallPlan, events chan<- tui.OperationEvent) (returnErr error) {
	prepared, err := c.matchStaged(plan)
	if err != nil {
		return err
	}
	defer func() {
		c.mu.Lock()
		if c.staged != nil && filepath.Clean(c.staged.packageData.Root) == filepath.Clean(prepared.packageData.Root) {
			c.staged.prepared.Close()
			_ = os.RemoveAll(c.staged.root)
			c.staged = nil
		}
		c.mu.Unlock()
	}()
	oldState, oldExists := c.loadState()
	if plan.ServiceMode == tui.ServiceModeService || oldExists && oldState.Service.Name != "" {
		if err := c.options.ServicePrivilegeCheck(); err != nil {
			return err
		}
	}
	configFiles, err := c.buildConfigFiles(ctx, plan, prepared.packageData.Root)
	if err != nil {
		return err
	}
	if oldExists {
		if err := c.validateStorageTransition(plan, oldState, configFiles[defaultConfigFileName]); err != nil {
			return err
		}
		// Mark the attempt before stopping services or changing credentials so interruption cannot look complete.
		// 在停止服务或修改凭据之前标记本次尝试，避免中断后仍显示安装完成。
		pending := oldState
		pending.InstallationComplete = false
		if err := state.Save(c.options.StatePath, pending); err != nil {
			return err
		}
	}
	stopped, err := c.pauseInstalledRuntime(ctx, oldState, oldExists, plan, events)
	if err != nil {
		if stopped != nil {
			_ = c.restoreStoppedRuntime(stopped, events)
		}
		return err
	}
	commitCompleted := false
	defer func() {
		if stopped != nil && !commitCompleted {
			_ = c.restoreStoppedRuntime(stopped, events)
		}
	}()
	paths := state.InstallPaths{ProgramRoot: plan.ProgramRoot, ConfigRoot: plan.ConfigRoot, DataRoot: plan.DataRoot}
	// Account selection follows package staging in the TUI, so transfer private roots only after stopping the old runtime.
	// TUI 在包暂存之后才选择账户，因此必须先停止旧运行时，再调整私有根目录归属。
	if plan.ServiceMode == tui.ServiceModeService {
		finishOwnership, err := install.TransferServiceRoots(paths, plan.ServiceUser)
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, finishOwnership(commitCompleted)) }()
		if err := validateServiceUserAccess(plan.ServiceUser, c.servicePathChecks(plan, plan.ConfigRoot, plan.DataRoot)); err != nil {
			return err
		}
	}
	credentialRollback, err := c.applyCredentialUpdates(plan)
	if err != nil {
		return err
	}
	defer func() {
		if !commitCompleted && credentialRollback != nil {
			credentialRollback()
		}
	}()
	serviceState := serviceStateForPlan(plan, c.options.ServiceName)
	if oldExists && plan.ServiceMode != tui.ServiceModeService {
		serviceState = oldState.Service
	}
	pathState := emptyPATHState()
	if oldExists {
		pathState = oldState.PATH
	}
	request := install.Request{ManagerRoot: c.options.ManagerRoot, Operation: prepared.operation, ManagerVersion: c.options.ManagerVersion, Manifest: prepared.release.Manifest, Artifact: prepared.artifact, Package: prepared.packageData, Expected: prepared.expected, Paths: paths, StatePath: c.options.StatePath, Source: sourceState(plan.Source.Source), Service: serviceState, PATH: pathState, ConfigFiles: configFiles, ValidateConfig: c.validateFunc()}
	request.Repair = plan.Repair
	c.emitProgress(events, "validate-config", "Validating candidate configuration with VMM")
	result, err := prepared.prepared.BeginInstall(ctx, request)
	if err != nil {
		return errors.New("candidate VMM configuration or installation transaction failed")
	}
	pathChanged := false
	var completedSnapshot *tui.InstallationSnapshot
	previousPATH, currentPATH := emptyPATHState(), emptyPATHState()
	defer func() {
		if !commitCompleted {
			recovery, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			stopErr := c.stopCandidateRuntime(recovery, result.State, stopped)
			cancel()
			if stopErr != nil {
				// Retain files when a runtime cannot be stopped, preventing execution against a partial rollback.
				// 无法停止运行时时保留文件，避免其使用部分回滚的程序。
				commitCompleted = true
				returnErr = errors.Join(returnErr, errors.New("VMM rollback could not stop the runtime; current installation was retained"), stopErr)
			} else if pathChanged {
				c.rollbackPathChange(result.State.Paths, previousPATH, currentPATH)
			}
		}
		if finishErr := result.Finish(commitCompleted, completedSnapshot != nil); finishErr != nil {
			returnErr = errors.Join(returnErr, finishErr)
			if !commitCompleted {
				// Failed file recovery must not restart a process against an uncertain executable tree.
				// 文件恢复失败后，不能在身份不确定的程序树上重启进程。
				commitCompleted = true
			}
		} else if commitCompleted && completedSnapshot != nil {
			completedSnapshot.Installed = true
			completedSnapshot.Incomplete = false
			completedSnapshot.IntegrityIssue = ""
			c.emit(events, tui.OperationEvent{Kind: tui.OperationEventProgress, Snapshot: completedSnapshot, Progress: tui.Progress{Stage: "install", Message: "VMM installation is ready"}})
		}
	}()
	c.emitProgress(events, "install", "VMM files prepared; reconciling runtime and PATH")
	if err := c.applyServiceAfterInstall(ctx, plan, result.State, oldState, oldExists, stopped); err != nil {
		return err
	}
	updatedState, err := state.Load(c.options.StatePath)
	if err != nil {
		return errors.New("installed VMM state could not be reloaded")
	}
	previousPATH = updatedState.PATH
	updatedState.PATH, err = c.applyPath(plan, updatedState.Paths, updatedState.PATH)
	if err != nil {
		return err
	}
	currentPATH = updatedState.PATH
	pathChanged = true
	// This is the configuration already accepted by BeginInstall; failure rollback restores the previous registration.
	// 此处配置已经通过 BeginInstall 的权威检查；后续失败回滚会恢复原登记时间。
	updatedState.ConfigValidatedAt = c.options.Clock().UTC().Format(time.RFC3339Nano)
	if err := state.Save(c.options.StatePath, updatedState); err != nil {
		return errors.New("installed VMM state could not be updated")
	}
	if stopped != nil && stopped.wasRunning() {
		if err := c.startInstalledRuntime(ctx, plan, updatedState); err != nil {
			return err
		}
	}
	snapshot, err := c.snapshot(ctx)
	if err != nil {
		return err
	}
	if snapshot.IntegrityIssue != "" && snapshot.IntegrityIssue != "installation-not-completed" {
		return errors.New("installation verification did not complete")
	}
	commitCompleted = true
	stopped = nil
	completedSnapshot = &snapshot
	return nil
}

// stopCandidateRuntime stops newly reconciled processes before rolling files back and marks an old service for restoration.
// stopCandidateRuntime 在回滚文件前停止新协调的进程，并标记需要恢复的旧服务注册。
func (c *Controller) stopCandidateRuntime(ctx context.Context, candidate state.State, stopped *stoppedRuntime) error {
	current, err := c.requireState()
	if err != nil {
		return err
	}
	binaryPath := filepath.Join(candidate.Paths.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
	if current.Service.Name != "" {
		client, err := c.options.ServiceFactory(binaryPath)
		if err != nil {
			return err
		}
		status, err := client.GetStatus(ctx, current.Service.Name)
		if err != nil {
			return err
		}
		if status.State == "running" {
			if err := client.Stop(ctx, current.Service.Name); err != nil {
				return err
			}
		}
		if err := client.Uninstall(ctx, current.Service.Name); err != nil {
			return err
		}
		if stopped != nil && stopped.serviceName != "" {
			stopped.serviceUninstalled = true
		}
	}
	if c.process != nil {
		if binder, ok := c.process.(processConfigBinder); ok {
			binder.Bind(binaryPath, candidate.Paths.ConfigRoot)
		}
		status, err := c.process.Status(ctx, binaryPath)
		if err != nil {
			return err
		}
		if status.Running {
			return c.process.Stop(ctx, binaryPath)
		}
	}
	return nil
}

// validate runs the VMM validator against a temporary candidate tree without changing official roots.
// validate 在临时候选树上运行 VMM 校验，不修改正式目录。
func (c *Controller) validate(ctx context.Context, plan tui.InstallPlan, events chan<- tui.OperationEvent, includeEffective bool) error {
	prepared, err := c.matchStaged(plan)
	if err != nil {
		return err
	}
	packageRoot := prepared.packageData.Root
	var cleanup func()
	if staged := c.stagedSnapshot(); staged != nil && filepath.Clean(staged.packageData.Root) == filepath.Clean(packageRoot) {
		verified, release, verifyErr := c.reverifyStagedPackage(ctx, staged)
		if verifyErr != nil {
			return errors.New("staged VMM package could not be reverified")
		}
		packageRoot = verified.Root
		cleanup = release
	}
	if cleanup != nil {
		defer cleanup()
	}
	configFiles, err := c.buildConfigFiles(ctx, plan, packageRoot)
	if err != nil {
		return err
	}
	candidate, releaseCandidate, err := install.PrepareCandidateConfig(plan.ConfigRoot, c.options.CacheRoot, configFiles)
	if err != nil {
		return errors.New("could not create candidate configuration directory")
	}
	defer releaseCandidate()
	// Validate the same credentials and override assets that commit will use, without modifying the installed tree.
	// 校验与提交相同的凭据和规则覆盖文件，同时保持已安装配置树不变。
	candidatePlan := plan
	candidatePlan.ConfigRoot = candidate
	candidatePlan.Providers.CredentialPath = filepath.Join(candidate, ".env")
	candidatePlan.StorageSettings.PostgreSQLCredentialPath = filepath.Join(candidate, ".env")
	candidatePlan.ServiceMode = tui.ServiceModeForeground
	if _, err := c.applyCredentialUpdates(candidatePlan); err != nil {
		return err
	}
	binaryPath := filepath.Join(packageRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
	c.emitProgress(events, "validate-config", "Running authoritative VMM configuration validation")
	validation, err := c.options.Validate(ctx, binaryPath, candidate)
	if err != nil {
		return errors.New("VMM configuration validation could not be completed")
	}
	var preview *tui.ConfigPreview
	if validation.Valid {
		preview, err = c.configurationPreview(ctx, binaryPath, plan, configFiles)
		if err != nil {
			return err
		}
	}
	summary := validationSummary(validation)
	c.emit(events, tui.OperationEvent{Kind: tui.OperationEventProgress, Validation: &summary, Preview: preview, Progress: tui.Progress{Stage: "validate-config", Message: summary.Summary}})
	if !validation.Valid {
		return errors.New("VMM configuration is invalid")
	}
	if includeEffective {
		return c.emitEffective(ctx, binaryPath, candidate, true, events)
	}
	return nil
}

// serviceAction performs a real service or foreground process lifecycle action from durable state.
// serviceAction 根据持久化状态执行真实服务或前台进程生命周期操作。
func (c *Controller) serviceAction(ctx context.Context, request tui.OperationRequest, events chan<- tui.OperationEvent) (returnErr error) {
	releaseLock, err := install.LockInstallation(ctx, c.options.StatePath)
	if err != nil {
		return err
	}
	defer releaseLock()
	installed, err := c.requireState()
	if err != nil {
		return err
	}
	binaryPath := filepath.Join(installed.Paths.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
	if request.ServiceAction == tui.ServiceActionStatus {
		return c.refresh(ctx, events)
	}
	if !installed.InstallationComplete && request.ServiceAction != tui.ServiceActionStop && request.ServiceAction != tui.ServiceActionUninstall || install.FilesIntact(installed) != "" {
		return errors.New("installation is incomplete; reinstall before lifecycle control")
	}
	configRoot := installed.Paths.ConfigRoot
	if request.TargetMode == tui.ServiceModeForeground && installed.Service.Name != "" {
		return errors.New("registered VMM service must be removed before foreground control")
	}
	if request.TargetMode == tui.ServiceModeService || installed.Service.Name != "" {
		if err := c.options.ServicePrivilegeCheck(); err != nil {
			return err
		}
		name := installed.Service.Name
		if name == "" {
			name = c.options.ServiceName
		}
		client, err := c.options.ServiceFactory(binaryPath)
		if err != nil {
			return errors.New("VMM service control is unavailable")
		}
		previousService := installed.Service
		ownershipCommitted := false
		if request.ServiceAction == tui.ServiceActionInstall && previousService.Name != "" {
			return errors.New("VMM service is already registered; remove it before registering a different account")
		}
		if request.ServiceAction != tui.ServiceActionInstall && previousService.Name == "" {
			return errors.New("VMM service is not registered")
		}
		serviceWasRunning := false
		if request.ServiceAction == tui.ServiceActionUninstall {
			status, statusErr := client.GetStatus(ctx, name)
			if statusErr != nil {
				return errors.New("VMM service status could not be checked before removal")
			}
			serviceWasRunning = status.State == "running"
		}
		switch request.ServiceAction {
		case tui.ServiceActionInstall:
			if c.process != nil {
				if binder, ok := c.process.(processConfigBinder); ok {
					binder.Bind(binaryPath, configRoot)
				}
				status, err := c.process.Status(ctx, binaryPath)
				if err != nil || status.Running {
					return errors.New("stop the foreground runtime before registering a service")
				}
			}
			finishOwnership, err := install.TransferServiceRoots(installed.Paths, request.Plan.ServiceUser)
			if err != nil {
				return err
			}
			defer func() { returnErr = errors.Join(returnErr, finishOwnership(ownershipCommitted)) }()
			servicePlan := request.Plan
			servicePlan.ProgramRoot = installed.Paths.ProgramRoot
			servicePlan.ConfigRoot = configRoot
			servicePlan.DataRoot = installed.Paths.DataRoot
			if err := validateServiceUserAccess(servicePlan.ServiceUser, c.servicePathChecks(servicePlan, configRoot, installed.Paths.DataRoot)); err != nil {
				return err
			}
			if err := validateServiceLoggingConfigured(configRoot); err != nil {
				return err
			}
			if err := client.Install(ctx, name, configRoot, request.Plan.ServiceUser, request.Plan.AutoStart); err != nil {
				return errors.New("VMM service installation failed")
			}
			installed.Service = state.ServiceState{Name: name, User: serviceUserForState(request.Plan.ServiceUser), AutoStart: request.Plan.AutoStart}
		case tui.ServiceActionUninstall:
			if err := client.Uninstall(ctx, name); err != nil {
				return errors.New("VMM service removal failed")
			}
			installed.Service = state.ServiceState{}
		case tui.ServiceActionStart:
			if err := client.Start(ctx, name); err != nil {
				return errors.New("VMM service start failed")
			}
		case tui.ServiceActionStop:
			if err := client.Stop(ctx, name); err != nil {
				return errors.New("VMM service stop failed")
			}
		case tui.ServiceActionRestart:
			if err := client.Restart(ctx, name); err != nil {
				return errors.New("VMM service restart failed")
			}
		case tui.ServiceActionEnable:
			if err := client.Enable(ctx, name); err != nil {
				return errors.New("VMM service enable failed")
			}
			installed.Service = state.ServiceState{Name: name, User: installed.Service.User, AutoStart: true}
		case tui.ServiceActionDisable:
			if err := client.Disable(ctx, name); err != nil {
				return errors.New("VMM service disable failed")
			}
			installed.Service = state.ServiceState{Name: name, User: installed.Service.User, AutoStart: false}
		case tui.ServiceActionStatus:
			if _, err := client.GetStatus(ctx, name); err != nil {
				return errors.New("VMM service status failed")
			}
		default:
			return errors.New("unsupported service action")
		}
		if request.ServiceAction == tui.ServiceActionInstall || request.ServiceAction == tui.ServiceActionUninstall || request.ServiceAction == tui.ServiceActionEnable || request.ServiceAction == tui.ServiceActionDisable {
			if err := state.Save(c.options.StatePath, installed); err != nil {
				rollbackErr := rollbackServiceAction(ctx, client, name, configRoot, previousService, serviceWasRunning, request.ServiceAction)
				if rollbackErr != nil {
					return errors.Join(errors.New("VMM service state could not be saved; native service rollback failed"), rollbackErr)
				}
				return errors.New("VMM service state could not be saved; native service change was rolled back")
			}
			ownershipCommitted = true
		}
	} else {
		if c.process == nil {
			return ErrProcessControlUnavailable
		}
		if binder, ok := c.process.(processConfigBinder); ok {
			binder.Bind(binaryPath, configRoot)
		}
		switch request.ServiceAction {
		case tui.ServiceActionStart:
			if err := c.process.Start(ctx, binaryPath, configRoot); err != nil {
				return errors.New("VMM foreground start failed")
			}
		case tui.ServiceActionStop:
			if err := c.process.Stop(ctx, binaryPath); err != nil {
				return errors.New("VMM foreground stop failed")
			}
		case tui.ServiceActionRestart:
			if err := c.process.Restart(ctx, binaryPath, configRoot); err != nil {
				return errors.New("VMM foreground restart failed")
			}
		case tui.ServiceActionStatus:
			if _, err := c.process.Status(ctx, binaryPath); err != nil {
				return errors.New("VMM foreground status failed")
			}
		default:
			return errors.New("service registration requires service mode")
		}
	}
	if request.ServiceAction == tui.ServiceActionStart || request.ServiceAction == tui.ServiceActionRestart {
		if err := c.checkRuntimeHealth(ctx, binaryPath, configRoot); err != nil {
			return err
		}
	}
	snapshot, err := c.snapshot(ctx)
	if err != nil {
		return err
	}
	c.emit(events, tui.OperationEvent{Kind: tui.OperationEventProgress, Snapshot: &snapshot, Progress: tui.Progress{Stage: "service", Message: "Lifecycle action completed"}})
	return nil
}

// validateServiceLoggingConfigured prevents an existing foreground installation from registering a service that would write into the package root.
// validateServiceLoggingConfigured 防止已有前台安装注册会向程序包根目录写日志的服务。
func validateServiceLoggingConfigured(configRoot string) error {
	configBytes, err := readConfigBytes(configRoot)
	if err != nil {
		return errors.New("installed configuration could not be read before service registration")
	}
	draft, err := configedit.Parse(configBytes)
	if err != nil {
		return errors.New("installed configuration could not be parsed before service registration")
	}
	directory, err := draft.Get("logging.directory")
	if err != nil || directory.Value == "" || directory.Value != strings.TrimSpace(directory.Value) || !filepath.IsAbs(directory.Value) {
		return errors.New("set logging.directory to a writable absolute path before installing an existing VMM as a service")
	}
	return nil
}

// rollbackServiceAction restores the prior native registration when a durable state write fails.
// rollbackServiceAction 在持久化状态写入失败时恢复此前的系统服务注册。
func rollbackServiceAction(ctx context.Context, client ServiceClient, name string, configRoot string, previous state.ServiceState, wasRunning bool, action tui.ServiceAction) error {
	switch action {
	case tui.ServiceActionInstall:
		if previous.Name != "" {
			return errors.New("previous service registration cannot be recovered after replacement")
		}
		return client.Uninstall(ctx, name)
	case tui.ServiceActionUninstall:
		if err := client.Install(ctx, previous.Name, configRoot, previous.User, previous.AutoStart); err != nil {
			return err
		}
		if wasRunning {
			return client.Start(ctx, previous.Name)
		}
		return nil
	case tui.ServiceActionEnable:
		return client.Disable(ctx, name)
	case tui.ServiceActionDisable:
		return client.Enable(ctx, name)
	default:
		return errors.New("unsupported service rollback action")
	}
}

// pathAction applies one explicit PATH choice and persists its full reversal record.
// pathAction 应用明确的 PATH 选择，并持久化完整撤销记录。
func (c *Controller) pathAction(ctx context.Context, request tui.OperationRequest, events chan<- tui.OperationEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Serialize PATH and metadata updates with installation and service changes to avoid overwriting a newer registration.
	// 将 PATH 与元数据更新同安装和服务修改串行化，避免覆盖更新后的登记。
	releaseLock, err := install.LockInstallation(ctx, c.options.StatePath)
	if err != nil {
		return err
	}
	defer releaseLock()
	installed, err := c.requireState()
	if err != nil {
		return err
	}
	pathState, err := c.applyPath(tui.InstallPlan{AddToPath: request.AddToPath, ProgramRoot: installed.Paths.ProgramRoot}, installed.Paths, installed.PATH)
	if err != nil {
		return err
	}
	installed.PATH = pathState
	if err := state.Save(c.options.StatePath, installed); err != nil {
		return errors.New("PATH state could not be saved")
	}
	snapshot, err := c.snapshot(ctx)
	if err != nil {
		return err
	}
	c.emit(events, tui.OperationEvent{Kind: tui.OperationEventProgress, Snapshot: &snapshot, Progress: tui.Progress{Stage: "path", Message: "PATH choice applied"}})
	return nil
}

// uninstall removes VMM program files and explicitly selected service, PATH, config, and data roots.
// uninstall 删除 VMM 程序文件以及用户明确选择的服务、PATH、配置和数据根目录。
func (c *Controller) uninstall(ctx context.Context, options tui.UninstallOptions, events chan<- tui.OperationEvent) error {
	installed, err := c.requireState()
	if err != nil {
		return err
	}
	if installed.Service.Name != "" {
		if install.FilesIntact(installed) != "" {
			return ErrDamagedServiceControl
		}
		if !options.RemoveService {
			return errors.New("installed VMM service must be removed explicitly before uninstall")
		}
		binaryPath := filepath.Join(installed.Paths.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
		client, err := c.options.ServiceFactory(binaryPath)
		if err != nil {
			return errors.New("VMM service control is unavailable")
		}
		if err := client.Uninstall(ctx, installed.Service.Name); err != nil {
			return errors.New("VMM service removal failed")
		}
	} else if c.process != nil {
		binaryPath := filepath.Join(installed.Paths.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
		if binder, ok := c.process.(processConfigBinder); ok {
			binder.Bind(binaryPath, installed.Paths.ConfigRoot)
		}
		status, statusErr := c.process.Status(ctx, binaryPath)
		if statusErr != nil {
			return errors.New("VMM foreground status failed")
		}
		if status.Running {
			if err := c.process.Stop(ctx, binaryPath); err != nil {
				return errors.New("VMM foreground stop failed")
			}
		}
	}
	if options.RemovePath && installed.PATH.Owner == state.PATHOwnerManager {
		if err := c.removePathRecord(c.controlStateRoot()); err != nil {
			return err
		}
		installed.PATH = emptyPATHState()
	}
	if _, err := install.Uninstall(ctx, install.UninstallRequest{ManagerRoot: c.options.ManagerRoot, Paths: installed.Paths, StatePath: c.options.StatePath, DeleteRegistration: true}); err != nil {
		return errors.New("VMM program uninstall failed")
	}
	if options.RemovePath {
		_ = os.Remove(pathRecordPath(c.controlStateRoot()))
	}
	if !options.KeepConfig {
		if err := removeOwnedRoot(installed.Paths.ConfigRoot); err != nil {
			return errors.New("VMM configuration root could not be removed")
		}
	}
	if !options.KeepData {
		if err := removeOwnedRoot(installed.Paths.DataRoot); err != nil {
			return errors.New("VMM data root could not be removed")
		}
	}
	c.emitProgress(events, "uninstall", "VMM program files were removed")
	return nil
}

// refresh reads the durable registration and reports current service/process state.
// refresh 读取持久化登记并报告当前服务或进程状态。
func (c *Controller) refresh(ctx context.Context, events chan<- tui.OperationEvent) error {
	snapshot, err := c.snapshot(ctx)
	if err != nil {
		return err
	}
	c.emit(events, tui.OperationEvent{Kind: tui.OperationEventProgress, Snapshot: &snapshot, Progress: tui.Progress{Stage: "refresh", Message: "Installation status refreshed"}})
	return nil
}

// activeConfigTarget chooses the staged target first, then the durable installed target.
// activeConfigTarget 优先选择暂存目标，其次选择持久化安装目标。
func (c *Controller) activeConfigTarget() (string, string, error) {
	c.mu.Lock()
	if c.staged != nil {
		binary := filepath.Join(c.staged.packageData.Root, filepath.FromSlash(c.identity.VMMExecutablePath))
		root := c.staged.configRoot
		c.mu.Unlock()
		return binary, root, nil
	}
	c.mu.Unlock()
	installed, err := c.requireState()
	if err != nil {
		return "", "", err
	}
	if install.FilesIntact(installed) != "" {
		return "", "", errors.New("installed VMM files failed integrity verification")
	}
	return filepath.Join(installed.Paths.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath)), installed.Paths.ConfigRoot, nil
}

// stagedSnapshot copies the staged identity while keeping the package lock short.
// stagedSnapshot 复制暂存身份信息，同时让持锁时间保持很短。
func (c *Controller) stagedSnapshot() *stagedPackage {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.staged == nil {
		return nil
	}
	copy := *c.staged
	return &copy
}

// discardStaged releases an abandoned package and its install lock before a different management transaction begins.
// discardStaged 在开始另一项管理事务前释放被放弃的暂存包及安装锁。
func (c *Controller) discardStaged() {
	c.mu.Lock()
	staged := c.staged
	c.staged = nil
	c.mu.Unlock()
	if staged != nil {
		staged.prepared.Close()
		_ = os.RemoveAll(staged.root)
	}
}

// reverifyStagedPackage extracts a fresh authenticated package before any schema or validation process runs.
// reverifyStagedPackage 在运行 schema 或校验进程前重新解包并认证一个新暂存包。
// This closes the interval in which a mutable staging tree could be replaced after the first inspection.
// 这样可以关闭首次检查后可变暂存目录被替换的时间窗口。
func (c *Controller) reverifyStagedPackage(ctx context.Context, staged *stagedPackage) (archive.Package, func(), error) {
	if staged == nil || ctx == nil {
		return archive.Package{}, func() {}, errors.New("staged package is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return archive.Package{}, func() {}, err
	}
	if staged.artifact.Path == "" || filepath.IsAbs(staged.artifact.Path) == false {
		return archive.Package{}, func() {}, errors.New("staged archive path is invalid")
	}
	root, err := os.MkdirTemp(c.options.CacheRoot, ".vmmm-reverify-")
	if err != nil {
		return archive.Package{}, func() {}, err
	}
	extractRoot := filepath.Join(root, "extracted")
	if err := os.MkdirAll(extractRoot, 0o700); err != nil {
		_ = os.RemoveAll(root)
		return archive.Package{}, func() {}, err
	}
	packageData, err := c.options.Extract(ctx, staged.artifact.Path, extractRoot, staged.expected)
	if err != nil {
		_ = os.RemoveAll(root)
		return archive.Package{}, func() {}, err
	}
	cleanup := func() {
		if filepath.Clean(packageData.Root) != filepath.Clean(staged.packageData.Root) {
			_ = os.RemoveAll(root)
		}
	}
	return packageData, cleanup, nil
}

// matchStaged binds a final plan to the exact in-memory package handle.
// matchStaged 将最终计划绑定到精确的内存暂存包句柄。
func (c *Controller) matchStaged(plan tui.InstallPlan) (*stagedPackage, error) {
	if err := validatePlanRoots(plan); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.staged == nil {
		return nil, ErrNoStagedPackage
	}
	if c.staged.planKey != planKey(plan, c.identity.PlatformID) {
		return nil, errors.New("final install plan differs from staged package")
	}
	copy := *c.staged
	return &copy, nil
}

// overlayConfigFields preserves edits already held by the TUI while refreshing authoritative schema metadata.
// overlayConfigFields 在刷新权威 schema 元数据时保留 TUI 已经持有的编辑。
func overlayConfigFields(authoritative []tui.ConfigField, edited []tui.ConfigField) []tui.ConfigField {
	if len(edited) == 0 {
		return authoritative
	}
	values := make(map[string]tui.ConfigField, len(edited))
	for _, field := range edited {
		values[field.Path] = field
	}
	for index := range authoritative {
		field, ok := values[authoritative[index].Path]
		if !ok || !field.Changed || !authoritative[index].Editable {
			continue
		}
		authoritative[index].Value = field.Value
		authoritative[index].Null = field.Null
		authoritative[index].Changed = true
	}
	return authoritative
}

// configFieldsChanged reports whether the returned editable values differ from the previous snapshot.
// configFieldsChanged 报告返回的可编辑值是否与之前快照不同。
func configFieldsChanged(current []tui.ConfigField, previous []tui.ConfigField) bool {
	if len(previous) == 0 {
		return false
	}
	values := make(map[string]tui.ConfigField, len(previous))
	for _, field := range previous {
		values[field.Path] = field
	}
	for _, field := range current {
		if value, ok := values[field.Path]; ok && (value.Value != field.Value || value.Null != field.Null) {
			return true
		}
	}
	return false
}

// buildConfigFiles renders the YAML overlay while retaining the editor's comments and ordering.
// buildConfigFiles 渲染 YAML 覆盖层，同时保留编辑器中的注释和顺序。
func (c *Controller) buildConfigFiles(ctx context.Context, plan tui.InstallPlan, packageRoot string) (map[string][]byte, error) {
	if staged := c.stagedSnapshot(); staged != nil && filepath.Clean(staged.packageData.Root) == filepath.Clean(packageRoot) {
		verified, cleanup, err := c.reverifyStagedPackage(ctx, staged)
		if err != nil {
			return nil, errors.New("staged VMM package could not be reverified")
		}
		defer cleanup()
		packageRoot = verified.Root
	}
	binaryPath := filepath.Join(packageRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
	configRoot := plan.ConfigRoot
	schema, err := c.options.Schema(ctx, binaryPath, configRoot)
	if err != nil {
		return nil, errors.New("VMM configuration schema could not be loaded")
	}
	base, err := readConfigBytes(configRoot)
	if err != nil {
		return nil, errors.New("VMM configuration could not be read")
	}
	editor, err := configflow.New(schema, base)
	if err != nil {
		return nil, errors.New("VMM configuration editor could not be created")
	}
	storage := configflow.StorageOptions{Choice: configflow.StorageChoice(plan.Storage.Mode), LocalDataRoot: plan.StorageSettings.LocalDataRoot, NativeSQLitePath: plan.StorageSettings.NativeSQLitePath, NativeLanceDBPath: plan.StorageSettings.NativeLanceDBPath, PostgresDSNVariable: plan.StorageSettings.PostgreSQLDSNVariable}
	if storage.LocalDataRoot == "" {
		storage.LocalDataRoot = plan.DataRoot
	}
	if storage.NativeSQLitePath == "" {
		storage.NativeSQLitePath = filepath.Join(plan.DataRoot, "database", "sqlite.db")
	}
	if storage.NativeLanceDBPath == "" {
		storage.NativeLanceDBPath = filepath.Join(plan.DataRoot, "database", "lancedb")
	}
	if storage.PostgresDSNVariable == "" {
		storage.PostgresDSNVariable = "VMM_POSTGRES_DSN"
	}
	if plan.Storage.Mode == "" {
		return nil, errors.New("storage mode must be selected")
	}
	installed, alreadyInstalled := c.loadState()
	if alreadyInstalled {
		if plan.Storage.Mode != storageModeFromConfig(installed.Paths.ConfigRoot) {
			return nil, errors.New("changing storage mode requires an explicit data migration")
		}
		// Preserve saved paths unless the user explicitly supplied a replacement, which migration validation will check.
		// 保留已保存路径；仅应用用户明确填写的替换值，再由迁移校验判断是否允许。
		explicitStorage := map[string]string{}
		switch plan.Storage.Mode {
		case tui.StorageNative:
			explicitStorage["sqlite.native.path"] = plan.StorageSettings.NativeSQLitePath
			explicitStorage["lancedb.native.path"] = plan.StorageSettings.NativeLanceDBPath
		case tui.StorageSplit, tui.StorageController:
			explicitStorage["storage.local_data_root"] = plan.StorageSettings.LocalDataRoot
		case tui.StoragePostgreSQL, tui.StorageParadeDB:
			if plan.StorageSettings.PostgreSQLDSNVariable != "" {
				explicitStorage["postgres.dsn"] = "${" + plan.StorageSettings.PostgreSQLDSNVariable + "}"
			}
		}
		for path, value := range explicitStorage {
			if value != "" {
				if err := editor.SetScalar(path, value); err != nil {
					return nil, errors.New("selected storage configuration is incomplete")
				}
			}
		}
	} else if err := editor.ApplyStorage(storage); err != nil {
		return nil, errors.New("selected storage configuration is incomplete")
	}
	// Keep managed logs in the data root for both run modes so a later service conversion does not reopen the administrator-owned package.
	// 两种运行方式均将受管日志放入数据根，避免日后转为服务时重新写入管理员持有的程序包。
	if !alreadyInstalled {
		if err := editor.SetScalar("logging.directory", filepath.Join(plan.DataRoot, "logs")); err != nil {
			return nil, errors.New("managed logging directory is absent from the VMM configuration schema")
		}
	}
	ruleFiles := make(map[string][]byte)
	for _, field := range plan.ConfigFields {
		if field.Path == "" || !field.Editable || !field.Changed {
			continue
		}
		if field.RuleAsset {
			if !validRuleAssetPath(field.Path) || len(field.Value) > maxRuleFileBytes {
				return nil, errors.New("rule asset path or size is invalid")
			}
			ruleFiles[field.Path] = []byte(field.Value)
			continue
		}
		if err := setEditorField(editor, schema, field); err != nil {
			return nil, err
		}
	}
	if err := applyProviderPlan(editor, plan.Providers); err != nil {
		return nil, err
	}
	rendered, err := editor.Render()
	if err != nil {
		return nil, errors.New("VMM configuration could not be rendered")
	}
	if err := validateCredentialReferences(rendered, c.credentialPath(plan)); err != nil {
		return nil, err
	}
	if path := c.credentialPath(plan); path != "" && filepath.Clean(path) != filepath.Join(filepath.Clean(plan.ConfigRoot), ".env") {
		return nil, errors.New("credentials must use .env inside the selected configuration root")
	}
	ruleFiles[defaultConfigFileName] = rendered
	return ruleFiles, nil
}

// setEditorField applies one scalar schema field without guessing unsupported types.
// setEditorField 在不猜测不支持类型的前提下应用一个标量 schema 字段。
func setEditorField(editor *configflow.Editor, schema configbridge.Schema, field tui.ConfigField) error {
	for _, item := range schema.Fields {
		if item.Path != schemaPathForConcrete(field.Path) {
			continue
		}
		if field.Null {
			return editor.SetNull(field.Path)
		}
		if item.Sensitive {
			if err := validateSensitiveReference(item.Type, field.Value); err != nil {
				return err
			}
		}
		switch item.Type {
		case "string", "boolean", "integer", "number", "duration":
			if err := editor.SetScalar(field.Path, field.Value); err != nil {
				return errors.New("configuration field could not be changed")
			}
			return nil
		case "object", "array", "map":
			if strings.TrimSpace(field.Value) == "" {
				return errors.New("structured configuration field cannot be empty")
			}
			if err := editor.SetStructured(field.Path, []byte(field.Value)); err != nil {
				return errors.New("structured configuration field could not be changed")
			}
			if hasSensitiveDescendant(schema.Fields, item.Path) {
				if err := validateStructuredSecrets(editor, schema, field.Path); err != nil {
					return err
				}
			}
			return nil
		default:
			return errors.New("configuration field type is not editable")
		}
	}
	return errors.New("configuration field is absent from the VMM schema")
}

// validateStructuredSecrets checks sensitive descendants after a collection edit, allowing only environment references in the changed subtree.
// validateStructuredSecrets 在集合编辑后检查敏感子字段，仅允许被修改子树中的敏感值使用环境变量引用。
func validateStructuredSecrets(editor *configflow.Editor, schema configbridge.Schema, parent string) error {
	rendered, err := editor.Render()
	if err != nil {
		return errors.New("structured configuration could not be checked")
	}
	draft, err := configedit.Parse(rendered)
	if err != nil {
		return errors.New("structured configuration could not be checked")
	}
	for _, field := range schema.Fields {
		if !field.Sensitive {
			continue
		}
		paths, err := expandSchemaPath(draft, field.Path)
		if err != nil {
			return errors.New("sensitive configuration paths could not be checked")
		}
		for _, path := range paths {
			if !strings.HasPrefix(path, parent+".") && !strings.HasPrefix(path, parent+"[") {
				continue
			}
			value := ""
			if field.Type == "array" {
				value, err = draft.GetStructured(path, configedit.StructuredArray)
			} else {
				var scalar configedit.Scalar
				scalar, err = draft.Get(path)
				value = scalar.Value
			}
			if errors.Is(err, configedit.ErrNotFound) {
				continue
			}
			if err != nil || validateSensitiveReference(field.Type, value) != nil {
				return errors.New("sensitive fields inside collections require environment references")
			}
		}
	}
	return nil
}

// validateSensitiveReference requires edited secrets to remain environment references in YAML.
// validateSensitiveReference 要求新编辑的秘密在 YAML 中保持为环境变量引用。
func validateSensitiveReference(fieldType string, value string) error {
	if fieldType == "string" {
		if validSecretReference(value) {
			return nil
		}
		return errors.New("sensitive configuration fields require a ${NAME} environment reference")
	}
	if fieldType != "array" {
		return errors.New("sensitive structured field cannot be edited directly")
	}
	decoder := yaml.NewDecoder(strings.NewReader(value))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.SequenceNode {
		return errors.New("sensitive array must contain only environment references")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("sensitive array must contain one YAML document")
	}
	for _, element := range document.Content[0].Content {
		if element.Kind != yaml.ScalarNode || element.Tag != "!!str" || !validSecretReference(element.Value) {
			return errors.New("sensitive array must contain only ${NAME} environment references")
		}
	}
	return nil
}

// validSecretReference accepts one complete environment name without evaluating the value.
// validSecretReference 仅接受完整的环境变量名，不解析其实际值。
func validSecretReference(value string) bool {
	if !strings.HasPrefix(value, "${") || !strings.HasSuffix(value, "}") {
		return false
	}
	return credentialNamePattern.MatchString(value[2 : len(value)-1])
}

// displayFields creates a secret-safe schema snapshot for the advanced TUI editor.
// displayFields 为高级 TUI 编辑器创建不泄露秘密的 schema 快照。
func displayFields(schema configbridge.Schema, configBytes []byte, prefix string) ([]tui.ConfigField, error) {
	draft, err := configedit.Parse(configBytes)
	if err != nil {
		return nil, err
	}
	fields := make([]tui.ConfigField, 0, len(schema.Fields))
	concreteFields, err := expandSchemaFields(schema.Fields, draft)
	if err != nil {
		return nil, err
	}
	for _, item := range concreteFields {
		if prefix != "" && item.Path != prefix && !strings.HasPrefix(item.Path, prefix+".") {
			continue
		}
		sensitive := item.Sensitive || hasSensitiveDescendant(schema.Fields, schemaPathForConcrete(item.Path))
		value := ""
		isNull := false
		switch item.Type {
		case "object", "array", "map":
			kind := configedit.StructuredObject
			if item.Type == "array" {
				kind = configedit.StructuredArray
			}
			fragment, readErr := draft.GetStructured(item.Path, kind)
			if readErr == nil {
				value = fragment
			} else if !errors.Is(readErr, configedit.ErrNotFound) {
				return nil, fmt.Errorf("read structured configuration field %q: %w", item.Path, readErr)
			}
		default:
			scalar, readErr := draft.Get(item.Path)
			if readErr == nil {
				value = scalar.Value
				isNull = scalar.Tag == "!!null"
				if isNull {
					value = "null"
				}
			} else if !errors.Is(readErr, configedit.ErrNotFound) && !(errors.Is(readErr, configedit.ErrNotScalar) && (item.Type == "any" || item.Type == "unknown")) {
				return nil, fmt.Errorf("read configuration field %q: %w", item.Path, readErr)
			}
		}
		if sensitive && value != "" {
			value = "<configured>"
		}
		editable := item.Type != "any" && item.Type != "unknown"
		fields = append(fields, tui.ConfigField{Path: item.Path, Type: item.Type, Value: value, Nullable: item.Nullable, Null: isNull, Sensitive: sensitive, Editable: editable, Enum: append([]string(nil), item.Enum...)})
	}
	return fields, nil
}

var schemaConcreteIndex = regexp.MustCompile(`\[[0-9]+\]`)

// schemaPathForConcrete restores template brackets for authoritative schema lookup.
// schemaPathForConcrete 将具体数组下标还原为权威 schema 查询所需的模板括号。
func schemaPathForConcrete(path string) string {
	return schemaConcreteIndex.ReplaceAllString(path, "[]")
}

// expandSchemaFields presents only existing array elements as concrete editable paths.
// expandSchemaFields 仅把现有数组元素展开为可编辑的具体路径。
func expandSchemaFields(fields []configbridge.Field, draft *configedit.Draft) ([]configbridge.Field, error) {
	result := make([]configbridge.Field, 0, len(fields))
	for _, field := range fields {
		paths, err := expandSchemaPath(draft, field.Path)
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			concrete := field
			concrete.Path = path
			result = append(result, concrete)
		}
	}
	return result, nil
}

// expandSchemaPath replaces each array template marker with indexes proven to exist in YAML.
// expandSchemaPath 将数组模板标记替换为已在 YAML 中证实存在的下标。
func expandSchemaPath(draft *configedit.Draft, path string) ([]string, error) {
	marker := strings.Index(path, "[]")
	if marker < 0 {
		return []string{path}, nil
	}
	arrayPath := path[:marker]
	length, err := draft.ArrayLength(arrayPath)
	if errors.Is(err, configedit.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("expand configuration array %q: %w", arrayPath, err)
	}
	result := make([]string, 0, length)
	for index := 0; index < length; index++ {
		concrete := path[:marker] + "[" + strconv.Itoa(index) + "]" + path[marker+2:]
		children, expandErr := expandSchemaPath(draft, concrete)
		if expandErr != nil {
			return nil, expandErr
		}
		result = append(result, children...)
	}
	return result, nil
}

// hasSensitiveDescendant detects secret-bearing schema fields below a structured parent.
// hasSensitiveDescendant 检测结构化父字段之下是否存在携带秘密的 schema 字段。
func hasSensitiveDescendant(fields []configbridge.Field, parent string) bool {
	for _, field := range fields {
		if !field.Sensitive {
			continue
		}
		if strings.HasPrefix(field.Path, parent+".") || strings.HasPrefix(field.Path, parent+"[]") {
			return true
		}
	}
	return false
}

// runtimeCanRestoreService reports whether an old service registration still matches committed roots.
// runtimeCanRestoreService 判断旧服务注册是否仍与提交后的根目录一致。
func (c *Controller) runtimeCanRestoreService(stopped *stoppedRuntime, installed state.State) bool {
	if stopped == nil || stopped.serviceClient == nil {
		return false
	}
	return filepath.Clean(stopped.serviceProgramRoot) == filepath.Clean(installed.Paths.ProgramRoot) && filepath.Clean(stopped.serviceConfigRoot) == filepath.Clean(installed.Paths.ConfigRoot)
}

// recoverPostCommitService keeps durable service state aligned when service reconciliation fails.
// recoverPostCommitService 在服务协调失败时保持持久化服务状态一致。
//
// Recovery only restores the old registration when the committed program and configuration roots
// are unchanged. A cross-root recovery would point state at an old executable, so it is marked as
// unregistered and can be retried explicitly by the service command.
// 只有提交后的程序和配置根未改变时才恢复旧注册。跨根恢复会让状态指向旧可执行文件，因此标记
// 为未注册，用户可以通过服务命令显式重试。
func (c *Controller) recoverPostCommitService(ctx context.Context, installed state.State, old state.State, oldExists bool, stopped *stoppedRuntime, failure error) error {
	if !oldExists || old.Service.Name == "" || !c.runtimeCanRestoreService(stopped, installed) {
		installed.Service = state.ServiceState{}
		if err := state.Save(c.options.StatePath, installed); err != nil {
			return errors.Join(failure, fmt.Errorf("save unregistered service recovery state: %w", err))
		}
		return failure
	}
	if stopped.serviceUninstalled {
		if err := stopped.serviceClient.Install(ctx, old.Service.Name, stopped.serviceConfigRoot, old.Service.User, old.Service.AutoStart); err != nil {
			installed.Service = state.ServiceState{}
			if saveErr := state.Save(c.options.StatePath, installed); saveErr != nil {
				return errors.Join(errors.New("previous VMM service could not be restored"), fmt.Errorf("save unregistered service recovery state: %w", saveErr))
			}
			return errors.New("previous VMM service could not be restored")
		}
	}
	if stopped.serviceWasRunning {
		if err := stopped.serviceClient.Start(ctx, old.Service.Name); err != nil {
			installed.Service = old.Service
			if saveErr := state.Save(c.options.StatePath, installed); saveErr != nil {
				return errors.Join(errors.New("previous VMM service could not be restarted"), fmt.Errorf("save registered service recovery state: %w", saveErr))
			}
			return errors.New("previous VMM service could not be restarted")
		}
	}
	installed.Service = old.Service
	if err := state.Save(c.options.StatePath, installed); err != nil {
		return errors.New("recovered VMM service state could not be saved")
	}
	return failure
}

// applyServiceAfterInstall reconciles the durable service record with the real service manager.
// applyServiceAfterInstall 将持久化服务记录与真实服务管理器对齐。
func (c *Controller) applyServiceAfterInstall(ctx context.Context, plan tui.InstallPlan, installed state.State, old state.State, oldExists bool, stopped *stoppedRuntime) error {
	var newlyInstalledService ServiceClient
	serviceRemoved := stopped != nil && stopped.serviceUninstalled
	if plan.ServiceMode == tui.ServiceModeService {
		if err := validateServiceUserAccess(plan.ServiceUser, c.servicePathChecks(plan, installed.Paths.ConfigRoot, installed.Paths.DataRoot)); err != nil {
			return c.recoverPostCommitService(ctx, installed, old, oldExists, stopped, errors.New("VMM service account cannot access the installed roots"))
		}
		binaryPath := filepath.Join(installed.Paths.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
		client, err := c.options.ServiceFactory(binaryPath)
		if err != nil {
			return c.recoverPostCommitService(ctx, installed, old, oldExists, stopped, errors.New("VMM service control is unavailable"))
		}
		name := c.options.ServiceName
		if err := client.Install(ctx, name, installed.Paths.ConfigRoot, plan.ServiceUser, plan.AutoStart); err != nil {
			// CommitInstall may already have replaced the executable. Re-register the previous
			// service identity against the committed root so a failed new registration does not
			// leave a stopped or missing service without a durable recovery record.
			// CommitInstall 可能已经替换可执行文件。将旧服务身份重新注册到已提交根目录，避免
			// 新注册失败后留下停止或缺失服务且没有持久化恢复记录。
			if oldExists && old.Service.Name != "" {
				if restoreErr := client.Install(ctx, old.Service.Name, installed.Paths.ConfigRoot, old.Service.User, old.Service.AutoStart); restoreErr == nil {
					installed.Service = old.Service
					if stopped != nil && stopped.serviceWasRunning {
						if startErr := client.Start(ctx, old.Service.Name); startErr != nil {
							if saveErr := state.Save(c.options.StatePath, installed); saveErr != nil {
								return errors.Join(errors.New("previous VMM service could not be restarted"), fmt.Errorf("save registered service recovery state: %w", saveErr))
							}
							return errors.New("previous VMM service could not be restarted")
						}
					}
					if saveErr := state.Save(c.options.StatePath, installed); saveErr != nil {
						return errors.Join(errors.New("VMM service installation failed"), fmt.Errorf("save registered service recovery state: %w", saveErr))
					}
					return errors.New("VMM service installation failed; previous registration was restored")
				}
			}
			return c.recoverPostCommitService(ctx, installed, old, oldExists, stopped, errors.New("VMM service installation failed"))
		}
		newlyInstalledService = client
		installed.Service = state.ServiceState{Name: name, User: serviceUserForState(plan.ServiceUser), AutoStart: plan.AutoStart}
	} else if oldExists && old.Service.Name != "" {
		binaryPath := filepath.Join(installed.Paths.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
		client, err := c.options.ServiceFactory(binaryPath)
		if err != nil {
			failure := errors.New("old VMM service cannot be reconciled")
			return c.recoverPostCommitService(ctx, installed, old, oldExists, stopped, failure)
		}
		if !serviceRemoved {
			if err := client.Uninstall(ctx, old.Service.Name); err != nil {
				return c.recoverPostCommitService(ctx, installed, old, oldExists, stopped, errors.New("old VMM service removal failed"))
			}
			serviceRemoved = true
		}
		installed.Service = state.ServiceState{}
	} else {
		installed.Service = state.ServiceState{}
	}
	if err := state.Save(c.options.StatePath, installed); err != nil {
		// CommitInstall already persisted the service state for a newly registered service.
		// CommitInstall 已经为新注册服务持久化了服务状态。
		// Keeping that registration avoids turning a durable new-service state into a missing
		// service when this follow-up state refresh is rejected by the filesystem.
		// 保留该注册可以避免后续状态刷新被文件系统拒绝时，持久化的新服务状态指向不存在的服务。
		if newlyInstalledService == nil && serviceRemoved && oldExists && old.Service.Name != "" {
			oldBinaryPath := filepath.Join(installed.Paths.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
			if oldClient, factoryErr := c.options.ServiceFactory(oldBinaryPath); factoryErr == nil {
				if installErr := oldClient.Install(ctx, old.Service.Name, installed.Paths.ConfigRoot, old.Service.User, old.Service.AutoStart); installErr == nil && stopped != nil && stopped.serviceWasRunning {
					_ = oldClient.Start(ctx, old.Service.Name)
				}
			}
		}
		return errors.New("VMM service state could not be saved")
	}
	return nil
}

// applyPath changes PATH only after the permanent manager target is known and persists exact metadata.
// applyPath 仅在永久管理器目标确定后修改 PATH，并持久化精确元数据。
func (c *Controller) applyPath(plan tui.InstallPlan, paths state.InstallPaths, previous state.PATHState) (state.PATHState, error) {
	if !plan.AddToPath {
		if previous.Owner == state.PATHOwnerManager {
			if err := c.removePathRecord(c.controlStateRoot()); err != nil {
				return state.PATHState{}, err
			}
		} else if previous.Owner == state.PATHOwnerExternal {
			return previous, nil
		}
		return emptyPATHState(), nil
	}
	if previous.Owner == state.PATHOwnerManager {
		if _, found, err := loadPathRecord(c.controlStateRoot()); err != nil {
			return state.PATHState{}, ErrPathRecordUnavailable
		} else if found {
			return previous, nil
		}
	}
	pathClient := c.options.PathFactory()
	if pathClient == nil {
		return state.PATHState{}, errors.New("PATH control is unavailable")
	}
	options, err := c.defaultPathOptions()
	if err != nil {
		return state.PATHState{}, err
	}
	record, err := pathClient.Install(options)
	if err != nil {
		return state.PATHState{}, errors.New("manager PATH integration failed")
	}
	if err := savePathRecord(c.controlStateRoot(), record); err != nil {
		_ = pathClient.Remove(record)
		return state.PATHState{}, ErrPathRecordUnavailable
	}
	return record.Path, nil
}

// controlStateRoot keeps PATH ownership metadata with the manager-owned registration.
// controlStateRoot 将 PATH 所有权记录与管理器持有的安装登记放在同一目录。
func (c *Controller) controlStateRoot() string {
	return filepath.Dir(c.options.StatePath)
}

// removePathRecord loads and safely removes the exact manager-owned PATH integration.
// removePathRecord 读取并安全撤销精确的管理器 PATH 集成。
func (c *Controller) removePathRecord(controlRoot string) error {
	record, found, err := loadPathRecord(controlRoot)
	if err != nil || !found {
		return ErrPathRecordUnavailable
	}
	pathClient := c.options.PathFactory()
	if pathClient == nil {
		return errors.New("PATH control is unavailable")
	}
	if err := pathClient.Remove(record); err != nil {
		return errors.New("manager PATH integration could not be removed")
	}
	if err := os.Remove(pathRecordPath(controlRoot)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrPathRecordUnavailable
	}
	return nil
}

// rollbackPathChange restores the observed PATH integration when durable state persistence fails.
// rollbackPathChange 在持久化状态失败时恢复已观察到的 PATH 集成。
func (c *Controller) rollbackPathChange(paths state.InstallPaths, previous state.PATHState, current state.PATHState) {
	if pathStatesEqual(previous, current) {
		return
	}
	if current.Owner == state.PATHOwnerManager && previous.Owner != state.PATHOwnerManager {
		_ = c.removePathRecord(c.controlStateRoot())
		return
	}
	if previous.Owner != state.PATHOwnerManager || current.Owner == state.PATHOwnerManager {
		return
	}
	pathClient := c.options.PathFactory()
	if pathClient == nil {
		return
	}
	options, err := c.defaultPathOptions()
	if err != nil {
		return
	}
	record, err := pathClient.Install(options)
	if err != nil {
		return
	}
	_ = savePathRecord(c.controlStateRoot(), record)
}

// pathStatesEqual compares the durable PATH portion without relying on slice identity.
// pathStatesEqual 比较持久化 PATH 部分的值，不依赖切片地址。
func pathStatesEqual(left state.PATHState, right state.PATHState) bool {
	if left.Owner != right.Owner || left.Scope != right.Scope || len(left.Entries) != len(right.Entries) {
		return false
	}
	for index := range left.Entries {
		if left.Entries[index] != right.Entries[index] {
			return false
		}
	}
	return true
}

// defaultPathOptions selects the platform's explicit manager command entry.
// defaultPathOptions 选择平台明确的管理器命令入口。
func (c *Controller) defaultPathOptions() (pathctl.Options, error) {
	if runtime.GOOS == "windows" {
		return pathctl.Options{Method: pathctl.MethodWindowsUserPath, Directory: c.options.ManagerRoot}, nil
	}
	if os.Geteuid() == 0 {
		if runtime.GOOS == "darwin" {
			return pathctl.Options{Method: pathctl.MethodDarwinPathsD, Directory: c.options.ManagerRoot, ProfilePath: pathctl.DarwinPathsFile}, nil
		}
		return pathctl.Options{Method: pathctl.MethodUnixSystemBin, Directory: c.options.ManagerRoot, LinkPath: "/usr/local/bin/vmmm", TargetPath: filepath.Join(c.options.ManagerRoot, c.identity.ManagerExecutableName)}, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || filepath.IsAbs(home) == false {
		return pathctl.Options{}, errors.New("user home directory is unavailable")
	}
	return pathctl.Options{Method: pathctl.MethodUnixLocalBin, Directory: c.options.ManagerRoot, LinkPath: filepath.Join(home, ".local", "bin", "vmmm"), TargetPath: filepath.Join(c.options.ManagerRoot, c.identity.ManagerExecutableName)}, nil
}

// snapshot loads the registration file and adds a real service or process status.
// snapshot 读取安装登记文件，并补充真实服务或进程状态。
func (c *Controller) snapshot(ctx context.Context) (tui.InstallationSnapshot, error) {
	installed, err := c.requireState()
	if err != nil {
		if isMissingState(err) {
			return tui.InstallationSnapshot{}, nil
		}
		return tui.InstallationSnapshot{}, err
	}
	snapshot := tui.InstallationSnapshot{Installed: true, ManagerVersion: installed.ManagerVersion, VMMVersion: installed.VMM.Tag, SourceID: installed.DownloadSource.ID, ProgramRoot: installed.Paths.ProgramRoot, ConfigRoot: installed.Paths.ConfigRoot, DataRoot: installed.Paths.DataRoot, ServiceMode: tui.ServiceModeForeground, AutoStart: installed.Service.AutoStart, PathEnabled: installed.PATH.Owner == state.PATHOwnerManager, Storage: storageModeFromConfig(installed.Paths.ConfigRoot), ServiceState: "not-registered"}
	snapshot.SourcePrefix = installed.DownloadSource.CustomPrefix
	snapshot.LastValidation = installed.ConfigValidatedAt
	if installed.Service.Name != "" {
		snapshot.ServiceMode = tui.ServiceModeService
		snapshot.ServiceState = "unverified"
	}
	snapshot.IntegrityIssue = install.FilesIntact(installed)
	snapshot.Incomplete = !installed.InstallationComplete || snapshot.IntegrityIssue != ""
	snapshot.Installed = !snapshot.Incomplete
	if snapshot.IntegrityIssue != "" {
		return snapshot, nil
	}
	if !installed.InstallationComplete {
		snapshot.IntegrityIssue = "installation-not-completed"
	}
	if installed.Service.Name != "" {
		snapshot.ServiceMode = tui.ServiceModeService
		binaryPath := filepath.Join(installed.Paths.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
		client, err := c.options.ServiceFactory(binaryPath)
		if err != nil {
			snapshot.Installed, snapshot.Incomplete, snapshot.IntegrityIssue = false, true, "service-unverified"
			return snapshot, nil
		}
		status, err := client.GetStatus(ctx, installed.Service.Name)
		if err != nil {
			snapshot.Installed, snapshot.Incomplete, snapshot.IntegrityIssue = false, true, "service-unverified"
			return snapshot, nil
		}
		snapshot.ServiceState = status.State
		if status.State == "not-installed" {
			snapshot.Installed, snapshot.Incomplete, snapshot.IntegrityIssue = false, true, "service-missing"
			return snapshot, nil
		}
		snapshot.AutoStart = strings.EqualFold(status.AutoStart, "true") || strings.EqualFold(status.AutoStart, "enabled") || strings.EqualFold(status.StartType, "automatic")
		snapshot.Running = strings.EqualFold(status.State, "running")
	} else if c.process != nil {
		binaryPath := filepath.Join(installed.Paths.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
		if binder, ok := c.process.(processConfigBinder); ok {
			binder.Bind(binaryPath, installed.Paths.ConfigRoot)
		}
		status, err := c.process.Status(ctx, binaryPath)
		if err != nil {
			snapshot.Installed, snapshot.Incomplete, snapshot.IntegrityIssue = false, true, "process-unverified"
			return snapshot, nil
		}
		snapshot.ServiceState = "foreground"
		snapshot.Running = status.Running
	}
	return snapshot, nil
}

// requireState loads a complete durable installation registration.
// requireState 读取完整的持久化安装登记。
func (c *Controller) requireState() (state.State, error) {
	loaded, err := state.Load(c.options.StatePath)
	if err != nil {
		if isMissingState(err) {
			return state.State{}, errors.New("VMM is not installed")
		}
		return state.State{}, errors.New("VMM installation state is invalid")
	}
	return loaded, nil
}

// validateFunc creates the callback required by install after package staging.
// validateFunc 创建 install 在提交前要求的校验回调。
func (c *Controller) validateFunc() install.ValidateFunc {
	return func(ctx context.Context, binaryPath string, configRoot string) (configbridge.ValidationResult, error) {
		return c.options.Validate(ctx, binaryPath, configRoot)
	}
}

// emitProgress emits a bounded progress update for the TUI.
// emitProgress 向 TUI 发出有界进度更新。
func (c *Controller) emitProgress(events chan<- tui.OperationEvent, stage string, message string) {
	c.emit(events, tui.OperationEvent{Kind: tui.OperationEventProgress, Progress: tui.Progress{Stage: stage, Message: message}, Message: message})
}

// emit sends an event without blocking cancellation cleanup or leaking internal errors.
// emit 发送事件时不阻塞取消清理，也不泄漏内部错误。
func (c *Controller) emit(events chan<- tui.OperationEvent, event tui.OperationEvent) {
	select {
	case events <- event:
	default:
	}
}

// safeOperationError converts internal failures to stable user-facing text.
// safeOperationError 将内部失败转换为稳定的用户可见文本。
func safeOperationError(err error) string {
	if errors.Is(err, ErrDamagedServiceControl) {
		return "Service program files are damaged; stop the service with the operating system and restore the verified package at the original program root before retrying"
	}
	if err == nil {
		return "Operation failed"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "Operation cancelled"
	}
	if errors.Is(err, ErrNoStagedPackage) {
		return "No verified VMM package is staged"
	}
	if errors.Is(err, ErrProcessControlUnavailable) {
		return "Foreground process control is unavailable"
	}
	if errors.Is(err, ErrPathRecordUnavailable) {
		return "Manager PATH integration cannot be safely reversed"
	}
	if errors.Is(err, ErrRuntimeNotHealthy) {
		return "VMM runtime did not become healthy; run vmmm doctor for diagnostics"
	}
	return "Operation failed"
}

// sanitizeDiagnostic strips control characters, common secret assignments, and unbounded text.
// sanitizeDiagnostic 移除控制字符、常见秘密赋值以及无界文本。
func sanitizeDiagnostic(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	secretPattern := regexp.MustCompile(`(?i)(api[-_ ]?key|password|passwd|token|secret|dsn)\s*[:=]\s*[^\s,;]+`)
	value = secretPattern.ReplaceAllString(value, "$1=<redacted>")
	if len(value) > maxDiagnosticBytes {
		value = value[:maxDiagnosticBytes]
	}
	return value
}

// validationSummary converts a bridge result to secret-safe TUI diagnostics.
// validationSummary 将桥接结果转换为不泄露秘密的 TUI 诊断。
func validationSummary(result configbridge.ValidationResult) tui.ValidationSummary {
	summary := tui.ValidationSummary{Valid: result.Valid}
	if result.Valid {
		summary.Summary = "VMM configuration is valid"
		return summary
	}
	summary.Summary = "VMM configuration is invalid"
	for _, item := range result.Errors {
		message := sanitizeDiagnostic(item.Message)
		if validDiagnosticPath(item.Path) {
			summary.Errors = append(summary.Errors, item.Path+": "+message)
		} else {
			summary.Errors = append(summary.Errors, message)
		}
	}
	return summary
}

// validDiagnosticPath accepts only schema-like paths before they are displayed.
// validDiagnosticPath 仅在路径符合 schema 形式时允许显示。
func validDiagnosticPath(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._[]-", r) {
			continue
		}
		return false
	}
	return true
}

// cloneTrustKeys prevents release discovery from observing caller mutations.
// cloneTrustKeys 防止发行版本发现过程观察到调用方的并发修改。
func cloneTrustKeys(input map[string]ed25519.PublicKey) map[string]ed25519.PublicKey {
	result := make(map[string]ed25519.PublicKey, len(input))
	for keyID, key := range input {
		result[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	return result
}

// validatePlanRoots checks explicit install roots before network and filesystem work.
// validatePlanRoots 在网络和文件系统操作前检查明确的安装根目录。
func validatePlanRoots(plan tui.InstallPlan) error {
	for _, root := range []string{plan.ProgramRoot, plan.ConfigRoot, plan.DataRoot} {
		if err := validateAbsolutePath(root); err != nil {
			return errors.New("installation roots are invalid")
		}
	}
	return nil
}

// servicePathChecks expands an install plan into all paths the service account will need.
// servicePathChecks 将安装计划展开为服务账户实际需要访问的全部路径。
//
// The list includes the binary root and file, configuration and data roots, selected native
// database and log paths, the generated config file, and the protected dotenv file. This is used both
// before commit and after commit; the second pass validates files actually created by install.
// 列表包括二进制根和文件、配置与数据根、选定的原生数据库与日志路径、生成的配置文件以及受保护
// 的 dotenv 文件。提交前后都会执行，第二次用于校验安装实际创建的文件。
func (c *Controller) servicePathChecks(plan tui.InstallPlan, configRoot string, dataRoot string) []servicePathCheck {
	if configRoot == "" {
		configRoot = plan.ConfigRoot
	}
	if dataRoot == "" {
		dataRoot = plan.DataRoot
	}
	programRoot := plan.ProgramRoot
	checks := make([]servicePathCheck, 0, 12)
	seen := make(map[string]struct{}, 12)
	add := func(path string, writable bool, rootOwned bool) {
		if strings.TrimSpace(path) == "" {
			return
		}
		cleaned := filepath.Clean(path)
		if _, exists := seen[cleaned]; exists {
			return
		}
		seen[cleaned] = struct{}{}
		checks = append(checks, servicePathCheck{path: cleaned, writable: writable, rootOwned: rootOwned})
	}
	add(programRoot, false, true)
	if programRoot != "" {
		add(filepath.Join(programRoot, filepath.FromSlash(c.identity.VMMExecutablePath)), false, true)
	}
	add(configRoot, true, false)
	add(dataRoot, true, false)
	add(filepath.Join(dataRoot, "logs"), true, false)
	add(filepath.Join(configRoot, defaultConfigFileName), false, false)
	add(filepath.Join(configRoot, ".env"), false, false)

	switch plan.Storage.Mode {
	case tui.StorageNative:
		sqlitePath := plan.StorageSettings.NativeSQLitePath
		if sqlitePath == "" {
			sqlitePath = filepath.Join(dataRoot, "database", "sqlite.db")
		}
		lancePath := plan.StorageSettings.NativeLanceDBPath
		if lancePath == "" {
			lancePath = filepath.Join(dataRoot, "database", "lancedb")
		}
		add(filepath.Dir(sqlitePath), true, false)
		add(sqlitePath, true, false)
		add(lancePath, true, false)
	case tui.StorageSplit, tui.StorageController:
		localRoot := plan.StorageSettings.LocalDataRoot
		if localRoot == "" {
			localRoot = dataRoot
		}
		add(localRoot, true, false)
	}
	if credentialPath := c.credentialPath(plan); credentialPath != "" {
		add(credentialPath, false, false)
	}
	return checks
}

// validateAbsolutePath rejects relative, empty, and control-containing paths.
// validateAbsolutePath 拒绝相对、空以及含控制字符的路径。
func validateAbsolutePath(value string) error {
	if strings.TrimSpace(value) == "" || !filepath.IsAbs(value) || strings.ContainsAny(value, "\x00\r\n\t") {
		return errors.New("path is invalid")
	}
	return nil
}

// targetForPlatform returns the closed compilation target paired with each release platform.
// targetForPlatform 返回每个发行平台对应的封闭编译目标。
func targetForPlatform(value string) (string, error) {
	targets := map[string]string{"windows-x64": "x86_64-pc-windows-msvc", "linux-x64": "x86_64-unknown-linux-gnu", "linux-arm64": "aarch64-unknown-linux-gnu", "macos-intel": "x86_64-apple-darwin", "macos-arm64": "aarch64-apple-darwin"}
	target, ok := targets[value]
	if !ok {
		return "", errors.New("current platform is unsupported")
	}
	return target, nil
}

// releaseTagOlderThan compares the numeric core of two verified semantic release tags.
// releaseTagOlderThan 比较两个已验证语义版本标签的数字核心。
// A false comparability result keeps malformed or prerelease-only values fail-closed in install validation.
// 不可比较时返回 false，后续安装校验仍会显式拒绝异常版本。
func releaseTagOlderThan(candidate string, installed string) (older bool, comparable bool) {
	parse := func(value string) ([3]int64, bool) {
		var result [3]int64
		if !strings.HasPrefix(value, "v") {
			return result, false
		}
		core := strings.TrimPrefix(value, "v")
		if separator := strings.IndexByte(core, '-'); separator >= 0 {
			core = core[:separator]
		}
		parts := strings.Split(core, ".")
		if len(parts) != len(result) {
			return result, false
		}
		for index, part := range parts {
			if part == "" || (len(part) > 1 && part[0] == '0') {
				return result, false
			}
			parsed, err := strconv.ParseInt(part, 10, 64)
			if err != nil || parsed < 0 {
				return result, false
			}
			result[index] = parsed
		}
		return result, true
	}
	candidateCore, candidateOK := parse(candidate)
	installedCore, installedOK := parse(installed)
	if !candidateOK || !installedOK {
		return false, false
	}
	for index := range candidateCore {
		if candidateCore[index] != installedCore[index] {
			return candidateCore[index] < installedCore[index], true
		}
	}
	return false, true
}

// sourceState converts the download source into the non-secret state representation.
// sourceState 将下载源转换为不含秘密的状态表示。
func sourceState(source download.Source) state.DownloadSource {
	custom := ""
	if source.Kind == download.SourceKindProxy {
		custom = source.Prefix
	}
	return state.DownloadSource{ID: string(source.ID), CustomPrefix: custom}
}

// serviceStateForPlan converts user execution choices into a validated state value.
// serviceStateForPlan 将用户执行选择转换为经过约束的状态值。
func serviceStateForPlan(plan tui.InstallPlan, defaultName string) state.ServiceState {
	if plan.ServiceMode != tui.ServiceModeService {
		return state.ServiceState{}
	}
	return state.ServiceState{Name: defaultName, User: serviceUserForState(plan.ServiceUser), AutoStart: plan.AutoStart}
}

// serviceUserForState persists Unix identities while keeping Windows state compatible with SCM.
// serviceUserForState 持久化 Unix 账户，同时保持 Windows 状态与 SCM 契约兼容。
func serviceUserForState(value string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return value
}

// emptyPATHState returns the explicit zero PATH value accepted by state.State.
// emptyPATHState 返回 state.State 接受的明确空 PATH 值。
func emptyPATHState() state.PATHState {
	return state.PATHState{Owner: state.PATHOwnerNone, Scope: state.PATHScopeNone, Entries: []string{}}
}

// storageModes converts the authenticated receipt capability list into TUI choices.
// storageModes 将已认证收据能力列表转换为 TUI 选择。
func storageModes(receipt archive.Receipt) []tui.StorageMode {
	result := make([]tui.StorageMode, 0, len(receipt.Capabilities.StorageModes)+2)
	for _, mode := range receipt.Capabilities.StorageModes {
		switch mode {
		case archive.StorageModeNative:
			result = append(result, tui.StorageNative)
		case archive.StorageModeSplit:
			result = append(result, tui.StorageSplit)
		case archive.StorageModeController:
			result = append(result, tui.StorageController)
		case archive.StorageModeCombined:
			if receipt.Capabilities.Combined == nil {
				continue
			}
			for _, flavor := range receipt.Capabilities.Combined.Flavors {
				if flavor == "standard" {
					result = append(result, tui.StoragePostgreSQL)
				}
				if flavor == "paradedb" {
					result = append(result, tui.StorageParadeDB)
				}
			}
		}
	}
	return result
}

// combinedFlavors returns a defensive copy of authenticated combined storage flavors.
// combinedFlavors 返回已认证组合存储风味的防御性副本。
func combinedFlavors(receipt archive.Receipt) []string {
	if receipt.Capabilities.Combined == nil {
		return nil
	}
	return append([]string(nil), receipt.Capabilities.Combined.Flavors...)
}

// planKey creates a stable non-secret identity for the staged package binding.
// planKey 创建用于暂存包绑定的稳定不含秘密身份。
func planKey(plan tui.InstallPlan, platformID string) string {
	return strings.Join([]string{string(plan.Source.Source.ID), plan.Version.Tag, platformID, filepath.Clean(plan.ProgramRoot), filepath.Clean(plan.ConfigRoot), filepath.Clean(plan.DataRoot), strconv.FormatBool(plan.Rollback), strconv.FormatBool(plan.Repair)}, "\x00")
}

// readConfigBytes reads one existing config.yaml or returns an empty mapping.
// readConfigBytes 读取已有 config.yaml，若不存在则返回空映射。
func readConfigBytes(configRoot string) ([]byte, error) {
	if err := validateAbsolutePath(configRoot); err != nil {
		return nil, err
	}
	path := configRoot
	info, err := os.Stat(path)
	if err == nil && info.IsDir() {
		path = filepath.Join(path, defaultConfigFileName)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []byte("{}\n"), nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil || int64(len(data)) > maxConfigBytes {
		return nil, errors.New("configuration file is too large")
	}
	return data, nil
}

// safeRelativePath resolves a config file below its candidate root without traversal.
// safeRelativePath 将配置文件安全解析到候选根目录下并拒绝路径穿越。
func safeRelativePath(root string, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || strings.ContainsAny(relative, "\\\x00\r\n") {
		return "", errors.New("relative path is invalid")
	}
	clean := filepath.Clean(filepath.FromSlash(relative))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("relative path escapes root")
	}
	return filepath.Join(root, clean), nil
}

// isMissingState recognizes the state package's wrapped missing-file errors on all platforms.
// isMissingState 识别 state 包在各平台包装后的缺失文件错误。
func isMissingState(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "cannot find the path") || strings.Contains(message, "no such file or directory")
}

// loadState returns a state snapshot and whether a valid record was found.
// loadState 返回状态快照以及是否找到有效登记。
func (c *Controller) loadState() (state.State, bool) {
	loaded, err := state.Load(c.options.StatePath)
	if err != nil {
		return state.State{}, false
	}
	return loaded, true
}

// pathRecordPath returns the sidecar path below the user data root.
// pathRecordPath 返回用户数据根目录下的 PATH 侧车文件路径。
func pathRecordPath(dataRoot string) string { return filepath.Join(dataRoot, pathRecordFileName) }

// savePathRecord atomically writes a validated path reversal record with private permissions.
// savePathRecord 以原子方式写入经过校验且权限收紧的 PATH 撤销记录。
func savePathRecord(dataRoot string, record pathctl.Record) error {
	if err := record.Validate(); err != nil {
		return err
	}
	if err := validateAbsolutePath(dataRoot); err != nil {
		return err
	}
	if err := os.MkdirAll(dataRoot, 0o700); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	temporary, err := os.CreateTemp(dataRoot, ".vmmm-path-record-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, pathRecordPath(dataRoot)); err != nil {
		return err
	}
	return nil
}

// loadPathRecord strictly decodes the sidecar and rejects untrusted extra data.
// loadPathRecord 严格解码 PATH 侧车并拒绝不可信额外数据。
func loadPathRecord(dataRoot string) (pathctl.Record, bool, error) {
	file, err := os.Open(pathRecordPath(dataRoot))
	if errors.Is(err, os.ErrNotExist) {
		return pathctl.Record{}, false, nil
	}
	if err != nil {
		return pathctl.Record{}, false, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var record pathctl.Record
	if err := decoder.Decode(&record); err != nil {
		return pathctl.Record{}, false, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return pathctl.Record{}, false, errors.New("path record contains trailing data")
	}
	if err := record.Validate(); err != nil {
		return pathctl.Record{}, false, err
	}
	return record, true, nil
}

// removeOwnedRoot removes one explicit user-selected root after refusing symlinks and filesystem roots.
// removeOwnedRoot 删除明确选择的根目录，并拒绝符号链接和文件系统根目录。
func removeOwnedRoot(root string) error {
	if err := validateAbsolutePath(root); err != nil {
		return err
	}
	clean := filepath.Clean(root)
	volume := filepath.VolumeName(clean)
	if volume != "" && strings.EqualFold(clean, volume+string(filepath.Separator)) {
		return errors.New("refusing to remove a filesystem root")
	}
	info, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("selected root is not a real directory")
	}
	if !info.IsDir() {
		return errors.New("selected root is not a directory")
	}
	return os.RemoveAll(clean)
}

// validateCredentialReferences checks an optional dotenv file without reading credential values into errors.
// validateCredentialReferences 检查可选 dotenv 文件，但不会把凭据值写入错误信息。
func validateCredentialReferences(data []byte, dotenvPath string) error {
	if dotenvPath == "" {
		return nil
	}
	if err := validateAbsolutePath(dotenvPath); err != nil || filepath.Base(dotenvPath) != ".env" {
		return errors.New("credential path is invalid")
	}
	document, err := credentials.Load(dotenvPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("credential file could not be read")
	}
	for _, name := range credentialReferences(data) {
		if _, ok, err := document.Value(name); err != nil {
			return errors.New("credential file could not be checked")
		} else if !ok {
			continue
		}
	}
	return nil
}

// credentialReferences extracts only environment-variable names from explicit ${NAME} references.
// credentialReferences 仅从明确的 ${NAME} 引用中提取环境变量名称。
func credentialReferences(data []byte) []string {
	var result []string
	seen := map[string]struct{}{}
	for index := 0; index+3 < len(data); index++ {
		if data[index] != '$' || data[index+1] != '{' {
			continue
		}
		end := bytes.IndexByte(data[index+2:], '}')
		if end < 1 {
			continue
		}
		name := string(data[index+2 : index+2+end])
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(name) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
		index += end + 2
	}
	return result
}

// validateStorageTransition rejects topology changes that need an explicit data migration.
// validateStorageTransition 拒绝必须经过显式数据迁移的存储拓扑变化。
//
// An upgrade may replace binaries and provider settings, but it must not silently point an
// existing installation at an empty database or a different embedding identity. The guard
// compares the effective values already present in the installed YAML with the candidate YAML
// before credentials, services, PATH, or permanent files are changed.
// 升级可以替换二进制和供应商设置，但不能静默指向空数据库或不同的 embedding 身份。该门禁
// 在写入凭据、服务、PATH 或永久文件前比较已安装 YAML 与候选 YAML 的有效值。
func (c *Controller) validateStorageTransition(plan tui.InstallPlan, installed state.State, candidate []byte) error {
	oldBytes, err := readConfigBytes(installed.Paths.ConfigRoot)
	if err != nil {
		return errors.New("installed storage configuration could not be read")
	}
	oldDraft, err := configedit.Parse(oldBytes)
	if err != nil {
		return errors.New("installed storage configuration is invalid")
	}
	candidateDraft, err := configedit.Parse(candidate)
	if err != nil {
		return errors.New("candidate storage configuration is invalid")
	}
	oldMode, err := storageModeFromDraft(oldDraft)
	if err != nil {
		return errors.New("installed storage mode could not be determined")
	}
	candidateMode, err := storageModeFromDraft(candidateDraft)
	if err != nil {
		return errors.New("candidate storage mode could not be determined")
	}
	if oldMode != candidateMode {
		return errors.New("changing storage mode requires an explicit data migration")
	}
	if err := compareRequiredStorageScalar(oldDraft, candidateDraft, "storage.mode"); err != nil {
		return errors.New("storage mode changed without a data migration")
	}
	for _, path := range embeddingIdentityPaths {
		if err := compareOptionalStorageScalar(oldDraft, candidateDraft, path); err != nil {
			return errors.New("embedding identity changed without a data migration")
		}
	}
	switch oldMode {
	case tui.StorageNative:
		for _, path := range []string{"sqlite.native.path", "lancedb.native.path"} {
			if err := compareRequiredStorageScalar(oldDraft, candidateDraft, path); err != nil {
				return errors.New("native database path changed without a data migration")
			}
		}
	case tui.StorageSplit, tui.StorageController:
		if err := compareRequiredStorageScalar(oldDraft, candidateDraft, "storage.local_data_root"); err != nil {
			return errors.New("local data root changed without a data migration")
		}
	case tui.StoragePostgreSQL, tui.StorageParadeDB:
		for _, path := range []string{"storage.combined_provider", "postgres.flavor", "postgres.dsn"} {
			if err := compareRequiredStorageScalar(oldDraft, candidateDraft, path); err != nil {
				return errors.New("PostgreSQL storage identity changed without a data migration")
			}
		}
		if err := c.compareStorageCredential(plan, installed, oldDraft, candidateDraft); err != nil {
			return err
		}
	default:
		return errors.New("installed storage mode is unsupported")
	}
	return nil
}

// embeddingIdentityPaths lists values that determine the vector space of stored memories.
// embeddingIdentityPaths 列出决定已存记忆向量空间的值。
var embeddingIdentityPaths = []string{"embedding.provider", "embedding.model", "embedding.dimension"}

// storageModeFromDraft decodes the selected storage mode without treating a missing key as safe.
// storageModeFromDraft 解码选定的存储模式，不把缺失键当作安全值。
func storageModeFromDraft(draft *configedit.Draft) (tui.StorageMode, error) {
	if draft == nil {
		return "", errors.New("storage draft is unavailable")
	}
	scalar, err := draft.Get("storage.mode")
	if err != nil {
		return "", err
	}
	switch scalar.Value {
	case "native":
		return tui.StorageNative, nil
	case "split":
		return tui.StorageSplit, nil
	case "controller":
		return tui.StorageController, nil
	case "combined":
		flavor, err := draft.Get("postgres.flavor")
		if err != nil {
			return "", err
		}
		if flavor.Value == "paradedb" {
			return tui.StorageParadeDB, nil
		}
		if flavor.Value == "standard" {
			return tui.StoragePostgreSQL, nil
		}
		return "", errors.New("unknown combined storage flavor")
	default:
		return "", errors.New("unknown storage mode")
	}
}

// compareRequiredStorageScalar compares a topology field and rejects either missing side.
// compareRequiredStorageScalar 比较拓扑字段，并拒绝任一侧缺失。
func compareRequiredStorageScalar(oldDraft *configedit.Draft, candidate *configedit.Draft, path string) error {
	oldValue, oldErr := oldDraft.Get(path)
	candidateValue, candidateErr := candidate.Get(path)
	if oldErr != nil || candidateErr != nil {
		return errors.New("required storage field is missing")
	}
	if oldValue.Value != candidateValue.Value {
		return errors.New("storage field changed")
	}
	return nil
}

// compareOptionalStorageScalar compares an embedding identity field when either document declares it.
// compareOptionalStorageScalar 当任一文档声明 embedding 身份字段时比较该字段。
func compareOptionalStorageScalar(oldDraft *configedit.Draft, candidate *configedit.Draft, path string) error {
	oldValue, oldErr := oldDraft.Get(path)
	candidateValue, candidateErr := candidate.Get(path)
	oldMissing := errors.Is(oldErr, configedit.ErrNotFound)
	candidateMissing := errors.Is(candidateErr, configedit.ErrNotFound)
	if oldMissing && candidateMissing {
		return nil
	}
	if oldErr != nil || candidateErr != nil || oldValue.Value != candidateValue.Value {
		return errors.New("embedding identity field changed")
	}
	return nil
}

// compareStorageCredential verifies the actual DSN value when the YAML references dotenv storage.
// compareStorageCredential 当 YAML 引用 dotenv 时校验实际 DSN 值。
//
// The raw value is compared only in memory and never included in an error or progress event.
// 原始值只在内存中比较，绝不会写入错误或进度事件。
func (c *Controller) compareStorageCredential(plan tui.InstallPlan, installed state.State, oldDraft *configedit.Draft, candidate *configedit.Draft) error {
	oldScalar, oldErr := oldDraft.Get("postgres.dsn")
	candidateScalar, candidateErr := candidate.Get("postgres.dsn")
	if oldErr != nil || candidateErr != nil || oldScalar.Value != candidateScalar.Value {
		return errors.New("PostgreSQL DSN changed without a data migration")
	}
	oldNames := credentialReferences([]byte(oldScalar.Value))
	candidateNames := credentialReferences([]byte(candidateScalar.Value))
	if len(oldNames) != 1 || len(candidateNames) != 1 || oldNames[0] != candidateNames[0] {
		return nil
	}
	oldPath := filepath.Join(installed.Paths.ConfigRoot, ".env")
	candidatePath := c.credentialPath(plan)
	if candidatePath == "" {
		candidatePath = filepath.Join(plan.ConfigRoot, ".env")
	}
	if filepath.Clean(oldPath) != filepath.Clean(candidatePath) {
		return errors.New("PostgreSQL credential path changed without a data migration")
	}
	document, err := credentials.Load(oldPath)
	if err != nil {
		return errors.New("installed PostgreSQL credential could not be read")
	}
	oldValue, configured, err := document.Value(oldNames[0])
	if err != nil || !configured {
		return errors.New("installed PostgreSQL credential is not configured")
	}
	candidateValue := oldValue
	if value := strings.TrimSpace(plan.StorageSettings.PostgreSQLDSNValue); value != "" {
		candidateValue = plan.StorageSettings.PostgreSQLDSNValue
	}
	for _, update := range plan.Providers.CredentialUpdates {
		if update.EnvironmentName != candidateNames[0] {
			continue
		}
		if update.KeepExisting || update.Value == "" {
			continue
		}
		candidateValue = update.Value
	}
	if candidateValue != oldValue {
		return errors.New("PostgreSQL DSN changed without a data migration")
	}
	return nil
}

// storageModeFromConfig reads only a stable top-level mode for installed summaries.
// storageModeFromConfig 仅读取已安装摘要所需的稳定顶层模式。
func storageModeFromConfig(configRoot string) tui.StorageMode {
	data, err := readConfigBytes(configRoot)
	if err != nil {
		return ""
	}
	draft, err := configedit.Parse(data)
	if err != nil {
		return ""
	}
	scalar, err := draft.Get("storage.mode")
	if err != nil {
		return ""
	}
	switch scalar.Value {
	case "native":
		return tui.StorageNative
	case "split":
		return tui.StorageSplit
	case "controller":
		return tui.StorageController
	case "combined":
		if flavor, err := draft.Get("postgres.flavor"); err == nil && flavor.Value == "paradedb" {
			return tui.StorageParadeDB
		}
		return tui.StoragePostgreSQL
	default:
		return ""
	}
}

// processctlAdapter maps the controller boundary to the verified processctl package.
// processctlAdapter 将 controller 边界映射到经过身份校验的 processctl 包。
type processctlAdapter struct {
	// statePath is the manager-owned process registration path, separate from installation state.
	// statePath 是独立于安装状态的管理器进程登记路径。
	statePath string
	// mu protects configRoots used when an existing process registration is inspected.
	// mu 保护检查已有进程登记时使用的配置根映射。
	mu sync.Mutex
	// configRoots binds an executable to the configuration root selected by the installed state.
	// configRoots 将可执行文件绑定到安装状态选定的配置根目录。
	configRoots map[string]string
}

// newProcessctlController constructs the default verified foreground adapter.
// newProcessctlController 构造默认的、经过身份校验的前台进程适配器。
func newProcessctlController(statePath string) *processctlAdapter {
	return &processctlAdapter{statePath: statePath + ".process.json", configRoots: make(map[string]string)}
}

// Bind remembers the explicit configuration root before a lifecycle operation.
// Bind 在生命周期操作前记录明确的配置根目录。
func (p *processctlAdapter) Bind(binaryPath string, configRoot string) {
	p.mu.Lock()
	p.configRoots[binaryPath] = configRoot
	p.mu.Unlock()
}

// client constructs a processctl client with fixed executable, config, and state roots.
// client 使用固定的可执行文件、配置根和状态根构造 processctl 客户端。
func (p *processctlAdapter) client(binaryPath string, configRoot string) (*processctl.Client, error) {
	if p == nil || strings.TrimSpace(p.statePath) == "" {
		return nil, errors.New("foreground process control is unavailable")
	}
	if err := validateAbsolutePath(binaryPath); err != nil || validateAbsolutePath(configRoot) != nil || validateAbsolutePath(p.statePath) != nil {
		return nil, errors.New("foreground process arguments are invalid")
	}
	return processctl.New(processctl.Options{BinaryPath: binaryPath, ConfigRoot: configRoot, StatePath: p.statePath})
}

// lookupConfigRoot returns the last bound root or fails closed when it is unknown.
// lookupConfigRoot 返回最近绑定的根目录，未知时显式失败。
func (p *processctlAdapter) lookupConfigRoot(binaryPath string) (string, error) {
	p.mu.Lock()
	configRoot := p.configRoots[binaryPath]
	p.mu.Unlock()
	if configRoot == "" {
		return "", errors.New("foreground process configuration root is unknown")
	}
	return configRoot, nil
}

// Start launches one verified foreground VMM process.
// Start 启动一个经过身份校验的 VMM 前台进程。
func (p *processctlAdapter) Start(ctx context.Context, binaryPath string, configRoot string) error {
	p.Bind(binaryPath, configRoot)
	client, err := p.client(binaryPath, configRoot)
	if err != nil {
		return err
	}
	_, err = client.Start(ctx)
	return err
}

// Stop terminates only the verified foreground VMM process.
// Stop 仅终止经过身份校验的 VMM 前台进程。
func (p *processctlAdapter) Stop(ctx context.Context, binaryPath string) error {
	configRoot, err := p.lookupConfigRoot(binaryPath)
	if err != nil {
		return err
	}
	client, err := p.client(binaryPath, configRoot)
	if err != nil {
		return err
	}
	return client.Stop(ctx)
}

// Restart replaces the verified foreground VMM process.
// Restart 替换经过身份校验的 VMM 前台进程。
func (p *processctlAdapter) Restart(ctx context.Context, binaryPath string, configRoot string) error {
	p.Bind(binaryPath, configRoot)
	client, err := p.client(binaryPath, configRoot)
	if err != nil {
		return err
	}
	_, err = client.Restart(ctx)
	return err
}

// Status reports the verified foreground VMM process state.
// Status 报告经过身份校验的 VMM 前台进程状态。
func (p *processctlAdapter) Status(ctx context.Context, binaryPath string) (ProcessStatus, error) {
	configRoot, err := p.lookupConfigRoot(binaryPath)
	if err != nil {
		return ProcessStatus{}, err
	}
	client, err := p.client(binaryPath, configRoot)
	if err != nil {
		return ProcessStatus{}, err
	}
	status, err := client.Status(ctx)
	if err != nil {
		return ProcessStatus{}, err
	}
	return ProcessStatus{Running: status.State == processctl.StateRunning}, nil
}

// providerPatch exposes the provider wizard through the controller layer without exposing secrets.
// providerPatch 通过 controller 层暴露供应商向导，同时不暴露秘密。
func providerPatch(configuration providerwizard.Configuration) ([]byte, error) {
	return providerwizard.BuildYAMLPatch(configuration)
}

// applyProviderPlan validates typed provider routes and merges their value-free YAML into the preserved draft.
// applyProviderPlan 校验强类型供应商路由，并把只含变量引用的 YAML 合并进保留原貌的草稿。
func applyProviderPlan(editor *configflow.Editor, plan tui.ProviderPlan) error {
	configuration, selected := providerConfiguration(plan)
	if !selected {
		return nil
	}
	patch, err := providerPatch(configuration)
	if err != nil {
		return errors.New("provider configuration is invalid")
	}
	if len(bytes.TrimSpace(patch)) == 0 {
		return nil
	}
	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(patch))
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return errors.New("provider configuration patch is invalid")
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("provider configuration patch is invalid")
	}
	root := document.Content[0]
	for index := 0; index+1 < len(root.Content); index += 2 {
		key := root.Content[index].Value
		path := ""
		switch key {
		case "llm":
			path = "llm.routes"
		case "embedding":
			path = "embedding"
		case "rerank":
			path = "rerank"
		default:
			return errors.New("provider configuration contains an unsupported section")
		}
		value := root.Content[index+1]
		if key == "llm" {
			value = mappingValue(value, "routes")
			if value == nil {
				return errors.New("provider configuration is incomplete")
			}
		}
		fragment, err := encodeYAMLNode(value)
		if err != nil {
			return errors.New("provider configuration patch is invalid")
		}
		if err := editor.SetStructured(path, fragment); err != nil {
			return errors.New("provider configuration is not accepted by the VMM schema")
		}
	}
	return nil
}

// providerConfiguration converts TUI routes to the provider package's source-verified input types.
// providerConfiguration 将 TUI 路由转换为 provider 包基于源码核实的输入类型。
func providerConfiguration(plan tui.ProviderPlan) (providerwizard.Configuration, bool) {
	configuration := providerwizard.Configuration{}
	selected := false
	if len(plan.LLMRoutes) > 0 {
		selected = true
		configuration.LLMRoutes = make([]providerwizard.LLMRouteInput, 0, len(plan.LLMRoutes))
		for _, route := range plan.LLMRoutes {
			configuration.LLMRoutes = append(configuration.LLMRoutes, providerwizard.LLMRouteInput{
				Name: route.Name, Provider: route.Provider, Endpoint: route.Endpoint, Model: route.Model,
				APIKeyEnvironmentNames: append([]string(nil), route.APIKeyEnvironmentNames...),
			})
		}
	}
	if plan.Embedding != nil {
		selected = true
		route := plan.Embedding
		configuration.Embedding = &providerwizard.EmbeddingInput{
			Provider: route.Provider, Endpoint: route.Endpoint, Model: route.Model, Dimension: route.Dimension,
			APIKeyEnvironmentNames: append([]string(nil), route.APIKeyEnvironmentNames...),
		}
	}
	if plan.RerankConfigured || plan.RerankEnabled || len(plan.RerankRoutes) > 0 {
		selected = true
		configuration.Rerank = &providerwizard.RerankInput{Enabled: plan.RerankEnabled, Routes: make([]providerwizard.RerankRouteInput, 0, len(plan.RerankRoutes))}
		for _, route := range plan.RerankRoutes {
			configuration.Rerank.Routes = append(configuration.Rerank.Routes, providerwizard.RerankRouteInput{
				Name: route.Name, Priority: route.Priority, Provider: route.Provider, Endpoint: route.Endpoint, Model: route.Model,
				APIKeyEnvironmentNames: append([]string(nil), route.APIKeyEnvironmentNames...),
			})
		}
	}
	return configuration, selected
}

// mappingValue finds one named child in a YAML mapping emitted by providerwizard.
// mappingValue 在 providerwizard 生成的 YAML 映射中查找指定子节点。
func mappingValue(mapping *yaml.Node, wanted string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == wanted {
			return mapping.Content[index+1]
		}
	}
	return nil
}

// encodeYAMLNode serializes one structured node as a standalone YAML document for configflow.
// encodeYAMLNode 将结构化节点序列化为供 configflow 使用的独立 YAML 文档。
func encodeYAMLNode(node *yaml.Node) ([]byte, error) {
	if node == nil {
		return nil, errors.New("YAML node is nil")
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(node); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// credentialPath chooses the plan-specific dotenv file and never invents a path outside the selected config root.
// credentialPath 选择计划指定的 dotenv 文件，并且不会在选定配置根目录之外臆造路径。
func (c *Controller) credentialPath(plan tui.InstallPlan) string {
	if value := strings.TrimSpace(plan.Providers.CredentialPath); value != "" {
		return value
	}
	if value := strings.TrimSpace(plan.StorageSettings.PostgreSQLCredentialPath); value != "" {
		return value
	}
	if _, selected := providerConfiguration(plan.Providers); selected || len(plan.Providers.CredentialUpdates) > 0 || combinedStorageSelected(plan) {
		return filepath.Join(plan.ConfigRoot, ".env")
	}
	return ""
}

// applyCredentialUpdates writes provider secrets only after dry-run validation and returns a rollback closure.
// applyCredentialUpdates 仅在 dry-run 校验后写入供应商密钥，并返回可回滚闭包。
func (c *Controller) applyCredentialUpdates(plan tui.InstallPlan) (func(), error) {
	updates := append([]tui.CredentialUpdate(nil), plan.Providers.CredentialUpdates...)
	if combinedStorageSelected(plan) && (plan.StorageSettings.PostgreSQLDSNVariable != "" || plan.StorageSettings.PostgreSQLDSNValue != "" || plan.StorageSettings.PostgreSQLCredentialConfigured) {
		variable := strings.TrimSpace(plan.StorageSettings.PostgreSQLDSNVariable)
		if variable == "" {
			variable = "VMM_POSTGRES_DSN"
		}
		updates = append(updates, tui.CredentialUpdate{
			EnvironmentName: variable,
			Value:           plan.StorageSettings.PostgreSQLDSNValue,
			KeepExisting:    plan.StorageSettings.PostgreSQLCredentialConfigured && plan.StorageSettings.PostgreSQLDSNValue == "",
		})
	}
	if len(updates) == 0 {
		return nil, nil
	}
	path := c.credentialPath(plan)
	if err := validateCredentialFilePath(path); err != nil {
		return nil, errors.New("credential path is invalid")
	}
	var serviceOwner *credentials.Owner
	if plan.ServiceMode == tui.ServiceModeService && runtime.GOOS != "windows" {
		uid, gid, err := install.PrepareServiceConfigRoot(filepath.Dir(path), plan.ServiceUser)
		if err != nil {
			return nil, errors.New("service credential directory ownership is invalid")
		}
		serviceOwner = &credentials.Owner{UID: uid, GID: gid}
		if err := credentials.CheckOwner(path, *serviceOwner); err != nil {
			return nil, errors.New("service credential ownership is invalid")
		}
	}
	values := make(map[string]string, len(updates))
	seen := make(map[string]struct{}, len(updates))
	document, loadErr := credentials.Load(path)
	if loadErr != nil {
		return nil, errors.New("credential file could not be read")
	}
	for _, update := range updates {
		name := strings.TrimSpace(update.EnvironmentName)
		if !credentialNamePattern.MatchString(name) {
			return nil, errors.New("credential environment name is invalid")
		}
		canonical := strings.ToUpper(name)
		if _, exists := seen[canonical]; exists {
			return nil, errors.New("credential updates contain duplicate names")
		}
		seen[canonical] = struct{}{}
		if update.Value == "" {
			if !update.KeepExisting {
				return nil, errors.New("credential value is required")
			}
			if _, configured, err := document.Value(name); err != nil || !configured {
				return nil, errors.New("existing credential is unavailable")
			}
			continue
		}
		values[name] = update.Value
	}
	if len(values) == 0 {
		return nil, nil
	}
	var dryRunErr error
	if serviceOwner != nil {
		_, dryRunErr = credentials.DryRunAs(path, values, nil, *serviceOwner)
	} else {
		_, dryRunErr = credentials.DryRun(path, values, nil)
	}
	if dryRunErr != nil {
		return nil, errors.New("credential update is invalid")
	}
	original, existed, _, err := readCredentialBackup(path)
	if err != nil {
		return nil, errors.New("credential file could not be backed up")
	}
	if !existed && serviceOwner == nil {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, errors.New("credential directory could not be prepared")
		}
	}
	var applyErr error
	if serviceOwner != nil {
		_, applyErr = credentials.ApplyAs(path, values, nil, *serviceOwner)
	} else {
		_, applyErr = credentials.Apply(path, values, nil)
	}
	if applyErr != nil {
		return nil, errors.New("credential update failed")
	}
	rollback := func() {
		if existed {
			if serviceOwner != nil {
				_ = credentials.RestoreAs(path, original, *serviceOwner)
				return
			}
			_ = credentials.Restore(path, original)
			return
		}
		_ = os.Remove(path)
	}
	return rollback, nil
}

// combinedStorageSelected reports whether the plan needs a PostgreSQL-compatible credential reference.
// combinedStorageSelected 判断计划是否需要 PostgreSQL 兼容数据库凭据引用。
func combinedStorageSelected(plan tui.InstallPlan) bool {
	mode := string(plan.Storage.Mode)
	return mode == string(tui.StoragePostgreSQL) || mode == string(tui.StorageParadeDB)
}

// readCredentialBackup captures only the pre-commit bytes needed for a failure recovery path.
// readCredentialBackup 只捕获失败恢复所需的提交前原始字节。
func readCredentialBackup(path string) ([]byte, bool, os.FileMode, error) {
	return credentials.ReadSnapshot(path)
}

// validateCredentialFilePath applies the same portable absolute .env rule used by credentials.
// validateCredentialFilePath 应用 credentials 包使用的绝对 .env 文件规则。
func validateCredentialFilePath(path string) error {
	if err := validateAbsolutePath(path); err != nil || filepath.Base(path) != ".env" {
		return errors.New("credential path is invalid")
	}
	return nil
}

// credentialNamePattern validates names before a value-bearing operation reaches credentials.
// credentialNamePattern 在带值操作进入 credentials 前校验变量名。
var credentialNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// credentialDraftConfigured checks only whether each referenced name has an existing value.
// credentialDraftConfigured 只检查每个引用名是否已有值，不返回任何秘密内容。
func credentialDraftConfigured(path string, names []string) bool {
	if path == "" || filepath.Base(path) != ".env" || !filepath.IsAbs(path) {
		return false
	}
	document, err := credentials.Load(path)
	if err != nil {
		return false
	}
	if len(names) == 0 {
		return false
	}
	for _, name := range names {
		value, ok, err := document.Value(name)
		if err != nil || !ok || value == "" {
			return false
		}
	}
	return true
}
