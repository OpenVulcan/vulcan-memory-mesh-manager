// Package install applies verified VMM packages to a stable program root.
// install 包负责把已验签、已解包的 VMM 发行包事务化安装到稳定程序根目录。
//
// The manager executable has a separate lifecycle and is never copied by this package.
// 管理器可执行文件有独立生命周期，本包不会复制或替换管理器自身文件。
package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/archive"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/fetch"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/manifest"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/platform"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
)

const (
	// RegistrationFileName is the manager-owned state filename below the control root.
	// RegistrationFileName 是管理器控制根目录下的状态文件名。
	RegistrationFileName = "installation.json"

	// UserConfigFileName is the default user overlay written below ConfigRoot.
	// UserConfigFileName 是 ConfigRoot 下默认写入的用户覆盖配置文件名。
	UserConfigFileName = "config.yaml"

	// InstallLockFileName serializes all transactions for one control root.
	// InstallLockFileName 串行化同一控制根目录下的全部安装事务。
	InstallLockFileName = ".vmmm-install.lock"

	// transactionPrefix identifies private same-volume transaction directories.
	// transactionPrefix 标识位于同一卷上的私有事务目录。
	transactionPrefix = ".vmmm-install-"

	// maxConfigFileBytes prevents a malformed request from exhausting memory.
	// maxConfigFileBytes 防止异常配置请求耗尽管理器内存。
	maxConfigFileBytes = 64 << 20

	// maxConfigTotalBytes bounds the complete user overlay transaction.
	// maxConfigTotalBytes 限制一次用户覆盖配置事务的总字节数。
	maxConfigTotalBytes = 256 << 20

	// maxReceiptFileBytes bounds the on-disk receipt before strict decoding.
	// maxReceiptFileBytes 限制磁盘 receipt 在严格解码前的最大字节数。
	maxReceiptFileBytes int64 = 16 << 20
)

var (
	// ErrAlreadyInstalled indicates that Install was requested for an existing registration.
	// ErrAlreadyInstalled 表示调用 Install 时发现已有安装登记。
	ErrAlreadyInstalled = errors.New("VMM is already installed; use upgrade")

	// ErrNotInstalled indicates that an upgrade or rollback lacks a registration.
	// ErrNotInstalled 表示升级或回滚缺少现有安装登记。
	ErrNotInstalled = errors.New("VMM installation is not registered")

	// ErrConfigInvalid indicates that the candidate configuration failed runtime validation.
	// ErrConfigInvalid 表示候选配置没有通过 VMM 运行时校验。
	ErrConfigInvalid = errors.New("VMM configuration is invalid")

	// ErrConflict indicates that an existing unmanaged file blocks a safe transaction.
	// ErrConflict 表示现有的非管理文件阻止安全事务继续。
	ErrConflict = errors.New("installation path contains an unmanaged conflict")
)

// Operation identifies the intended lifecycle transition for one VMM package.
// Operation 标识一个 VMM 安装包要执行的生命周期转换。
type Operation string

const (
	// OperationInstall creates a first installation and refuses an existing registration.
	// OperationInstall 创建首次安装，并拒绝已有安装登记。
	OperationInstall Operation = "install"

	// OperationUpgrade replaces the registered package while preserving user data.
	// OperationUpgrade 替换已有登记的程序包，同时保留用户数据。
	OperationUpgrade Operation = "upgrade"

	// OperationRollback applies a caller-provided, already verified older package.
	// OperationRollback 应用调用方提供且已经验证过的旧版本程序包。
	OperationRollback Operation = "rollback"
)

// ValidateFunc validates a candidate VMM binary against a candidate user config root.
// ValidateFunc 使用候选 VMM 可执行文件和候选用户配置根目录执行真实运行时校验。
//
// The callback must invoke the fixed VMM config bridge without a shell.
// 回调必须通过固定的 VMM 配置桥接执行，不能经过 shell。
type ValidateFunc func(context.Context, string, string) (configbridge.ValidationResult, error)

// Request describes one authenticated VMM transaction.
// Request 描述一次经过认证的 VMM 安装事务。
//
// ManagerRoot is informational and is never modified here; the manager's own
// installation is handled by a separate bootstrap/manager transaction.
// ManagerRoot 仅用于表达边界，本包不会修改它；管理器自身安装由独立引导/管理器事务处理。
type Request struct {
	// ManagerRoot is the independent root of the vmmm manager executable.
	// ManagerRoot 是 vmmm 管理器可执行文件所在的独立根目录。
	ManagerRoot string

	// Operation selects install, upgrade, or package-based rollback semantics.
	// Operation 选择首次安装、升级或基于程序包回滚语义。
	Operation Operation

	// ManagerVersion identifies the manager build writing the registration.
	// ManagerVersion 标识写入安装登记的管理器版本。
	ManagerVersion string

	// Manifest is the authenticated VMMM release metadata snapshot.
	// Manifest 是经过认证的 VMMM 发行元数据快照。
	Manifest manifest.VerifiedManifest

	// Artifact is the fetched VMM archive after transport size and digest checks.
	// Artifact 是传输大小和摘要均已校验的 VMM 压缩包。
	Artifact fetch.Result

	// Package is retained for compatibility; StagePackage ignores its root and re-extracts the authenticated artifact.
	// Package 仅为兼容既有调用方保留；StagePackage 不信任其根目录，而是重新解包已认证的归档。
	Package archive.Package

	// Expected binds the extracted package to the exact outer artifact digest.
	// Expected 将已解包程序包绑定到外层资产的精确摘要。
	//
	// Callers copy these values from the verified manifest artifact; StagePackage checks them again during extraction.
	// 调用方应从已验签清单复制这些值；StagePackage 会在解包期间再次检查它们。
	Expected archive.ExpectedRelease

	// Paths separates stable program, user config, and persistent data roots.
	// Paths 分离稳定程序根目录、用户配置根目录和持久化数据根目录。
	Paths state.InstallPaths

	// StatePath is the explicit manager-owned registration path outside Unix service data.
	// StatePath 是明确的管理器状态路径，在 Unix 服务模式下位于服务数据目录之外。
	StatePath string

	// Source records the selected download source without credentials.
	// Source 记录所选下载源，但不保存凭据。
	Source state.DownloadSource

	// Service records service metadata; service adapters apply it outside this package.
	// Service 记录服务元数据；服务适配器在本包之外应用它。
	Service state.ServiceState

	// PATH records PATH ownership; PATH adapters apply it outside this package.
	// PATH 记录 PATH 所有权；PATH 适配器在本包之外应用它。
	PATH state.PATHState

	// ConfigFiles contains explicit user overlay files relative to ConfigRoot.
	// ConfigFiles 包含相对于 ConfigRoot 的明确用户覆盖文件。
	//
	// The map is copied before use and never treated as a package or database tree.
	// 使用前会复制该映射，绝不把它当作程序包或数据库目录处理。
	ConfigFiles map[string][]byte

	// ValidateConfig is required because installation must pass the real VMM validator.
	// ValidateConfig 必须提供，因为正式安装前必须通过真实 VMM 校验器。
	ValidateConfig ValidateFunc
}

// Result describes the committed installation and any configuration files changed.
// Result 描述已经提交的安装结果以及发生变化的配置文件。
type Result struct {
	// State is the atomically persisted registration snapshot.
	// State 是已经原子持久化的安装登记快照。
	State state.State

	// Operation is the lifecycle transition that completed.
	// Operation 是已经完成的生命周期转换。
	Operation Operation

	// ConfigFiles lists user overlay paths replaced or created by the transaction.
	// ConfigFiles 列出事务替换或创建的用户覆盖路径。
	ConfigFiles []string

	// PreservedFiles lists stale or user-modified files intentionally left untouched.
	// PreservedFiles 列出有意保留的过期文件或用户修改过的文件。
	PreservedFiles []string
}

// PreparedPackage is a validated package handle kept between download and final confirmation.
// PreparedPackage 是在下载完成与最终确认之间保留的已校验程序包句柄。
//
// It owns a private re-extracted package tree; Close removes that tree and invalidates the handle.
// 它拥有私有的重新解包目录；Close 删除该目录并使句柄失效，但不删除调用方的压缩包。
type PreparedPackage struct {
	// request is the immutable release and path identity checked during staging.
	// request 是暂存阶段校验过的不可变发行版本和路径身份。
	request Request

	// files is the package inventory hashed during staging.
	// files 是暂存阶段计算摘要的程序包文件清单。
	files []packageFile

	// closed prevents a prepared handle from being reused after cleanup.
	// closed 防止清理后再次使用已准备句柄。
	closed bool

	// stageRoot is the private same-volume extraction root owned by this handle.
	// stageRoot 是此句柄拥有的同卷私有解包根目录。
	stageRoot string

	// lock serializes state reads and promotion until the prepared handle closes.
	// lock 从读取状态到提交完成期间串行化事务，直到准备句柄关闭。
	lock *installLock
}

// StagePackage validates a downloaded and extracted package before the TUI asks for options.
// StagePackage 在 TUI 询问配置选项前校验已下载并解包的程序包。
//
// No program, config, service, PATH, or database path is modified by this function.
// 本函数不会修改程序、配置、服务、PATH 或数据库路径。
func StagePackage(ctx context.Context, request Request) (PreparedPackage, error) {
	if ctx == nil {
		return PreparedPackage{}, errors.New("stage context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return PreparedPackage{}, err
	}
	if err := validateRequestMetadata(request); err != nil {
		return PreparedPackage{}, err
	}
	lock, err := acquireRequestInstallLock(ctx, request.StatePath)
	if err != nil {
		return PreparedPackage{}, err
	}
	keepLock := true
	defer func() {
		if keepLock {
			_ = lock.Close()
		}
	}()
	oldState, registered, err := loadOptionalState(request.StatePath)
	if err != nil {
		return PreparedPackage{}, err
	}
	if err := validateLifecycleState(request, oldState, registered); err != nil {
		return PreparedPackage{}, err
	}
	packageValue, stageRoot, err := extractAuthenticatedPackage(ctx, request)
	if err != nil {
		return PreparedPackage{}, err
	}
	request.Package = packageValue
	if err := validateRequest(request); err != nil {
		_ = os.RemoveAll(stageRoot)
		return PreparedPackage{}, err
	}
	files, err := inspectPackage(request)
	if err != nil {
		_ = os.RemoveAll(stageRoot)
		return PreparedPackage{}, err
	}
	if err := validateProgramConflicts(request.Paths.ProgramRoot, oldState, registered, files); err != nil {
		_ = os.RemoveAll(stageRoot)
		return PreparedPackage{}, err
	}
	request.ConfigFiles = cloneConfigFiles(request.ConfigFiles)
	keepLock = false
	return PreparedPackage{request: request, files: files, stageRoot: stageRoot, lock: lock}, nil
}

// extractAuthenticatedPackage re-extracts the signed artifact into a private same-volume root.
// extractAuthenticatedPackage 将已认证归档重新解到同卷私有根目录，切断调用方 Package 结构的信任链。
func extractAuthenticatedPackage(ctx context.Context, request Request) (archive.Package, string, error) {
	base, err := nearestExistingDirectory(filepath.Dir(filepath.Clean(request.Paths.ProgramRoot)))
	if err != nil {
		return archive.Package{}, "", fmt.Errorf("select package staging directory: %w", err)
	}
	stageRoot, err := os.MkdirTemp(base, ".vmmm-package-")
	if err != nil {
		return archive.Package{}, "", fmt.Errorf("create package staging directory: %w", err)
	}
	packageValue, err := archive.Extract(ctx, request.Artifact.Path, stageRoot, request.Expected)
	if err != nil {
		_ = os.RemoveAll(stageRoot)
		return archive.Package{}, "", fmt.Errorf("extract authenticated VMM package: %w", err)
	}
	return packageValue, stageRoot, nil
}

// acquireRequestInstallLock creates the manager control root and acquires its advisory lock.
// acquireRequestInstallLock 创建管理器控制根目录并获取建议锁。
func acquireRequestInstallLock(ctx context.Context, statePath string) (*installLock, error) {
	controlRoot := filepath.Dir(filepath.Clean(statePath))
	if err := ensureInstallControlRoot(controlRoot); err != nil {
		return nil, fmt.Errorf("prepare installation lock root: %w", err)
	}
	path := filepath.Join(controlRoot, InstallLockFileName)
	lock, err := acquireInstallLock(ctx, path)
	if err != nil {
		return nil, err
	}
	return lock, nil
}

// LockInstallation serializes direct lifecycle changes with staged install transactions; callers must release the returned lock.
// LockInstallation 将直接生命周期变更与暂存安装事务串行化；调用方必须释放返回的锁。
func LockInstallation(ctx context.Context, statePath string) (func() error, error) {
	if err := validateStatePath(statePath); err != nil {
		return nil, err
	}
	lock, err := acquireRequestInstallLock(ctx, statePath)
	if err != nil {
		return nil, err
	}
	return lock.Close, nil
}

// validateInstallLockPath rejects a lock path redirected by a symlink or reparse point.
// validateInstallLockPath 拒绝被符号链接或重解析点重定向的事务锁路径。
func validateInstallLockPath(path string) error {
	if err := validateAbsolutePath("installation lock", path); err != nil {
		return err
	}
	if err := validateDirectoryPath("installation lock parent", filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect installation lock: %w", err)
	}
	if isUnsafePathEntry(path, info) || !info.Mode().IsRegular() {
		return errors.New("installation lock must be a regular non-reparse file")
	}
	return nil
}

// verifyOpenedInstallLock binds the open descriptor to the checked lock pathname.
// verifyOpenedInstallLock 将已打开的锁描述符绑定到已检查的锁路径。
func verifyOpenedInstallLock(path string, file *os.File) error {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect opened installation lock: %w", err)
	}
	if isUnsafePathEntry(path, pathInfo) || !pathInfo.Mode().IsRegular() {
		return errors.New("opened installation lock is not a regular non-reparse file")
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat opened installation lock: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return errors.New("installation lock changed while it was opened")
	}
	return nil
}

// nearestExistingDirectory selects an existing real directory without creating user paths during staging.
// nearestExistingDirectory 选择已存在的真实目录，避免预备阶段创建用户路径。
func nearestExistingDirectory(path string) (string, error) {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if isUnsafePathEntry(current, info) || !info.IsDir() {
				return "", fmt.Errorf("staging ancestor %q must be a real directory", current)
			}
			return current, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("no existing staging ancestor was found")
		}
		current = parent
	}
}

// CommitInstall rechecks a prepared package and performs the final validated transaction.
// CommitInstall 重新校验已准备程序包并执行最终配置校验和安装事务。
//
// Caller-selected config, service, and PATH options may change after staging.
// 暂存后允许调用方更新配置、服务和 PATH 选项。
func (prepared *PreparedPackage) CommitInstall(ctx context.Context, request Request) (Result, error) {
	if prepared == nil || prepared.closed {
		return Result{}, errors.New("prepared package is closed")
	}
	if err := samePreparedRelease(prepared.request, request); err != nil {
		return Result{}, err
	}
	request.Package = prepared.request.Package
	request.ConfigFiles = cloneConfigFiles(request.ConfigFiles)
	return applyPrepared(ctx, request)
}

// Close removes the private extracted package and invalidates the prepared handle.
// Close 删除私有解包目录并使已准备句柄失效，但不会删除调用方拥有的压缩包。
func (prepared *PreparedPackage) Close() {
	if prepared != nil {
		if prepared.stageRoot != "" {
			_ = os.RemoveAll(prepared.stageRoot)
		}
		if prepared.lock != nil {
			_ = prepared.lock.Close()
		}
		prepared.closed = true
		prepared.files = nil
		prepared.stageRoot = ""
		prepared.lock = nil
		prepared.request = Request{}
	}
}

// UninstallRequest describes a data-preserving program-file removal operation.
// UninstallRequest 描述一次保留配置和数据的程序文件卸载操作。
type UninstallRequest struct {
	// ManagerRoot is informational and is not removed by this package.
	// ManagerRoot 仅用于边界说明，本包不会删除它。
	ManagerRoot string

	// Paths must match the registration's recorded roots.
	// Paths 必须与安装登记中记录的根目录一致。
	Paths state.InstallPaths

	// StatePath is the explicit registration path to read and update.
	// StatePath 是要读取和更新的明确登记路径。
	StatePath string

	// DeleteRegistration removes the registration only after all owned files are gone.
	// DeleteRegistration 仅在所有仍由管理器拥有的文件都删除后移除登记。
	DeleteRegistration bool
}

// UninstallResult reports removed and preserved files without touching ConfigRoot or DataRoot contents.
// UninstallResult 报告已删除和已保留文件，且不触碰 ConfigRoot 或 DataRoot 内容。
type UninstallResult struct {
	// State is the remaining registration when changed files require preservation.
	// State 是存在被修改文件需要保留时留下的登记。
	State state.State

	// RemovedFiles contains files whose recorded digest still matched.
	// RemovedFiles 包含登记摘要仍匹配并被删除的文件。
	RemovedFiles []string

	// PreservedFiles contains missing, modified, or unsafe paths left untouched.
	// PreservedFiles 包含缺失、已修改或不安全而被保留的路径。
	PreservedFiles []string

	// RegistrationDeleted reports whether the registration file was removed.
	// RegistrationDeleted 表示安装登记文件是否已被删除。
	RegistrationDeleted bool
}

// Install applies a first-install transaction and rejects an existing registration.
// Install 执行首次安装事务，并拒绝已有登记。
func Install(ctx context.Context, request Request) (Result, error) {
	request.Operation = OperationInstall
	return Apply(ctx, request)
}

// Upgrade replaces the registered VMM package without moving its database tree.
// Upgrade 替换已登记的 VMM 程序包，但不会移动其数据库目录。
func Upgrade(ctx context.Context, request Request) (Result, error) {
	request.Operation = OperationUpgrade
	return Apply(ctx, request)
}

// Rollback applies a caller-provided verified package as a reversible downgrade transaction.
// Rollback 将调用方提供的已验证程序包作为可回滚的降级事务应用。
//
// A rollback without a complete verified package fails closed; no implicit backup is trusted.
// 没有完整已验证程序包的回滚会显式失败，不会信任隐式备份。
func Rollback(ctx context.Context, request Request) (Result, error) {
	request.Operation = OperationRollback
	return Apply(ctx, request)
}

// Apply validates the trust boundary, stages files, validates config, and commits atomically.
// Apply 校验信任边界、暂存文件、校验配置并以事务方式提交。
func Apply(ctx context.Context, request Request) (Result, error) {
	prepared, err := StagePackage(ctx, request)
	if err != nil {
		return Result{}, err
	}
	defer prepared.Close()
	return prepared.CommitInstall(ctx, request)
}

// applyPrepared performs the final transaction using the private package captured by StagePackage.
// applyPrepared 使用 StagePackage 捕获的私有包目录执行最终事务。
func applyPrepared(ctx context.Context, request Request) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("install context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := validateRequest(request); err != nil {
		return Result{}, err
	}
	request.ConfigFiles = cloneConfigFiles(request.ConfigFiles)

	oldState, registered, err := loadOptionalState(request.StatePath)
	if err != nil {
		return Result{}, err
	}
	if err := validateLifecycleState(request, oldState, registered); err != nil {
		return Result{}, err
	}

	files, err := inspectPackage(request)
	if err != nil {
		return Result{}, err
	}
	if err := validateProgramConflicts(request.Paths.ProgramRoot, oldState, registered, files); err != nil {
		return Result{}, err
	}

	programParent := filepath.Dir(filepath.Clean(request.Paths.ProgramRoot))
	if err := os.MkdirAll(programParent, 0o755); err != nil {
		return Result{}, fmt.Errorf("create program parent: %w", err)
	}
	transactionRoot, err := os.MkdirTemp(programParent, transactionPrefix)
	if err != nil {
		return Result{}, fmt.Errorf("create installation transaction: %w", err)
	}
	transaction := newTransaction(transactionRoot)
	defer transaction.cleanup()

	if err := stageProgramFiles(transaction, request.Package.Root, files); err != nil {
		return Result{}, err
	}
	validationRoot, configFiles, cleanupConfig, err := prepareConfigValidationRoot(request, transaction)
	if err != nil {
		return Result{}, err
	}
	defer cleanupConfig()
	if err := validateCandidateConfig(ctx, request, transaction, validationRoot); err != nil {
		return Result{}, err
	}

	if err := prepareServiceOwnership(request); err != nil {
		return Result{}, transaction.fail(err)
	}
	if err := applyConfigFiles(request.Paths.ConfigRoot, validationRoot, configFiles, transaction); err != nil {
		return Result{}, transaction.fail(err)
	}
	if err := assignServiceConfigOwnership(request, configFiles); err != nil {
		return Result{}, transaction.fail(err)
	}
	if err := applyProgramFiles(request.Paths.ProgramRoot, oldState, registered, files, transaction); err != nil {
		return Result{}, transaction.fail(err)
	}
	if err := validateServiceOwnership(request); err != nil {
		return Result{}, transaction.fail(err)
	}

	newState, err := buildState(request, files)
	if err != nil {
		return Result{}, transaction.fail(err)
	}
	if err := saveStateWithPreparation(request.StatePath, request.Paths.DataRoot, newState); err != nil {
		return Result{}, transaction.fail(err)
	}
	transaction.commit()

	return Result{
		State:          newState,
		Operation:      request.Operation,
		ConfigFiles:    append([]string(nil), configFiles...),
		PreservedFiles: transaction.preservedFiles(),
	}, nil
}

// Uninstall removes only owned files whose recorded summaries still match.
// Uninstall 只删除登记摘要仍匹配的管理文件。
//
// ConfigRoot and DataRoot contents are preserved; the registration file is removed only when requested and safe.
// ConfigRoot 与 DataRoot 内容会保留；登记文件仅在调用方请求且操作安全时删除。
func Uninstall(ctx context.Context, request UninstallRequest) (result UninstallResult, returnErr error) {
	if ctx == nil {
		return UninstallResult{}, errors.New("uninstall context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return UninstallResult{}, err
	}
	if err := validateUninstallRequest(request); err != nil {
		return UninstallResult{}, err
	}
	lock, err := acquireRequestInstallLock(ctx, request.StatePath)
	if err != nil {
		return UninstallResult{}, err
	}
	var transaction *fileTransaction
	defer func() {
		if transaction != nil && !transaction.committed && !transaction.rolledBack {
			if cleanupErr := transaction.cleanup(); cleanupErr != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("uninstall transaction cleanup failed: %w", cleanupErr))
				result = UninstallResult{}
			}
		}
		if closeErr := lock.Close(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("release installation lock: %w", closeErr))
			result = UninstallResult{}
		}
	}()
	current, err := state.Load(request.StatePath)
	if err != nil {
		return UninstallResult{}, err
	}
	if err := validateExistingState(current, request.Paths); err != nil {
		return UninstallResult{}, err
	}

	result = UninstallResult{State: current}
	ensureTransaction := func() (*fileTransaction, error) {
		if transaction != nil {
			return transaction, nil
		}
		programParent := filepath.Dir(filepath.Clean(request.Paths.ProgramRoot))
		if err := os.MkdirAll(programParent, 0o755); err != nil {
			return nil, fmt.Errorf("create uninstall transaction parent: %w", err)
		}
		root, err := os.MkdirTemp(programParent, transactionPrefix)
		if err != nil {
			return nil, fmt.Errorf("create uninstall transaction: %w", err)
		}
		transaction = newTransaction(root)
		return transaction, nil
	}
	failTransaction := func(operationErr error) error {
		if transaction == nil {
			return operationErr
		}
		return transaction.fail(operationErr)
	}
	remaining := make([]state.ManagedFile, 0, len(current.ManagedFiles))
	for _, managed := range current.ManagedFiles {
		if err := ctx.Err(); err != nil {
			return UninstallResult{}, err
		}
		if isProtectedProgramPath(managed.Path) {
			remaining = append(remaining, managed)
			result.PreservedFiles = append(result.PreservedFiles, managed.Path)
			continue
		}
		absolute, err := safeProgramPath(request.Paths.ProgramRoot, managed.Path)
		if err != nil {
			return UninstallResult{}, failTransaction(fmt.Errorf("%w: unsafe managed path %q: %v", ErrConflict, managed.Path, err))
		}
		if err := validateDirectoryChain(request.Paths.ProgramRoot, filepath.Dir(absolute)); err != nil {
			return UninstallResult{}, failTransaction(fmt.Errorf("%w: unsafe parent for managed file %q: %v", ErrConflict, managed.Path, err))
		}
		info, err := os.Lstat(absolute)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || isUnsafePathEntry(absolute, info) || !info.Mode().IsRegular() {
			remaining = append(remaining, managed)
			result.PreservedFiles = append(result.PreservedFiles, managed.Path)
			continue
		}
		matches, err := fileMatches(absolute, managed.SHA256, managed.Size)
		if err != nil || !matches {
			remaining = append(remaining, managed)
			result.PreservedFiles = append(result.PreservedFiles, managed.Path)
			continue
		}
		activeTransaction, err := ensureTransaction()
		if err != nil {
			if transaction != nil {
				err = transaction.fail(err)
			}
			return UninstallResult{}, err
		}
		if err := activeTransaction.removeFile(absolute, managed.Path); err != nil {
			return UninstallResult{}, activeTransaction.fail(fmt.Errorf("remove managed file %q: %w", managed.Path, err))
		}
		result.RemovedFiles = append(result.RemovedFiles, managed.Path)
	}

	current.ManagedFiles = remaining
	if len(remaining) == 0 && request.DeleteRegistration {
		if err := validateStatePath(request.StatePath); err != nil {
			return UninstallResult{}, failTransaction(fmt.Errorf("%w: unsafe installation registration path: %v", ErrConflict, err))
		}
		if err := os.Remove(request.StatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			if transaction != nil {
				err = transaction.fail(fmt.Errorf("remove installation registration: %w", err))
				return UninstallResult{}, err
			}
			return UninstallResult{}, fmt.Errorf("remove installation registration: %w", err)
		}
		if transaction != nil {
			transaction.commit()
			transaction.cleanup()
		}
		result.RegistrationDeleted = true
		result.State = state.State{}
		return result, nil
	}
	if err := state.Save(request.StatePath, current); err != nil {
		if transaction != nil {
			err = transaction.fail(err)
			return UninstallResult{}, err
		}
		return UninstallResult{}, err
	}
	if transaction != nil {
		transaction.commit()
		transaction.cleanup()
	}
	result.State = current
	return result, nil
}

// validateRequest checks authenticated metadata and explicit non-overlapping roots.
// validateRequest 校验已认证元数据以及明确且不重叠的根目录。
// releaseVersion is the comparable semantic version form accepted by package archives.
// releaseVersion 是程序包归档接受的可比较语义版本形式。
type releaseVersion struct {
	// major is the canonical major component.
	// major 是规范主版本组件。
	major string
	// minor is the canonical minor component.
	// minor 是规范次版本组件。
	minor string
	// patch is the canonical patch component.
	// patch 是规范修订版本组件。
	patch string
	// prerelease contains ordered prerelease identifiers.
	// prerelease 包含有序的预发行标识符。
	prerelease []string
}

// parseReleaseVersion parses the vMAJOR.MINOR.PATCH release contract without lossy integer conversion.
// parseReleaseVersion 解析 vMAJOR.MINOR.PATCH 发行约定，并避免整数转换溢出。
func parseReleaseVersion(tag string) (releaseVersion, error) {
	if len(tag) < 6 || tag[0] != 'v' {
		return releaseVersion{}, fmt.Errorf("release tag %q is not semantic versioning", tag)
	}
	parts := strings.SplitN(tag[1:], "-", 2)
	core := strings.Split(parts[0], ".")
	if len(core) != 3 {
		return releaseVersion{}, fmt.Errorf("release tag %q must contain major, minor, and patch", tag)
	}
	for _, value := range core {
		if !validDecimalIdentifier(value) {
			return releaseVersion{}, fmt.Errorf("release tag %q has an invalid numeric component", tag)
		}
	}
	version := releaseVersion{major: core[0], minor: core[1], patch: core[2]}
	if len(parts) == 2 {
		if parts[1] == "" {
			return releaseVersion{}, fmt.Errorf("release tag %q has an empty prerelease", tag)
		}
		for _, identifier := range strings.Split(parts[1], ".") {
			if !validPrereleaseIdentifier(identifier) {
				return releaseVersion{}, fmt.Errorf("release tag %q has an invalid prerelease identifier", tag)
			}
			version.prerelease = append(version.prerelease, identifier)
		}
	}
	return version, nil
}

// validDecimalIdentifier accepts a non-empty decimal component without leading zeroes.
// validDecimalIdentifier 接受非空十进制组件，并拒绝前导零。
func validDecimalIdentifier(value string) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

// validPrereleaseIdentifier accepts the ASCII identifiers permitted by the archive receipt schema.
// validPrereleaseIdentifier 接受归档 receipt 允许的 ASCII 预发行标识符。
func validPrereleaseIdentifier(value string) bool {
	if value == "" || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= '0' && character <= '9') || (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || character == '-' {
			continue
		}
		return false
	}
	return !isNumericIdentifier(value) || validDecimalIdentifier(value)
}

// isNumericIdentifier reports whether a prerelease identifier contains only decimal digits.
// isNumericIdentifier 判断预发行标识符是否只包含十进制数字。
func isNumericIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

// compareReleaseVersions returns negative, zero, or positive according to semantic precedence.
// compareReleaseVersions 按语义版本优先级返回负数、零或正数。
func compareReleaseVersions(left releaseVersion, right releaseVersion) int {
	for _, pair := range [][2]string{{left.major, right.major}, {left.minor, right.minor}, {left.patch, right.patch}} {
		if comparison := compareNumericIdentifiers(pair[0], pair[1]); comparison != 0 {
			return comparison
		}
	}
	if len(left.prerelease) == 0 && len(right.prerelease) == 0 {
		return 0
	}
	if len(left.prerelease) == 0 {
		return 1
	}
	if len(right.prerelease) == 0 {
		return -1
	}
	limit := len(left.prerelease)
	if len(right.prerelease) < limit {
		limit = len(right.prerelease)
	}
	for index := 0; index < limit; index++ {
		leftIdentifier, rightIdentifier := left.prerelease[index], right.prerelease[index]
		leftNumeric, rightNumeric := isNumericIdentifier(leftIdentifier), isNumericIdentifier(rightIdentifier)
		if leftNumeric && rightNumeric {
			if comparison := compareNumericIdentifiers(leftIdentifier, rightIdentifier); comparison != 0 {
				return comparison
			}
			continue
		}
		if leftNumeric != rightNumeric {
			if leftNumeric {
				return -1
			}
			return 1
		}
		if leftIdentifier < rightIdentifier {
			return -1
		}
		if leftIdentifier > rightIdentifier {
			return 1
		}
	}
	if len(left.prerelease) < len(right.prerelease) {
		return -1
	}
	if len(left.prerelease) > len(right.prerelease) {
		return 1
	}
	return 0
}

// compareNumericIdentifiers compares canonical decimal strings without integer overflow.
// compareNumericIdentifiers 比较规范十进制字符串，避免整数溢出。
func compareNumericIdentifiers(left string, right string) int {
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

// rejectUpgradeDowngrade permits only forward or equal semantic versions during Upgrade.
// rejectUpgradeDowngrade 只允许 Upgrade 使用相同或更高语义版本，降级必须显式 Rollback。
func rejectUpgradeDowngrade(currentTag string, candidateTag string) error {
	current, err := parseReleaseVersion(currentTag)
	if err != nil {
		return fmt.Errorf("current installed version is invalid: %w", err)
	}
	candidate, err := parseReleaseVersion(candidateTag)
	if err != nil {
		return fmt.Errorf("candidate upgrade version is invalid: %w", err)
	}
	if compareReleaseVersions(candidate, current) < 0 {
		return fmt.Errorf("upgrade from %s to %s is a downgrade; use explicit rollback", currentTag, candidateTag)
	}
	return nil
}

func validateRequest(request Request) error {
	if err := validateRequestMetadata(request); err != nil {
		return err
	}
	tag, err := request.Manifest.Tag()
	if err != nil {
		return err
	}
	commit, err := request.Manifest.Commit()
	if err != nil {
		return err
	}
	platformID := platformIDForRuntime()
	if err := validatePackageIdentity(request.Package, tag, commit, platformID, request.Expected.Target); err != nil {
		return err
	}
	if pathsOverlap(request.Package.Root, request.Paths.ProgramRoot) {
		return errors.New("package staging root must be separate from program root")
	}
	if packageVolume := filepath.VolumeName(request.Package.Root); packageVolume != "" && !strings.EqualFold(packageVolume, filepath.VolumeName(request.Paths.ProgramRoot)) {
		return errors.New("package staging root must be on the same volume as program root")
	}
	return nil
}

// validateRequestMetadata checks trust, roots, artifact bytes, and user overlay bounds before extraction.
// validateRequestMetadata 在解包前校验信任边界、目录、归档字节和用户配置覆盖大小。
func validateRequestMetadata(request Request) error {
	if request.Operation != OperationInstall && request.Operation != OperationUpgrade && request.Operation != OperationRollback {
		return fmt.Errorf("unsupported install operation %q", request.Operation)
	}
	if strings.TrimSpace(request.ManagerVersion) == "" {
		return errors.New("manager version must not be empty")
	}
	if strings.TrimSpace(request.ManagerVersion) != request.ManagerVersion || strings.ContainsAny(request.ManagerVersion, "\x00\r\n") {
		return errors.New("manager version contains surrounding whitespace or control characters")
	}
	if request.ValidateConfig == nil {
		return errors.New("VMM config validator is required")
	}
	if !request.Manifest.IsVerified() {
		return errors.New("release manifest has not been verified")
	}
	product, err := request.Manifest.Product()
	if err != nil || product != manifest.ProductVMM {
		return errors.New("release manifest is not a verified VMM manifest")
	}
	if err := validateAbsolutePath("manager root", request.ManagerRoot); err != nil {
		return err
	}
	if err := validateAbsolutePath("program root", request.Paths.ProgramRoot); err != nil {
		return err
	}
	if err := validateAbsolutePath("config root", request.Paths.ConfigRoot); err != nil {
		return err
	}
	if err := validateAbsolutePath("data root", request.Paths.DataRoot); err != nil {
		return err
	}
	if err := validateAbsolutePath("state path", request.StatePath); err != nil {
		return err
	}
	if runtime.GOOS == "windows" && !isWithin(request.Paths.DataRoot, request.StatePath) {
		return errors.New("state path must be below data root")
	}
	if runtime.GOOS != "windows" {
		// All Unix installs keep control state outside service-writable roots so later service changes and uninstall remain safe.
		// 所有 Unix 安装都将控制状态置于服务可写根之外，确保后续切换服务和卸载仍然安全。
		if err := validateUnixControlStateLocation(request.StatePath, request.ManagerRoot, request.Paths); err != nil {
			return err
		}
	}
	roots := []struct {
		name string
		path string
	}{
		{"manager root", request.ManagerRoot},
		{"program root", request.Paths.ProgramRoot},
		{"config root", request.Paths.ConfigRoot},
		{"data root", request.Paths.DataRoot},
	}
	for index := range roots {
		for next := index + 1; next < len(roots); next++ {
			if pathsOverlap(roots[index].path, roots[next].path) {
				return fmt.Errorf("%s and %s must not overlap", roots[index].name, roots[next].name)
			}
		}
	}
	for _, root := range roots {
		if err := validateDirectoryPath(root.name, root.path); err != nil {
			return err
		}
	}
	if err := validateStatePath(request.StatePath); err != nil {
		return err
	}
	if err := validateServiceOwnership(request); err != nil {
		return err
	}

	tag, err := request.Manifest.Tag()
	if err != nil {
		return err
	}
	if _, err := parseReleaseVersion(tag); err != nil {
		return err
	}
	commit, err := request.Manifest.Commit()
	if err != nil {
		return err
	}
	platformID := platformIDForRuntime()
	if platformID == "" {
		return errors.New("current runtime platform is unsupported")
	}
	artifact, err := request.Manifest.FindArtifact(manifest.ProductVMM, platformID)
	if err != nil {
		return fmt.Errorf("select current VMM artifact: %w", err)
	}
	if request.Artifact.Filename != artifact.Filename || request.Artifact.Bytes != artifact.Bytes || request.Artifact.SHA256 != artifact.SHA256 {
		return errors.New("fetched artifact does not match the authenticated VMM artifact")
	}
	if err := validateAbsolutePath("fetched artifact", request.Artifact.Path); err != nil {
		return err
	}
	if err := validateDirectoryPath("fetched artifact parent", filepath.Dir(filepath.Clean(request.Artifact.Path))); err != nil {
		return err
	}
	if request.Artifact.Bytes <= 0 || request.Artifact.SHA256 == "" {
		return errors.New("fetched artifact size and digest are required")
	}
	if matches, err := fileMatches(request.Artifact.Path, request.Artifact.SHA256, request.Artifact.Bytes); err != nil || !matches {
		if err != nil {
			return fmt.Errorf("verify fetched artifact: %w", err)
		}
		return errors.New("fetched artifact bytes do not match the signed digest")
	}
	if err := validateExpectedRelease(request.Expected, tag, commit, platformID, artifact); err != nil {
		return err
	}
	if err := validateConfigFiles(request.ConfigFiles); err != nil {
		return err
	}
	return nil
}

// cloneConfigFiles copies caller-provided config bytes before any transaction work.
// cloneConfigFiles 在事务处理前复制调用方提供的配置字节。
func cloneConfigFiles(files map[string][]byte) map[string][]byte {
	if files == nil {
		return nil
	}
	copyFiles := make(map[string][]byte, len(files))
	for name, data := range files {
		copyFiles[name] = append([]byte(nil), data...)
	}
	return copyFiles
}

// samePreparedRelease prevents a final confirmation from swapping the staged artifact.
// samePreparedRelease 防止最终确认阶段替换掉已暂存的发行资产。
func samePreparedRelease(prepared Request, request Request) error {
	preparedTag, err := prepared.Manifest.Tag()
	if err != nil {
		return errors.New("prepared manifest is invalid")
	}
	requestTag, err := request.Manifest.Tag()
	if err != nil || requestTag != preparedTag {
		return errors.New("final request release tag differs from prepared package")
	}
	preparedCommit, err := prepared.Manifest.Commit()
	if err != nil {
		return errors.New("prepared manifest is invalid")
	}
	requestCommit, err := request.Manifest.Commit()
	if err != nil || requestCommit != preparedCommit {
		return errors.New("final request release commit differs from prepared package")
	}
	if prepared.Artifact.Path != request.Artifact.Path || prepared.Artifact.Filename != request.Artifact.Filename || prepared.Artifact.Bytes != request.Artifact.Bytes || prepared.Artifact.SHA256 != request.Artifact.SHA256 {
		return errors.New("final request artifact differs from prepared package")
	}
	if prepared.ManagerRoot != request.ManagerRoot || prepared.Expected != request.Expected || prepared.Paths != request.Paths || prepared.Operation != request.Operation {
		return errors.New("final request package identity differs from prepared package")
	}
	return nil
}

// validateUninstallRequest checks roots before any removal is attempted.
// validateUninstallRequest 在执行任何删除前校验根目录。
func validateUninstallRequest(request UninstallRequest) error {
	if err := validateAbsolutePath("manager root", request.ManagerRoot); err != nil {
		return err
	}
	if err := validateAbsolutePath("program root", request.Paths.ProgramRoot); err != nil {
		return err
	}
	if err := validateAbsolutePath("config root", request.Paths.ConfigRoot); err != nil {
		return err
	}
	if err := validateAbsolutePath("data root", request.Paths.DataRoot); err != nil {
		return err
	}
	if err := validateAbsolutePath("state path", request.StatePath); err != nil {
		return err
	}
	if runtime.GOOS == "windows" && !isWithin(request.Paths.DataRoot, request.StatePath) {
		return errors.New("state path must be below data root")
	}
	if runtime.GOOS != "windows" {
		if err := validateUnixControlStateLocation(request.StatePath, request.ManagerRoot, request.Paths); err != nil {
			return err
		}
	}
	if pathsOverlap(request.ManagerRoot, request.Paths.ProgramRoot) || pathsOverlap(request.ManagerRoot, request.Paths.ConfigRoot) || pathsOverlap(request.ManagerRoot, request.Paths.DataRoot) || pathsOverlap(request.Paths.ProgramRoot, request.Paths.ConfigRoot) || pathsOverlap(request.Paths.ProgramRoot, request.Paths.DataRoot) || pathsOverlap(request.Paths.ConfigRoot, request.Paths.DataRoot) {
		return errors.New("uninstall roots must not overlap")
	}
	for _, root := range []struct {
		name string
		path string
	}{
		{"manager root", request.ManagerRoot},
		{"program root", request.Paths.ProgramRoot},
		{"config root", request.Paths.ConfigRoot},
		{"data root", request.Paths.DataRoot},
	} {
		if err := validateDirectoryPath(root.name, root.path); err != nil {
			return err
		}
	}
	return validateStatePath(request.StatePath)
}

// validateUnixControlStateLocation excludes service-owned and executable roots from the control state.
// validateUnixControlStateLocation 禁止把管理器控制状态放入服务可写或程序目录。
func validateUnixControlStateLocation(statePath string, managerRoot string, paths state.InstallPaths) error {
	controlRoot := filepath.Dir(filepath.Clean(statePath))
	for _, root := range []string{managerRoot, paths.ProgramRoot, paths.ConfigRoot, paths.DataRoot} {
		if pathsOverlap(controlRoot, root) {
			return errors.New("Unix control state root must be separate from manager, program, config, and data roots")
		}
	}
	return nil
}

// platformIDForRuntime returns the exact release platform supported by this process.
// platformIDForRuntime 返回当前进程支持的精确发行平台标识。
func platformIDForRuntime() string {
	identity, err := platform.Current()
	if err != nil {
		return ""
	}
	return identity.PlatformID
}

// validateAbsolutePath requires an explicit absolute path with no control characters.
// validateAbsolutePath 要求明确的绝对路径且不允许控制字符。
func validateAbsolutePath(label string, value string) error {
	if value == "" || strings.TrimSpace(value) != value || !filepath.IsAbs(value) || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%s must be an absolute path without surrounding whitespace or control characters", label)
	}
	return nil
}

// validateDirectoryPath permits a missing leaf but rejects symlinked or non-directory ancestors.
// validateDirectoryPath 允许目标目录尚未创建，但拒绝符号链接或非目录的所有上级路径。
func validateDirectoryPath(label string, value string) error {
	current := filepath.Clean(value)
	first := true
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if isUnsafePathEntry(current, info) {
				return fmt.Errorf("%s contains a symlink at %q", label, current)
			}
			if !info.IsDir() {
				if first {
					return fmt.Errorf("%s must be a directory", label)
				}
				return fmt.Errorf("%s parent %q must be a directory", label, current)
			}
			parent := filepath.Dir(current)
			if parent == current {
				return nil
			}
			current = parent
			first = false
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect %s: %w", label, err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
		first = false
	}
}

// validateStatePath permits a missing registration but rejects symlinked or directory state paths.
// validateStatePath 允许登记文件尚不存在，但拒绝符号链接或目录形式的登记路径。
func validateStatePath(path string) error {
	current := filepath.Clean(path)
	first := true
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if first {
				if isUnsafePathEntry(current, info) {
					return errors.New("state path must not be a symbolic link")
				}
				if info.IsDir() || !info.Mode().IsRegular() {
					return errors.New("state path must be a regular file")
				}
			} else if isUnsafePathEntry(current, info) || !info.IsDir() {
				return fmt.Errorf("state path parent %q must be a real directory", current)
			}
			parent := filepath.Dir(current)
			if parent == current {
				return nil
			}
			current = parent
			first = false
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect state path: %w", err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
		first = false
	}
}

// validatePackageIdentity matches receipt identity to the authenticated manifest.
// validatePackageIdentity 将包内 receipt 身份与已认证发行清单匹配。
func validatePackageIdentity(pkg archive.Package, tag string, commit string, platformID string, target string) error {
	if pkg.Receipt.ManifestSchema != archive.ManifestSchemaVersion {
		return fmt.Errorf("unsupported package receipt schema %d", pkg.Receipt.ManifestSchema)
	}
	if pkg.Receipt.Version != tag || pkg.Receipt.Commit != commit || pkg.Receipt.Platform != platformID || pkg.Receipt.Target != target {
		return errors.New("package receipt identity does not match the authenticated release")
	}
	if pkg.Receipt.StorageMode != archive.StorageModeNative || pkg.Receipt.StorageProfile != "all" {
		return errors.New("package does not declare the complete all storage profile")
	}
	if err := validateCapabilities(pkg.Receipt.Capabilities); err != nil {
		return err
	}
	if len(pkg.Receipt.Files) == 0 {
		return errors.New("package receipt has no payload files")
	}
	if pkg.Root == "" || !filepath.IsAbs(pkg.Root) {
		return errors.New("package root must be an absolute path")
	}
	rootInfo, err := os.Lstat(pkg.Root)
	if err != nil || isUnsafePathEntry(pkg.Root, rootInfo) || !rootInfo.IsDir() {
		return errors.New("package root must be a real directory")
	}
	if err := validateDirectoryPath("package root", pkg.Root); err != nil {
		return err
	}
	if filepath.Base(filepath.Clean(pkg.Root)) != "vulcan-memory-mesh-"+tag+"-"+platformID {
		return errors.New("package root name does not match the authenticated release")
	}
	if err := verifyReceiptFile(pkg.Root, pkg.Receipt); err != nil {
		return err
	}
	return nil
}

// verifyReceiptFile ensures the on-disk receipt equals the authenticated archive result.
// verifyReceiptFile 确保磁盘上的 receipt 与已认证的解包结果完全一致。
func verifyReceiptFile(root string, expected archive.Receipt) error {
	path := filepath.Join(root, "release-manifest.json")
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect package receipt: %w", err)
	}
	if isUnsafePathEntry(path, info) || !info.Mode().IsRegular() {
		return errors.New("package receipt must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxReceiptFileBytes {
		return fmt.Errorf("package receipt must be between 1 and %d bytes", maxReceiptFileBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read package receipt: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxReceiptFileBytes+1))
	if err != nil {
		return fmt.Errorf("read package receipt: %w", err)
	}
	if int64(len(data)) > maxReceiptFileBytes {
		return fmt.Errorf("package receipt exceeds %d bytes", maxReceiptFileBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var actual archive.Receipt
	if err := decoder.Decode(&actual); err != nil {
		return fmt.Errorf("decode package receipt: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("package receipt contains trailing JSON")
		}
		return fmt.Errorf("read package receipt end: %w", err)
	}
	if !reflect.DeepEqual(actual, expected) {
		return errors.New("on-disk package receipt differs from the verified archive receipt")
	}
	return nil
}

// validateExpectedRelease binds archive metadata to the authenticated artifact and runtime target.
// validateExpectedRelease 将解包期望元数据绑定到已认证资产和当前运行时目标。
func validateExpectedRelease(expected archive.ExpectedRelease, tag string, commit string, platformID string, artifact manifest.Artifact) error {
	if expected.Version != tag || expected.Commit != commit || expected.Platform != platformID {
		return errors.New("archive expectation does not match the authenticated release")
	}
	if expected.ArchiveBytes != artifact.Bytes || expected.ArchiveSHA256 != artifact.SHA256 {
		return errors.New("archive expectation does not match the signed artifact digest")
	}
	targets := map[string]string{
		"windows-x64": "x86_64-pc-windows-msvc",
		"linux-x64":   "x86_64-unknown-linux-gnu",
		"linux-arm64": "aarch64-unknown-linux-gnu",
		"macos-intel": "x86_64-apple-darwin",
		"macos-arm64": "aarch64-apple-darwin",
	}
	if expected.Target != targets[platformID] {
		return errors.New("archive expectation target does not match the platform")
	}
	return nil
}

// validateCapabilities requires the complete storage profile advertised by VMM releases.
// validateCapabilities 要求 VMM 发行包声明完整存储配置能力。
func validateCapabilities(capabilities archive.Capabilities) error {
	if capabilities.SchemaVersion != 1 {
		return fmt.Errorf("unsupported storage capability schema %d", capabilities.SchemaVersion)
	}
	wanted := map[archive.StorageMode]bool{
		archive.StorageModeSplit:      false,
		archive.StorageModeController: false,
		archive.StorageModeNative:     false,
		archive.StorageModeCombined:   false,
	}
	for _, mode := range capabilities.StorageModes {
		if _, exists := wanted[mode]; !exists {
			return fmt.Errorf("unsupported storage mode %q", mode)
		}
		if wanted[mode] {
			return fmt.Errorf("duplicate storage mode %q", mode)
		}
		wanted[mode] = true
	}
	for mode, seen := range wanted {
		if !seen {
			return fmt.Errorf("complete package is missing storage mode %q", mode)
		}
	}
	if capabilities.Combined == nil || capabilities.Combined.Provider != "postgres" {
		return errors.New("complete package must declare postgres combined storage")
	}
	flavors := map[string]bool{"standard": false, "paradedb": false}
	for _, flavor := range capabilities.Combined.Flavors {
		if _, exists := flavors[flavor]; !exists {
			return fmt.Errorf("unsupported combined storage flavor %q", flavor)
		}
		if flavors[flavor] {
			return fmt.Errorf("duplicate combined storage flavor %q", flavor)
		}
		flavors[flavor] = true
	}
	for flavor, seen := range flavors {
		if !seen {
			return fmt.Errorf("complete package is missing combined storage flavor %q", flavor)
		}
	}
	return nil
}

// validateExistingState ensures an operation cannot silently switch installation roots.
// validateExistingState 确保升级或回滚不会静默切换安装根目录。
func validateExistingState(old state.State, paths state.InstallPaths) error {
	if old.Paths != paths {
		return errors.New("existing installation roots do not match the requested roots")
	}
	if old.VMM.Platform != platformIDForRuntime() {
		return errors.New("existing installation platform does not match the current runtime")
	}
	return nil
}

// validateLifecycleState enforces registration presence and blocks implicit downgrade during Upgrade.
// validateLifecycleState 校验登记存在性，并阻止 Upgrade 隐式降级。
func validateLifecycleState(request Request, old state.State, registered bool) error {
	switch request.Operation {
	case OperationInstall:
		if registered {
			return ErrAlreadyInstalled
		}
	case OperationUpgrade, OperationRollback:
		if !registered {
			return ErrNotInstalled
		}
		if err := validateExistingState(old, request.Paths); err != nil {
			return err
		}
		if request.Operation == OperationUpgrade {
			candidateTag, err := request.Manifest.Tag()
			if err != nil {
				return err
			}
			if err := rejectUpgradeDowngrade(old.VMM.Tag, candidateTag); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported install operation %q", request.Operation)
	}
	return nil
}

// loadOptionalState distinguishes a missing registration from a malformed one.
// loadOptionalState 将缺失登记与损坏登记明确区分。
func loadOptionalState(path string) (state.State, bool, error) {
	loaded, err := state.Load(path)
	if errors.Is(err, os.ErrNotExist) || (err != nil && strings.Contains(err.Error(), "open state file: open ") && strings.Contains(err.Error(), "cannot find the path")) {
		return state.State{}, false, nil
	}
	if err != nil {
		return state.State{}, false, err
	}
	return loaded, true, nil
}

// packageFile records one verified package payload file.
// packageFile 记录一个已经重新摘要校验的程序包文件。
type packageFile struct {
	// Relative is the forward-slash path below ProgramRoot.
	// Relative 是相对于 ProgramRoot 的正斜杠路径。
	Relative string

	// Source is the absolute path below the verified package root.
	// Source 是已验证程序包根目录下的绝对源路径。
	Source string

	// SHA256 is the lowercase content digest.
	// SHA256 是内容的小写摘要。
	SHA256 string

	// Size is the exact file size.
	// Size 是文件的精确字节数。
	Size int64

	// Mode preserves only portable permission bits.
	// Mode 仅保留可移植权限位。
	Mode os.FileMode
}

// inspectPackage walks the extracted package and rechecks its receipt inventory.
// inspectPackage 遍历已解包程序包并重新校验包内文件清单。
func inspectPackage(request Request) ([]packageFile, error) {
	root := filepath.Clean(request.Package.Root)
	files := make([]packageFile, 0, len(request.Package.Receipt.Files)+1)
	seen := make(map[string]struct{})
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relativeOS, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative := filepath.ToSlash(relativeOS)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if isUnsafePathEntry(path, info) {
			return fmt.Errorf("package path %q is a symbolic link or reparse point", relative)
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("package path %q is not a regular file", relative)
		}
		if isProtectedProgramPath(relative) {
			return fmt.Errorf("package must not contain protected database path %q", relative)
		}
		expectedDigest, listed := request.Package.Receipt.Files[relative]
		if relative == "release-manifest.json" {
			if listed {
				return errors.New("package receipt must not list itself")
			}
		} else if !listed {
			return fmt.Errorf("package file %q is missing from receipt", relative)
		}
		digest, size, err := digestFile(path)
		if err != nil {
			return err
		}
		if listed && digest != expectedDigest {
			return fmt.Errorf("package file %q digest does not match receipt", relative)
		}
		if _, exists := seen[relative]; exists {
			return fmt.Errorf("package file %q appears more than once", relative)
		}
		seen[relative] = struct{}{}
		files = append(files, packageFile{Relative: relative, Source: path, SHA256: digest, Size: size, Mode: info.Mode().Perm()})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("inspect extracted package: %w", err)
	}
	if len(files) == 0 || len(seen) != len(request.Package.Receipt.Files)+1 {
		return nil, errors.New("package file inventory does not exactly match its receipt")
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Relative < files[right].Relative })
	return files, nil
}

// validateProgramConflicts prevents unmanaged files from being overwritten.
// validateProgramConflicts 防止覆盖不属于管理器的现有文件。
func validateProgramConflicts(programRoot string, old state.State, registered bool, files []packageFile) error {
	rootInfo, err := os.Lstat(programRoot)
	if err == nil && (isUnsafePathEntry(programRoot, rootInfo) || !rootInfo.IsDir()) {
		return errors.New("program root must be a real directory")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect program root: %w", err)
	}
	oldFiles := make(map[string]state.ManagedFile, len(old.ManagedFiles))
	for _, item := range old.ManagedFiles {
		oldFiles[item.Path] = item
	}
	for _, item := range files {
		target, err := safeProgramPath(programRoot, item.Relative)
		if err != nil {
			return err
		}
		info, err := os.Lstat(target)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect program file %q: %w", item.Relative, err)
		}
		if err := validateDirectoryChain(programRoot, filepath.Dir(target)); err != nil {
			return fmt.Errorf("inspect program parent for %q: %w", item.Relative, err)
		}
		if isUnsafePathEntry(target, info) || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: program file %q is not a regular file", ErrConflict, item.Relative)
		}
		matches, err := fileMatches(target, item.SHA256, item.Size)
		if err != nil {
			return err
		}
		if matches {
			continue
		}
		previous, known := oldFiles[item.Relative]
		if !registered || !known {
			return fmt.Errorf("%w: existing file %q is not managed by this installation", ErrConflict, item.Relative)
		}
		previousMatches, err := fileMatches(target, previous.SHA256, previous.Size)
		if err != nil {
			return err
		}
		if !previousMatches {
			return fmt.Errorf("%w: existing managed file %q was modified", ErrConflict, item.Relative)
		}
	}
	return nil
}

// validateDirectoryChain rejects symlinked or non-directory parents before promotion.
// validateDirectoryChain 在推广文件前拒绝符号链接或非目录父路径。
func validateDirectoryChain(root string, targetParent string) error {
	root = filepath.Clean(root)
	targetParent = filepath.Clean(targetParent)
	if !isWithin(root, targetParent) {
		return errors.New("target parent escapes installation root")
	}
	relative, err := filepath.Rel(root, targetParent)
	if err != nil {
		return err
	}
	current := root
	if err := inspectDirectoryOrMissing(current); err != nil {
		return err
	}
	if relative == "." {
		return nil
	}
	for _, component := range strings.Split(filepath.ToSlash(relative), "/") {
		current = filepath.Join(current, component)
		if err := inspectDirectoryOrMissing(current); err != nil {
			return err
		}
	}
	return nil
}

// inspectDirectoryOrMissing allows a missing directory but never follows an existing symlink.
// inspectDirectoryOrMissing 允许目录尚未创建，但绝不跟随已有符号链接。
func inspectDirectoryOrMissing(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if isUnsafePathEntry(path, info) || !info.IsDir() {
		return errors.New("path component is not a real directory")
	}
	return nil
}

// stageProgramFiles copies package files into the private same-volume transaction tree.
// stageProgramFiles 将程序包文件复制到同卷私有事务目录。
func stageProgramFiles(transaction *fileTransaction, packageRoot string, files []packageFile) error {
	for _, item := range files {
		destination := filepath.Join(transaction.newRoot, filepath.FromSlash(item.Relative))
		if err := copyVerifiedFile(item.Source, destination, item.SHA256, item.Size, item.Mode); err != nil {
			return fmt.Errorf("stage program file %q: %w", item.Relative, err)
		}
	}
	return nil
}

// prepareConfigValidationRoot creates a complete candidate user overlay tree.
// prepareConfigValidationRoot 创建完整的候选用户覆盖配置树。
func prepareConfigValidationRoot(request Request, transaction *fileTransaction) (string, []string, func(), error) {
	configRoot := filepath.Clean(request.Paths.ConfigRoot)
	// Keep candidate configuration inside the already-created transaction root so validation
	// cannot create a user config parent before the final commit decision.
	// 将候选配置放在已创建的事务根中，避免最终提交决定前创建用户配置父目录。
	validationRoot, err := os.MkdirTemp(transaction.root, ".vmmm-config-")
	if err != nil {
		return "", nil, func() {}, fmt.Errorf("create config validation root: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(validationRoot) }
	if info, err := os.Lstat(configRoot); err == nil {
		if isUnsafePathEntry(configRoot, info) || !info.IsDir() {
			cleanup()
			return "", nil, func() {}, errors.New("config root must be a real directory")
		}
		if err := copyTree(configRoot, validationRoot); err != nil {
			cleanup()
			return "", nil, func() {}, fmt.Errorf("copy existing config root: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		cleanup()
		return "", nil, func() {}, fmt.Errorf("inspect config root: %w", err)
	}
	configPaths := make([]string, 0, len(request.ConfigFiles))
	keys := make([]string, 0, len(request.ConfigFiles))
	for key := range request.ConfigFiles {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, relative := range keys {
		destination := filepath.Join(validationRoot, filepath.FromSlash(relative))
		if err := copyBytesFile(destination, request.ConfigFiles[relative], 0o600); err != nil {
			cleanup()
			return "", nil, func() {}, fmt.Errorf("stage config file %q: %w", relative, err)
		}
		configPaths = append(configPaths, relative)
	}
	return validationRoot, configPaths, cleanup, nil
}

// PrepareCandidateConfig copies an existing override tree and overlays files in a private staging directory; callers must invoke cleanup.
// PrepareCandidateConfig 在私有暂存目录复制现有覆盖树并叠加文件；调用方必须执行返回的清理函数。
func PrepareCandidateConfig(configRoot, stagingParent string, files map[string][]byte) (string, func(), error) {
	if err := validateDirectoryPath("config root", configRoot); err != nil {
		return "", func() {}, err
	}
	if err := validateDirectoryPath("staging parent", stagingParent); err != nil {
		return "", func() {}, err
	}
	if err := validateConfigFiles(files); err != nil {
		return "", func() {}, err
	}
	root, _, cleanup, err := prepareConfigValidationRoot(Request{Paths: state.InstallPaths{ConfigRoot: configRoot}, ConfigFiles: files}, &fileTransaction{root: stagingParent})
	return root, cleanup, err
}

// validateCandidateConfig invokes the runtime validator before any program promotion.
// validateCandidateConfig 在程序包正式替换前调用运行时校验器。
func validateCandidateConfig(ctx context.Context, request Request, transaction *fileTransaction, validationRoot string) error {
	identity, err := platform.Resolve(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	binaryPath := filepath.Join(transaction.newRoot, filepath.FromSlash(identity.VMMExecutablePath))
	result, err := request.ValidateConfig(ctx, binaryPath, validationRoot)
	if err != nil {
		return fmt.Errorf("validate candidate VMM configuration: %w", err)
	}
	if !result.Valid || len(result.Errors) != 0 {
		return fmt.Errorf("%w: %s", ErrConfigInvalid, formatValidationErrors(result.Errors))
	}
	return nil
}

// formatValidationErrors renders only bridge-supplied redacted diagnostics.
// formatValidationErrors 仅渲染桥接层提供的已脱敏诊断。
func formatValidationErrors(items []configbridge.ValidationError) string {
	if len(items) == 0 {
		return "runtime validator rejected the configuration"
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		if item.Path == "" {
			parts = append(parts, item.Message)
		} else {
			parts = append(parts, item.Path+": "+item.Message)
		}
	}
	return strings.Join(parts, "; ")
}

// applyConfigFiles promotes only explicitly requested user overlay files with rollback backups.
// applyConfigFiles 仅推广调用方明确请求的用户覆盖文件，并保留回滚备份。
func applyConfigFiles(configRoot string, validationRoot string, configFiles []string, transaction *fileTransaction) error {
	if len(configFiles) == 0 {
		return nil
	}
	if err := validateDirectoryPath("config root", configRoot); err != nil {
		return err
	}
	if err := os.MkdirAll(configRoot, 0o700); err != nil {
		return fmt.Errorf("create config root: %w", err)
	}
	for _, relative := range configFiles {
		source := filepath.Join(validationRoot, filepath.FromSlash(relative))
		target, err := safeConfigPath(configRoot, relative)
		if err != nil {
			return err
		}
		if err := validateDirectoryChain(configRoot, filepath.Dir(target)); err != nil {
			return fmt.Errorf("inspect config parent for %q: %w", relative, err)
		}
		if err := transaction.replaceConfigFile(source, configRoot, relative, 0o600); err != nil {
			return fmt.Errorf("apply config file %q: %w", relative, err)
		}
	}
	return nil
}

// applyProgramFiles promotes program files and removes only unchanged stale managed files.
// applyProgramFiles 推广程序文件，并仅删除摘要未变化的过期管理文件。
func applyProgramFiles(programRoot string, old state.State, registered bool, files []packageFile, transaction *fileTransaction) error {
	if err := validateDirectoryPath("program root", programRoot); err != nil {
		return err
	}
	if err := os.MkdirAll(programRoot, 0o755); err != nil {
		return fmt.Errorf("create program root: %w", err)
	}
	for _, item := range files {
		target, err := safeProgramPath(programRoot, item.Relative)
		if err != nil {
			return err
		}
		source := filepath.Join(transaction.newRoot, filepath.FromSlash(item.Relative))
		if err := transaction.replaceFile(source, target, item.Mode); err != nil {
			return fmt.Errorf("apply program file %q: %w", item.Relative, err)
		}
	}
	if !registered {
		return nil
	}
	newFiles := make(map[string]struct{}, len(files))
	for _, item := range files {
		newFiles[item.Relative] = struct{}{}
	}
	for _, previous := range old.ManagedFiles {
		if _, stillPresent := newFiles[previous.Path]; stillPresent || isProtectedProgramPath(previous.Path) {
			continue
		}
		target, err := safeProgramPath(programRoot, previous.Path)
		if err != nil {
			return fmt.Errorf("%w: unsafe parent for stale managed file %q: %v", ErrConflict, previous.Path, err)
		}
		if err := validateDirectoryChain(programRoot, filepath.Dir(target)); err != nil {
			return fmt.Errorf("%w: unsafe parent for stale managed file %q: %v", ErrConflict, previous.Path, err)
		}
		info, err := os.Lstat(target)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || isUnsafePathEntry(target, info) || !info.Mode().IsRegular() {
			transaction.preserve(previous.Path)
			continue
		}
		matches, err := fileMatches(target, previous.SHA256, previous.Size)
		if err != nil {
			return err
		}
		if !matches {
			transaction.preserve(previous.Path)
			continue
		}
		if err := transaction.removeFile(target, previous.Path); err != nil {
			return fmt.Errorf("remove stale managed file %q: %w", previous.Path, err)
		}
	}
	return nil
}

// buildState creates a complete non-secret state snapshot from the authenticated request.
// buildState 根据已认证请求创建完整的非敏感状态快照。
func buildState(request Request, files []packageFile) (state.State, error) {
	tag, err := request.Manifest.Tag()
	if err != nil {
		return state.State{}, err
	}
	commit, err := request.Manifest.Commit()
	if err != nil {
		return state.State{}, err
	}
	managed := make([]state.ManagedFile, 0, len(files))
	for _, item := range files {
		managed = append(managed, state.ManagedFile{Path: item.Relative, SHA256: item.SHA256, Size: item.Size})
	}
	return state.State{
		ProtocolVersion: state.ProtocolVersion,
		ManagerVersion:  request.ManagerVersion,
		VMM:             state.VMMIdentity{Tag: tag, Commit: commit, Platform: platformIDForRuntime()},
		Paths:           request.Paths,
		DownloadSource:  request.Source,
		Service:         request.Service,
		PATH:            request.PATH,
		ManagedFiles:    managed,
	}, nil
}

// saveStateWithPreparation creates independent control and data roots before atomic state.Save.
// saveStateWithPreparation 在原子保存登记前分别准备控制根与数据根。
func saveStateWithPreparation(statePath string, dataRoot string, registration state.State) error {
	if err := ensureInstallDataRoot(dataRoot); err != nil {
		return fmt.Errorf("prepare data root: %w", err)
	}
	if err := ensureInstallControlRoot(filepath.Dir(statePath)); err != nil {
		return fmt.Errorf("prepare manager control root: %w", err)
	}
	return state.Save(statePath, registration)
}

// digestFile hashes one regular file without following a symbolic link.
// digestFile 在不跟随符号链接的前提下计算普通文件摘要。
func digestFile(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if isUnsafePathEntry(path, info) || !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("path %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), info.Size(), nil
}

// fileMatches compares both size and digest before a destructive operation.
// fileMatches 在任何删除操作前同时比较大小和摘要。
func fileMatches(path string, expectedDigest string, expectedSize int64) (bool, error) {
	digest, size, err := digestFile(path)
	if err != nil {
		return false, err
	}
	return digest == expectedDigest && size == expectedSize, nil
}

// copyVerifiedFile copies one source file and verifies the resulting bytes.
// copyVerifiedFile 复制一个源文件并校验写入结果的字节摘要。
func copyVerifiedFile(source string, destination string, expectedDigest string, expectedSize int64, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	temporaryPath, err := stageVerifiedFile(source, filepath.Dir(destination), expectedDigest, expectedSize, mode)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

// stageVerifiedFile writes verified bytes to a temporary file beside the target volume.
// stageVerifiedFile 将经过校验的字节写入目标卷旁的临时文件。
func stageVerifiedFile(source string, directory string, expectedDigest string, expectedSize int64, mode os.FileMode) (string, error) {
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	temporary, err := os.CreateTemp(directory, ".vmmm-copy-")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary, hasher), input)
	if err != nil {
		_ = temporary.Close()
		return "", err
	}
	if written != expectedSize || hex.EncodeToString(hasher.Sum(nil)) != expectedDigest {
		_ = temporary.Close()
		return "", errors.New("copied file failed digest or size verification")
	}
	if err := temporary.Chmod((mode & 0o777) | 0o600); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	removeTemporary = false
	return temporaryPath, nil
}

// copyBytesFile writes one bounded config file into a private candidate tree.
// copyBytesFile 将一个受大小限制的配置文件写入私有候选树。
func copyBytesFile(destination string, data []byte, mode os.FileMode) error {
	if len(data) > maxConfigFileBytes {
		return fmt.Errorf("config file exceeds %d bytes", maxConfigFileBytes)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".vmmm-config-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode | 0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
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
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

// copyTree copies a symlink-free directory tree for config validation.
// copyTree 复制不含符号链接的目录树供配置校验使用。
func copyTree(source string, destination string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if isUnsafePathEntry(path, info) {
			return fmt.Errorf("config tree path %q is a symbolic link or reparse point", relative)
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("config tree path %q is not a regular file", relative)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return copyBytesFile(target, data, info.Mode().Perm())
	})
}

// validateConfigFiles rejects traversal, package, and database paths.
// validateConfigFiles 拒绝遍历路径、程序包路径和数据库路径。
func validateConfigFiles(files map[string][]byte) error {
	var total int64
	for relative, data := range files {
		if _, err := safeRelativePath(relative); err != nil {
			return fmt.Errorf("config file %q: %w", relative, err)
		}
		if isProtectedProgramPath(relative) {
			return fmt.Errorf("config file %q targets a protected database path", relative)
		}
		if len(data) > maxConfigFileBytes {
			return fmt.Errorf("config file %q exceeds %d bytes", relative, maxConfigFileBytes)
		}
		total += int64(len(data))
		if total > maxConfigTotalBytes {
			return fmt.Errorf("config overlay exceeds %d bytes", maxConfigTotalBytes)
		}
	}
	return nil
}

// safeRelativePath validates one portable forward-slash path.
// safeRelativePath 校验一个可移植的正斜杠相对路径。
func safeRelativePath(relative string) (string, error) {
	if relative == "" || strings.ContainsAny(relative, "\\:\x00\r\n") || filepath.IsAbs(filepath.FromSlash(relative)) {
		return "", errors.New("path must be relative and free of control characters")
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(relative)))
	if clean != relative || clean == "." || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", errors.New("path is not normalized or contains traversal")
	}
	for _, component := range strings.Split(clean, "/") {
		if component == "" || component == "." || component == ".." {
			return "", errors.New("path contains an invalid component")
		}
	}
	return clean, nil
}

// safeProgramPath joins one package path below ProgramRoot without traversal.
// safeProgramPath 将程序包相对路径安全地连接到 ProgramRoot 下。
func safeProgramPath(programRoot string, relative string) (string, error) {
	clean, err := safeRelativePath(relative)
	if err != nil {
		return "", fmt.Errorf("program path %q: %w", relative, err)
	}
	root := filepath.Clean(programRoot)
	target := filepath.Join(root, filepath.FromSlash(clean))
	if err := validateDirectoryChain(root, filepath.Dir(target)); err != nil {
		return "", fmt.Errorf("program path %q has an unsafe parent: %w", relative, err)
	}
	return target, nil
}

// safeConfigPath joins one user overlay path below ConfigRoot without traversal.
// safeConfigPath 将用户覆盖路径安全地连接到 ConfigRoot 下。
func safeConfigPath(configRoot string, relative string) (string, error) {
	clean, err := safeRelativePath(relative)
	if err != nil {
		return "", fmt.Errorf("config path %q: %w", relative, err)
	}
	root := filepath.Clean(configRoot)
	target := filepath.Join(root, filepath.FromSlash(clean))
	if err := validateDirectoryChain(root, filepath.Dir(target)); err != nil {
		return "", fmt.Errorf("config path %q has an unsafe parent: %w", relative, err)
	}
	return target, nil
}

// isProtectedProgramPath identifies database paths that upgrades must never move or clear.
// isProtectedProgramPath 识别升级绝不能移动或清空的数据库路径。
func isProtectedProgramPath(relative string) bool {
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(relative)))
	return clean == "database" || strings.HasPrefix(clean, "database/")
}

// pathsOverlap reports lexical equality or containment after cleaning absolute paths.
// pathsOverlap 在清理绝对路径后判断相等或包含关系。
func pathsOverlap(left string, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	return isWithin(left, right) || isWithin(right, left)
}

// isWithin reports whether child equals or is below parent.
// isWithin 判断 child 是否等于 parent 或位于其下方。
func isWithin(parent string, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	if samePath(parent, child) {
		return true
	}
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+transactionSeparator)
}

// samePath compares paths using the host's case sensitivity contract.
// samePath 按当前主机路径大小写规则比较两个路径。
func samePath(left string, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

// transactionSeparator is kept as a variable because filepath.Separator is a byte constant.
// transactionSeparator 使用变量表达平台路径分隔符，便于路径边界判断。
const transactionSeparator = string(filepath.Separator)

// fileTransaction owns staged files and reversible replacements for one operation.
// fileTransaction 拥有一次操作的暂存文件和可逆替换记录。
type fileTransaction struct {
	// root is the same-volume private transaction directory.
	// root 是同卷私有事务目录。
	root string

	// newRoot contains candidate program files.
	// newRoot 包含候选程序文件。
	newRoot string

	// backupRoot contains original files moved out of the way.
	// backupRoot 包含被暂时移出的原文件。
	backupRoot string

	// privateRoots contains per-target same-volume backup directories.
	// privateRoots 包含按目标卷创建的同卷备份目录。
	privateRoots []string

	// configChanges retain pinned configuration parents until rollback and cleanup finish.
	// configChanges 固定配置父目录句柄，直到回滚与清理完成，避免目录替换越界。
	configChanges []*configFileChange

	// replacements records target and backup paths for rollback.
	// replacements 记录目标路径和备份路径供回滚使用。
	replacements []replacement

	// created records new targets and their bytes for safe rollback.
	// created 记录新目标及其字节摘要，供安全回滚使用。
	created []createdFile

	// preserved records files deliberately not removed.
	// preserved 记录有意保留的文件。
	preserved []string

	// committed prevents cleanup from removing a committed tree.
	// committed 防止清理逻辑删除已经提交的事务树。
	committed bool

	// rolledBack makes repeated error cleanup idempotent.
	// rolledBack 让重复的错误清理保持幂等，避免二次回滚删除已恢复文件。
	rolledBack bool

	// rollbackErr retains recovery failures so cleanup cannot hide them.
	// rollbackErr 保存恢复失败，避免清理流程掩盖事务回滚问题。
	rollbackErr error
}

// replacement records one original file moved to a private backup.
// replacement 记录一个被移到私有备份的原文件。
type replacement struct {
	// Target is the original destination path.
	// Target 是原始目标路径。
	Target string

	// Backup is the same-volume backup path.
	// Backup 是同卷备份路径。
	Backup string

	// Digest and Size identify the transaction-installed bytes before rollback.
	// Digest 和 Size 标识回滚前事务安装的字节内容。
	Digest string
	Size   int64
}

// createdFile records a transaction-created target and its expected content.
// createdFile 记录事务创建的目标及其预期内容。
type createdFile struct {
	// path is the transaction-created target path.
	// path 是事务创建的目标路径。
	path string
	// digest is the SHA-256 digest expected during rollback.
	// digest 是回滚时预期的 SHA-256 摘要。
	digest string
	// size is the byte count expected during rollback.
	// size 是回滚时预期的字节数。
	size int64
}

// newTransaction creates the private transaction layout.
// newTransaction 创建私有事务目录布局。
func newTransaction(root string) *fileTransaction {
	transaction := &fileTransaction{root: root, newRoot: filepath.Join(root, "new"), backupRoot: filepath.Join(root, "backup")}
	_ = os.MkdirAll(transaction.newRoot, 0o700)
	_ = os.MkdirAll(transaction.backupRoot, 0o700)
	return transaction
}

// createTargetBackupPath creates a private backup directory beside the target file.
// createTargetBackupPath 在目标文件旁创建私有备份目录，保证备份与目标位于同一卷。
func (transaction *fileTransaction) createTargetBackupPath(target string) (string, error) {
	parent := filepath.Dir(target)
	if err := validateDirectoryPath("target backup parent", parent); err != nil {
		return "", err
	}
	backupRoot, err := os.MkdirTemp(parent, ".vmmm-backup-")
	if err != nil {
		return "", fmt.Errorf("create same-volume backup directory: %w", err)
	}
	transaction.privateRoots = append(transaction.privateRoots, backupRoot)
	return filepath.Join(backupRoot, fmt.Sprintf("%d-%s", len(transaction.replacements), filepath.Base(target))), nil
}

// replaceFile moves an existing target to backup, then atomically installs a staged file.
// replaceFile 将已有目标移入备份，再原子安装暂存文件。
func (transaction *fileTransaction) replaceFile(source string, target string, mode os.FileMode) error {
	if err := validateDirectoryPath("target parent", filepath.Dir(target)); err != nil {
		return err
	}
	digest, size, err := digestFile(source)
	if err != nil {
		return err
	}
	// Program directories must be traversable by a different service account; configuration uses replaceConfigFile.
	// 程序目录必须允许另一服务账户穿越；私有配置目录由 replaceConfigFile 单独处理。
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if info, err := os.Lstat(target); err == nil {
		if isUnsafePathEntry(target, info) || !info.Mode().IsRegular() {
			return fmt.Errorf("target %q is not a regular file", target)
		}
		backup, err := transaction.createTargetBackupPath(target)
		if err != nil {
			return err
		}
		if err := os.Rename(target, backup); err != nil {
			return err
		}
		transaction.replacements = append(transaction.replacements, replacement{Target: target, Backup: backup, Digest: digest, Size: size})
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(source, target); err != nil {
		return err
	}
	transaction.created = append(transaction.created, createdFile{path: target, digest: digest, size: size})
	if err := os.Chmod(target, (mode&0o777)|0o600); err != nil {
		return err
	}
	return nil
}

// removeFile moves a stale managed file to the transaction backup instead of deleting it.
// removeFile 将过期管理文件移入事务备份，而不是直接删除。
func (transaction *fileTransaction) removeFile(target string, relative string) error {
	if err := validateDirectoryPath("target parent", filepath.Dir(target)); err != nil {
		return err
	}
	digest, size, err := digestFile(target)
	if err != nil {
		return err
	}
	backup, err := transaction.createTargetBackupPath(target)
	if err != nil {
		return err
	}
	if err := os.Rename(target, backup); err != nil {
		return err
	}
	transaction.replacements = append(transaction.replacements, replacement{Target: target, Backup: backup, Digest: digest, Size: size})
	return nil
}

// preserve records a path retained because its content or type is no longer manager-owned.
// preserve 记录因内容或类型变化而不再由管理器安全拥有的路径。
func (transaction *fileTransaction) preserve(relative string) {
	transaction.preserved = append(transaction.preserved, relative)
}

// preservedFiles returns a sorted defensive copy for callers.
// preservedFiles 返回排序后的防御性副本供调用方使用。
func (transaction *fileTransaction) preservedFiles() []string {
	values := append([]string(nil), transaction.preserved...)
	sort.Strings(values)
	return values
}

// rollback removes new targets and restores every original replacement in reverse order.
// rollback 删除新目标，并按逆序恢复每一个原始替换。
func (transaction *fileTransaction) rollback() error {
	if transaction.committed {
		return nil
	}
	if transaction.rolledBack {
		return transaction.rollbackErr
	}
	transaction.rolledBack = true
	var failures []error
	for index := len(transaction.configChanges) - 1; index >= 0; index-- {
		if err := transaction.configChanges[index].rollback(); err != nil {
			failures = append(failures, fmt.Errorf("restore configuration file: %w", err))
		}
	}
	for index := len(transaction.created) - 1; index >= 0; index-- {
		item := transaction.created[index]
		if err := validateDirectoryPath("rollback target parent", filepath.Dir(item.path)); err != nil {
			failures = append(failures, fmt.Errorf("inspect created path parent %q: %w", item.path, err))
			continue
		}
		if err := removeTransactionTarget(item.path, item.digest, item.size); err != nil {
			failures = append(failures, fmt.Errorf("remove created path %q: %w", item.path, err))
		}
	}
	for index := len(transaction.replacements) - 1; index >= 0; index-- {
		item := transaction.replacements[index]
		if err := validateDirectoryPath("rollback target parent", filepath.Dir(item.Target)); err != nil {
			failures = append(failures, fmt.Errorf("inspect replaced path parent %q: %w", item.Target, err))
			continue
		}
		if err := removeTransactionTarget(item.Target, item.Digest, item.Size); err != nil {
			failures = append(failures, fmt.Errorf("remove replaced path %q: %w", item.Target, err))
			continue
		}
		if err := os.MkdirAll(filepath.Dir(item.Target), 0o700); err != nil {
			failures = append(failures, fmt.Errorf("recreate replaced path parent %q: %w", item.Target, err))
			continue
		}
		backupInfo, err := os.Lstat(item.Backup)
		if err != nil {
			failures = append(failures, fmt.Errorf("inspect replacement backup %q: %w", item.Backup, err))
			continue
		}
		if isUnsafePathEntry(item.Backup, backupInfo) || !backupInfo.Mode().IsRegular() {
			failures = append(failures, fmt.Errorf("replacement backup %q is not a regular file", item.Backup))
			continue
		}
		if err := os.Rename(item.Backup, item.Target); err != nil {
			failures = append(failures, fmt.Errorf("restore replaced path %q: %w", item.Target, err))
		}
	}
	transaction.rollbackErr = errors.Join(failures...)
	return transaction.rollbackErr
}

// removeTransactionTarget removes only a regular file or symlink owned by the transaction.
// removeTransactionTarget 只删除事务拥有的普通文件或符号链接，拒绝移除外部目录和特殊文件。
func removeTransactionTarget(path string, expectedDigest string, expectedSize int64) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if isUnsafePathEntry(path, info) || !info.Mode().IsRegular() {
		return errors.New("transaction target is no longer a regular file")
	}
	matches, err := fileMatches(path, expectedDigest, expectedSize)
	if err != nil {
		return err
	}
	if !matches {
		return errors.New("transaction target changed before rollback")
	}
	return os.Remove(path)
}

// commit marks the transaction as complete; backup cleanup remains best effort.
// commit 标记事务完成，备份清理采用尽力而为策略。
func (transaction *fileTransaction) commit() {
	transaction.committed = true
}

// cleanup removes private staging and backups after commit or rollback.
// cleanup 在提交或回滚后清理私有暂存与备份目录。
func (transaction *fileTransaction) cleanup() error {
	defer func() {
		for _, change := range transaction.configChanges {
			change.close()
		}
	}()
	if !transaction.committed {
		if err := transaction.rollback(); err != nil {
			return err
		}
	}
	var failures []error
	for _, change := range transaction.configChanges {
		if err := change.cleanup(); err != nil {
			failures = append(failures, fmt.Errorf("remove configuration backup: %w", err))
		}
	}
	if err := os.RemoveAll(transaction.root); err != nil {
		failures = append(failures, fmt.Errorf("remove transaction root: %w", err))
	}
	for _, root := range transaction.privateRoots {
		if err := os.RemoveAll(root); err != nil {
			failures = append(failures, fmt.Errorf("remove same-volume backup root %q: %w", root, err))
		}
	}
	return errors.Join(failures...)
}

// fail cleans up a failed transaction and reports rollback errors to the caller.
// fail 清理失败事务，并把回滚错误报告给调用方。
func (transaction *fileTransaction) fail(operationErr error) error {
	if cleanupErr := transaction.cleanup(); cleanupErr != nil {
		return errors.Join(operationErr, fmt.Errorf("transaction cleanup failed: %w", cleanupErr))
	}
	return operationErr
}
