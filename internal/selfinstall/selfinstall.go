// Package selfinstall safely persists and upgrades the standalone VMMM executable.
// selfinstall 包负责将独立 VMMM 可执行文件安全持久化、升级、回滚和卸载。
//
// The package only accepts a verified single-file artifact and records ownership
// in a strict local JSON file. It does not modify PATH or native services.
// 本包只接受已经校验过的单文件资产，并使用严格的本地 JSON 记录所有权；它不修改 PATH 或系统服务。
package selfinstall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
)

const (
	// ProtocolVersion identifies the persisted self-installation record format.
	// ProtocolVersion 标识持久化自安装记录的格式版本。
	ProtocolVersion = 1

	// defaultStateName is kept inside the selected installation root by default.
	// defaultStateName 默认位于用户选择的安装根目录中。
	defaultStateName = ".vmmm-install.json"

	// backupDirectoryName contains only backups created and owned by this package.
	// backupDirectoryName 只包含本包创建并拥有的回滚备份。
	backupDirectoryName = ".vmmm-backups"

	// lockFileName is the persistent kernel-lock anchor for one installation root.
	// lockFileName 是单个安装根目录的持久化内核锁锚点。
	lockFileName = ".vmmm-install.lock"

	// uninstallJournalName records an interrupted uninstall transaction.
	// uninstallJournalName 记录被中断的卸载事务。
	uninstallJournalName = ".vmmm-uninstall.json"

	// uninstallTransactionName contains files moved during an uninstall transaction.
	// uninstallTransactionName 包含卸载事务期间移动的文件。
	uninstallTransactionName = ".vmmm-uninstall-txn"

	// uninstallProtocolVersion identifies the uninstall journal format.
	// uninstallProtocolVersion 标识卸载日志格式。
	uninstallProtocolVersion = 1

	// uninstallStatusPrepared means files may have been moved and must be restored.
	// uninstallStatusPrepared 表示文件可能已移动，必须执行恢复。
	uninstallStatusPrepared = "prepared"

	// uninstallStatusCommitted means the uninstall may be safely completed.
	// uninstallStatusCommitted 表示卸载可以安全完成。
	uninstallStatusCommitted = "committed"

	// maxStateBytes bounds untrusted local state before JSON decoding.
	// maxStateBytes 在 JSON 解码前限制不可信本地状态的大小。
	maxStateBytes int64 = 1 << 20

	// maxReleaseFileBytes prevents an accidental or malicious oversized copy.
	// maxReleaseFileBytes 防止意外或恶意的超大文件复制。
	maxReleaseFileBytes int64 = 2 << 30
)

var (
	// ErrNotInstalled means that no valid self-installation record exists.
	// ErrNotInstalled 表示不存在有效的自安装记录。
	ErrNotInstalled = errors.New("VMMM is not installed")

	// ErrAlreadyInstalled means that another installed version already owns the target.
	// ErrAlreadyInstalled 表示目标已经被另一个已安装版本拥有。
	ErrAlreadyInstalled = errors.New("VMMM is already installed")

	// ErrConflict means that an unmanaged file or directory blocks the target.
	// ErrConflict 表示非本包管理的文件或目录阻塞了目标路径。
	ErrConflict = errors.New("self-installation target is occupied by unmanaged content")

	// ErrModified means that an owned file no longer matches its recorded digest.
	// ErrModified 表示受管文件已经与记录的摘要不一致。
	ErrModified = errors.New("a managed VMMM file was modified")

	// ErrRunningExecutable means that the operation would touch the current process image.
	// ErrRunningExecutable 表示操作会触碰当前进程正在使用的可执行映像。
	ErrRunningExecutable = errors.New("the installed VMMM executable is still running")

	// ErrRollbackUnavailable means that no verified owned backup can be selected.
	// ErrRollbackUnavailable 表示没有可验证且属于本包的回滚备份。
	ErrRollbackUnavailable = errors.New("no verified VMMM rollback is available")

	// ErrUnsafePath means that a path enters a temporary or reparse/symlink location.
	// ErrUnsafePath 表示路径进入了临时目录或重解析点/符号链接位置。
	ErrUnsafePath = errors.New("self-installation path is unsafe")

	// ErrCorruptState means that the ownership record cannot be trusted.
	// ErrCorruptState 表示无法信任安装所有权记录。
	ErrCorruptState = errors.New("self-installation state is corrupt")

	// ErrUninstallRecovery means an interrupted uninstall requires another recovery attempt.
	// ErrUninstallRecovery 表示中断的卸载需要再次执行恢复。
	ErrUninstallRecovery = errors.New("self-installation uninstall recovery is incomplete")
)

// Options specifies the explicit permanent location and process identity used by an installer.
// Options 指定安装器使用的明确永久位置和进程身份。
type Options struct {
	// InstallRoot is the permanent user-selected directory containing vmmm(.exe).
	// InstallRoot 是包含 vmmm(.exe) 的用户选择的永久目录。
	InstallRoot string

	// StatePath optionally overrides the ownership record path; empty keeps it in InstallRoot.
	// StatePath 可选地覆盖所有权记录路径；为空时记录保存在 InstallRoot 中。
	StatePath string

	// CurrentExecutable identifies the currently running manager image for fail-closed checks.
	// CurrentExecutable 标识当前运行的管理器映像，用于失败关闭检查。
	CurrentExecutable string

	// ExecutableName is the managed basename; empty selects vmmm or vmmm.exe by the OS.
	// ExecutableName 是受管文件名；为空时按操作系统选择 vmmm 或 vmmm.exe。
	ExecutableName string
}

// Release describes the authenticated identity and exact bytes of one VMMM executable.
// Release 描述一个 VMMM 可执行文件经认证的身份和精确字节信息。
type Release struct {
	// Version is the immutable release tag recorded in the signed manifest.
	// Version 是签名清单中记录的不可变发行标签。
	Version string

	// Commit is the source commit recorded in the signed manifest.
	// Commit 是签名清单中记录的源代码提交。
	Commit string

	// Platform is the canonical platform identifier selected by the caller.
	// Platform 是调用方选择的规范平台标识。
	Platform string

	// Filename is the authenticated release asset basename.
	// Filename 是经认证的发行资产文件名。
	Filename string

	// SHA256 is the lowercase digest of the exact executable bytes.
	// SHA256 是可执行文件精确字节的小写摘要。
	SHA256 string

	// Size is the exact expected executable byte count.
	// Size 是可执行文件预期的精确字节数。
	Size int64
}

// Backup describes an owned executable retained for rollback.
// Backup 描述一个为回滚保留的受管可执行文件。
type Backup struct {
	// Release is the authenticated identity represented by Path.
	// Release 是 Path 所代表的经认证发行身份。
	Release Release

	// Path is the absolute backup path returned for diagnostics and inspection.
	// Path 是返回给诊断和检查使用的绝对备份路径。
	Path string
}

// Installation is a verified snapshot of the currently installed manager.
// Installation 是当前已安装管理器的经验证快照。
type Installation struct {
	// Current is the release whose bytes occupy the managed executable path.
	// Current 是当前受管可执行文件所承载的发行版本。
	Current Release

	// ExecutablePath is the permanent command path exposed to PATH integration.
	// ExecutablePath 是供 PATH 集成使用的永久命令路径。
	ExecutablePath string

	// Backups lists verified owned rollback files from newest to oldest.
	// Backups 按从新到旧列出经验证的受管回滚文件。
	Backups []Backup
}

// Result describes the committed self-installation operation.
// Result 描述已经提交的自安装操作。
type Result struct {
	// Action is one of installed, upgraded, rolled_back, or unchanged.
	// Action 是 installed、upgraded、rolled_back 或 unchanged 之一。
	Action string

	// Version is the release now occupying ExecutablePath.
	// Version 是当前占用 ExecutablePath 的发行版本。
	Version string

	// ExecutablePath is the permanent path of vmmm(.exe).
	// ExecutablePath 是 vmmm(.exe) 的永久路径。
	ExecutablePath string

	// ExecutableDirectory is the permanent directory that PATH integration should expose.
	// ExecutableDirectory 是 PATH 集成应暴露的永久目录。
	ExecutableDirectory string
}

// Installer performs self-installation operations within one validated root.
// Installer 在一个已经验证的根目录内执行自安装操作。
type Installer struct {
	// options contains normalized immutable caller choices.
	// options 保存规范化后的调用方不可变选择。
	options Options

	// statePath is the normalized ownership record location.
	// statePath 是规范化后的所有权记录位置。
	statePath string

	// executablePath is the only path this package may replace or remove.
	// executablePath 是本包允许替换或删除的唯一路径。
	executablePath string

	// backupRoot contains only package-owned rollback files.
	// backupRoot 只包含本包拥有的回滚文件。
	backupRoot string

	// lockPath is the persistent kernel-lock anchor inside InstallRoot.
	// lockPath 是 InstallRoot 内的持久化内核锁锚点。
	lockPath string

	// uninstallJournalPath records an in-progress uninstall beside the executable.
	// uninstallJournalPath 在可执行文件旁记录进行中的卸载事务。
	uninstallJournalPath string

	// uninstallTransactionPath contains staged owned files during uninstall.
	// uninstallTransactionPath 在卸载期间包含暂存的受管文件。
	uninstallTransactionPath string

	// verifyPublishedFile verifies the new image after an atomic replacement; tests may inject a failure.
	// verifyPublishedFile 在原子替换后验证新映像；测试可注入故障。
	verifyPublishedFile func(string, Release) error

	// restoreCurrentFile restores the previous image during failure recovery; tests may inject a failure.
	// restoreCurrentFile 在故障恢复期间恢复旧映像；测试可注入故障。
	restoreCurrentFile func(string, Release) error

	// uninstallMoveFile moves one owned file into or out of the uninstall transaction.
	// uninstallMoveFile 将一个受管文件移入或移出卸载事务。
	uninstallMoveFile func(string, string) error

	// uninstallRemoveFile removes one staged file after ownership verification.
	// uninstallRemoveFile 在所有权验证后删除一个暂存文件。
	uninstallRemoveFile func(string, Release) error
}

// persistedRecord is the strict on-disk ownership document.
// persistedRecord 是磁盘上的严格所有权文档。
type persistedRecord struct {
	// ProtocolVersion identifies the record format.
	// ProtocolVersion 标识记录格式。
	ProtocolVersion int `json:"protocol_version"`

	// InstallRoot binds the record to the explicit installation root.
	// InstallRoot 将记录绑定到明确的安装根目录。
	InstallRoot string `json:"install_root"`

	// Executable is the managed basename, never an arbitrary path.
	// Executable 是受管文件名，不是任意路径。
	Executable string `json:"executable"`

	// Current is the release metadata for the managed executable.
	// Current 是受管可执行文件的发行元数据。
	Current persistedRelease `json:"current"`

	// Backups contains paths relative to InstallRoot and their exact metadata.
	// Backups 包含相对于 InstallRoot 的路径及其精确元数据。
	Backups []persistedBackup `json:"backups"`
}

// persistedRelease is the JSON-safe form of Release.
// persistedRelease 是 Release 的 JSON 安全表示。
type persistedRelease struct {
	// Version stores the immutable release tag.
	// Version 保存不可变发行标签。
	Version string `json:"version"`
	// Commit stores the source commit.
	// Commit 保存源代码提交。
	Commit string `json:"commit"`
	// Platform stores the canonical platform identifier.
	// Platform 保存规范平台标识。
	Platform string `json:"platform"`
	// Filename stores the authenticated asset basename.
	// Filename 保存经认证的资产文件名。
	Filename string `json:"filename"`
	// SHA256 stores the lowercase executable digest.
	// SHA256 保存可执行文件的小写摘要。
	SHA256 string `json:"sha256"`
	// Size stores the exact executable size.
	// Size 保存可执行文件的精确大小。
	Size int64 `json:"size"`
}

// persistedBackup binds one owned relative path to one release identity.
// persistedBackup 将一个受管相对路径绑定到一个发行身份。
type persistedBackup struct {
	// Path is normalized relative to InstallRoot.
	// Path 是相对于 InstallRoot 的规范化路径。
	Path string `json:"path"`
	// Release is the exact release represented by Path.
	// Release 是 Path 所代表的精确发行版本。
	Release persistedRelease `json:"release"`
}

// uninstallJournal is the strict recovery document for a staged uninstall.
// uninstallJournal 是暂存卸载的严格恢复文档。
type uninstallJournal struct {
	// ProtocolVersion identifies this journal format.
	// ProtocolVersion 标识此日志格式。
	ProtocolVersion int `json:"protocol_version"`

	// Status selects rollback of a partial move or completion of a committed uninstall.
	// Status 选择回滚部分移动或完成已提交的卸载。
	Status string `json:"status"`

	// InstallRoot binds the journal to one explicit installation root.
	// InstallRoot 将日志绑定到一个明确的安装根目录。
	InstallRoot string `json:"install_root"`

	// Executable binds the journal to the managed executable basename.
	// Executable 将日志绑定到受管可执行文件名。
	Executable string `json:"executable"`

	// StatePath binds recovery to the ownership record selected by the installer.
	// StatePath 将恢复绑定到安装器选定的所有权记录路径。
	StatePath string `json:"state_path"`

	// Entries lists each owned executable moved to the transaction directory.
	// Entries 列出移动到事务目录的每个受管可执行文件。
	Entries []uninstallEntry `json:"entries"`
}

// uninstallEntry maps an owned source path to its staged path and release identity.
// uninstallEntry 将受管源路径映射到暂存路径及其发行版本身份。
type uninstallEntry struct {
	// Source is relative to InstallRoot and is restored on an uncommitted transaction.
	// Source 是相对于 InstallRoot 的路径，未提交事务时会恢复到此处。
	Source string `json:"source"`

	// Staged is relative to the fixed uninstall transaction directory.
	// Staged 是相对于固定卸载事务目录的路径。
	Staged string `json:"staged"`

	// Release authenticates the bytes moved for this entry.
	// Release 验证此条目移动的字节内容。
	Release persistedRelease `json:"release"`
}

// New validates explicit paths and prepares an installer without selecting a default directory.
// New 验证明确路径并创建安装器，不会自行选择默认目录。
func New(options Options) (*Installer, error) {
	installRoot, err := normalizeAbsolutePath("install root", options.InstallRoot)
	if err != nil {
		return nil, err
	}
	if err := rejectTemporaryPath(installRoot); err != nil {
		return nil, err
	}
	if err := validateSecurePathChain(installRoot, true); err != nil {
		return nil, fmt.Errorf("validate install root: %w", err)
	}
	if err := validatePrivilegedManagerRoot(installRoot); err != nil {
		return nil, err
	}

	executableName := options.ExecutableName
	if executableName == "" {
		executableName = defaultExecutableName()
	}
	if err := validateExecutableName(executableName); err != nil {
		return nil, err
	}

	statePath := options.StatePath
	if statePath == "" {
		statePath = filepath.Join(installRoot, defaultStateName)
	}
	statePath, err = normalizeAbsolutePath("state path", statePath)
	if err != nil {
		return nil, err
	}
	if err := rejectTemporaryPath(statePath); err != nil {
		return nil, err
	}
	if err := validateSecurePathChain(filepath.Dir(statePath), true); err != nil {
		return nil, fmt.Errorf("validate state parent: %w", err)
	}

	currentExecutable := options.CurrentExecutable
	if currentExecutable == "" {
		currentExecutable, err = os.Executable()
		if err != nil && runtime.GOOS == "windows" {
			return nil, fmt.Errorf("resolve current executable on Windows: %w", err)
		}
		if err != nil {
			currentExecutable = ""
		}
	}
	if currentExecutable != "" {
		currentExecutable, err = normalizeAbsolutePath("current executable", currentExecutable)
		if err != nil {
			return nil, err
		}
	}

	executablePath := filepath.Join(installRoot, executableName)
	if samePath(statePath, executablePath) {
		return nil, fmt.Errorf("state path must not equal executable path: %w", ErrUnsafePath)
	}
	backupRoot := filepath.Join(installRoot, backupDirectoryName)
	if samePath(statePath, backupRoot) || pathWithin(statePath, backupRoot) {
		return nil, fmt.Errorf("state path must not be inside backup root: %w", ErrUnsafePath)
	}
	lockPath := filepath.Join(installRoot, lockFileName)
	uninstallJournalPath := filepath.Join(installRoot, uninstallJournalName)
	uninstallTransactionPath := filepath.Join(installRoot, uninstallTransactionName)
	if samePath(statePath, lockPath) || samePath(statePath, uninstallJournalPath) || pathWithin(statePath, uninstallTransactionPath) {
		return nil, fmt.Errorf("state path overlaps an installation control path: %w", ErrUnsafePath)
	}

	installer := &Installer{
		options: Options{
			InstallRoot:       installRoot,
			StatePath:         statePath,
			CurrentExecutable: currentExecutable,
			ExecutableName:    executableName,
		},
		statePath:                statePath,
		executablePath:           executablePath,
		backupRoot:               backupRoot,
		lockPath:                 lockPath,
		uninstallJournalPath:     uninstallJournalPath,
		uninstallTransactionPath: uninstallTransactionPath,
	}
	installer.verifyPublishedFile = verifyFile
	installer.restoreCurrentFile = installer.restoreCurrent
	installer.uninstallMoveFile = os.Rename
	installer.uninstallRemoveFile = removeOwnedFile
	return installer, nil
}

// ExecutablePath returns the permanent path that PATH integration should expose.
// ExecutablePath 返回 PATH 集成应暴露的永久路径。
func (i *Installer) ExecutablePath() string {
	if i == nil {
		return ""
	}
	return i.executablePath
}

// ExecutableDirectory returns the permanent directory containing vmmm(.exe).
// ExecutableDirectory 返回包含 vmmm(.exe) 的永久目录。
func (i *Installer) ExecutableDirectory() string {
	if i == nil {
		return ""
	}
	return filepath.Dir(i.executablePath)
}

// Detect loads and verifies the owned executable and all recorded rollback files.
// Detect 加载并验证受管可执行文件和所有记录的回滚文件。
func (i *Installer) Detect() (Installation, error) {
	lock, err := i.acquireExclusiveLock(false)
	if err != nil {
		return Installation{}, err
	}
	if lock != nil {
		defer func() { _ = lock.close() }()
	}
	return i.detectLocked()
}

// detectLocked performs detection after any interrupted uninstall has been recovered.
// detectLocked 在恢复中断卸载后执行检测。
func (i *Installer) detectLocked() (Installation, error) {
	if err := i.valid(); err != nil {
		return Installation{}, err
	}
	finished, err := i.recoverUninstallTransaction()
	if err != nil {
		return Installation{}, err
	}
	if finished {
		return Installation{}, ErrNotInstalled
	}
	record, err := i.loadRecord()
	if err != nil {
		return Installation{}, err
	}
	if err := i.validateRecord(record); err != nil {
		return Installation{}, fmt.Errorf("%w: %v", ErrCorruptState, err)
	}
	current := record.Current.release()
	if err := verifyFile(i.executablePath, current); err != nil {
		return Installation{}, fmt.Errorf("verify installed executable: %w", classifyOwnedFileError(err))
	}
	installation := Installation{
		Current:        current,
		ExecutablePath: i.executablePath,
		Backups:        make([]Backup, 0, len(record.Backups)),
	}
	verifiedBackups, err := i.verifyBackups(record)
	if err != nil {
		return Installation{}, err
	}
	for _, backup := range verifiedBackups {
		absolute, err := i.absoluteOwnedPath(backup.Path)
		if err != nil {
			return Installation{}, fmt.Errorf("%w: invalid rollback path: %v", ErrCorruptState, err)
		}
		installation.Backups = append(installation.Backups, Backup{Release: backup.Release.release(), Path: absolute})
	}
	return installation, nil
}

// Install securely copies one verified single-file asset into an unoccupied permanent path.
// Install 将一个经验证的单文件资产安全复制到未占用的永久路径。
func (i *Installer) Install(sourcePath string, release Release) (Result, error) {
	lock, err := i.acquireExclusiveLock(true)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = lock.close() }()
	return i.installLocked(sourcePath, release)
}

// installLocked performs first installation while holding the root lock.
// installLocked 在持有根目录锁时执行首次安装。
func (i *Installer) installLocked(sourcePath string, release Release) (Result, error) {
	if err := i.valid(); err != nil {
		return Result{}, err
	}
	_, err := i.recoverUninstallTransaction()
	if err != nil {
		return Result{}, err
	}
	if err := validateRelease(release); err != nil {
		return Result{}, err
	}
	if record, err := i.loadRecord(); err == nil {
		if sameRelease(record.Current.release(), release) {
			if verifyErr := verifyFile(i.executablePath, release); verifyErr == nil {
				return i.result("unchanged", release), nil
			}
		}
		return Result{}, ErrAlreadyInstalled
	} else if !errors.Is(err, ErrNotInstalled) {
		return Result{}, err
	}
	if err := ensureDirectory(i.options.InstallRoot, 0755); err != nil {
		return Result{}, fmt.Errorf("prepare install root: %w", err)
	}
	if info, err := os.Lstat(i.executablePath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return Result{}, fmt.Errorf("%w: executable path is not a regular file", ErrConflict)
		}
		return Result{}, ErrConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, fmt.Errorf("inspect executable path: %w", err)
	}
	if err := ensureDirectory(i.backupRoot, 0700); err != nil {
		return Result{}, fmt.Errorf("prepare backup root: %w", err)
	}

	temporary, err := i.copyIntoRoot(sourcePath, release, ".vmmm-install-")
	if err != nil {
		return Result{}, err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if err := publishNewFile(temporary, i.executablePath); err != nil {
		return Result{}, err
	}
	removeTemporary = false
	if err := verifyFile(i.executablePath, release); err != nil {
		_ = removeOwnedFile(i.executablePath, release)
		return Result{}, fmt.Errorf("verify newly installed executable: %w", err)
	}
	record := persistedRecord{
		ProtocolVersion: ProtocolVersion,
		InstallRoot:     i.options.InstallRoot,
		Executable:      i.options.ExecutableName,
		Current:         release.persisted(),
		Backups:         []persistedBackup{},
	}
	if err := i.saveRecord(record); err != nil {
		_ = removeOwnedFile(i.executablePath, release)
		return Result{}, err
	}
	return i.result("installed", release), nil
}

// Upgrade verifies a new asset, retains the old release, and atomically replaces the executable.
// Upgrade 验证新资产、保留旧版本并原子替换可执行文件。
func (i *Installer) Upgrade(sourcePath string, release Release) (Result, error) {
	lock, err := i.acquireExclusiveLock(true)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = lock.close() }()
	return i.upgradeLocked(sourcePath, release)
}

// upgradeLocked performs an upgrade while holding the root lock.
// upgradeLocked 在持有根目录锁时执行升级。
func (i *Installer) upgradeLocked(sourcePath string, release Release) (Result, error) {
	if err := i.valid(); err != nil {
		return Result{}, err
	}
	finished, err := i.recoverUninstallTransaction()
	if err != nil {
		return Result{}, err
	}
	if finished {
		return Result{}, ErrNotInstalled
	}
	if err := validateRelease(release); err != nil {
		return Result{}, err
	}
	record, err := i.loadRecord()
	if err != nil {
		return Result{}, err
	}
	if err := i.validateRecord(record); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrCorruptState, err)
	}
	current := record.Current.release()
	if err := verifyFile(i.executablePath, current); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrModified, err)
	}
	if _, err := i.verifyBackups(record); err != nil {
		return Result{}, err
	}
	if sameRelease(current, release) {
		return i.result("unchanged", current), nil
	}
	if i.isRunningExecutable() {
		return Result{}, ErrRunningExecutable
	}
	if err := ensureDirectory(i.backupRoot, 0700); err != nil {
		return Result{}, fmt.Errorf("prepare backup root: %w", err)
	}
	backupPath, backupRecord, err := i.createBackup(current)
	if err != nil {
		return Result{}, err
	}
	temporary, err := i.copyIntoRoot(sourcePath, release, ".vmmm-upgrade-")
	if err != nil {
		_ = os.Remove(backupPath)
		return Result{}, err
	}
	if err := replaceFile(temporary, i.executablePath); err != nil {
		_ = os.Remove(temporary)
		_ = os.Remove(backupPath)
		return Result{}, err
	}
	if err := i.verifyPublishedFile(i.executablePath, release); err != nil {
		return Result{}, i.recoverReplacementFailure(backupPath, current, "verify upgraded executable", err)
	}
	updated := record
	updated.Current = release.persisted()
	updated.Backups = prependBackup(backupRecord, record.Backups)
	if err := i.saveRecord(updated); err != nil {
		return Result{}, i.recoverReplacementFailure(backupPath, current, "save upgrade state", err)
	}
	return i.result("upgraded", release), nil
}

// Rollback promotes the newest verified owned backup and retains the current release as a backup.
// Rollback 提升最新的经验证受管备份，并将当前版本保留为备份。
func (i *Installer) Rollback() (Result, error) {
	lock, err := i.acquireExclusiveLock(true)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = lock.close() }()
	return i.rollbackLocked()
}

// rollbackLocked performs a rollback while holding the root lock.
// rollbackLocked 在持有根目录锁时执行回滚。
func (i *Installer) rollbackLocked() (Result, error) {
	if err := i.valid(); err != nil {
		return Result{}, err
	}
	finished, err := i.recoverUninstallTransaction()
	if err != nil {
		return Result{}, err
	}
	if finished {
		return Result{}, ErrNotInstalled
	}
	record, err := i.loadRecord()
	if err != nil {
		return Result{}, err
	}
	if err := i.validateRecord(record); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrCorruptState, err)
	}
	if len(record.Backups) == 0 {
		return Result{}, ErrRollbackUnavailable
	}
	current := record.Current.release()
	if err := verifyFile(i.executablePath, current); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrModified, err)
	}
	if _, err := i.verifyBackups(record); err != nil {
		return Result{}, err
	}
	if i.isRunningExecutable() {
		return Result{}, ErrRunningExecutable
	}
	selected := record.Backups[0]
	selectedRelease := selected.Release.release()
	selectedPath, err := i.absoluteOwnedPath(selected.Path)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrCorruptState, err)
	}
	if err := verifyFile(selectedPath, selectedRelease); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrRollbackUnavailable, classifyOwnedFileError(err))
	}
	newCurrentBackupPath, newCurrentBackup, err := i.createBackup(current)
	if err != nil {
		return Result{}, err
	}
	temporary, err := i.copyIntoRoot(selectedPath, selectedRelease, ".vmmm-rollback-")
	if err != nil {
		_ = os.Remove(newCurrentBackupPath)
		return Result{}, err
	}
	if err := replaceFile(temporary, i.executablePath); err != nil {
		_ = os.Remove(temporary)
		_ = os.Remove(newCurrentBackupPath)
		return Result{}, err
	}
	if err := i.verifyPublishedFile(i.executablePath, selectedRelease); err != nil {
		return Result{}, i.recoverReplacementFailure(newCurrentBackupPath, current, "verify rolled back executable", err)
	}
	updated := record
	updated.Current = selectedRelease.persisted()
	updated.Backups = prependBackup(newCurrentBackup, record.Backups)
	if err := i.saveRecord(updated); err != nil {
		return Result{}, i.recoverReplacementFailure(newCurrentBackupPath, current, "save rollback state", err)
	}
	return i.result("rolled_back", selectedRelease), nil
}

// Uninstall removes only files whose contents match this package's ownership record.
// Uninstall 只删除内容与本包所有权记录匹配的文件。
func (i *Installer) Uninstall() error {
	lock, err := i.acquireExclusiveLock(true)
	if err != nil {
		return err
	}
	defer func() { _ = lock.close() }()
	return i.uninstallLocked()
}

// uninstallLocked performs transactional removal while holding the root lock.
// uninstallLocked 在持有根目录锁时执行事务式卸载。
func (i *Installer) uninstallLocked() error {
	if err := i.valid(); err != nil {
		return err
	}
	finished, err := i.recoverUninstallTransaction()
	if err != nil {
		return err
	}
	if finished {
		return ErrNotInstalled
	}
	record, err := i.loadRecord()
	if err != nil {
		return err
	}
	if err := i.validateRecord(record); err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptState, err)
	}
	if i.isRunningExecutable() {
		return ErrRunningExecutable
	}
	if err := verifyFile(i.executablePath, record.Current.release()); err != nil {
		return fmt.Errorf("%w: %v", ErrModified, err)
	}
	for _, backup := range record.Backups {
		path, pathErr := i.absoluteOwnedPath(backup.Path)
		if pathErr != nil {
			return fmt.Errorf("%w: %v", ErrCorruptState, pathErr)
		}
		if verifyErr := verifyFile(path, backup.Release.release()); verifyErr != nil {
			return fmt.Errorf("%w: %v", ErrModified, verifyErr)
		}
	}
	journal, err := i.newUninstallJournal(record)
	if err != nil {
		return err
	}
	if err := i.saveUninstallJournal(journal); err != nil {
		return err
	}
	if err := i.prepareUninstallTransactionDirectory(); err != nil {
		return i.rollbackPreparedUninstall(journal, fmt.Errorf("prepare uninstall transaction: %w", err))
	}
	if err := i.moveUninstallEntries(journal); err != nil {
		return i.rollbackPreparedUninstall(journal, err)
	}
	journal.Status = uninstallStatusCommitted
	if err := i.saveUninstallJournal(journal); err != nil {
		return i.rollbackPreparedUninstall(journal, fmt.Errorf("commit uninstall transaction: %w", err))
	}
	if err := i.finalizeCommittedUninstall(journal); err != nil {
		return fmt.Errorf("%w: finalize uninstall: %v", ErrUninstallRecovery, err)
	}
	return nil
}

// acquireExclusiveLock opens the root anchor and waits for every other installer process to leave.
// acquireExclusiveLock 打开根目录锚点，并等待其他安装器进程离开。
func (i *Installer) acquireExclusiveLock(createRoot bool) (*processLock, error) {
	if i == nil {
		return nil, errors.New("self-installation client is nil")
	}
	if i.options.InstallRoot == "" || i.lockPath == "" {
		return nil, errors.New("self-installation lock is not initialized")
	}
	if err := rejectTemporaryPath(i.options.InstallRoot); err != nil {
		return nil, err
	}
	if createRoot {
		if err := ensureDirectory(i.options.InstallRoot, 0700); err != nil {
			return nil, fmt.Errorf("prepare installation lock root: %w", err)
		}
	} else {
		info, err := os.Lstat(i.options.InstallRoot)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("inspect installation lock root: %w", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || hasReparsePoint(i.options.InstallRoot) {
			return nil, fmt.Errorf("%w: installation lock root is not a secure directory", ErrUnsafePath)
		}
	}
	if err := validateSecurePathChain(i.options.InstallRoot, false); err != nil {
		return nil, fmt.Errorf("validate installation lock root: %w", err)
	}
	lock, err := acquireProcessLock(i.lockPath)
	if err != nil {
		return nil, err
	}
	return lock, nil
}

// valid rejects a nil or internally inconsistent installer before filesystem work.
// valid 在文件系统操作前拒绝空对象或内部不一致的安装器。
func (i *Installer) valid() error {
	if i == nil {
		return errors.New("self-installation client is nil")
	}
	if i.executablePath == "" || i.statePath == "" || i.backupRoot == "" || i.lockPath == "" || i.uninstallJournalPath == "" || i.uninstallTransactionPath == "" || i.verifyPublishedFile == nil || i.restoreCurrentFile == nil || i.uninstallMoveFile == nil || i.uninstallRemoveFile == nil {
		return errors.New("self-installation client is not initialized")
	}
	if err := validateSecurePathChain(i.options.InstallRoot, true); err != nil {
		return fmt.Errorf("validate install root before operation: %w", err)
	}
	if err := validatePrivilegedManagerRoot(i.options.InstallRoot); err != nil {
		return err
	}
	if err := validateSecurePathChain(filepath.Dir(i.statePath), true); err != nil {
		return fmt.Errorf("validate state parent before operation: %w", err)
	}
	if err := validateSecurePathChain(i.backupRoot, true); err != nil {
		return fmt.Errorf("validate backup root before operation: %w", err)
	}
	if err := validateSecurePathChain(i.uninstallTransactionPath, true); err != nil {
		return fmt.Errorf("validate uninstall transaction before operation: %w", err)
	}
	if err := validateSecurePathChain(filepath.Dir(i.uninstallJournalPath), true); err != nil {
		return fmt.Errorf("validate uninstall journal parent before operation: %w", err)
	}
	return nil
}

// recoverUninstallTransaction restores an uncommitted transaction or completes a committed one.
// recoverUninstallTransaction 恢复未提交事务或完成已提交事务。
func (i *Installer) recoverUninstallTransaction() (bool, error) {
	journal, exists, err := i.loadUninstallJournal()
	if err != nil {
		return false, err
	}
	if !exists {
		if err := i.rejectOrRemoveOrphanUninstallDirectory(); err != nil {
			return false, err
		}
		return false, nil
	}
	if journal.Status == uninstallStatusPrepared {
		if err := i.requireUninstallState(journal); err != nil {
			return false, fmt.Errorf("%w: validate prepared uninstall state: %v", ErrUninstallRecovery, err)
		}
		if err := i.restorePreparedUninstall(journal); err != nil {
			return false, fmt.Errorf("%w: restore interrupted uninstall: %v", ErrUninstallRecovery, err)
		}
		return false, nil
	}
	if journal.Status == uninstallStatusCommitted {
		if err := i.finalizeCommittedUninstall(journal); err != nil {
			return false, fmt.Errorf("%w: finalize committed uninstall: %v", ErrUninstallRecovery, err)
		}
		return true, nil
	}
	return false, fmt.Errorf("%w: unsupported uninstall status %q", ErrUninstallRecovery, journal.Status)
}

// newUninstallJournal creates the prepared manifest from a verified ownership record.
// newUninstallJournal 根据已验证的所有权记录创建预备清单。
func (i *Installer) newUninstallJournal(record persistedRecord) (uninstallJournal, error) {
	currentSource, err := filepath.Rel(i.options.InstallRoot, i.executablePath)
	if err != nil {
		return uninstallJournal{}, fmt.Errorf("relativize installed executable: %w", err)
	}
	entries := make([]uninstallEntry, 0, len(record.Backups)+1)
	entries = append(entries, uninstallEntry{
		Source:  filepath.ToSlash(currentSource),
		Staged:  "current",
		Release: record.Current,
	})
	for index, backup := range record.Backups {
		entries = append(entries, uninstallEntry{
			Source:  backup.Path,
			Staged:  fmt.Sprintf("backup-%06d", index),
			Release: backup.Release,
		})
	}
	journal := uninstallJournal{
		ProtocolVersion: uninstallProtocolVersion,
		Status:          uninstallStatusPrepared,
		InstallRoot:     i.options.InstallRoot,
		Executable:      i.options.ExecutableName,
		StatePath:       i.statePath,
		Entries:         entries,
	}
	if err := i.validateUninstallJournal(journal); err != nil {
		return uninstallJournal{}, fmt.Errorf("validate uninstall journal: %w", err)
	}
	return journal, nil
}

// validateUninstallJournal binds every transaction path to this installer and rejects ambiguous ownership.
// validateUninstallJournal 将每个事务路径绑定到当前安装器并拒绝含糊的所有权。
func (i *Installer) validateUninstallJournal(journal uninstallJournal) error {
	if journal.ProtocolVersion != uninstallProtocolVersion {
		return fmt.Errorf("unsupported uninstall protocol version %d", journal.ProtocolVersion)
	}
	if journal.Status != uninstallStatusPrepared && journal.Status != uninstallStatusCommitted {
		return fmt.Errorf("unsupported uninstall status %q", journal.Status)
	}
	if !samePath(journal.InstallRoot, i.options.InstallRoot) {
		return errors.New("uninstall journal root does not match installer root")
	}
	if journal.Executable != i.options.ExecutableName {
		return errors.New("uninstall journal executable does not match installer executable")
	}
	if !samePath(journal.StatePath, i.statePath) {
		return errors.New("uninstall journal state path does not match installer state path")
	}
	if journal.Entries == nil || len(journal.Entries) == 0 {
		return errors.New("uninstall journal entries must be a non-empty array")
	}
	currentSource, err := filepath.Rel(i.options.InstallRoot, i.executablePath)
	if err != nil {
		return fmt.Errorf("relativize current uninstall source: %w", err)
	}
	currentSource = filepath.ToSlash(currentSource)
	if journal.Entries[0].Source != currentSource || journal.Entries[0].Staged != "current" {
		return errors.New("uninstall journal current entry is invalid")
	}
	seenSources := make(map[string]struct{}, len(journal.Entries))
	seenStaged := make(map[string]struct{}, len(journal.Entries))
	for index, entry := range journal.Entries {
		if err := validateRelativePath(entry.Source); err != nil {
			return fmt.Errorf("entry[%d] source: %w", index, err)
		}
		if err := validateFilename(entry.Staged); err != nil {
			return fmt.Errorf("entry[%d] staged: %w", index, err)
		}
		if err := validateRelease(entry.Release.release()); err != nil {
			return fmt.Errorf("entry[%d] release: %w", index, err)
		}
		source, err := i.absoluteUninstallSource(entry.Source)
		if err != nil {
			return fmt.Errorf("entry[%d] source: %w", index, err)
		}
		staged, err := i.absoluteUninstallStaged(entry.Staged)
		if err != nil {
			return fmt.Errorf("entry[%d] staged: %w", index, err)
		}
		sourceKey := canonicalPath(source)
		if _, exists := seenSources[sourceKey]; exists {
			return fmt.Errorf("entry[%d] source is duplicated", index)
		}
		seenSources[sourceKey] = struct{}{}
		stagedKey := canonicalPath(staged)
		if _, exists := seenStaged[stagedKey]; exists {
			return fmt.Errorf("entry[%d] staged path is duplicated", index)
		}
		seenStaged[stagedKey] = struct{}{}
	}
	return nil
}

// requireUninstallState verifies that a prepared journal still matches the ownership record on disk.
// requireUninstallState 验证预备日志仍与磁盘上的所有权记录一致。
func (i *Installer) requireUninstallState(journal uninstallJournal) error {
	record, err := i.loadRecord()
	if err != nil {
		return err
	}
	if err := i.validateRecord(record); err != nil {
		return err
	}
	if len(journal.Entries) != len(record.Backups)+1 || journal.Entries[0].Release != record.Current {
		return errors.New("uninstall journal no longer matches current release")
	}
	for index, backup := range record.Backups {
		entry := journal.Entries[index+1]
		if entry.Source != backup.Path || entry.Release != backup.Release {
			return fmt.Errorf("uninstall journal no longer matches backup[%d]", index)
		}
	}
	return nil
}

// absoluteUninstallSource resolves a journal source and limits it to the executable or backup root.
// absoluteUninstallSource 解析日志源路径，并将其限制在可执行文件或备份根目录内。
func (i *Installer) absoluteUninstallSource(relative string) (string, error) {
	abs := filepath.Join(i.options.InstallRoot, filepath.FromSlash(relative))
	if samePath(abs, i.executablePath) {
		return abs, nil
	}
	if pathWithin(abs, i.backupRoot) {
		return abs, nil
	}
	return "", errors.New("uninstall source escapes owned paths")
}

// absoluteUninstallStaged resolves a staged basename below the fixed transaction directory.
// absoluteUninstallStaged 解析固定事务目录下的暂存文件名。
func (i *Installer) absoluteUninstallStaged(name string) (string, error) {
	if err := validateFilename(name); err != nil {
		return "", err
	}
	abs := filepath.Join(i.uninstallTransactionPath, name)
	if !pathWithin(abs, i.uninstallTransactionPath) {
		return "", errors.New("uninstall staged path escapes transaction directory")
	}
	return abs, nil
}

// loadUninstallJournal reads a strict recovery journal and reports whether it exists.
// loadUninstallJournal 读取严格恢复日志，并报告日志是否存在。
func (i *Installer) loadUninstallJournal() (uninstallJournal, bool, error) {
	info, err := os.Lstat(i.uninstallJournalPath)
	if errors.Is(err, os.ErrNotExist) {
		return uninstallJournal{}, false, nil
	}
	if err != nil {
		return uninstallJournal{}, false, fmt.Errorf("inspect uninstall journal: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || hasReparsePoint(i.uninstallJournalPath) {
		return uninstallJournal{}, false, fmt.Errorf("%w: uninstall journal is not a regular file", ErrUninstallRecovery)
	}
	file, err := os.Open(i.uninstallJournalPath)
	if err != nil {
		return uninstallJournal{}, false, fmt.Errorf("open uninstall journal: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return uninstallJournal{}, false, fmt.Errorf("%w: uninstall journal changed while opening", ErrUninstallRecovery)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil {
		return uninstallJournal{}, false, fmt.Errorf("read uninstall journal: %w", err)
	}
	if int64(len(data)) > maxStateBytes {
		return uninstallJournal{}, false, fmt.Errorf("%w: uninstall journal exceeds %d bytes", ErrUninstallRecovery, maxStateBytes)
	}
	journal, err := decodeUninstallJournal(data)
	if err != nil {
		return uninstallJournal{}, false, fmt.Errorf("%w: decode uninstall journal: %v", ErrUninstallRecovery, err)
	}
	if err := i.validateUninstallJournal(journal); err != nil {
		return uninstallJournal{}, false, fmt.Errorf("%w: validate uninstall journal: %v", ErrUninstallRecovery, err)
	}
	return journal, true, nil
}

// decodeUninstallJournal rejects unknown fields, duplicate keys, and trailing JSON values.
// decodeUninstallJournal 拒绝未知字段、重复键和尾随 JSON 值。
func decodeUninstallJournal(data []byte) (uninstallJournal, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return uninstallJournal{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var journal uninstallJournal
	if err := decoder.Decode(&journal); err != nil {
		return uninstallJournal{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return uninstallJournal{}, errors.New("uninstall journal contains multiple JSON values")
		}
		return uninstallJournal{}, err
	}
	return journal, nil
}

// saveUninstallJournal atomically writes a validated recovery journal beside the executable.
// saveUninstallJournal 在可执行文件旁原子写入已验证的恢复日志。
func (i *Installer) saveUninstallJournal(journal uninstallJournal) error {
	if err := i.validateUninstallJournal(journal); err != nil {
		return fmt.Errorf("validate uninstall journal before write: %w", err)
	}
	if err := ensureDirectory(i.options.InstallRoot, 0700); err != nil {
		return fmt.Errorf("prepare uninstall journal directory: %w", err)
	}
	payload, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal uninstall journal: %w", err)
	}
	payload = append(payload, '\n')
	temporary, err := os.CreateTemp(i.options.InstallRoot, ".vmmm-uninstall-state-")
	if err != nil {
		return fmt.Errorf("create uninstall journal temporary: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set uninstall journal permissions: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write uninstall journal: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync uninstall journal: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close uninstall journal: %w", err)
	}
	if info, err := os.Lstat(i.uninstallJournalPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || hasReparsePoint(i.uninstallJournalPath) {
			return fmt.Errorf("%w: uninstall journal path is not a regular file", ErrUnsafePath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect uninstall journal path: %w", err)
	}
	if err := os.Rename(temporaryPath, i.uninstallJournalPath); err != nil {
		return fmt.Errorf("replace uninstall journal: %w", err)
	}
	removeTemporary = false
	return nil
}

// prepareUninstallTransactionDirectory creates an empty secure staging directory.
// prepareUninstallTransactionDirectory 创建空的安全暂存目录。
func (i *Installer) prepareUninstallTransactionDirectory() error {
	if info, err := os.Lstat(i.uninstallTransactionPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || hasReparsePoint(i.uninstallTransactionPath) {
			return fmt.Errorf("%w: uninstall transaction path is not a secure directory", ErrUninstallRecovery)
		}
		entries, readErr := os.ReadDir(i.uninstallTransactionPath)
		if readErr != nil {
			return fmt.Errorf("read uninstall transaction directory: %w", readErr)
		}
		if len(entries) != 0 {
			return fmt.Errorf("%w: uninstall transaction directory is not empty", ErrUninstallRecovery)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect uninstall transaction directory: %w", err)
	}
	if err := os.Mkdir(i.uninstallTransactionPath, 0700); err != nil {
		return fmt.Errorf("create uninstall transaction directory: %w", err)
	}
	return nil
}

// moveUninstallEntries stages every verified owned file before committing the uninstall.
// moveUninstallEntries 在提交卸载前暂存每个已验证的受管文件。
func (i *Installer) moveUninstallEntries(journal uninstallJournal) error {
	for index, entry := range journal.Entries {
		source, err := i.absoluteUninstallSource(entry.Source)
		if err != nil {
			return fmt.Errorf("entry[%d] source: %w", index, err)
		}
		staged, err := i.absoluteUninstallStaged(entry.Staged)
		if err != nil {
			return fmt.Errorf("entry[%d] staged: %w", index, err)
		}
		if err := verifyFile(source, entry.Release.release()); err != nil {
			return fmt.Errorf("verify uninstall source %q: %w", entry.Source, err)
		}
		if _, err := os.Lstat(staged); err == nil {
			return fmt.Errorf("%w: uninstall staged path already exists", ErrUninstallRecovery)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect uninstall staged path: %w", err)
		}
		if err := i.uninstallMoveFile(source, staged); err != nil {
			return fmt.Errorf("move uninstall entry %q: %w", entry.Source, err)
		}
		if err := verifyFile(staged, entry.Release.release()); err != nil {
			return fmt.Errorf("verify staged uninstall entry %q: %w", entry.Staged, err)
		}
	}
	return nil
}

// rollbackPreparedUninstall restores staged files and removes the prepared journal when possible.
// rollbackPreparedUninstall 恢复暂存文件，并在可能时删除预备日志。
func (i *Installer) rollbackPreparedUninstall(journal uninstallJournal, cause error) error {
	if err := i.restorePreparedUninstall(journal); err != nil {
		return fmt.Errorf("%w: %v; rollback failed, transaction retained at %s: %v", ErrUninstallRecovery, cause, i.uninstallTransactionPath, err)
	}
	return cause
}

// restorePreparedUninstall moves every staged entry back without overwriting a replacement file.
// restorePreparedUninstall 将每个暂存条目移回，并拒绝覆盖替代文件。
func (i *Installer) restorePreparedUninstall(journal uninstallJournal) error {
	for index := len(journal.Entries) - 1; index >= 0; index-- {
		entry := journal.Entries[index]
		source, err := i.absoluteUninstallSource(entry.Source)
		if err != nil {
			return fmt.Errorf("entry[%d] source: %w", index, err)
		}
		staged, err := i.absoluteUninstallStaged(entry.Staged)
		if err != nil {
			return fmt.Errorf("entry[%d] staged: %w", index, err)
		}
		_, sourceErr := os.Lstat(source)
		stagedInfo, stagedErr := os.Lstat(staged)
		sourceExists := sourceErr == nil
		stagedExists := stagedErr == nil
		if sourceErr != nil && !errors.Is(sourceErr, os.ErrNotExist) {
			return fmt.Errorf("inspect uninstall source %q: %w", entry.Source, sourceErr)
		}
		if stagedErr != nil && !errors.Is(stagedErr, os.ErrNotExist) {
			return fmt.Errorf("inspect uninstall staged %q: %w", entry.Staged, stagedErr)
		}
		if sourceExists && stagedExists {
			return fmt.Errorf("entry[%d] has both source and staged files", index)
		}
		if !sourceExists && !stagedExists {
			return fmt.Errorf("entry[%d] lost both source and staged files", index)
		}
		if sourceExists {
			if err := verifyFile(source, entry.Release.release()); err != nil {
				return fmt.Errorf("verify restored uninstall source %q: %w", entry.Source, err)
			}
			continue
		}
		if stagedInfo.Mode()&os.ModeSymlink != 0 || !stagedInfo.Mode().IsRegular() || hasReparsePoint(staged) {
			return fmt.Errorf("entry[%d] staged path is not a regular file", index)
		}
		if err := verifyFile(staged, entry.Release.release()); err != nil {
			return fmt.Errorf("verify staged uninstall entry %q: %w", entry.Staged, err)
		}
		if err := i.uninstallMoveFile(staged, source); err != nil {
			return fmt.Errorf("restore uninstall entry %q: %w", entry.Source, err)
		}
		if err := verifyFile(source, entry.Release.release()); err != nil {
			return fmt.Errorf("verify restored uninstall entry %q: %w", entry.Source, err)
		}
	}
	if err := i.removeEmptyUninstallTransactionDirectory(); err != nil {
		return err
	}
	if err := removeStateFile(i.uninstallJournalPath); err != nil {
		return fmt.Errorf("remove prepared uninstall journal: %w", err)
	}
	return nil
}

// finalizeCommittedUninstall removes the state and staged files, allowing retries after any failure.
// finalizeCommittedUninstall 删除状态和暂存文件，允许在失败后重试。
func (i *Installer) finalizeCommittedUninstall(journal uninstallJournal) error {
	if _, err := os.Lstat(i.statePath); err == nil {
		if err := i.requireUninstallState(journal); err != nil {
			return fmt.Errorf("validate committed uninstall state: %w", err)
		}
		if err := removeStateFile(i.statePath); err != nil {
			return fmt.Errorf("remove self-installation state: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect self-installation state during uninstall: %w", err)
	}
	for index, entry := range journal.Entries {
		source, err := i.absoluteUninstallSource(entry.Source)
		if err != nil {
			return fmt.Errorf("entry[%d] source: %w", index, err)
		}
		staged, err := i.absoluteUninstallStaged(entry.Staged)
		if err != nil {
			return fmt.Errorf("entry[%d] staged: %w", index, err)
		}
		stagedInfo, stagedErr := os.Lstat(staged)
		if errors.Is(stagedErr, os.ErrNotExist) {
			if _, sourceErr := os.Lstat(source); sourceErr == nil {
				return fmt.Errorf("%w: cleaned entry %q was recreated at source", ErrUninstallRecovery, entry.Source)
			} else if !errors.Is(sourceErr, os.ErrNotExist) {
				return fmt.Errorf("inspect cleaned source %q: %w", entry.Source, sourceErr)
			}
			continue
		}
		if stagedErr != nil {
			return fmt.Errorf("inspect staged uninstall entry %q: %w", entry.Staged, stagedErr)
		}
		if stagedInfo.Mode()&os.ModeSymlink != 0 || !stagedInfo.Mode().IsRegular() || hasReparsePoint(staged) {
			return fmt.Errorf("entry[%d] staged path is not a regular file", index)
		}
		if err := i.uninstallRemoveFile(staged, entry.Release.release()); err != nil {
			return fmt.Errorf("remove staged uninstall entry %q: %w", entry.Staged, err)
		}
	}
	if err := i.removeEmptyUninstallTransactionDirectory(); err != nil {
		return err
	}
	if err := removeStateFile(i.uninstallJournalPath); err != nil {
		return fmt.Errorf("remove committed uninstall journal: %w", err)
	}
	return nil
}

// removeEmptyUninstallTransactionDirectory removes only the known empty staging directory.
// removeEmptyUninstallTransactionDirectory 只删除已知且为空的暂存目录。
func (i *Installer) removeEmptyUninstallTransactionDirectory() error {
	info, err := os.Lstat(i.uninstallTransactionPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect uninstall transaction directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || hasReparsePoint(i.uninstallTransactionPath) {
		return fmt.Errorf("%w: uninstall transaction directory is not secure", ErrUninstallRecovery)
	}
	entries, err := os.ReadDir(i.uninstallTransactionPath)
	if err != nil {
		return fmt.Errorf("read uninstall transaction directory: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("%w: uninstall transaction directory still contains files", ErrUninstallRecovery)
	}
	if err := os.Remove(i.uninstallTransactionPath); err != nil {
		return fmt.Errorf("remove uninstall transaction directory: %w", err)
	}
	return nil
}

// rejectOrRemoveOrphanUninstallDirectory fails closed on unknown staged files.
// rejectOrRemoveOrphanUninstallDirectory 对未知暂存文件失败关闭。
func (i *Installer) rejectOrRemoveOrphanUninstallDirectory() error {
	info, err := os.Lstat(i.uninstallTransactionPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect orphan uninstall transaction: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || hasReparsePoint(i.uninstallTransactionPath) {
		return fmt.Errorf("%w: orphan uninstall transaction is not secure", ErrUninstallRecovery)
	}
	entries, err := os.ReadDir(i.uninstallTransactionPath)
	if err != nil {
		return fmt.Errorf("read orphan uninstall transaction: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("%w: orphan uninstall transaction has no journal", ErrUninstallRecovery)
	}
	if err := os.Remove(i.uninstallTransactionPath); err != nil {
		return fmt.Errorf("remove empty orphan uninstall transaction: %w", err)
	}
	return nil
}

// result creates a stable caller-facing operation result.
// result 创建稳定的调用方操作结果。
func (i *Installer) result(action string, release Release) Result {
	return Result{Action: action, Version: release.Version, ExecutablePath: i.executablePath, ExecutableDirectory: i.ExecutableDirectory()}
}

// loadRecord reads and validates the presence of the strict ownership document.
// loadRecord 读取并验证严格所有权文档是否存在。
func (i *Installer) loadRecord() (persistedRecord, error) {
	info, statErr := os.Lstat(i.statePath)
	if errors.Is(statErr, os.ErrNotExist) {
		return persistedRecord{}, ErrNotInstalled
	}
	if statErr != nil {
		return persistedRecord{}, fmt.Errorf("inspect self-installation state: %w", statErr)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return persistedRecord{}, fmt.Errorf("%w: state path is not a regular file", ErrCorruptState)
	}
	file, err := os.Open(i.statePath)
	if err != nil {
		return persistedRecord{}, fmt.Errorf("open self-installation state: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return persistedRecord{}, fmt.Errorf("%w: state path changed while it was opened", ErrCorruptState)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil {
		return persistedRecord{}, fmt.Errorf("read self-installation state: %w", err)
	}
	if int64(len(data)) > maxStateBytes {
		return persistedRecord{}, fmt.Errorf("%w: state exceeds %d bytes", ErrCorruptState, maxStateBytes)
	}
	record, err := decodeStrict(data)
	if err != nil {
		return persistedRecord{}, fmt.Errorf("%w: decode state: %v", ErrCorruptState, err)
	}
	return record, nil
}

// saveRecord writes the record beside the final path and replaces it atomically.
// saveRecord 在最终路径旁写入记录并原子替换记录文件。
func (i *Installer) saveRecord(record persistedRecord) error {
	if err := i.validateRecord(record); err != nil {
		return fmt.Errorf("validate self-installation state: %w", err)
	}
	if err := ensureDirectory(filepath.Dir(i.statePath), 0700); err != nil {
		return fmt.Errorf("prepare state directory: %w", err)
	}
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal self-installation state: %w", err)
	}
	payload = append(payload, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(i.statePath), ".vmmm-state-")
	if err != nil {
		return fmt.Errorf("create state temporary: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set state permissions: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	if info, err := os.Lstat(i.statePath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: state path is not a regular file", ErrUnsafePath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect state path: %w", err)
	}
	if err := os.Rename(temporaryPath, i.statePath); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	removeTemporary = false
	return nil
}

// validateRecord binds every persisted path to this installer and rejects ambiguous ownership.
// validateRecord 将每个持久化路径绑定到本安装器，并拒绝不明确的所有权。
func (i *Installer) validateRecord(record persistedRecord) error {
	if record.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %d", record.ProtocolVersion)
	}
	if !samePath(record.InstallRoot, i.options.InstallRoot) {
		return errors.New("state install root does not match installer root")
	}
	if record.Executable != i.options.ExecutableName {
		return errors.New("state executable does not match installer executable")
	}
	if err := validateRelease(record.Current.release()); err != nil {
		return fmt.Errorf("current release: %w", err)
	}
	if record.Backups == nil {
		return errors.New("backups must be an array")
	}
	seen := make(map[string]struct{}, len(record.Backups))
	for index, backup := range record.Backups {
		if err := validateRelease(backup.Release.release()); err != nil {
			return fmt.Errorf("backup[%d] release: %w", index, err)
		}
		absolute, err := i.absoluteOwnedPath(backup.Path)
		if err != nil {
			return fmt.Errorf("backup[%d] path: %w", index, err)
		}
		key := canonicalPath(absolute)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("backup[%d] path is duplicated", index)
		}
		seen[key] = struct{}{}
		if samePath(absolute, i.executablePath) || samePath(absolute, i.statePath) {
			return fmt.Errorf("backup[%d] path overlaps a protected file", index)
		}
	}
	return nil
}

// verifyBackups verifies every recorded backup before a mutating operation starts.
// verifyBackups 在变更操作开始前验证每个已记录的备份。
func (i *Installer) verifyBackups(record persistedRecord) ([]persistedBackup, error) {
	verified := make([]persistedBackup, 0, len(record.Backups))
	for _, backup := range record.Backups {
		release := backup.Release.release()
		absolute, err := i.absoluteOwnedPath(backup.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid rollback path: %v", ErrCorruptState, err)
		}
		if err := verifyFile(absolute, release); err != nil {
			return nil, fmt.Errorf("verify rollback %q: %w", backup.Path, classifyOwnedFileError(err))
		}
		verified = append(verified, backup)
	}
	return verified, nil
}

// absoluteOwnedPath resolves a relative backup path and enforces the backup-root boundary.
// absoluteOwnedPath 解析相对备份路径并强制其位于备份根目录内。
func (i *Installer) absoluteOwnedPath(relative string) (string, error) {
	if err := validateRelativePath(relative); err != nil {
		return "", err
	}
	if err := validateSecurePathChain(i.backupRoot, true); err != nil {
		return "", err
	}
	abs := filepath.Join(i.options.InstallRoot, filepath.FromSlash(relative))
	if !pathWithin(abs, i.backupRoot) {
		return "", errors.New("backup path escapes backup root")
	}
	return abs, nil
}

// copyIntoRoot verifies source bytes and creates a private executable temporary file in InstallRoot.
// copyIntoRoot 验证源文件字节并在 InstallRoot 中创建私有可执行临时文件。
func (i *Installer) copyIntoRoot(sourcePath string, release Release, prefix string) (string, error) {
	temporary, err := os.CreateTemp(i.options.InstallRoot, prefix)
	if err != nil {
		return "", fmt.Errorf("create executable temporary: %w", err)
	}
	path := temporary.Name()
	if err := temporary.Chmod(0755); err != nil {
		_ = temporary.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("set executable temporary permissions: %w", err)
	}
	if err := copyVerified(sourcePath, temporary, release); err != nil {
		_ = temporary.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("sync executable temporary: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close executable temporary: %w", err)
	}
	return path, nil
}

// createBackup copies a verified current executable into the owned backup root.
// createBackup 将经验证的当前可执行文件复制到受管备份根目录。
func (i *Installer) createBackup(release Release) (string, persistedBackup, error) {
	if err := ensureDirectory(i.backupRoot, 0700); err != nil {
		return "", persistedBackup{}, fmt.Errorf("prepare backup root: %w", err)
	}
	temporary, err := os.CreateTemp(i.backupRoot, ".vmmm-rollback-")
	if err != nil {
		return "", persistedBackup{}, fmt.Errorf("create rollback file: %w", err)
	}
	path := temporary.Name()
	if err := temporary.Chmod(0755); err != nil {
		_ = temporary.Close()
		_ = os.Remove(path)
		return "", persistedBackup{}, fmt.Errorf("set rollback permissions: %w", err)
	}
	if err := copyVerified(i.executablePath, temporary, release); err != nil {
		_ = temporary.Close()
		_ = os.Remove(path)
		return "", persistedBackup{}, fmt.Errorf("copy rollback: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		_ = os.Remove(path)
		return "", persistedBackup{}, fmt.Errorf("sync rollback: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(path)
		return "", persistedBackup{}, fmt.Errorf("close rollback: %w", err)
	}
	relative, err := filepath.Rel(i.options.InstallRoot, path)
	if err != nil {
		_ = os.Remove(path)
		return "", persistedBackup{}, fmt.Errorf("relativize rollback path: %w", err)
	}
	relative = filepath.ToSlash(relative)
	backup := persistedBackup{Path: relative, Release: release.persisted()}
	return path, backup, nil
}

// recoverReplacementFailure restores the previous image and preserves the backup when recovery is incomplete.
// recoverReplacementFailure 恢复旧映像，并在恢复未完成时保留备份以防止数据丢失。
func (i *Installer) recoverReplacementFailure(backupPath string, release Release, phase string, cause error) error {
	restoreErr := i.restoreCurrentFile(backupPath, release)
	if restoreErr != nil {
		return fmt.Errorf("%s: %w; restore previous executable failed, backup retained at %s: %v", phase, cause, backupPath, restoreErr)
	}
	if removeErr := removeOwnedFile(backupPath, release); removeErr != nil {
		return fmt.Errorf("%s: %w; previous executable restored, backup retained at %s because cleanup failed: %v", phase, cause, backupPath, removeErr)
	}
	return fmt.Errorf("%s: %w; previous executable restored", phase, cause)
}

// restoreCurrent restores a verified backup over the managed executable after a state failure.
// restoreCurrent 在状态写入失败后将经验证备份恢复到受管可执行文件。
func (i *Installer) restoreCurrent(backupPath string, release Release) error {
	temporary, err := os.CreateTemp(i.options.InstallRoot, ".vmmm-restore-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Chmod(0755); err != nil {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := copyVerified(backupPath, temporary, release); err != nil {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := replaceFile(temporaryPath, i.executablePath); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	return verifyFile(i.executablePath, release)
}

// isRunningExecutable applies the process-image guard before replacement or deletion.
// isRunningExecutable 在替换或删除前执行当前进程映像保护。
func (i *Installer) isRunningExecutable() bool {
	if i == nil || runtime.GOOS != "windows" || i.options.CurrentExecutable == "" {
		return false
	}
	return samePath(i.options.CurrentExecutable, i.executablePath)
}

// publishNewFile uses create-if-absent hard-link publication to avoid overwriting an owner.
// publishNewFile 使用仅创建硬链接的发布方式，避免覆盖已有所有者。
func publishNewFile(temporary string, destination string) error {
	if info, err := os.Lstat(destination); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: destination is not a regular file", ErrConflict)
		}
		return ErrConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect destination: %w", err)
	}
	if err := os.Link(temporary, destination); err != nil {
		if _, statErr := os.Lstat(destination); statErr == nil {
			return ErrConflict
		}
		return fmt.Errorf("publish executable without overwrite: %w", err)
	}
	if err := os.Remove(temporary); err != nil {
		// The hard link is still the same file as the temporary path. Remove the
		// destination when cleanup fails so a failed first install cannot leave an
		// unrecorded executable behind.
		// 硬链接仍然与临时路径指向同一文件；清理失败时删除目标，避免首装失败留下未登记可执行文件。
		_ = os.Remove(destination)
		return fmt.Errorf("remove executable temporary after publish: %w", err)
	}
	return nil
}

// replaceFile atomically renames a same-directory temporary over the owned destination.
// replaceFile 将同目录临时文件原子重命名覆盖受管目标。
func replaceFile(temporary string, destination string) error {
	if info, err := os.Lstat(destination); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect replacement destination: %w", err)
		}
	} else if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: replacement destination is not a regular file", ErrUnsafePath)
	}
	if err := os.Rename(temporary, destination); err != nil {
		return fmt.Errorf("replace executable: %w", err)
	}
	return nil
}

// copyVerified streams one regular source file into an already-created destination and checks exact bytes.
// copyVerified 将一个普通源文件流式复制到已创建目标，并检查精确字节。
func copyVerified(sourcePath string, destination *os.File, release Release) error {
	if err := validateAbsoluteExistingFile(sourcePath); err != nil {
		return err
	}
	initialInfo, err := os.Lstat(sourcePath)
	if err != nil {
		return fmt.Errorf("inspect executable source: %w", err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open executable source: %w", err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("executable source changed from a regular file")
	}
	if !os.SameFile(initialInfo, info) {
		return errors.New("executable source changed while it was opened")
	}
	if info.Size() > maxReleaseFileBytes {
		return fmt.Errorf("executable source exceeds %d bytes", maxReleaseFileBytes)
	}
	hash := sha256.New()
	writer := io.MultiWriter(destination, hash)
	limited := io.LimitReader(source, release.Size+1)
	written, err := io.CopyBuffer(writer, limited, make([]byte, 64*1024))
	if err != nil {
		return fmt.Errorf("copy executable bytes: %w", err)
	}
	if written != release.Size {
		return fmt.Errorf("executable size is %d, expected %d", written, release.Size)
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if digest != release.SHA256 {
		return errors.New("executable SHA-256 does not match the authenticated release")
	}
	if after, statErr := source.Stat(); statErr != nil || after.Size() != info.Size() {
		return errors.New("executable source changed while it was copied")
	}
	return nil
}

// verifyFile checks ownership metadata without following a final symlink.
// verifyFile 检查所有权元数据且不跟随最终符号链接。
func verifyFile(path string, release Release) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("owned path is not a regular file")
	}
	if info.Size() != release.Size {
		return fmt.Errorf("owned file size is %d, expected %d", info.Size(), release.Size)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return errors.New("owned path changed while it was opened")
	}
	hash := sha256.New()
	if _, err := io.CopyBuffer(hash, io.LimitReader(file, release.Size+1), make([]byte, 64*1024)); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != release.SHA256 {
		return ErrModified
	}
	return nil
}

// removeOwnedFile removes a regular file only after its exact release digest is verified.
// removeOwnedFile 只有在验证文件与发行摘要完全一致后才删除普通文件。
func removeOwnedFile(path string, release Release) error {
	if err := verifyFile(path, release); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return nil
}

// removeStateFile removes a regular ownership record and rejects a replacement symlink.
// removeStateFile 删除普通所有权记录，并拒绝替代符号链接。
func removeStateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ErrUnsafePath
	}
	return os.Remove(path)
}

// classifyOwnedFileError keeps ownership failures distinguishable to callers.
// classifyOwnedFileError 保持所有权文件错误对调用方可区分。
func classifyOwnedFileError(err error) error {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrModified) {
		return ErrModified
	}
	return err
}

// decodeStrict decodes one ownership record with unknown, duplicate, and trailing data rejected.
// decodeStrict 解码一个所有权记录，并拒绝未知键、重复键和尾随数据。
func decodeStrict(data []byte) (persistedRecord, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return persistedRecord{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record persistedRecord
	if err := decoder.Decode(&record); err != nil {
		return persistedRecord{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return persistedRecord{}, errors.New("state contains multiple JSON values")
		}
		return persistedRecord{}, err
	}
	return record, nil
}

// rejectDuplicateKeys recursively rejects duplicate object keys before struct decoding.
// rejectDuplicateKeys 在结构体解码前递归拒绝重复对象键。
func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSON(decoder, "$", 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("JSON contains multiple top-level values")
		}
		return err
	}
	return nil
}

// walkJSON consumes one JSON value and tracks keys with a bounded recursion depth.
// walkJSON 消费一个 JSON 值并在有界递归深度内跟踪对象键。
func walkJSON(decoder *json.Decoder, location string, depth int) error {
	if depth > 128 {
		return errors.New("JSON nesting exceeds 128 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key at %s is not a string", location)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q at %s", key, location)
			}
			seen[key] = struct{}{}
			if err := walkJSON(decoder, location+"."+key, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			if err != nil {
				return err
			}
			return fmt.Errorf("JSON object at %s is not closed", location)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := walkJSON(decoder, fmt.Sprintf("%s[%d]", location, index), depth+1); err != nil {
				return err
			}
			index++
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			if err != nil {
				return err
			}
			return fmt.Errorf("JSON array at %s is not closed", location)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, location)
	}
	return nil
}

// validateRelease rejects malformed identity, filename, digest, or unbounded copy metadata.
// validateRelease 拒绝可能进入路径或造成无界复制的元数据。
func validateRelease(release Release) error {
	if err := validateMetadataText("release version", release.Version, 256); err != nil {
		return err
	}
	if err := validateMetadataText("release commit", release.Commit, 256); err != nil {
		return err
	}
	if err := validateSafeComponent("release platform", release.Platform, 64); err != nil {
		return err
	}
	if err := validateFilename(release.Filename); err != nil {
		return err
	}
	if release.Size <= 0 || release.Size > maxReleaseFileBytes {
		return fmt.Errorf("release size %d is outside the supported range", release.Size)
	}
	if len(release.SHA256) != sha256.Size*2 || strings.ToLower(release.SHA256) != release.SHA256 || !isLowerHex(release.SHA256) {
		return errors.New("release SHA-256 must be lowercase hexadecimal")
	}
	return nil
}

// validateMetadataText accepts signed identity text without inventing a commit format.
// validateMetadataText 接受签名身份文本，不擅自发明提交格式。
func validateMetadataText(field string, value string, maximum int) error {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is empty, too long, or padded", field)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return nil
}

// validateExecutableName accepts only the fixed command basename shape.
// validateExecutableName 只接受固定命令的文件名形状。
func validateExecutableName(name string) error {
	if name != "vmmm" && name != "vmmm.exe" {
		return errors.New("executable name must be vmmm or vmmm.exe")
	}
	if runtime.GOOS == "windows" && name != "vmmm.exe" {
		return errors.New("Windows executable name must be vmmm.exe")
	}
	if runtime.GOOS != "windows" && name != "vmmm" {
		return errors.New("POSIX executable name must be vmmm")
	}
	return nil
}

// validateFilename rejects path separators, controls, and special path names.
// validateFilename 拒绝路径分隔符、控制字符和特殊路径名。
func validateFilename(name string) error {
	if name == "" || len(name) > 256 || name == "." || name == ".." || strings.Contains(name, "..") || filepath.Base(name) != name || strings.TrimSpace(name) != name || strings.ContainsRune(name, '\x00') {
		return errors.New("release filename must be a regular basename")
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return errors.New("release filename contains a control character")
		}
	}
	return nil
}

// validateSafeComponent accepts path-free printable metadata components.
// validateSafeComponent 接受不含路径且可打印的元数据组件。
func validateSafeComponent(field string, value string, maximum int) error {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is empty, too long, or padded", field)
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '/' || character == '\\' {
			return fmt.Errorf("%s contains an unsafe character", field)
		}
	}
	return nil
}

// validateRelativePath accepts a normalized forward-slash path below the backup directory.
// validateRelativePath 接受备份目录下规范化的正斜杠相对路径。
func validateRelativePath(value string) error {
	if value == "" || strings.ContainsRune(value, '\\') || filepath.IsAbs(filepath.FromSlash(value)) || filepath.VolumeName(filepath.FromSlash(value)) != "" {
		return errors.New("owned backup path must be relative and use forward slashes")
	}
	if filepath.ToSlash(filepath.Clean(filepath.FromSlash(value))) != value || strings.HasPrefix(value, "/") {
		return errors.New("owned backup path is not normalized")
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("owned backup path contains an invalid component")
		}
	}
	return nil
}

// validateAbsoluteExistingFile rejects a final symlink before it is opened as an artifact.
// validateAbsoluteExistingFile 在打开资产前拒绝最终符号链接。
func validateAbsoluteExistingFile(path string) error {
	absolute, err := normalizeAbsolutePath("source path", path)
	if err != nil || absolute != path {
		if err != nil {
			return err
		}
		return errors.New("source path must already be normalized")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect executable source: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ErrUnsafePath
	}
	return nil
}

// normalizeAbsolutePath enforces explicit normalized absolute paths with no controls.
// normalizeAbsolutePath 强制路径为明确、规范、绝对且不含控制字符的形式。
func normalizeAbsolutePath(field string, value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || !filepath.IsAbs(value) {
		return "", fmt.Errorf("%s must be an absolute path without surrounding whitespace", field)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", fmt.Errorf("%s contains a control character", field)
		}
	}
	cleaned := filepath.Clean(value)
	if cleaned != value {
		return "", fmt.Errorf("%s must be normalized", field)
	}
	return cleaned, nil
}

// validateSecurePathChain checks existing components for symlink/reparse traversal.
// validateSecurePathChain 检查现有路径组件，拒绝符号链接或重解析点穿越。
func validateSecurePathChain(path string, allowMissingLeaf bool) error {
	cleaned, err := normalizeAbsolutePath("secure path", path)
	if err != nil {
		return err
	}
	components := pathComponents(cleaned)
	for index, component := range components {
		info, statErr := os.Lstat(component)
		if errors.Is(statErr, os.ErrNotExist) {
			if !allowMissingLeaf {
				return os.ErrNotExist
			}
			if index != len(components)-1 {
				continue
			}
			break
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || hasReparsePoint(component) {
			return ErrUnsafePath
		}
		if !info.IsDir() {
			return fmt.Errorf("secure path component %q is not a directory", component)
		}
		resolved, resolveErr := filepath.EvalSymlinks(component)
		if resolveErr != nil || !samePath(resolved, component) {
			return ErrUnsafePath
		}
	}
	return nil
}

// ensureDirectory creates missing components one at a time and rechecks every result.
// ensureDirectory 逐个创建缺失组件并重新检查每个结果。
func ensureDirectory(path string, mode os.FileMode) error {
	cleaned, err := normalizeAbsolutePath("directory", path)
	if err != nil {
		return err
	}
	if err := validateSecurePathChain(cleaned, true); err != nil {
		return err
	}
	components := pathComponents(cleaned)
	for _, component := range components {
		info, statErr := os.Lstat(component)
		if errors.Is(statErr, os.ErrNotExist) {
			if err := os.Mkdir(component, mode); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			info, statErr = os.Lstat(component)
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || hasReparsePoint(component) {
			return ErrUnsafePath
		}
	}
	return nil
}

// pathComponents returns root-to-leaf components for secure incremental checks.
// pathComponents 返回用于安全逐级检查的根到叶路径组件。
func pathComponents(path string) []string {
	var reversed []string
	current := filepath.Clean(path)
	for {
		reversed = append(reversed, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	components := make([]string, len(reversed))
	for index := range reversed {
		components[len(reversed)-index-1] = reversed[index]
	}
	return components
}

// rejectTemporaryPath keeps the permanent installation and state outside the system temporary tree.
// rejectTemporaryPath 保持永久安装目录和状态目录位于系统临时树之外。
func rejectTemporaryPath(path string) error {
	temporary, err := filepath.Abs(os.TempDir())
	if err != nil {
		return nil
	}
	if pathWithin(path, temporary) {
		return fmt.Errorf("%w: path is inside the system temporary directory", ErrUnsafePath)
	}
	return nil
}

// pathWithin reports whether candidate is equal to or below parent after normalization.
// pathWithin 判断 candidate 规范化后是否等于 parent 或位于其下方。
func pathWithin(candidate string, parent string) bool {
	candidate = canonicalPath(candidate)
	parent = canonicalPath(parent)
	relative, err := filepath.Rel(parent, candidate)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

// samePath compares paths with the platform's case rules.
// samePath 按当前平台的大小写规则比较路径。
func samePath(left string, right string) bool {
	return canonicalPath(left) == canonicalPath(right)
}

// canonicalPath normalizes separators and applies Windows case folding.
// canonicalPath 规范化分隔符并在 Windows 上执行大小写折叠。
func canonicalPath(value string) string {
	cleaned := filepath.Clean(value)
	if runtime.GOOS == "windows" {
		return strings.ToLower(cleaned)
	}
	return cleaned
}

// defaultExecutableName chooses the command basename for the current target OS.
// defaultExecutableName 为当前目标操作系统选择命令文件名。
func defaultExecutableName() string {
	if runtime.GOOS == "windows" {
		return "vmmm.exe"
	}
	return "vmmm"
}

// isLowerHex checks the canonical lowercase hexadecimal representation.
// isLowerHex 检查规范的小写十六进制表示。
func isLowerHex(value string) bool {
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return value != ""
}

// sameRelease compares every authenticated release field that controls ownership.
// sameRelease 比较控制所有权的每个经认证发行字段。
func sameRelease(left Release, right Release) bool {
	return left == right
}

// prependBackup returns a new slice so callers cannot mutate persisted ordering accidentally.
// prependBackup 返回新切片，避免调用方意外修改持久化顺序。
func prependBackup(first persistedBackup, rest []persistedBackup) []persistedBackup {
	result := make([]persistedBackup, 0, len(rest)+1)
	result = append(result, first)
	result = append(result, rest...)
	return result
}

// release converts the strict persisted form back to the public value.
// release 将严格持久化形式转换回公开值。
func (value persistedRelease) release() Release {
	return Release{Version: value.Version, Commit: value.Commit, Platform: value.Platform, Filename: value.Filename, SHA256: value.SHA256, Size: value.Size}
}

// persisted converts the public release to its JSON-safe form.
// persisted 将公开发行信息转换为 JSON 安全形式。
func (value Release) persisted() persistedRelease {
	return persistedRelease{Version: value.Version, Commit: value.Commit, Platform: value.Platform, Filename: value.Filename, SHA256: value.SHA256, Size: value.Size}
}
