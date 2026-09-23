// install_test.go verifies VMM transaction boundaries, config validation, and data preservation.
// install_test.go 验证 VMM 事务边界、配置校验和数据保留行为。
package install

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/archive"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/fetch"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/manifest"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/platform"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/testpath"
)

// TestInstallPromotesVerifiedPackageAndValidatesConfig checks the complete first-install transaction.
// TestInstallPromotesVerifiedPackageAndValidatesConfig 验证完整的首次安装事务。
func TestInstallPromotesVerifiedPackageAndValidatesConfig(t *testing.T) {
	request, paths, packageRoot := newInstallRequest(t, "")
	var validatedBinary string
	var validatedConfig string
	request.ValidateConfig = func(_ context.Context, binaryPath string, configRoot string) (configbridge.ValidationResult, error) {
		validatedBinary = binaryPath
		validatedConfig = configRoot
		if _, err := os.Stat(binaryPath); err != nil {
			return configbridge.ValidationResult{}, err
		}
		if _, err := os.Stat(filepath.Join(configRoot, UserConfigFileName)); err != nil {
			return configbridge.ValidationResult{}, err
		}
		return configbridge.ValidationResult{Valid: true, Errors: []configbridge.ValidationError{}}, nil
	}

	result, err := Install(context.Background(), request)
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if result.Operation != OperationInstall || result.State.Paths != paths {
		t.Fatalf("unexpected install result: %#v", result)
	}
	if validatedBinary == "" || validatedConfig == "" {
		t.Fatal("candidate validator was not called")
	}
	assertFileExists(t, filepath.Join(paths.ProgramRoot, "bin", vmmExecutableName()))
	assertFileExists(t, filepath.Join(paths.ProgramRoot, "configs", "base.yaml"))
	assertFileExists(t, filepath.Join(paths.ProgramRoot, "libs", "vldb.dll"))
	assertFileExists(t, filepath.Join(paths.ConfigRoot, UserConfigFileName))
	if _, err := os.Stat(packageRoot); err != nil {
		t.Fatalf("package staging should remain caller-owned: %v", err)
	}
	loaded, err := state.Load(request.StatePath)
	if err != nil {
		t.Fatalf("state.Load() error = %v", err)
	}
	if len(loaded.ManagedFiles) != 4 {
		t.Fatalf("managed file count = %d, want 4", len(loaded.ManagedFiles))
	}
}

// TestStagePackageSeparatesDownloadFromFinalCommit checks the two-phase installer handle.
// TestStagePackageSeparatesDownloadFromFinalCommit 验证下载暂存与最终提交分离。
func TestStagePackageSeparatesDownloadFromFinalCommit(t *testing.T) {
	request, paths, _ := newInstallRequest(t, "")
	request.ValidateConfig = validConfigValidator(t)
	prepared, err := StagePackage(context.Background(), request)
	if err != nil {
		t.Fatalf("StagePackage() error = %v", err)
	}
	request.ConfigFiles = map[string][]byte{UserConfigFileName: []byte("mode: native\n")}
	result, err := prepared.CommitInstall(context.Background(), request)
	if err != nil {
		t.Fatalf("CommitInstall() error = %v", err)
	}
	if result.State.Paths != paths {
		t.Fatalf("committed paths = %#v, want %#v", result.State.Paths, paths)
	}
	prepared.Close()
	if _, err := prepared.CommitInstall(context.Background(), request); err == nil {
		t.Fatal("closed prepared package unexpectedly committed")
	}
}

// TestInstallRejectsUnixControlStateInDataRoot prevents a CLI install from creating state that later service or uninstall operations cannot use.
// TestInstallRejectsUnixControlStateInDataRoot 防止命令行安装创建后续服务操作或卸载无法安全使用的状态。
func TestInstallRejectsUnixControlStateInDataRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows keeps registration state below its protected data root")
	}
	request, paths, _ := newInstallRequest(t, "")
	request.ValidateConfig = validConfigValidator(t)
	request.StatePath = filepath.Join(paths.DataRoot, RegistrationFileName)
	if _, err := Install(context.Background(), request); err == nil || !strings.Contains(err.Error(), "Unix control state root") {
		t.Fatalf("install with service-writable control state error = %v", err)
	}
}

// TestInstallRejectsInvalidConfigBeforeProgramPromotion verifies fail-closed config validation.
// TestInstallRejectsInvalidConfigBeforeProgramPromotion 验证配置失败时不会推广程序文件。
func TestInstallRejectsInvalidConfigBeforeProgramPromotion(t *testing.T) {
	request, paths, _ := newInstallRequest(t, "")
	request.ValidateConfig = func(context.Context, string, string) (configbridge.ValidationResult, error) {
		return configbridge.ValidationResult{Valid: false, Errors: []configbridge.ValidationError{{Path: "storage.mode", Message: "invalid mode"}}}, nil
	}
	if _, err := Install(context.Background(), request); !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("Install() error = %v, want ErrConfigInvalid", err)
	}
	if _, err := os.Stat(paths.ProgramRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("program root after invalid config = %v, want missing", err)
	}
	if _, err := os.Stat(request.StatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state path after invalid config = %v, want missing", err)
	}
	if _, err := os.Stat(paths.ConfigRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("config root after invalid config = %v, want missing", err)
	}
}

// TestUpgradePreservesDatabaseAndModifiedStaleFiles checks the protected data boundary.
// TestUpgradePreservesDatabaseAndModifiedStaleFiles 验证数据库和用户修改文件不会被升级破坏。
func TestUpgradePreservesDatabaseAndModifiedStaleFiles(t *testing.T) {
	request, paths, _ := newInstallRequest(t, "")
	request.ValidateConfig = validConfigValidator(t)
	if _, err := Install(context.Background(), request); err != nil {
		t.Fatalf("initial Install() error = %v", err)
	}
	databasePath := filepath.Join(paths.ProgramRoot, "database", "sqlite.db")
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(databasePath, []byte("database-preserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	modifiedPath := filepath.Join(paths.ProgramRoot, "libs", "vldb.dll")
	if err := os.WriteFile(modifiedPath, []byte("user-modified"), 0o600); err != nil {
		t.Fatal(err)
	}
	newRequest, _, _ := newInstallRequest(t, request.Package.Root)
	newRequest.Paths = paths
	newRequest.StatePath = request.StatePath
	newRequest.ValidateConfig = validConfigValidator(t)
	newRequest.Operation = OperationUpgrade
	if _, err := Upgrade(context.Background(), newRequest); !errors.Is(err, ErrConflict) {
		t.Fatalf("Upgrade() error = %v, want ErrConflict", err)
	}
	if got, _ := os.ReadFile(databasePath); string(got) != "database-preserved" {
		t.Fatalf("database content = %q, want preserved", got)
	}
	if got, _ := os.ReadFile(modifiedPath); string(got) != "user-modified" {
		t.Fatalf("modified stale file content = %q, want preserved", got)
	}
}

// TestUninstallDeletesOnlyMatchingFiles checks digest ownership and data preservation.
// TestUninstallDeletesOnlyMatchingFiles 验证卸载只删除摘要匹配的管理文件并保留数据。
func TestUninstallDeletesOnlyMatchingFiles(t *testing.T) {
	request, paths, _ := newInstallRequest(t, "")
	request.ValidateConfig = validConfigValidator(t)
	if _, err := Install(context.Background(), request); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	modifiedPath := filepath.Join(paths.ProgramRoot, "libs", "vldb.dll")
	if err := os.WriteFile(modifiedPath, []byte("modified"), 0o600); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(paths.ProgramRoot, "database", "sqlite.db")
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(databasePath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Uninstall(context.Background(), UninstallRequest{
		ManagerRoot:        request.ManagerRoot,
		Paths:              paths,
		StatePath:          request.StatePath,
		DeleteRegistration: true,
	})
	if err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}
	if result.RegistrationDeleted {
		t.Fatal("registration was deleted while a modified file remained")
	}
	if _, err := os.Stat(request.StatePath); err != nil {
		t.Fatalf("state after partial uninstall = %v, want retained", err)
	}
	if got, _ := os.ReadFile(modifiedPath); string(got) != "modified" {
		t.Fatalf("modified file content = %q, want preserved", got)
	}
	if got, _ := os.ReadFile(databasePath); string(got) != "keep" {
		t.Fatalf("database content = %q, want preserved", got)
	}
}

// TestUninstallRejectsSymlinkedManagedParent protects the path boundary during uninstall.
// TestUninstallRejectsSymlinkedManagedParent 验证卸载遇到符号链接父目录时拒绝越界操作。
func TestUninstallRejectsSymlinkedManagedParent(t *testing.T) {
	request, paths, _ := newInstallRequest(t, "")
	request.ValidateConfig = validConfigValidator(t)
	if _, err := Install(context.Background(), request); err != nil {
		t.Fatalf("Install() error = %v", err)
	}

	outsideRoot := filepath.Join(testpath.CanonicalTempDir(t), "outside")
	if err := os.MkdirAll(outsideRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outsideRoot, "vldb.dll")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	managedDirectory := filepath.Join(paths.ProgramRoot, "libs")
	managedDirectoryBackup := filepath.Join(paths.ProgramRoot, "libs-real")
	if err := os.Rename(managedDirectory, managedDirectoryBackup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideRoot, managedDirectory); err != nil {
		t.Skipf("creating symlink requires platform permission: %v", err)
	}

	if _, err := Uninstall(context.Background(), UninstallRequest{
		ManagerRoot:        request.ManagerRoot,
		Paths:              paths,
		StatePath:          request.StatePath,
		DeleteRegistration: true,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("Uninstall() error = %v, want ErrConflict", err)
	}
	if got, err := os.ReadFile(outsideFile); err != nil || string(got) != "outside" {
		t.Fatalf("outside file after rejected uninstall = %q, error = %v", got, err)
	}
}

// TestCallerPackageMutationCannotChangeInstalledArtifact verifies that caller package input is ignored.
// TestCallerPackageMutationCannotChangeInstalledArtifact 验证调用方传入的包目录不会改变安装内容。
func TestCallerPackageMutationCannotChangeInstalledArtifact(t *testing.T) {
	request, _, _ := newInstallRequest(t, "")
	request.ValidateConfig = validConfigValidator(t)
	binaryPath := filepath.Join(request.Package.Root, "bin", vmmExecutableName())
	if err := os.WriteFile(binaryPath, []byte("attacker binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(request.Package.Root, "release-manifest.json"), []byte(`{"manifest_schema":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Install(context.Background(), request)
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if result.State.VMM.Tag != "v1.2.3" {
		t.Fatalf("installed version = %q, want v1.2.3", result.State.VMM.Tag)
	}
	installed, err := os.ReadFile(filepath.Join(request.Paths.ProgramRoot, "bin", vmmExecutableName()))
	if err != nil {
		t.Fatal(err)
	}
	if string(installed) != "vmm executable" {
		t.Fatalf("installed binary = %q, want archive payload", installed)
	}
}

// TestPreparedCommitUsesPrivatePackage verifies that final commit uses the private re-extracted package.
// TestPreparedCommitUsesPrivatePackage 验证最终提交使用私有重新解包的程序包。
func TestPreparedCommitUsesPrivatePackage(t *testing.T) {
	request, _, _ := newInstallRequest(t, "")
	request.ValidateConfig = validConfigValidator(t)
	forgedRoot := filepath.Join(testpath.CanonicalTempDir(t), filepath.Base(request.Package.Root))
	if err := os.MkdirAll(forgedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	request.Package.Root = forgedRoot
	prepared, err := StagePackage(context.Background(), request)
	if err != nil {
		t.Fatalf("StagePackage() error = %v", err)
	}
	defer prepared.Close()
	result, err := prepared.CommitInstall(context.Background(), request)
	if err != nil {
		t.Fatalf("CommitInstall() error = %v", err)
	}
	if result.State.VMM.Tag != "v1.2.3" {
		t.Fatalf("installed version = %q, want v1.2.3", result.State.VMM.Tag)
	}
}

// TestRejectUpgradeDowngrade enforces monotonic upgrades and explicit rollback semantics.
// TestRejectUpgradeDowngrade 验证升级版本单调递增，降级必须显式回滚。
func TestRejectUpgradeDowngrade(t *testing.T) {
	cases := []struct {
		current   string
		candidate string
		wantError bool
	}{
		{current: "v1.2.3", candidate: "v1.2.2", wantError: true},
		{current: "v1.2.3", candidate: "v1.2.3", wantError: false},
		{current: "v1.2.3", candidate: "v1.3.0", wantError: false},
		{current: "v1.2.3-rc.2", candidate: "v1.2.3-rc.10", wantError: false},
		{current: "v1.2.3", candidate: "release-latest", wantError: true},
	}
	for _, testCase := range cases {
		err := rejectUpgradeDowngrade(testCase.current, testCase.candidate)
		if (err != nil) != testCase.wantError {
			t.Errorf("rejectUpgradeDowngrade(%q, %q) error = %v, wantError %v", testCase.current, testCase.candidate, err, testCase.wantError)
		}
	}
}

// TestInstallLockSerializesTransactions checks that a second transaction waits and honors cancellation.
// TestInstallLockSerializesTransactions 验证第二个事务会等待，并且遵守取消信号。
func TestInstallLockSerializesTransactions(t *testing.T) {
	lockPath := filepath.Join(testpath.CanonicalTempDir(t), InstallLockFileName)
	first, err := acquireInstallLock(context.Background(), lockPath)
	if err != nil {
		t.Fatal(err)
	}
	firstClosed := false
	defer func() {
		if !firstClosed {
			_ = first.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := acquireInstallLock(ctx, lockPath); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second acquire error = %v, want context deadline", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	firstClosed = true
	second, err := acquireInstallLock(context.Background(), lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestPreparedPackageHoldsInstallLockUntilClose verifies the two-phase handle keeps state exclusive.
// TestPreparedPackageHoldsInstallLockUntilClose 验证两阶段句柄在关闭前持续独占状态锁。
func TestPreparedPackageHoldsInstallLockUntilClose(t *testing.T) {
	request, _, _ := newInstallRequest(t, "")
	request.ValidateConfig = validConfigValidator(t)
	prepared, err := StagePackage(context.Background(), request)
	if err != nil {
		t.Fatalf("StagePackage() error = %v", err)
	}
	defer prepared.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	lockPath := filepath.Join(filepath.Dir(request.StatePath), InstallLockFileName)
	if _, err := acquireInstallLock(ctx, lockPath); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("concurrent lock acquire error = %v, want context deadline", err)
	}
	prepared.Close()
	lock, err := acquireInstallLock(context.Background(), lockPath)
	if err != nil {
		t.Fatalf("lock acquire after prepared close: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestTransactionCopySupportsSeparateSourceAndTargetRoots verifies same-volume target staging for a separate root.
// TestTransactionCopySupportsSeparateSourceAndTargetRoots 验证源目录与目标目录分离时仍在目标卷暂存。
func TestTransactionCopySupportsSeparateSourceAndTargetRoots(t *testing.T) {
	sourceRoot := testpath.CanonicalTempDir(t)
	targetRoot := testpath.CanonicalTempDir(t)
	source := filepath.Join(sourceRoot, "candidate.yaml")
	target := filepath.Join(targetRoot, "config.yaml")
	if err := os.WriteFile(source, []byte("new-config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old-config"), 0o600); err != nil {
		t.Fatal(err)
	}
	transactionRoot := filepath.Join(sourceRoot, "transaction")
	if err := os.Mkdir(transactionRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	transaction := newTransaction(transactionRoot)
	if err := transaction.replaceFileCopy(source, target, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "new-config" {
		t.Fatalf("target after copy promotion = %q, error = %v", got, err)
	}
	if len(transaction.replacements) != 1 {
		t.Fatalf("replacement count = %d, want 1", len(transaction.replacements))
	}
	if volume := filepath.VolumeName(transaction.replacements[0].Backup); volume != filepath.VolumeName(target) {
		t.Fatalf("backup volume = %q, target volume = %q", volume, filepath.VolumeName(target))
	}
	if err := transaction.rollback(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "old-config" {
		t.Fatalf("target after rollback = %q, error = %v", got, err)
	}
	if err := transaction.cleanup(); err != nil {
		t.Fatal(err)
	}
}

// TestInstallSupportsConfigRootOnDifferentVolume exercises a real Windows cross-volume configuration install when available.
// TestInstallSupportsConfigRootOnDifferentVolume 在可用时实测 Windows 跨卷配置目录安装。
func TestInstallSupportsConfigRootOnDifferentVolume(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cross-volume drive selection is Windows-specific")
	}
	request, paths, _ := newInstallRequest(t, "")
	configVolumeRoot := alternateVolumeTempDir(t, paths.ProgramRoot)
	paths.ConfigRoot = filepath.Join(configVolumeRoot, "config")
	request.Paths = paths
	request.ValidateConfig = validConfigValidator(t)
	if _, err := Install(context.Background(), request); err != nil {
		t.Fatalf("cross-volume Install() error = %v", err)
	}
	assertFileExists(t, filepath.Join(paths.ConfigRoot, UserConfigFileName))
}

// alternateVolumeTempDir creates a disposable directory on a different available Windows volume.
// alternateVolumeTempDir 在另一个可用 Windows 卷上创建可清理的临时目录。
func alternateVolumeTempDir(t *testing.T, currentPath string) string {
	t.Helper()
	currentVolume := filepath.VolumeName(currentPath)
	for drive := byte('A'); drive <= byte('Z'); drive++ {
		root := string([]byte{drive}) + string(filepath.Separator)
		if strings.EqualFold(filepath.VolumeName(root), currentVolume) {
			continue
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		directory, err := os.MkdirTemp(root, "vmmm-cross-volume-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(directory) })
		return directory
	}
	t.Skipf("no writable Windows volume differs from %q", currentVolume)
	return ""
}

// TestTransactionRollbackIsIdempotent ensures deferred cleanup cannot remove restored files.
// TestTransactionRollbackIsIdempotent 验证重复回滚不会删除已经恢复的文件。
func TestTransactionRollbackIsIdempotent(t *testing.T) {
	root := testpath.CanonicalTempDir(t)
	target := filepath.Join(root, "target.txt")
	source := filepath.Join(root, "source.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	transactionRoot := filepath.Join(root, "transaction")
	if err := os.Mkdir(transactionRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	transaction := newTransaction(transactionRoot)
	if err := transaction.replaceFile(source, target, 0o600); err != nil {
		t.Fatal(err)
	}
	transaction.rollback()
	transaction.rollback()
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("target after repeated rollback = %q, want original", got)
	}
	transaction.cleanup()
}

// TestTransactionRollbackPreservesExternalModification keeps a changed target and its backup on rollback failure.
// TestTransactionRollbackPreservesExternalModification 验证目标被外部修改后回滚会保留目标和备份。
func TestTransactionRollbackPreservesExternalModification(t *testing.T) {
	root := testpath.CanonicalTempDir(t)
	target := filepath.Join(root, "target.txt")
	source := filepath.Join(root, "source.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	transactionRoot := filepath.Join(root, "transaction")
	if err := os.Mkdir(transactionRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	transaction := newTransaction(transactionRoot)
	if err := transaction.replaceFile(source, target, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("external change"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := transaction.rollback(); err == nil {
		t.Fatal("rollback unexpectedly succeeded after target mutation")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "external change" {
		t.Fatalf("target after failed rollback = %q, want external change", got)
	}
	if _, err := os.Stat(transactionRoot); err != nil {
		t.Fatalf("transaction backup root = %v, want preserved", err)
	}
	_ = os.RemoveAll(transactionRoot)
}

// newInstallRequest builds a complete local verified request for transaction tests.
// newInstallRequest 为事务测试构造完整的本地已验证请求。
func newInstallRequest(t *testing.T, packageRootOverride string) (Request, state.InstallPaths, string) {
	t.Helper()
	identity, err := platform.Current()
	if err != nil {
		t.Fatal(err)
	}
	base := testpath.CanonicalTempDir(t)
	paths := state.InstallPaths{
		ProgramRoot: filepath.Join(base, "vmm"),
		ConfigRoot:  filepath.Join(base, "config"),
		DataRoot:    filepath.Join(base, "data"),
	}
	statePath := filepath.Join(paths.DataRoot, RegistrationFileName)
	if runtime.GOOS != "windows" {
		// Unix control state belongs to a separate root so the service account cannot rewrite manager registration.
		// Unix 控制状态使用独立根目录，避免服务账户改写管理器注册记录。
		statePath = filepath.Join(base, "control", RegistrationFileName)
	}
	tag := "v1.2.3"
	commit := strings.Repeat("a", 40)
	packageRoot := packageRootOverride
	archiveSourceRoot := filepath.Join(base, "archive-source", "vulcan-memory-mesh-"+tag+"-"+identity.PlatformID)
	if packageRoot == "" {
		packageRoot = archiveSourceRoot
		if err := os.MkdirAll(packageRoot, 0o700); err != nil {
			t.Fatal(err)
		}
	} else if err := os.MkdirAll(archiveSourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"bin/" + filepath.Base(filepath.FromSlash(identity.VMMExecutablePath)): []byte("vmm executable"),
		"configs/base.yaml": []byte("mode: native\n"),
		"libs/vldb.dll":     []byte("vldb library"),
	}
	receipt := archive.Receipt{
		ManifestSchema: archive.ManifestSchemaVersion,
		Version:        tag,
		Commit:         commit,
		Platform:       identity.PlatformID,
		Target:         releaseTarget(identity.PlatformID),
		StorageMode:    archive.StorageModeNative,
		StorageProfile: "all",
		Capabilities: archive.Capabilities{
			SchemaVersion: 1,
			StorageModes:  []archive.StorageMode{archive.StorageModeSplit, archive.StorageModeController, archive.StorageModeNative, archive.StorageModeCombined},
			Combined:      &archive.CombinedCapability{Provider: "postgres", Flavors: []string{"standard", "paradedb"}},
		},
		Files: map[string]string{},
	}
	for relative, data := range files {
		path := filepath.Join(archiveSourceRoot, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o700); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		receipt.Files[relative] = hex.EncodeToString(digest[:])
	}
	receiptBytes, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archiveSourceRoot, "release-manifest.json"), append(receiptBytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(base, "vulcan-memory-mesh-"+tag+"-"+identity.PlatformID+archiveSuffix(identity.PlatformID))
	writeFixtureArchive(t, archivePath, archiveSourceRoot, filepath.Base(archiveSourceRoot), identity.PlatformID)
	artifactBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	artifactDigest := sha256.Sum256(artifactBytes)
	artifact := manifest.Artifact{Platform: identity.PlatformID, Filename: filepath.Base(archivePath), Bytes: int64(len(artifactBytes)), SHA256: hex.EncodeToString(artifactDigest[:])}
	verifiedManifest := signedManifest(t, tag, commit, artifact)
	return Request{
		ManagerRoot:    filepath.Join(base, "manager"),
		Operation:      OperationInstall,
		ManagerVersion: "vmmm-test",
		Manifest:       verifiedManifest,
		Artifact:       fetch.Result{Path: archivePath, Filename: artifact.Filename, Bytes: artifact.Bytes, SHA256: artifact.SHA256},
		Package:        archive.Package{Root: packageRoot, Receipt: receipt},
		Expected:       archive.ExpectedRelease{Version: tag, Commit: commit, Platform: identity.PlatformID, Target: releaseTarget(identity.PlatformID), ArchiveBytes: artifact.Bytes, ArchiveSHA256: artifact.SHA256},
		Paths:          paths,
		StatePath:      statePath,
		Source:         state.DownloadSource{ID: "github"},
		Service:        state.ServiceState{},
		PATH:           state.PATHState{Owner: state.PATHOwnerNone, Scope: state.PATHScopeNone, Entries: []string{}},
		ConfigFiles:    map[string][]byte{UserConfigFileName: []byte("mode: native\n")},
	}, paths, packageRoot
}

// archiveSuffix returns the format selected by the production archive extractor.
// archiveSuffix 返回生产解包器按平台选择的归档后缀。
func archiveSuffix(platformID string) string {
	if platformID == "windows-x64" {
		return ".zip"
	}
	return ".tar.gz"
}

// writeFixtureArchive creates a real package archive whose receipt and bytes are authenticated by the test request.
// writeFixtureArchive 创建真实程序包归档，使 receipt 和归档字节都由测试请求认证。
func writeFixtureArchive(t *testing.T, destination string, root string, packageName string, platformID string) {
	t.Helper()
	archiveFile, err := os.Create(destination)
	if err != nil {
		t.Fatal(err)
	}
	closeArchive := func() {
		if err := archiveFile.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if platformID == "windows-x64" {
		writer := zip.NewWriter(archiveFile)
		err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return err
			}
			header.Name = packageName + "/" + filepath.ToSlash(relative)
			header.Method = zip.Deflate
			fileWriter, err := writer.CreateHeader(header)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			_, err = fileWriter.Write(data)
			return err
		})
		if err == nil {
			err = writer.Close()
		}
		closeArchive()
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	gzipWriter := gzip.NewWriter(archiveFile)
	tarWriter := tar.NewWriter(gzipWriter)
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = packageName + "/" + filepath.ToSlash(relative)
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tarWriter, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err == nil {
		err = tarWriter.Close()
	}
	if err == nil {
		err = gzipWriter.Close()
	}
	closeArchive()
	if err != nil {
		t.Fatal(err)
	}
}

// signedManifest creates a release snapshot through the production verifier.
// signedManifest 通过生产验证器创建发行快照。
func signedManifest(t *testing.T, tag string, commit string, artifact manifest.Artifact) manifest.VerifiedManifest {
	t.Helper()
	manifestBytes, err := json.Marshal(manifest.Manifest{ProtocolVersion: manifest.ProtocolVersion, Product: manifest.ProductVMM, Tag: tag, Commit: commit, Artifacts: []manifest.Artifact{artifact}})
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes32(7))
	signature := ed25519.Sign(privateKey, manifestBytes)
	signatureBytes, err := json.Marshal(manifest.SignatureEnvelope{Version: manifest.SignatureVersion, KeyID: "test", Signature: base64.StdEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := manifest.Verify(manifestBytes, signatureBytes, map[string]ed25519.PublicKey{"test": privateKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

// bytes32 returns a deterministic Ed25519 seed for local tests.
// bytes32 返回本地测试使用的确定性 Ed25519 种子。
func bytes32(value byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = value
	}
	return seed
}

// validConfigValidator accepts an existing candidate binary and config root.
// validConfigValidator 接受存在的候选二进制和配置根目录。
func validConfigValidator(t *testing.T) ValidateFunc {
	t.Helper()
	return func(_ context.Context, binaryPath string, configRoot string) (configbridge.ValidationResult, error) {
		if _, err := os.Stat(binaryPath); err != nil {
			return configbridge.ValidationResult{}, err
		}
		if _, err := os.Stat(configRoot); err != nil {
			return configbridge.ValidationResult{}, err
		}
		return configbridge.ValidationResult{Valid: true, Errors: []configbridge.ValidationError{}}, nil
	}
}

// vmmExecutableName returns the current platform's VMM executable basename.
// vmmExecutableName 返回当前平台的 VMM 可执行文件名。
func vmmExecutableName() string {
	identity, _ := platform.Current()
	return filepath.Base(filepath.FromSlash(identity.VMMExecutablePath))
}

// releaseTarget returns the canonical target triple for one platform ID.
// releaseTarget 返回一个平台标识对应的规范目标三元组。
func releaseTarget(platformID string) string {
	return map[string]string{
		"windows-x64": "x86_64-pc-windows-msvc",
		"linux-x64":   "x86_64-unknown-linux-gnu",
		"linux-arm64": "aarch64-unknown-linux-gnu",
		"macos-intel": "x86_64-apple-darwin",
		"macos-arm64": "aarch64-apple-darwin",
	}[platformID]
}

// assertFileExists verifies one path is a regular file.
// assertFileExists 验证一个路径是普通文件。
func assertFileExists(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("file %q is missing or not regular: %v", path, err)
	}
}

// contains reports whether a sorted or unsorted string slice includes one value.
// contains 判断字符串切片中是否包含指定值。
func contains(values []string, wanted string) bool {
	copyValues := append([]string(nil), values...)
	sort.Strings(copyValues)
	index := sort.SearchStrings(copyValues, wanted)
	return index < len(copyValues) && copyValues[index] == wanted
}

// init keeps runtime imported in cross-platform test builds.
// init 保证跨平台测试构建保留 runtime 导入。
func init() {
	_ = runtime.GOOS
}
