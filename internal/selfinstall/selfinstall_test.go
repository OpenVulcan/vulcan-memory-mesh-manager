// Package selfinstall verifies the fail-closed executable ownership lifecycle.
// selfinstall 包测试可执行文件所有权生命周期的失败关闭行为。
package selfinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestInstallDetectAndIdempotentInstall verifies first install, detection, and repeated selection.
// TestInstallDetectAndIdempotentInstall 验证首装、检测和重复选择行为。
func TestInstallDetectAndIdempotentInstall(t *testing.T) {
	root := fixtureRoot(t)
	source := writeFixture(t, root, "source-v1", []byte("vmmm-release-one"))
	release := fixtureRelease(t, source, "v0.1.0")
	installer := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-vmmm"))

	result, err := installer.Install(source, release)
	if err != nil {
		t.Fatalf("Install() failed: %v", err)
	}
	if result.Action != "installed" || result.Version != release.Version || result.ExecutablePath != installer.ExecutablePath() {
		t.Fatalf("Install() result = %+v", result)
	}
	if got, err := os.ReadFile(installer.ExecutablePath()); err != nil || string(got) != "vmmm-release-one" {
		t.Fatalf("installed executable = %q, err=%v", got, err)
	}
	installation, err := installer.Detect()
	if err != nil {
		t.Fatalf("Detect() failed: %v", err)
	}
	if !sameRelease(installation.Current, release) || len(installation.Backups) != 0 {
		t.Fatalf("Detect() = %+v", installation)
	}
	repeated, err := installer.Install(source, release)
	if err != nil {
		t.Fatalf("repeated Install() failed: %v", err)
	}
	if repeated.Action != "unchanged" {
		t.Fatalf("repeated Install() action = %q, want unchanged", repeated.Action)
	}
}

// TestInstallDoesNotOverwriteUnmanagedTarget protects another user's executable.
// TestInstallDoesNotOverwriteUnmanagedTarget 保护其他用户的可执行文件不被覆盖。
func TestInstallDoesNotOverwriteUnmanagedTarget(t *testing.T) {
	root := fixtureRoot(t)
	installer := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-vmmm"))
	source := writeFixture(t, root, "source", []byte("trusted"))
	release := fixtureRelease(t, source, "v0.1.0")
	if err := os.WriteFile(installer.ExecutablePath(), []byte("someone-elses-vmmm"), 0755); err != nil {
		t.Fatalf("write occupied target: %v", err)
	}
	_, err := installer.Install(source, release)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Install() error = %v, want ErrConflict", err)
	}
	got, readErr := os.ReadFile(installer.ExecutablePath())
	if readErr != nil || string(got) != "someone-elses-vmmm" {
		t.Fatalf("occupied target = %q, err=%v", got, readErr)
	}
}

// TestUpgradeRollbackAndUninstall verifies the retained backup and owned cleanup path.
// TestUpgradeRollbackAndUninstall 验证保留备份、回滚和受管清理路径。
func TestUpgradeRollbackAndUninstall(t *testing.T) {
	root := fixtureRoot(t)
	sourceV1 := writeFixture(t, root, "source-v1", []byte("vmmm-release-one"))
	sourceV2 := writeFixture(t, root, "source-v2", []byte("vmmm-release-two"))
	releaseV1 := fixtureRelease(t, sourceV1, "v0.1.0")
	releaseV2 := fixtureRelease(t, sourceV2, "v0.2.0")
	installer := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-vmmm"))
	if _, err := installer.Install(sourceV1, releaseV1); err != nil {
		t.Fatalf("initial Install() failed: %v", err)
	}
	if _, err := installer.Upgrade(sourceV2, releaseV2); err != nil {
		t.Fatalf("Upgrade() failed: %v", err)
	}
	upgraded, err := installer.Detect()
	if err != nil {
		t.Fatalf("Detect() after upgrade failed: %v", err)
	}
	if !sameRelease(upgraded.Current, releaseV2) || len(upgraded.Backups) != 1 || !sameRelease(upgraded.Backups[0].Release, releaseV1) {
		t.Fatalf("upgraded installation = %+v", upgraded)
	}
	rolledBack, err := installer.Rollback()
	if err != nil {
		t.Fatalf("Rollback() failed: %v", err)
	}
	if rolledBack.Action != "rolled_back" || rolledBack.Version != releaseV1.Version {
		t.Fatalf("Rollback() result = %+v", rolledBack)
	}
	afterRollback, err := installer.Detect()
	if err != nil {
		t.Fatalf("Detect() after rollback failed: %v", err)
	}
	if !sameRelease(afterRollback.Current, releaseV1) || len(afterRollback.Backups) != 2 || !sameRelease(afterRollback.Backups[0].Release, releaseV2) {
		t.Fatalf("rolled-back installation = %+v", afterRollback)
	}
	marker := filepath.Join(root, "user-file.txt")
	if err := os.WriteFile(marker, []byte("leave me"), 0600); err != nil {
		t.Fatalf("write unmanaged marker: %v", err)
	}
	if err := installer.Uninstall(); err != nil {
		t.Fatalf("Uninstall() failed: %v", err)
	}
	if _, err := os.Stat(installer.ExecutablePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("executable after Uninstall() err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".vmmm-install.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state after Uninstall() err = %v", err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "leave me" {
		t.Fatalf("unmanaged marker = %q, err=%v", got, err)
	}
}

// TestUpgradeVerificationFailureRetainsBackup verifies that failed recovery never discards the only old image.
// TestUpgradeVerificationFailureRetainsBackup 验证升级校验失败且恢复失败时绝不丢弃唯一旧映像。
func TestUpgradeVerificationFailureRetainsBackup(t *testing.T) {
	root := fixtureRoot(t)
	sourceV1 := writeFixture(t, root, "source-v1", []byte("vmmm-release-one"))
	sourceV2 := writeFixture(t, root, "source-v2", []byte("vmmm-release-two"))
	releaseV1 := fixtureRelease(t, sourceV1, "v0.1.0")
	releaseV2 := fixtureRelease(t, sourceV2, "v0.2.0")
	installer := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-vmmm"))
	if _, err := installer.Install(sourceV1, releaseV1); err != nil {
		t.Fatalf("initial Install() failed: %v", err)
	}
	installer.verifyPublishedFile = func(string, Release) error {
		return errors.New("injected published-image verification failure")
	}
	installer.restoreCurrentFile = func(string, Release) error {
		return errors.New("injected restore failure")
	}
	if _, err := installer.Upgrade(sourceV2, releaseV2); err == nil || !strings.Contains(err.Error(), "restore previous executable failed") || !strings.Contains(err.Error(), "backup retained") {
		t.Fatalf("Upgrade() error = %v, want explicit retained-backup recovery failure", err)
	}
	entries, err := os.ReadDir(installer.backupRoot)
	if err != nil {
		t.Fatalf("read backup directory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("backup entries = %d, want one retained backup", len(entries))
	}
	backupPath := filepath.Join(installer.backupRoot, entries[0].Name())
	if err := verifyFile(backupPath, releaseV1); err != nil {
		t.Fatalf("retained upgrade backup does not match v1: %v", err)
	}
	if got, err := os.ReadFile(installer.ExecutablePath()); err != nil || string(got) != "vmmm-release-two" {
		t.Fatalf("executable after failed recovery = %q, err=%v", got, err)
	}
	record, err := installer.loadRecord()
	if err != nil {
		t.Fatalf("load state after failed recovery: %v", err)
	}
	if !sameRelease(record.Current.release(), releaseV1) {
		t.Fatalf("state current after failed recovery = %+v, want v1", record.Current.release())
	}
}

// TestRollbackVerificationFailureRetainsBackup verifies rollback keeps both generations when recovery fails.
// TestRollbackVerificationFailureRetainsBackup 验证回滚校验失败且恢复失败时保留两代备份。
func TestRollbackVerificationFailureRetainsBackup(t *testing.T) {
	root := fixtureRoot(t)
	sourceV1 := writeFixture(t, root, "source-v1", []byte("vmmm-release-one"))
	sourceV2 := writeFixture(t, root, "source-v2", []byte("vmmm-release-two"))
	releaseV1 := fixtureRelease(t, sourceV1, "v0.1.0")
	releaseV2 := fixtureRelease(t, sourceV2, "v0.2.0")
	installer := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-vmmm"))
	if _, err := installer.Install(sourceV1, releaseV1); err != nil {
		t.Fatalf("initial Install() failed: %v", err)
	}
	if _, err := installer.Upgrade(sourceV2, releaseV2); err != nil {
		t.Fatalf("Upgrade() failed: %v", err)
	}
	installer.verifyPublishedFile = func(string, Release) error {
		return errors.New("injected published-image verification failure")
	}
	installer.restoreCurrentFile = func(string, Release) error {
		return errors.New("injected restore failure")
	}
	if _, err := installer.Rollback(); err == nil || !strings.Contains(err.Error(), "restore previous executable failed") || !strings.Contains(err.Error(), "backup retained") {
		t.Fatalf("Rollback() error = %v, want explicit retained-backup recovery failure", err)
	}
	entries, err := os.ReadDir(installer.backupRoot)
	if err != nil {
		t.Fatalf("read backup directory: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("backup entries = %d, want two retained backups", len(entries))
	}
	v1Count, v2Count := 0, 0
	for _, entry := range entries {
		path := filepath.Join(installer.backupRoot, entry.Name())
		switch {
		case verifyFile(path, releaseV1) == nil:
			v1Count++
		case verifyFile(path, releaseV2) == nil:
			v2Count++
		default:
			t.Fatalf("retained backup %q matches neither release", path)
		}
	}
	if v1Count != 1 || v2Count != 1 {
		t.Fatalf("retained backup generations = v1:%d v2:%d, want one each", v1Count, v2Count)
	}
	if got, err := os.ReadFile(installer.ExecutablePath()); err != nil || string(got) != "vmmm-release-one" {
		t.Fatalf("executable after failed rollback recovery = %q, err=%v", got, err)
	}
	record, err := installer.loadRecord()
	if err != nil {
		t.Fatalf("load state after failed rollback recovery: %v", err)
	}
	if !sameRelease(record.Current.release(), releaseV2) {
		t.Fatalf("state current after failed rollback recovery = %+v, want v2", record.Current.release())
	}
}

// TestPartialUninstallCanBeReinstalled verifies a failed cleanup leaves explicit, repairable ownership.
// TestPartialUninstallCanBeReinstalled 验证清理失败后保留明确且可修复的所有权。
func TestPartialUninstallCanBeReinstalled(t *testing.T) {
	root := fixtureRoot(t)
	sourceV1 := writeFixture(t, root, "source-v1", []byte("vmmm-release-one"))
	sourceV2 := writeFixture(t, root, "source-v2", []byte("vmmm-release-two"))
	releaseV1 := fixtureRelease(t, sourceV1, "v0.1.0")
	releaseV2 := fixtureRelease(t, sourceV2, "v0.2.0")
	installer := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-vmmm"))
	if _, err := installer.Install(sourceV1, releaseV1); err != nil {
		t.Fatalf("initial Install() failed: %v", err)
	}
	if _, err := installer.Upgrade(sourceV2, releaseV2); err != nil {
		t.Fatalf("Upgrade() failed: %v", err)
	}
	marker := filepath.Join(root, "keep-user-data")
	if err := os.WriteFile(marker, []byte("untouched"), 0600); err != nil {
		t.Fatalf("write unmanaged marker: %v", err)
	}
	installer.uninstallRemoveFile = func(path string, release Release) error {
		if samePath(path, installer.ExecutablePath()) {
			return errors.New("injected executable removal failure")
		}
		return removeOwnedFile(path, release)
	}
	if err := installer.Uninstall(); err == nil || !strings.Contains(err.Error(), "injected executable removal failure") {
		t.Fatalf("Uninstall() error = %v, want injected failure", err)
	}
	if _, err := installer.Detect(); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Detect() after partial uninstall error = %v, want ErrIncomplete", err)
	}
	if _, err := os.Stat(installer.statePath); err != nil {
		t.Fatalf("ownership record was removed: %v", err)
	}
	installer.uninstallRemoveFile = removeOwnedFile
	result, err := installer.Install(sourceV2, releaseV2)
	if err != nil || result.Action != "reinstalled" {
		t.Fatalf("Install() repair = %+v, %v", result, err)
	}
	installed, err := installer.Detect()
	if err != nil || !sameRelease(installed.Current, releaseV2) || len(installed.Backups) != 0 {
		t.Fatalf("Detect() after reinstall = %+v, %v", installed, err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "untouched" {
		t.Fatalf("unmanaged marker = %q, %v", got, err)
	}
}

// TestUninstallRetryCompletesAfterPartialRemoval verifies no restart replay is needed.
// TestUninstallRetryCompletesAfterPartialRemoval 验证不需要重启回放即可完成部分卸载。
func TestUninstallRetryCompletesAfterPartialRemoval(t *testing.T) {
	root := fixtureRoot(t)
	sourceV1 := writeFixture(t, root, "source-v1", []byte("vmmm-release-one"))
	sourceV2 := writeFixture(t, root, "source-v2", []byte("vmmm-release-two"))
	releaseV1 := fixtureRelease(t, sourceV1, "v0.1.0")
	releaseV2 := fixtureRelease(t, sourceV2, "v0.2.0")
	installer := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-vmmm"))
	if _, err := installer.Install(sourceV1, releaseV1); err != nil {
		t.Fatalf("initial Install() failed: %v", err)
	}
	if _, err := installer.Upgrade(sourceV2, releaseV2); err != nil {
		t.Fatalf("Upgrade() failed: %v", err)
	}
	failed := false
	installer.uninstallRemoveFile = func(path string, release Release) error {
		if !failed && samePath(path, installer.ExecutablePath()) {
			failed = true
			return errors.New("injected cleanup failure")
		}
		return removeOwnedFile(path, release)
	}
	if err := installer.Uninstall(); err == nil || !strings.Contains(err.Error(), "injected cleanup failure") {
		t.Fatalf("first Uninstall() error = %v", err)
	}
	if err := installer.Uninstall(); err != nil {
		t.Fatalf("explicit Uninstall() retry failed: %v", err)
	}
	if _, err := installer.Detect(); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("Detect() after retry = %v, want ErrNotInstalled", err)
	}
}

// TestMissingExecutableRequiresExplicitReinstall verifies detection never silently changes disk state.
// TestMissingExecutableRequiresExplicitReinstall 验证检测不会暗中改变磁盘状态。
func TestMissingExecutableRequiresExplicitReinstall(t *testing.T) {
	root := fixtureRoot(t)
	source := writeFixture(t, root, "source", []byte("vmmm-release-one"))
	release := fixtureRelease(t, source, "v0.1.0")
	installer := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-vmmm"))
	if _, err := installer.Install(source, release); err != nil {
		t.Fatalf("initial Install() failed: %v", err)
	}
	if err := os.Remove(installer.ExecutablePath()); err != nil {
		t.Fatalf("remove owned executable: %v", err)
	}
	if _, err := installer.Detect(); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Detect() error = %v, want ErrIncomplete", err)
	}
	if _, err := os.Stat(installer.ExecutablePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Detect() unexpectedly restored executable: %v", err)
	}
	result, err := installer.Install(source, release)
	if err != nil || result.Action != "reinstalled" {
		t.Fatalf("Install() repair = %+v, %v", result, err)
	}
	if _, err := installer.Detect(); err != nil {
		t.Fatalf("Detect() after reinstall: %v", err)
	}
}

// TestIncompleteFirstInstallCanBeRetried verifies the single completion marker survives an interruption.
// TestIncompleteFirstInstallCanBeRetried 验证单个完成标记可支持中断后的重新安装。
func TestIncompleteFirstInstallCanBeRetried(t *testing.T) {
	root := fixtureRoot(t)
	source := writeFixture(t, root, "source", []byte("vmmm-release-one"))
	release := fixtureRelease(t, source, "v0.1.0")
	installer := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-vmmm"))
	if err := installer.saveRecord(persistedRecord{ProtocolVersion: ProtocolVersion, Complete: completionPointer(false), InstallRoot: root, Executable: installer.options.ExecutableName, Current: release.persisted(), Backups: []persistedBackup{}}); err != nil {
		t.Fatalf("save interrupted first-install marker: %v", err)
	}
	if _, err := installer.Detect(); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Detect() interrupted marker = %v, want ErrIncomplete", err)
	}
	result, err := installer.Install(source, release)
	if err != nil || result.Action != "reinstalled" {
		t.Fatalf("Install() retry = %+v, %v", result, err)
	}
	if _, err := installer.Detect(); err != nil {
		t.Fatalf("Detect() after retry: %v", err)
	}
}

// TestIncompleteInstallRejectsUnownedBytes verifies a marker cannot authorize an unrelated executable.
// TestIncompleteInstallRejectsUnownedBytes 验证完成标记不能授权无关可执行文件。
func TestIncompleteInstallRejectsUnownedBytes(t *testing.T) {
	root := fixtureRoot(t)
	source := writeFixture(t, root, "source", []byte("vmmm-release-one"))
	release := fixtureRelease(t, source, "v0.1.0")
	installer := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-vmmm"))
	if err := installer.saveRecord(persistedRecord{ProtocolVersion: ProtocolVersion, Complete: completionPointer(false), InstallRoot: root, Executable: installer.options.ExecutableName, Current: release.persisted(), Backups: []persistedBackup{}}); err != nil {
		t.Fatalf("save interrupted first-install marker: %v", err)
	}
	if err := os.WriteFile(installer.ExecutablePath(), []byte("unrelated executable"), 0755); err != nil {
		t.Fatalf("write unrelated executable: %v", err)
	}
	if _, err := installer.Install(source, release); !errors.Is(err, ErrModified) {
		t.Fatalf("Install() error = %v, want ErrModified", err)
	}
	if got, err := os.ReadFile(installer.ExecutablePath()); err != nil || string(got) != "unrelated executable" {
		t.Fatalf("unrelated executable changed: %q, %v", got, err)
	}
}

// TestLegacyCompletedRecordIsReadable verifies existing v1 ownership records remain valid.
// TestLegacyCompletedRecordIsReadable 验证既有版本一所有权记录继续有效。
func TestLegacyCompletedRecordIsReadable(t *testing.T) {
	root := fixtureRoot(t)
	source := writeFixture(t, root, "source", []byte("vmmm-release-one"))
	release := fixtureRelease(t, source, "v0.1.0")
	installer := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-vmmm"))
	if _, err := installer.Install(source, release); err != nil {
		t.Fatalf("Install() failed: %v", err)
	}
	record, err := installer.loadRecord()
	if err != nil {
		t.Fatalf("load installed record: %v", err)
	}
	record.ProtocolVersion = legacyProtocolVersion
	record.Complete = nil
	if err := installer.saveRecord(record); err != nil {
		t.Fatalf("save legacy record: %v", err)
	}
	if _, err := installer.Detect(); err != nil {
		t.Fatalf("Detect() legacy record: %v", err)
	}
}

// TestRetiredUninstallArtifactBlocksMutation verifies old staged ownership is never silently replayed.
// TestRetiredUninstallArtifactBlocksMutation 验证旧暂存所有权不会被暗中回放。
func TestRetiredUninstallArtifactBlocksMutation(t *testing.T) {
	root := fixtureRoot(t)
	source := writeFixture(t, root, "source", []byte("vmmm-release-one"))
	release := fixtureRelease(t, source, "v0.1.0")
	installer := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-vmmm"))
	artifact := filepath.Join(root, legacyUninstallJournalName)
	if err := os.WriteFile(artifact, []byte("retired state"), 0600); err != nil {
		t.Fatalf("write retired artifact: %v", err)
	}
	if _, err := installer.Detect(); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Detect() error = %v, want ErrIncomplete", err)
	}
	if _, err := installer.Install(source, release); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Install() error = %v, want ErrIncomplete", err)
	}
	if got, err := os.ReadFile(artifact); err != nil || string(got) != "retired state" {
		t.Fatalf("retired artifact changed: %q, %v", got, err)
	}
}

// TestInstallationLockSerializesConcurrentInstallers verifies the kernel lock blocks a second owner.
// TestInstallationLockSerializesConcurrentInstallers 验证内核锁阻塞第二个安装器所有者。
func TestInstallationLockSerializesConcurrentInstallers(t *testing.T) {
	root := fixtureRoot(t)
	first := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-one"))
	second := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-two"))
	firstLock, err := first.acquireExclusiveLock(true)
	if err != nil {
		t.Fatalf("acquire first installation lock: %v", err)
	}
	acquired := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		secondLock, acquireErr := second.acquireExclusiveLock(true)
		if acquireErr == nil {
			close(acquired)
			acquireErr = secondLock.close()
		}
		finished <- acquireErr
	}()
	select {
	case <-acquired:
		t.Fatal("second installer acquired the lock before the first released it")
	case <-time.After(200 * time.Millisecond):
	}
	if err := firstLock.close(); err != nil {
		t.Fatalf("release first installation lock: %v", err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("second installer lock acquisition: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second installer did not acquire the lock after release")
	}
}

// TestWindowsRunningExecutableGuard verifies that a current Windows image is never replaced.
// TestWindowsRunningExecutableGuard 验证 Windows 当前映像绝不会被替换。
func TestWindowsRunningExecutableGuard(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the running-image guard is Windows-specific")
	}
	root := fixtureRoot(t)
	sourceV1 := writeFixture(t, root, "source-v1", []byte("vmmm-release-one"))
	sourceV2 := writeFixture(t, root, "source-v2", []byte("vmmm-release-two"))
	releaseV1 := fixtureRelease(t, sourceV1, "v0.1.0")
	releaseV2 := fixtureRelease(t, sourceV2, "v0.2.0")
	bootstrap := filepath.Join(root, "bootstrap-vmmm")
	installer := newFixtureInstaller(t, root, bootstrap)
	if _, err := installer.Install(sourceV1, releaseV1); err != nil {
		t.Fatalf("initial Install() failed: %v", err)
	}
	runningInstaller, err := New(Options{InstallRoot: root, CurrentExecutable: installer.ExecutablePath()})
	if err != nil {
		t.Fatalf("New() for running image failed: %v", err)
	}
	if _, err := runningInstaller.Upgrade(sourceV2, releaseV2); !errors.Is(err, ErrRunningExecutable) {
		t.Fatalf("Upgrade() error = %v, want ErrRunningExecutable", err)
	}
	got, err := os.ReadFile(installer.ExecutablePath())
	if err != nil || string(got) != "vmmm-release-one" {
		t.Fatalf("running executable after rejected upgrade = %q, err=%v", got, err)
	}
}

// TestTemporaryAndSymlinkRootsAreRejected protects the permanent-root boundary.
// TestTemporaryAndSymlinkRootsAreRejected 保护永久根目录边界。
func TestTemporaryAndSymlinkRootsAreRejected(t *testing.T) {
	if _, err := New(Options{InstallRoot: filepath.Clean(os.TempDir())}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("New() temporary root error = %v, want ErrUnsafePath", err)
	}
	parent := fixtureRoot(t)
	target := filepath.Join(parent, "real-root")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatalf("mkdir real root: %v", err)
	}
	link := filepath.Join(parent, "linked-root")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := New(Options{InstallRoot: link}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("New() symlink root error = %v, want ErrUnsafePath", err)
	}
}

// TestModifiedBackupBlocksUninstall prevents deletion after an owned backup is changed.
// TestModifiedBackupBlocksUninstall 防止受管备份变化后继续删除。
func TestModifiedBackupBlocksUninstall(t *testing.T) {
	root := fixtureRoot(t)
	sourceV1 := writeFixture(t, root, "source-v1", []byte("vmmm-release-one"))
	sourceV2 := writeFixture(t, root, "source-v2", []byte("vmmm-release-two"))
	releaseV1 := fixtureRelease(t, sourceV1, "v0.1.0")
	releaseV2 := fixtureRelease(t, sourceV2, "v0.2.0")
	installer := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-vmmm"))
	if _, err := installer.Install(sourceV1, releaseV1); err != nil {
		t.Fatalf("initial Install() failed: %v", err)
	}
	if _, err := installer.Upgrade(sourceV2, releaseV2); err != nil {
		t.Fatalf("Upgrade() failed: %v", err)
	}
	installation, err := installer.Detect()
	if err != nil {
		t.Fatalf("Detect() failed: %v", err)
	}
	if err := os.WriteFile(installation.Backups[0].Path, []byte("tampered"), 0755); err != nil {
		t.Fatalf("tamper backup: %v", err)
	}
	if err := installer.Uninstall(); !errors.Is(err, ErrModified) {
		t.Fatalf("Uninstall() error = %v, want ErrModified", err)
	}
	if _, err := os.Stat(installer.ExecutablePath()); err != nil {
		t.Fatalf("current executable after rejected uninstall: %v", err)
	}
}

// TestDuplicateStateKeysAreRejected protects the ownership parser from ambiguous JSON.
// TestDuplicateStateKeysAreRejected 保护所有权解析器不接受有歧义的 JSON。
func TestDuplicateStateKeysAreRejected(t *testing.T) {
	root := fixtureRoot(t)
	source := writeFixture(t, root, "source", []byte("vmmm-release-one"))
	release := fixtureRelease(t, source, "v0.1.0")
	installer := newFixtureInstaller(t, root, filepath.Join(root, "bootstrap-vmmm"))
	if _, err := installer.Install(source, release); err != nil {
		t.Fatalf("Install() failed: %v", err)
	}
	statePath := filepath.Join(root, defaultStateName)
	if err := os.WriteFile(statePath, []byte(`{"protocol_version":1,"protocol_version":1}`), 0600); err != nil {
		t.Fatalf("write duplicate state: %v", err)
	}
	if _, err := installer.Detect(); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("Detect() error = %v, want ErrCorruptState", err)
	}
}

// fixtureRoot creates a temporary fixture below the package work tree so production temp rejection stays active.
// fixtureRoot 在包工作树下创建测试 fixture，使生产临时目录拒绝逻辑保持有效。
func fixtureRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp(".", ".selfinstall-fixture-")
	if err != nil {
		t.Fatalf("create fixture root: %v", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		t.Fatalf("resolve fixture root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

// newFixtureInstaller creates an installer with a source image outside the permanent executable path.
// newFixtureInstaller 创建源映像与永久可执行路径分离的安装器。
func newFixtureInstaller(t *testing.T, root string, currentExecutable string) *Installer {
	t.Helper()
	installer, err := New(Options{InstallRoot: root, CurrentExecutable: currentExecutable})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	return installer
}

// writeFixture writes one regular test file under the fixture root.
// writeFixture 在 fixture 根目录下写入一个普通测试文件。
func writeFixture(t *testing.T, root string, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, content, 0755); err != nil {
		t.Fatalf("write fixture %q: %v", name, err)
	}
	return path
}

// fixtureRelease calculates the exact authenticated metadata for one fixture file.
// fixtureRelease 为一个 fixture 文件计算精确的经认证元数据。
func fixtureRelease(t *testing.T, path string, version string) Release {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture source: %v", err)
	}
	digest := sha256.Sum256(content)
	return Release{
		Version:  version,
		Commit:   strings.Repeat("a", 40),
		Platform: "windows-x64",
		Filename: "vmmm-v0.1.0-windows-x64.exe",
		SHA256:   hex.EncodeToString(digest[:]),
		Size:     int64(len(content)),
	}
}
