//go:build linux

// This file verifies the controller's privileged installation boundary with a different local account.
// 本文件使用另一名本机账户验证控制器的提权安装边界，覆盖无 sudo 权限服务账户的真实文件访问。
package controller

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/credentials"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/install"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/service"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestServiceInstallForUnprivilegedAccount proves that root installs for an existing account without that account's sudo credentials.
// TestServiceInstallForUnprivilegedAccount 验证 root 可为已有普通账户安装，且无需该账户的 sudo 凭据。
func TestServiceInstallForUnprivilegedAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires a root Linux test process")
	}
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Fatalf("look up unprivileged local account: %v", err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		t.Fatalf("invalid unprivileged account UID %q: %v", account.Uid, err)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		t.Fatalf("invalid unprivileged account GID %q: %v", account.Gid, err)
	}
	// Use a protected system parent and grant traversal only on the newly created fixture.
	// 使用受保护的系统父目录，仅为本次新建测试目录开放穿越权限。
	base, err := os.MkdirTemp("/var/lib", ".vmmm-account-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	controller, plan, fixture := newFixtureControllerAt(t, base)
	adapter := &fakeService{status: service.Status{State: "stopped", User: account.Username}}
	controller.options.ServiceFactory = func(string) (ServiceClient, error) { return adapter, nil }
	events := make(chan tui.OperationEvent, 32)
	if err := controller.stagePackage(context.Background(), plan, events); err != nil {
		t.Fatalf("stage service package: %v", err)
	}
	// The real wizard asks for the account only after staging and directory preparation.
	// 真实向导在包暂存及目录准备之后才询问运行账户。
	plan.ServiceMode = tui.ServiceModeService
	plan.ServiceUser = account.Username
	if err := controller.install(context.Background(), plan, events); err != nil {
		t.Fatalf("install for unprivileged account: %v", err)
	}
	if adapter.lastUser != account.Username || !adapter.called("install") {
		t.Fatalf("service registration account = %q, calls = %v", adapter.lastUser, adapter.calls)
	}
	// Ask the kernel to enforce the selected account's access, including denied program/state writes.
	// 让内核以所选账户实际检查访问权限，同时确认该账户不能写入程序和管理状态。
	check := exec.Command("/bin/sh", "-c", `test -r "$1" && test -x "$2" && test -w "$3" && test -w "$4" && test ! -w "$2" && test ! -w "$5"`,
		"vmmm-account-check", filepath.Join(plan.ConfigRoot, defaultConfigFileName),
		filepath.Join(plan.ProgramRoot, filepath.FromSlash(fixture.identity.VMMExecutablePath)),
		plan.ConfigRoot, plan.DataRoot, controller.controlStateRoot())
	check.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("selected account access check failed: %v, output: %s", err, output)
	}
}

// TestServiceOwnershipRollback verifies the actual UID boundary, rollback, and refusal to follow a user-controlled link.
// TestServiceOwnershipRollback 验证真实 UID 边界、归属回退及拒绝跟随用户控制的链接。
func TestServiceOwnershipRollback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires a root Linux test process")
	}
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("/var/lib", ".vmmm-transfer-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	paths := state.InstallPaths{ProgramRoot: filepath.Join(base, "program"), ConfigRoot: filepath.Join(base, "config"), DataRoot: filepath.Join(base, "data")}
	for _, root := range []string{paths.ConfigRoot, paths.DataRoot} {
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(paths.DataRoot, "database.db")
	if err := os.WriteFile(file, []byte("preserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(paths.ConfigRoot, ".env")
	originalCredential := []byte("TEST_KEY=preserved\n")
	if err := os.WriteFile(envPath, originalCredential, 0o600); err != nil {
		t.Fatal(err)
	}
	finish, err := install.TransferServiceRoots(paths, account.Username)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.ConfigRoot, paths.DataRoot, file, envPath} {
		info, err := os.Stat(path)
		if err != nil || info.Sys().(*syscall.Stat_t).Uid != uint32(uid) {
			t.Fatalf("ownership transfer failed: %s", path)
		}
	}
	// The real credential rollback restores bytes through an atomic replacement before directory ownership is reverted.
	// 真实凭据回退在目录归属恢复前，通过原子替换恢复原始字节。
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	if err := credentials.RestoreAs(envPath, originalCredential, credentials.Owner{UID: uint32(uid), GID: uint32(gid)}); err != nil {
		t.Fatal(err)
	}
	if err := finish(false); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.ConfigRoot, paths.DataRoot, file, envPath} {
		info, err := os.Stat(path)
		if err != nil || info.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Fatalf("ownership rollback failed: %s", path)
		}
	}
	if err := os.Symlink(file, filepath.Join(paths.ConfigRoot, "linked-file")); err != nil {
		t.Fatal(err)
	}
	if _, err := install.TransferServiceRoots(paths, account.Username); err == nil {
		t.Fatal("ownership transfer accepted a symbolic link")
	}
	info, err := os.Stat(file)
	if err != nil || info.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("rejected link changed its destination owner")
	}
}
