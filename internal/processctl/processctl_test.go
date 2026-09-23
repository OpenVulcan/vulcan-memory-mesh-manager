// This file verifies non-service lifecycle, stale-state cleanup, and identity boundaries.
// 此文件验证非服务生命周期、陈旧状态清理和身份边界。
package processctl

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/testpath"
)

// TestMain turns the test binary into a long-lived fake VMM child when requested.
// TestMain 在收到请求时把测试二进制变成长驻 fake VMM 子进程。
func TestMain(main *testing.M) {
	if os.Getenv("VMMM_PROCESSCTL_HELPER") == "1" {
		select {}
	}
	os.Exit(main.Run())
}

// TestLifecycleUsesVerifiedIdentity exercises start, status, duplicate start, and stop.
// TestLifecycleUsesVerifiedIdentity 验证启动、状态、重复启动和停止都使用身份校验。
func TestLifecycleUsesVerifiedIdentity(t *testing.T) {
	root := testpath.CanonicalTempDir(t)
	configRoot := filepath.Join(root, "config")
	if err := os.Mkdir(configRoot, 0700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "state", "process.json")
	client, err := New(Options{
		BinaryPath:       mustExecutablePath(t),
		ConfigRoot:       configRoot,
		StatePath:        statePath,
		OperationTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Getenv("VMMM_PROCESSCTL_HELPER")
	if err := os.Setenv("VMMM_PROCESSCTL_HELPER", "1"); err != nil {
		t.Fatal(err)
	}
	defer os.Setenv("VMMM_PROCESSCTL_HELPER", previous)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	running, err := client.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if running.State != StateRunning || running.PID <= 0 {
		t.Fatalf("start status = %#v", running)
	}
	if _, err := client.Start(ctx); err != ErrAlreadyRunning {
		t.Fatalf("duplicate start error = %v, want %v", err, ErrAlreadyRunning)
	}
	observed, err := client.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if observed.State != StateRunning || observed.PID != running.PID {
		t.Fatalf("observed status = %#v, want running PID %d", observed, running.PID)
	}
	if err := client.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	stopped, err := client.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.State != StateStopped {
		t.Fatalf("stopped status = %#v", stopped)
	}
}

// TestStaleRecordIsCleanedWithoutKillingAnUnrelatedProcess proves PID mismatch is fail-closed.
// TestStaleRecordIsCleanedWithoutKillingAnUnrelatedProcess 验证 PID 不匹配时安全清理且不误杀。
func TestStaleRecordIsCleanedWithoutKillingAnUnrelatedProcess(t *testing.T) {
	root := testpath.CanonicalTempDir(t)
	configRoot := filepath.Join(root, "config")
	if err := os.Mkdir(configRoot, 0700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "process.json")
	client, err := New(Options{BinaryPath: mustExecutablePath(t), ConfigRoot: configRoot, StatePath: statePath})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		t.Fatal(err)
	}
	stale := processRecord{
		ProtocolVersion:   protocolVersion,
		PID:               os.Getpid(),
		ProcessGroupID:    os.Getpid(),
		ExecutablePath:    filepath.Join(root, "missing-vmm"),
		Arguments:         []string{"-config", configRoot},
		CommandLineDigest: commandLineDigest(filepath.Join(root, "missing-vmm"), []string{"-config", configRoot}),
		Owner:             "different-owner",
		StartToken:        "stale-token",
		StartedAtUnixNano: time.Now().UnixNano(),
	}
	if err := saveRecord(statePath, stale); err != nil {
		t.Fatal(err)
	}
	status, err := client.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateStopped {
		t.Fatalf("stale status = %#v", status)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("stale process state still exists, stat error = %v", err)
	}
}

// mustExecutablePath returns the current test binary as a regular fake executable.
// mustExecutablePath 返回当前测试二进制作为普通 fake 可执行文件。
func mustExecutablePath(t *testing.T) string {
	t.Helper()
	return testpath.CanonicalExecutable(t)
}
