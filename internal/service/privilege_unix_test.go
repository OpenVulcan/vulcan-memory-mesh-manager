//go:build linux || darwin

// This file verifies the Unix service privilege boundary without starting sudo or changing system services.
// 本文件在不启动 sudo 且不修改系统服务的前提下验证 Unix 服务提权边界。
package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPrivilegedRunnerUsesFixedSudoPath verifies the final process path and vector used for a non-root write.
// TestPrivilegedRunnerUsesFixedSudoPath 验证非 root 写操作使用的最终进程路径和参数数组。
func TestPrivilegedRunnerUsesFixedSudoPath(t *testing.T) {
	oldUID := effectiveUID
	oldResolver := resolveSudoExecutable
	defer func() {
		effectiveUID = oldUID
		resolveSudoExecutable = oldResolver
	}()
	effectiveUID = func() int { return 1000 }
	resolveSudoExecutable = func() (string, error) { return secureSudoExecutable, nil }

	client := &Client{
		binaryPath:  "/opt/vmm/vmm-local",
		timeout:     time.Second,
		outputLimit: statusOutputLimit,
	}
	var capturedPath string
	var capturedArgs []string
	var resolverCalled bool
	client.runner = func(_ context.Context, path string, args []string, _ bool) (string, error) {
		capturedPath = path
		capturedArgs = append([]string(nil), args...)
		return "", nil
	}
	resolveSudoExecutable = func() (string, error) {
		resolverCalled = true
		return secureSudoExecutable, nil
	}

	if _, err := client.runPrivileged(context.Background(), "start", []string{"service", "start", "vmm"}, false); err != nil {
		t.Fatalf("runPrivileged: %v", err)
	}
	if !resolverCalled {
		t.Fatal("privileged non-root run did not resolve the trusted sudo path")
	}
	if !filepath.IsAbs(capturedPath) || capturedPath != secureSudoExecutable {
		t.Fatalf("captured sudo path = %q, want absolute %q", capturedPath, secureSudoExecutable)
	}
	assertStringVector(t, capturedArgs, []string{"-n", client.binaryPath, "service", "start", "vmm"})

	resolverCalled = false
	if _, err := client.run(context.Background(), "status", []string{"service", "status", "vmm"}, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	if resolverCalled {
		t.Fatal("unprivileged status unexpectedly resolved sudo")
	}
	if capturedPath != client.binaryPath {
		t.Fatalf("captured unprivileged path = %q, want %q", capturedPath, client.binaryPath)
	}
	assertStringVector(t, capturedArgs, []string{"service", "status", "vmm"})
}

// TestPrivilegedRunnerFailsClosedWhenSudoTrustCheckFails verifies no process starts after the trust gate rejects sudo.
// TestPrivilegedRunnerFailsClosedWhenSudoTrustCheckFails 验证 sudo 信任门禁拒绝后不会启动任何进程。
func TestPrivilegedRunnerFailsClosedWhenSudoTrustCheckFails(t *testing.T) {
	oldUID := effectiveUID
	oldResolver := resolveSudoExecutable
	defer func() {
		effectiveUID = oldUID
		resolveSudoExecutable = oldResolver
	}()
	effectiveUID = func() int { return 1000 }
	resolveSudoExecutable = func() (string, error) { return "", ErrSecureSudoUnavailable }

	client := &Client{
		binaryPath:  "/opt/vmm/vmm-local",
		timeout:     time.Second,
		outputLimit: statusOutputLimit,
	}
	called := false
	client.runner = func(_ context.Context, _ string, _ []string, _ bool) (string, error) {
		called = true
		return "", nil
	}

	_, err := client.runPrivileged(context.Background(), "install", []string{"service", "install", "vmm"}, false)
	if err == nil {
		t.Fatal("runPrivileged succeeded despite an untrusted sudo helper")
	}
	if !errors.Is(err, ErrSecureSudoUnavailable) {
		t.Fatalf("runPrivileged error = %v, want ErrSecureSudoUnavailable", err)
	}
	if !strings.Contains(err.Error(), "sudo -v") {
		t.Fatalf("runPrivileged error = %v, want sudo -v guidance", err)
	}
	if called {
		t.Fatal("runner was called after sudo trust validation failed")
	}
}

// assertStringVector compares an exact process argument vector without relying on test-only reflection helpers.
// assertStringVector 精确比较进程参数数组，不依赖测试专用的反射辅助函数。
func assertStringVector(t *testing.T, actual []string, expected []string) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("argument count = %d, want %d: %#v", len(actual), len(expected), actual)
	}
	for index := range expected {
		if actual[index] != expected[index] {
			t.Fatalf("argument[%d] = %q, want %q; full args: %#v", index, actual[index], expected[index], actual)
		}
	}
}
