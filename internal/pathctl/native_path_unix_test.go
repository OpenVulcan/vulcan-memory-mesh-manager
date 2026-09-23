//go:build !windows

// This file verifies the real root-owned command link on disposable Linux and macOS CI runners.
// 本文件在临时 Linux 和 macOS CI 执行器中验证真实 root 所有的命令链接。
package pathctl

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestNativePATHRoundTrip creates the production system command link, invokes the built manager, and removes only its own link.
// TestNativePATHRoundTrip 创建正式系统命令链接并调用管理器，最后仅移除本次拥有的链接，无返回值。
func TestNativePATHRoundTrip(t *testing.T) {
	binary := nativePATHBinary(t)
	if os.Geteuid() != 0 {
		t.Fatal("system PATH verification requires the CI sudo step")
	}
	// The fixed link is the same system command path used by production installations.
	// 固定链接使用正式安装的相同系统命令路径。
	const link = "/usr/local/bin/vmmm"
	if _, err := os.Lstat(link); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("runner already has a vmmm entry; refusing to replace it")
	}
	if err := os.MkdirAll("/opt", 0o755); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("/opt", "vmmm-path-smoke-")
	if err != nil {
		t.Fatal(err)
	}
	// The fixed parent and unique child are verified before registering recursive fixture cleanup.
	// 在登记递归夹具清理前核对固定父目录和唯一子目录。
	if filepath.Dir(directory) != "/opt" {
		t.Fatal("unexpected fixture root")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove private CI fixture: %v", err)
		}
	})
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "vmmm")
	if err := os.WriteFile(target, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	controller := New()
	record, err := controller.Install(Options{Method: MethodUnixSystemBin, Directory: directory, TargetPath: target, LinkPath: link})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := controller.Remove(record); err != nil {
			t.Errorf("remove owned runner command: %v", err)
		}
	})
	actual, err := os.Readlink(link)
	if err != nil || actual != target {
		t.Fatalf("system link target mismatch: %v", err)
	}
	t.Setenv("PATH", "/usr/local/bin:"+os.Getenv("PATH"))
	verifyNativePATHCommand(t, target)
	if err := controller.Remove(record); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("system link remained after removal: %v", err)
	}
}
