//go:build !windows

// This file verifies real root-owned command entries on disposable Linux and macOS CI runners.
// 本文件在临时 Linux 和 macOS CI 执行器中验证真实 root 所有的命令入口。
package pathctl

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
)

// TestNativePATHRoundTrip creates the production system command entry, invokes the built manager, and removes only its own entry.
// TestNativePATHRoundTrip 创建正式系统命令入口并调用管理器，最后仅移除本次拥有的条目，无返回值。
func TestNativePATHRoundTrip(t *testing.T) {
	binary := nativePATHBinary(t)
	if os.Geteuid() != 0 {
		t.Fatal("system PATH verification requires the CI sudo step")
	}
	parent := "/usr/local/lib"
	options := Options{Method: MethodUnixSystemBin, LinkPath: "/usr/local/bin/vmmm"}
	entry := options.LinkPath
	if runtime.GOOS == "darwin" {
		parent = "/Library/Application Support"
		options = Options{Method: MethodDarwinPathsD, ProfilePath: DarwinPathsFile}
		entry = options.ProfilePath
	}
	if _, err := os.Lstat(entry); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("runner already has a vmmm entry; refusing to replace it")
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(parent, "vmmm-path-smoke-")
	if err != nil {
		t.Fatal(err)
	}
	// Validate the unique fixture's parent before registering recursive cleanup.
	// 登记递归清理前核对唯一夹具的父目录。
	if filepath.Dir(directory) != parent {
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
	options.Directory = directory
	controller := New()
	if runtime.GOOS != "darwin" {
		options.TargetPath = target
		// Hosted Linux images make their shared tool directory writable. Verify refusal before provisioning the disposable fixture.
		// Linux 托管镜像将共享工具目录设为可写；先验证拒绝，再准备临时执行器夹具。
		info, err := os.Lstat(filepath.Dir(entry))
		if err != nil {
			t.Fatal(err)
		}
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || metadata.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatal("runner command directory is not a root-owned real directory")
		}
		if info.Mode().Perm()&0o022 != 0 {
			if record, err := controller.Install(options); err == nil {
				_ = controller.Remove(record)
				t.Fatal("unsafe runner command directory was accepted")
			}
			if err := os.Chmod(filepath.Dir(entry), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(filepath.Dir(entry), info.Mode().Perm()); err != nil {
					t.Errorf("restore runner directory mode: %v", err)
				}
			})
		}
	}
	record, err := controller.Install(options)
	if err != nil {
		logNativePATHDirectories(t, directory)
		logNativePATHDirectories(t, filepath.Dir(entry))
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := controller.Remove(record); err != nil {
			t.Errorf("remove owned runner command: %v", err)
		}
	})
	if runtime.GOOS == "darwin" {
		verifyDarwinLoginCommand(t, target)
		// Existing identical entries remain external; changed content cannot be removed with the original receipt.
		// 既有相同条目仍归外部所有；内容变化后不能使用原收据删除。
		external, err := controller.Install(options)
		if err != nil || external.Path.Owner != state.PATHOwnerExternal {
			t.Fatalf("existing entry ownership changed: %+v %v", external, err)
		}
		if err := controller.Remove(external); err != nil {
			t.Fatal(err)
		}
		original, err := os.ReadFile(entry)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(entry, []byte("/changed-by-test\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		removeErr := controller.Remove(record)
		restoreErr := os.WriteFile(entry, original, 0o644)
		if !errors.Is(removeErr, ErrChanged) || restoreErr != nil {
			t.Fatalf("changed entry ownership check failed: %v %v", removeErr, restoreErr)
		}
	} else {
		actual, err := os.Readlink(entry)
		if err != nil || actual != target {
			t.Fatalf("system link target mismatch: %v", err)
		}
		t.Setenv("PATH", "/usr/local/bin:"+os.Getenv("PATH"))
		verifyNativePATHCommand(t, target)
	}
	if err := controller.Remove(record); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(entry); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("system entry remained after removal: %v", err)
	}
}

// logNativePATHDirectories records exact directory ownership on native failures without altering the runner's trust boundary.
// logNativePATHDirectories 在原生失败时记录精确目录归属，不修改执行器的信任边界，无返回值。
func logNativePATHDirectories(t *testing.T, directory string) {
	t.Helper()
	for current := directory; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			t.Logf("directory %s: %v", current, err)
		} else if metadata, ok := info.Sys().(*syscall.Stat_t); ok {
			t.Logf("directory %s: mode=%s uid=%d gid=%d", current, info.Mode(), metadata.Uid, metadata.Gid)
		}
		if current == filepath.Dir(current) {
			break
		}
	}
}

// verifyDarwinLoginCommand exercises the system login profile so path_helper reads the real paths.d entry.
// verifyDarwinLoginCommand 执行系统登录配置，使 path_helper 读取真实 paths.d 条目，验证所选文件与版本输出。
func verifyDarwinLoginCommand(t *testing.T, expected string) {
	t.Helper()
	resolved, err := exec.Command("/bin/zsh", "-l", "-c", "command -v vmmm").Output()
	if err != nil {
		t.Fatalf("login shell did not resolve manager: %v", err)
	}
	actualInfo, err := os.Stat(strings.TrimSpace(string(resolved)))
	if err != nil {
		t.Fatal(err)
	}
	expectedInfo, err := os.Stat(expected)
	if err != nil || !os.SameFile(actualInfo, expectedInfo) {
		t.Fatal("login shell selected a different manager")
	}
	output, err := exec.Command("/bin/zsh", "-l", "-c", "exec vmmm --json version").Output()
	if err != nil {
		t.Fatalf("manager did not run in login shell: %v", err)
	}
	var version struct {
		Product string `json:"product"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(output, &version); err != nil || version.Product != "vmmm" || version.Version == "" {
		t.Fatalf("unexpected login-shell manager response: %s %v", output, err)
	}
}
