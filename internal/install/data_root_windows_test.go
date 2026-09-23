// data_root_windows_test.go verifies Windows data-root ACL creation and rejection behavior.
// data_root_windows_test.go 验证 Windows 数据根目录的 ACL 创建与拒绝行为。
// It belongs to the installation transaction tests and exercises the same DACL contract as VMM.
// 它属于安装事务测试，并验证与 VMM 相同的 DACL 契约。
//go:build windows

package install

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"golang.org/x/sys/windows"
)

// TestInstallDataRootCreatesProtectedACL verifies newly created roots do not inherit broad access.
// TestInstallDataRootCreatesProtectedACL 验证新建数据根不会继承宽泛访问权限。
func TestInstallDataRootCreatesProtectedACL(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data", "nested")
	if err := ensureInstallDataRoot(root); err != nil {
		t.Fatalf("ensureInstallDataRoot() error = %v", err)
	}
	if err := validateInstallPrivateDirectory(root); err != nil {
		t.Fatalf("validateInstallPrivateDirectory() error = %v", err)
	}
	sddl := readInstallTestDACL(t, root)
	if !strings.Contains(sddl, "D:P") {
		t.Fatalf("new data-root DACL is not protected: %q", sddl)
	}
	for _, broadTrustee := range []string{"WD", "BU", "AU", "AN"} {
		if strings.Contains(sddl, broadTrustee) {
			t.Fatalf("new data-root DACL contains broad trustee %q: %q", broadTrustee, sddl)
		}
	}
}

// TestInstallDataRootRejectsBroadACLWithoutMutation verifies existing ACLs are checked read-only.
// TestInstallDataRootRejectsBroadACLWithoutMutation 验证已有 ACL 只读检查且不会被修改。
func TestInstallDataRootRejectsBroadACLWithoutMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("create data root: %v", err)
	}
	if err := setInstallTestDACL(root, "D:P(A;OICI;FA;;;WD)"); err != nil {
		t.Fatalf("set broad DACL: %v", err)
	}
	before := readInstallTestDACL(t, root)
	if err := ensureInstallDataRoot(root); err == nil {
		t.Fatal("expected broad DACL rejection")
	}
	after := readInstallTestDACL(t, root)
	if before != after {
		t.Fatalf("existing DACL changed after rejection: before=%q after=%q", before, after)
	}
}

// setInstallTestDACL installs a test-only descriptor through the native Windows security API.
// setInstallTestDACL 使用原生 Windows 安全 API 安装仅供测试的安全描述符。
func setInstallTestDACL(path string, sddl string) error {
	securityDescriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := securityDescriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
}

// readInstallTestDACL returns one directory's security descriptor in SDDL form.
// readInstallTestDACL 以 SDDL 形式返回一个目录的安全描述符。
func readInstallTestDACL(t *testing.T, path string) string {
	t.Helper()
	securityDescriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read directory DACL: %v", err)
	}
	if securityDescriptor == nil {
		t.Fatal("directory security descriptor is empty")
	}
	return securityDescriptor.String()
}

// TestStagePackageCreatesProtectedDataRoot verifies the real staging path prepares a VMM-compatible root.
// TestStagePackageCreatesProtectedDataRoot 验证真实暂存路径会准备兼容 VMM 的数据根目录。
func TestStagePackageCreatesProtectedDataRoot(t *testing.T) {
	request, _, _ := newInstallRequest(t, "")
	request.ValidateConfig = validConfigValidator(t)
	prepared, err := StagePackage(t.Context(), request)
	if err != nil {
		t.Fatalf("StagePackage() error = %v", err)
	}
	defer prepared.Close()
	if err := validateInstallPrivateDirectory(request.Paths.DataRoot); err != nil {
		t.Fatalf("staged data-root ACL is not VMM-compatible: %v", err)
	}
}

// TestStageAndValidateDefaultLocalStorageModes runs the actual VMM config validator when a built binary is available.
// TestStageAndValidateDefaultLocalStorageModes 在存在已构建 VMM 二进制时运行真实配置校验。
func TestStageAndValidateDefaultLocalStorageModes(t *testing.T) {
	binaryPath := isolateInstallTestVMMLayout(t, resolveInstallTestVMMBinary(t))
	for _, mode := range []string{"split", "controller"} {
		t.Run(mode, func(t *testing.T) {
			request, _, _ := newInstallRequest(t, "")
			request.ConfigFiles = map[string][]byte{
				UserConfigFileName: []byte(fmt.Sprintf("storage:\n  mode: %s\n  local_data_root: %q\nllm:\n  routes:\n    - provider: openai\n      endpoint: https://api.openai.com/v1\n      model: test-model\n      api_keys: [local-validation-only]\nembedding:\n  provider: openai\n  endpoint: https://api.openai.com/v1\n  model: test-embedding\n  api_keys: [local-validation-only]\nrerank:\n  enabled: false\n", mode, request.Paths.DataRoot)),
			}
			request.ValidateConfig = func(ctx context.Context, _ string, configRoot string) (configbridge.ValidationResult, error) {
				client, err := configbridge.New(binaryPath, configRoot)
				if err != nil {
					return configbridge.ValidationResult{}, err
				}
				return client.Validate(ctx)
			}
			prepared, err := StagePackage(t.Context(), request)
			if err != nil {
				t.Fatalf("StagePackage() error = %v", err)
			}
			defer prepared.Close()
			if _, err := prepared.CommitInstall(t.Context(), request); err != nil {
				t.Fatalf("CommitInstall() with real VMM %s validation error = %v", mode, err)
			}
		})
	}
}

// isolateInstallTestVMMLayout copies the real validator and its system config into a database-free package layout.
// isolateInstallTestVMMLayout 将真实校验器及系统配置复制到无数据库的测试包布局，避免读取开发者已有数据目录。
func isolateInstallTestVMMLayout(t *testing.T, sourceBinary string) string {
	t.Helper()
	root := t.TempDir()
	binaryPath := filepath.Join(root, "bin", filepath.Base(sourceBinary))
	digest, size, err := digestFile(sourceBinary)
	if err != nil {
		t.Fatalf("read validator binary: %v", err)
	}
	if err := copyVerifiedFile(sourceBinary, binaryPath, digest, size, 0o755); err != nil {
		t.Fatalf("copy validator binary: %v", err)
	}
	configs := filepath.Join(filepath.Dir(filepath.Dir(sourceBinary)), "configs")
	if err := os.CopyFS(filepath.Join(root, "configs"), os.DirFS(configs)); err != nil {
		t.Fatalf("copy validator system configuration: %v", err)
	}
	// Development overlays may require private credentials; the isolated test supplies its own complete provider fixture.
	// 开发覆盖可能要求私有凭据；隔离测试使用自己的完整供应商夹具，不依赖开发者环境。
	for _, name := range []string{"config.yaml", ".env"} {
		if err := os.Remove(filepath.Join(root, "configs", name)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	return binaryPath
}

// resolveInstallTestVMMBinary locates an explicit or adjacent release binary for the real validator test.
// resolveInstallTestVMMBinary 定位真实校验测试使用的显式或相邻发行二进制。
func resolveInstallTestVMMBinary(t *testing.T) string {
	t.Helper()
	candidates := []string{os.Getenv("VMMM_TEST_VMM_BINARY"), os.Getenv("VMM_LOCAL_BINARY")}
	workingDirectory, err := os.Getwd()
	if err == nil {
		ancestor := filepath.Clean(workingDirectory)
		for range 6 {
			candidates = append(candidates, filepath.Join(ancestor, "VulcanMemoryMesh", "output", "bin", "vmm-local.exe"))
			parent := filepath.Dir(ancestor)
			if parent == ancestor {
				break
			}
			ancestor = parent
		}
	}
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() {
			absolute, err := filepath.Abs(candidate)
			if err == nil {
				return absolute
			}
		}
	}
	t.Skip("set VMMM_TEST_VMM_BINARY or build the adjacent VMM output/bin/vmm-local.exe")
	return ""
}
