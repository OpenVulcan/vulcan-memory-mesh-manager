// service_test.go verifies the safe process boundary and VMM service CLI contract.
// service_test.go 用于验证安全的子进程边界和 VMM 服务 CLI 契约。
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/testpath"
)

const (
	// helperModeEnvironment selects the test executable's fake VMM process entry point.
	// helperModeEnvironment 用于选择测试可执行文件中的 fake VMM 子进程入口。
	helperModeEnvironment = "VMMM_SERVICE_TEST_HELPER"

	// helperLogEnvironment supplies a temporary file where the fake process records its received arguments.
	// helperLogEnvironment 指定 fake 子进程记录实际收到参数的临时文件。
	helperLogEnvironment = "VMMM_SERVICE_TEST_LOG"

	// helperStatusEnvironment supplies fake machine-readable status output for status parser tests.
	// helperStatusEnvironment 为状态解析测试提供 fake 机器可读状态输出。
	helperStatusEnvironment = "VMMM_SERVICE_TEST_STATUS"

	// helperExitEnvironment selects a fake process exit code for redaction and failure tests.
	// helperExitEnvironment 用于失败和脱敏测试指定 fake 子进程退出码。
	helperExitEnvironment = "VMMM_SERVICE_TEST_EXIT"

	// helperSleepEnvironment requests a bounded fake process delay for context cancellation tests.
	// helperSleepEnvironment 用于上下文取消测试要求 fake 子进程延迟指定毫秒数。
	helperSleepEnvironment = "VMMM_SERVICE_TEST_SLEEP_MS"

	// helperSecretEnvironment contains a marker that must never appear in returned errors.
	// helperSecretEnvironment 保存一个绝不能出现在返回错误中的测试标记。
	helperSecretEnvironment = "VMMM_SERVICE_TEST_SECRET"
)

// init turns the test executable into a fake VMM binary only when the dedicated child-process variable is set.
// init 仅在专用子进程环境变量存在时，将测试可执行文件切换为 fake VMM 程序。
// The test runner itself starts without this variable, so ordinary package tests continue through testing.Main.
// 测试运行器本身不会设置该变量，因此普通包测试仍由 testing.Main 正常执行。
func init() {
	if os.Getenv(helperModeEnvironment) != "1" {
		return
	}
	os.Exit(runFakeVMMProcess())
}

// runFakeVMMProcess records the exact argument vector and emits controlled output for the parent adapter.
// runFakeVMMProcess 记录精确参数数组，并为父进程适配器生成可控输出。
func runFakeVMMProcess() int {
	logPath := os.Getenv(helperLogEnvironment)
	if logPath != "" {
		encoded, err := json.Marshal(os.Args[1:])
		if err != nil {
			return 90
		}
		if err := os.WriteFile(logPath, encoded, 0o600); err != nil {
			return 91
		}
	}
	if delay, err := time.ParseDuration(os.Getenv(helperSleepEnvironment) + "ms"); err == nil && delay > 0 {
		time.Sleep(delay)
	}
	if status := os.Getenv(helperStatusEnvironment); status != "" {
		_, _ = fmt.Fprint(os.Stdout, status)
	}
	if secret := os.Getenv(helperSecretEnvironment); secret != "" {
		_, _ = fmt.Fprintln(os.Stderr, secret)
	}
	if code := os.Getenv(helperExitEnvironment); code != "" {
		var exitCode int
		if _, err := fmt.Sscanf(code, "%d", &exitCode); err != nil {
			return 92
		}
		return exitCode
	}
	return 0
}

// TestNewRequiresAbsoluteRegularBinary verifies the adapter never falls back to PATH or accepts directories.
// TestNewRequiresAbsoluteRegularBinary 验证适配器不会回退到 PATH 搜索，也不会接受目录路径。
func TestNewRequiresAbsoluteRegularBinary(t *testing.T) {
	if _, err := New("vmm-local.exe"); err == nil {
		t.Fatal("expected relative executable path to be rejected")
	}
	if _, err := New(testpath.CanonicalTempDir(t)); err == nil {
		t.Fatal("expected directory path to be rejected")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(executable)
	if err != nil {
		t.Fatalf("New(%q): %v", executable, err)
	}
	if client.binaryPath != filepath.Clean(executable) {
		t.Fatalf("stored binary = %q, want %q", client.binaryPath, filepath.Clean(executable))
	}
}

// TestInstallPassesFixedArgumentVector verifies install names and paths with spaces remain separate process arguments.
// TestInstallPassesFixedArgumentVector 验证带空格的服务名和路径仍作为独立子进程参数传递。
func TestInstallPassesFixedArgumentVector(t *testing.T) {
	client, logPath := newFakeClient(t)
	configDirectory := filepath.Join(testpath.CanonicalTempDir(t), "config with spaces")
	if err := os.Mkdir(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	serviceName := "VMM.Dev_01-Local"
	serviceUser := "vmm-service"
	if err := client.Install(context.Background(), serviceName, configDirectory, serviceUser, false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	assertArguments(t, logPath, installArgumentsForPlatform(serviceName, filepath.Clean(configDirectory), serviceUser, false, runtime.GOOS))
	if err := client.Install(context.Background(), serviceName, configDirectory, serviceUser, true); err != nil {
		t.Fatalf("Install with auto-start: %v", err)
	}
	assertArguments(t, logPath, installArgumentsForPlatform(serviceName, filepath.Clean(configDirectory), serviceUser, true, runtime.GOOS))
}

// TestLifecycleActionsUseOnlyAllowedArguments exercises every public lifecycle method against a fake executable.
// TestLifecycleActionsUseOnlyAllowedArguments 使用 fake 可执行文件覆盖所有公开生命周期方法。
func TestLifecycleActionsUseOnlyAllowedArguments(t *testing.T) {
	client, logPath := newFakeClient(t)
	serviceName := "vmm_test"
	actions := []struct {
		name string
		run  func(context.Context, string) error
	}{
		{name: "uninstall", run: client.Uninstall},
		{name: "start", run: client.Start},
		{name: "stop", run: client.Stop},
		{name: "restart", run: client.Restart},
		{name: "enable", run: client.Enable},
		{name: "disable", run: client.Disable},
	}
	for _, item := range actions {
		t.Run(item.name, func(t *testing.T) {
			if err := item.run(context.Background(), serviceName); err != nil {
				t.Fatalf("%s: %v", item.name, err)
			}
			assertArguments(t, logPath, []string{"service", item.name, serviceName})
		})
	}
}

// TestServiceNameValidationRejectsInjection verifies service identifiers cannot add arguments or native file paths.
// TestServiceNameValidationRejectsInjection 验证服务标识符无法注入参数或原生文件路径。
func TestServiceNameValidationRejectsInjection(t *testing.T) {
	invalidNames := []string{"", "../vmm", "vmm --status", "vmm\\other", "-vmm", strings.Repeat("a", maximumServiceNameLength+1), "服务"}
	for _, name := range invalidNames {
		if err := validateServiceName(name); err == nil {
			t.Errorf("validateServiceName(%q) succeeded", name)
		}
	}
	if err := validateServiceName("VMM.Dev_01-Local"); err != nil {
		t.Fatalf("valid service name rejected: %v", err)
	}
}

// TestServiceUserArgumentPolicy verifies Unix account validation and the absence of -user on Windows.
// TestServiceUserArgumentPolicy 验证 Unix 账户校验以及 Windows 不传递 -user。
func TestServiceUserArgumentPolicy(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, value := range []string{"", "vmm service", " vmm", "vmm ", "vmm\nservice", "vmm=service", "-vmm", "vmm/service", strings.Repeat("a", 129)} {
			if err := validateServiceUserForPlatform(value, platform); err == nil {
				t.Errorf("validateServiceUserForPlatform(%q, %q) succeeded", value, platform)
			}
		}
		if err := validateServiceUserForPlatform("vmm-service", platform); err != nil {
			t.Errorf("validateServiceUserForPlatform(valid, %q): %v", platform, err)
		}
		args := installArgumentsForPlatform("vmm", "C:\\vmm-config", "vmm-service", true, platform)
		if !containsArgumentPair(args, "-user", "vmm-service") {
			t.Errorf("Unix install args omit service user on %q: %#v", platform, args)
		}
	}
	if err := validateServiceUserForPlatform("", "windows"); err != nil {
		t.Fatalf("Windows should ignore Unix service user: %v", err)
	}
	if args := installArgumentsForPlatform("vmm", "C:\\vmm-config", "vmm-service", true, "windows"); containsArgument(args, "-user") {
		t.Fatalf("Windows install args unexpectedly contain -user: %#v", args)
	}
}

// TestSudoCommandArgumentsUsesAClosedVector verifies privilege escalation never invokes a shell or reorders VMM arguments.
// TestSudoCommandArgumentsUsesAClosedVector 验证提权参数不调用 shell，也不会重排 VMM 参数。
func TestSudoCommandArgumentsUsesAClosedVector(t *testing.T) {
	binaryPath := filepath.Join(testpath.CanonicalTempDir(t), "vmm-local")
	args := []string{"service", "install", "vmm", "-config", filepath.Join(testpath.CanonicalTempDir(t), "config root"), "-user", "vmm-service"}
	wrapped := sudoCommandArguments(binaryPath, args)
	want := append([]string{"-n", binaryPath}, args...)
	if len(wrapped) != len(want) {
		t.Fatalf("sudo argument count = %d, want %d: %#v", len(wrapped), len(want), wrapped)
	}
	for index := range want {
		if wrapped[index] != want[index] {
			t.Fatalf("sudo argument[%d] = %q, want %q; full args: %#v", index, wrapped[index], want[index], wrapped)
		}
	}
	args[0] = "mutated"
	if wrapped[2] != "service" {
		t.Fatalf("sudo vector aliases caller arguments: %#v", wrapped)
	}
}

// TestCommandFailureAddsSudoHintOnlyForPrivilegedFailures verifies Unix privilege errors have an actionable remediation.
// TestCommandFailureAddsSudoHintOnlyForPrivilegedFailures 验证 Unix 提权失败包含明确的修复提示。
func TestCommandFailureAddsSudoHintOnlyForPrivilegedFailures(t *testing.T) {
	cause := errors.New("permission denied")
	privileged := commandFailure("install", cause, true)
	if !errors.Is(privileged, cause) || !strings.Contains(privileged.Error(), "sudo -v") {
		t.Fatalf("privileged error = %v, want cause and sudo hint", privileged)
	}
	plain := commandFailure("status", cause, false)
	if !errors.Is(plain, cause) || strings.Contains(plain.Error(), "sudo -v") {
		t.Fatalf("plain error = %v, unexpected sudo hint", plain)
	}
}

// TestWindowsPrivilegeBoundaryKeepsVMMVectorUnchanged verifies Windows delegates elevation to SCM.
// TestWindowsPrivilegeBoundaryKeepsVMMVectorUnchanged 验证 Windows 将提权交给 SCM 并保持 VMM 参数不变。
func TestWindowsPrivilegeBoundaryKeepsVMMVectorUnchanged(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only invocation boundary")
	}
	binaryPath := filepath.Join(testpath.CanonicalTempDir(t), "vmm-local.exe")
	args := []string{"service", "start", "vmm"}
	path, actual, usedSudo, err := preparePrivilegedCommand(binaryPath, args, true)
	if err != nil {
		t.Fatalf("preparePrivilegedCommand: %v", err)
	}
	if path != binaryPath || usedSudo || len(actual) != len(args) {
		t.Fatalf("Windows privileged invocation changed: path=%q args=%#v usedSudo=%v", path, actual, usedSudo)
	}
}

// TestConfigPathValidationRequiresAbsoluteDirectoryOrYAML verifies install cannot persist a relative or arbitrary file path.
// TestConfigPathValidationRequiresAbsoluteDirectoryOrYAML 验证安装不能持久化相对路径或任意文件路径。
func TestConfigPathValidationRequiresAbsoluteDirectoryOrYAML(t *testing.T) {
	validDirectory := testpath.CanonicalTempDir(t)
	missingDirectory := filepath.Join(testpath.CanonicalTempDir(t), "future-config-root")
	validYAML := filepath.Join(testpath.CanonicalTempDir(t), "settings.yml")
	if err := os.WriteFile(validYAML, []byte("# test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missingYAML := filepath.Join(testpath.CanonicalTempDir(t), "not-created.yaml")
	for _, path := range []string{validDirectory, missingDirectory, validYAML, missingYAML} {
		if _, err := validateConfigPath(path); err != nil {
			t.Errorf("validateConfigPath(%q): %v", path, err)
		}
	}
	invalidPaths := []string{"config.yaml", filepath.Join(testpath.CanonicalTempDir(t), "config.json"), filepath.Join(testpath.CanonicalTempDir(t), "bad\nname.yaml"), filepath.Join(testpath.CanonicalTempDir(t), "missing.json")}
	for _, path := range invalidPaths {
		if _, err := validateConfigPath(path); err == nil {
			t.Errorf("validateConfigPath(%q) succeeded", path)
		}
	}
}

// TestStatusParserRequiresExactPlatformFields verifies supported fields, duplicates, and malformed lines are handled strictly.
// TestStatusParserRequiresExactPlatformFields 验证状态字段集合、重复字段和错误行均按严格规则处理。
func TestStatusParserRequiresExactPlatformFields(t *testing.T) {
	valid := validStatusFixture()
	status, err := parseStatusOutput(valid)
	if err != nil {
		t.Fatalf("valid status rejected: %v", err)
	}
	if status.State == "" || status.AutoStart == "" {
		t.Fatalf("missing required parsed fields: %#v", status)
	}
	if runtime.GOOS != "windows" && status.User != "vmm-service" {
		t.Fatalf("missing Unix service user: %#v", status)
	}
	invalidOutputs := []string{
		"state=running\nauto_start=enabled\nunknown=secret\n",
		valid + strings.Split(valid, "\n")[0] + "\n",
		strings.Replace(valid, "state=", "state=\x1b[31m", 1),
		"state=running\n\nauto_start=enabled\n",
		strings.Replace(valid, "auto_start=enabled", "auto_start=enabled extra", 1),
		strings.Replace(valid, "state=running", "state=loaded", 1),
	}
	for _, output := range invalidOutputs {
		if _, err := parseStatusOutput(output); !errors.Is(err, ErrInvalidStatus) {
			t.Errorf("parseStatusOutput(%q) error = %v, want ErrInvalidStatus", output, err)
		}
	}
}

// TestStatusParserAcceptsCrossPlatformFixtures verifies the exact line-oriented fixtures emitted by VMM on all supported platforms.
// TestStatusParserAcceptsCrossPlatformFixtures 验证 VMM 在所有支持平台上发出的精确逐行 fixture。
func TestStatusParserAcceptsCrossPlatformFixtures(t *testing.T) {
	tests := []struct {
		platform string
		output   string
		state    string
		user     string
	}{
		{platform: "windows", output: "state=running\nauto_start=enabled\nstart_type=automatic\n", state: "running"},
		{platform: "linux", output: "state=running\nsubstate=running\nauto_start=enabled\nuser=vmm-service\n", state: "running", user: "vmm-service"},
		{platform: "darwin", output: "state=stopped\nauto_start=disabled\nuser=vmm-service\n", state: "stopped", user: "vmm-service"},
	}
	for _, test := range tests {
		t.Run(test.platform, func(t *testing.T) {
			status, err := parseStatusOutputForPlatform(test.output, test.platform)
			if err != nil {
				t.Fatalf("parseStatusOutputForPlatform: %v", err)
			}
			if status.State != test.state || status.User != test.user {
				t.Fatalf("status = %#v, want state=%q user=%q", status, test.state, test.user)
			}
		})
	}
}

// TestStatusParserRejectsUnixFixtureWithoutUser verifies account identity cannot silently disappear from Unix status.
// TestStatusParserRejectsUnixFixtureWithoutUser 验证 Unix 状态缺少账户身份时不会被静默接受。
func TestStatusParserRejectsUnixFixtureWithoutUser(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			output := "state=running\nauto_start=enabled\n"
			if platform == "linux" {
				output = "state=running\nsubstate=running\nauto_start=enabled\n"
			}
			if _, err := parseStatusOutputForPlatform(output, platform); !errors.Is(err, ErrInvalidStatus) {
				t.Fatalf("parseStatusOutputForPlatform error = %v, want ErrInvalidStatus", err)
			}
		})
	}
}

// TestGetStatusReadsMachineDocument verifies the status action parses values without exposing raw process output.
// TestGetStatusReadsMachineDocument 验证 status 操作解析机器状态文档且不暴露原始子进程输出。
func TestGetStatusReadsMachineDocument(t *testing.T) {
	client, _ := newFakeClient(t)
	t.Setenv(helperStatusEnvironment, validStatusFixture())
	status, err := client.GetStatus(context.Background(), "vmm")
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.State != "running" || status.AutoStart != "enabled" || (runtime.GOOS != "windows" && status.User != "vmm-service") {
		t.Fatalf("parsed status = %#v", status)
	}
}

// TestProcessErrorsDoNotRevealConfigurationOrEnvironment verifies errors omit child diagnostics, config paths, and environment secrets.
// TestProcessErrorsDoNotRevealConfigurationOrEnvironment 验证错误不会包含子进程诊断、配置路径或环境密钥。
func TestProcessErrorsDoNotRevealConfigurationOrEnvironment(t *testing.T) {
	client, _ := newFakeClient(t)
	t.Setenv(helperExitEnvironment, "17")
	secret := "test-secret-do-not-log"
	t.Setenv(helperSecretEnvironment, secret)
	configPath := filepath.Join(testpath.CanonicalTempDir(t), "private-config.yaml")
	err := client.Install(context.Background(), "vmm", configPath, "vmm-service", false)
	if err == nil {
		t.Fatal("expected fake executable to fail")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), configPath) {
		t.Fatalf("returned error exposed sensitive context: %v", err)
	}
	if !strings.Contains(err.Error(), "exit code 17") {
		t.Fatalf("error omitted the safe exit code: %v", err)
	}
}

// TestContextTimeoutAndCancellationStopTheChild verifies both adapter deadlines and caller cancellation terminate the child.
// TestContextTimeoutAndCancellationStopTheChild 验证适配器时限和调用方取消都会终止子进程。
func TestContextTimeoutAndCancellationStopTheChild(t *testing.T) {
	client, _ := newFakeClient(t)
	t.Setenv(helperSleepEnvironment, "5000")
	client.timeout = 40 * time.Millisecond
	err := client.Start(context.Background(), "vmm")
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Start timeout error = %v, want ErrTimeout", err)
	}

	client.timeout = 3 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(40 * time.Millisecond)
		cancel()
	}()
	err = client.Stop(ctx, "vmm")
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("Stop cancellation error = %v, want ErrCanceled", err)
	}
}

// TestStatusOutputLimitBoundsCapture verifies oversized status output is drained but never parsed or retained as an error string.
// TestStatusOutputLimitBoundsCapture 验证超长状态输出会被排空，但不会被解析或放入错误文本。
func TestStatusOutputLimitBoundsCapture(t *testing.T) {
	client, _ := newFakeClient(t)
	client.outputLimit = 32
	t.Setenv(helperStatusEnvironment, strings.Repeat("state=running\n", 1000))
	_, err := client.GetStatus(context.Background(), "vmm")
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("GetStatus oversized output error = %v, want ErrOutputLimit", err)
	}
}

// TestStatusErrorsDoNotEchoMalformedLines verifies malformed status payloads are replaced with a fixed safe error.
// TestStatusErrorsDoNotEchoMalformedLines 验证错误状态文本会被固定安全错误替代。
func TestStatusErrorsDoNotEchoMalformedLines(t *testing.T) {
	client, _ := newFakeClient(t)
	secretLine := "token=private-credential"
	t.Setenv(helperStatusEnvironment, secretLine+"\n")
	_, err := client.GetStatus(context.Background(), "vmm")
	if !errors.Is(err, ErrInvalidStatus) || strings.Contains(err.Error(), "private-credential") {
		t.Fatalf("unsafe malformed status error: %v", err)
	}
}

// newFakeClient prepares the current Go test executable as a fake VMM command and returns its argument log path.
// newFakeClient 将当前 Go 测试可执行文件准备为 fake VMM 命令，并返回参数日志路径。
func newFakeClient(t *testing.T) (*Client, string) {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(testpath.CanonicalTempDir(t), "arguments.json")
	t.Setenv(helperModeEnvironment, "1")
	t.Setenv(helperLogEnvironment, logPath)
	t.Setenv(helperStatusEnvironment, "")
	t.Setenv(helperExitEnvironment, "")
	t.Setenv(helperSleepEnvironment, "")
	t.Setenv(helperSecretEnvironment, "")
	client, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	client.testUnprivileged = true
	return client, logPath
}

// assertArguments decodes the fake process log and compares the exact received argument vector.
// assertArguments 解码 fake 子进程日志，并比对精确收到的参数数组。
func assertArguments(t *testing.T, logPath string, expected []string) {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake process arguments: %v", err)
	}
	var actual []string
	if err := json.Unmarshal(data, &actual); err != nil {
		t.Fatalf("decode fake process arguments: %v", err)
	}
	if len(actual) != len(expected) {
		t.Fatalf("argument count = %d, want %d: %#v", len(actual), len(expected), actual)
	}
	for index := range expected {
		if actual[index] != expected[index] {
			t.Fatalf("argument[%d] = %q, want %q; full args: %#v", index, actual[index], expected[index], actual)
		}
	}
}

// containsArgument reports whether a fixed process vector contains one token.
// containsArgument 判断固定进程参数数组是否包含指定令牌。
func containsArgument(args []string, wanted string) bool {
	for _, argument := range args {
		if argument == wanted {
			return true
		}
	}
	return false
}

// containsArgumentPair reports whether a fixed process vector contains one key followed by its value.
// containsArgumentPair 判断固定进程参数数组是否包含相邻的键和值。
func containsArgumentPair(args []string, key string, value string) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == key && args[index+1] == value {
			return true
		}
	}
	return false
}

// validStatusFixture renders one valid status document using the current platform's VMM fields.
// validStatusFixture 按当前平台 VMM 的字段约定生成一份有效状态文档。
func validStatusFixture() string {
	return validStatusFixtureForPlatform(runtime.GOOS)
}

// validStatusFixtureForPlatform returns a status fixture with the exact fields required by one platform.
// validStatusFixtureForPlatform 返回指定平台要求的精确状态字段 fixture。
func validStatusFixtureForPlatform(platform string) string {
	fields := []string{"state=running", "auto_start=enabled"}
	switch platform {
	case "windows":
		fields = append(fields, "start_type=automatic")
	case "linux":
		fields = append(fields, "substate=running", "user=vmm-service")
	case "darwin":
		fields = append(fields, "user=vmm-service")
	default:
		return ""
	}
	return strings.Join(fields, "\n") + "\n"
}

// TestFakeHelperCanBeStartedDirectly confirms the current test executable can serve as a separate child process.
// TestFakeHelperCanBeStartedDirectly 确认当前测试可执行文件可以作为独立子进程启动。
func TestFakeHelperCanBeStartedDirectly(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(testpath.CanonicalTempDir(t), "arguments.json")
	command := exec.Command(path, "service", "status", "vmm")
	command.Env = append(os.Environ(), helperModeEnvironment+"=1", helperLogEnvironment+"="+logPath)
	if err := command.Run(); err != nil {
		t.Fatalf("run fake test executable: %v", err)
	}
	assertArguments(t, logPath, []string{"service", "status", "vmm"})
}
