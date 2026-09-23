// Package configbridge tests the VMM CLI bridge with isolated fixture subprocesses.
// configbridge 包使用隔离的 fixture 子进程测试 VMM CLI 桥接层。
// The tests never launch a production VMM binary or read a user's configuration.
// 测试不会启动生产 VMM 程序，也不会读取用户配置。
package configbridge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const configBridgeHelperMode = "VMMM_CONFIGBRIDGE_HELPER_MODE"

// TestConfigBridgeHelperProcess is the fixture executable selected by test clients.
// TestConfigBridgeHelperProcess 是测试客户端选择的 fixture 子进程入口。
// It emits deterministic protocol documents and process outcomes without invoking a shell.
// 它直接输出确定性的协议文档和进程结果，不经过 shell。
func TestConfigBridgeHelperProcess(t *testing.T) {
	mode := os.Getenv(configBridgeHelperMode)
	if mode == "" {
		return
	}
	exitCode := 0
	switch mode {
	case "health-ok":
		_, _ = fmt.Fprintln(os.Stdout, `{"status":"ok","class":"ok","elapsed_ms":1}`)
	case "health-unreachable":
		_, _ = fmt.Fprintln(os.Stdout, `{"status":"error","class":"unreachable","error":"grpc_unreachable","elapsed_ms":1}`)
		exitCode = 1
	case "schema":
		_, _ = fmt.Fprintln(os.Stdout, `{"version":"v1","config_type":"Config","fields":[{"path":"storage.mode","type":"string","sensitive":false,"enum":["native","split"],"default":"native"},{"path":"embedding.api_keys","type":"array","item_type":"string","sensitive":true}]}`)
	case "schema-duplicate":
		_, _ = fmt.Fprintln(os.Stdout, `{"version":"v1","version":"v1","config_type":"Config","fields":[]}`)
	case "schema-unknown-field":
		_, _ = fmt.Fprintln(os.Stdout, `{"version":"v1","config_type":"Config","fields":[],"extra":true}`)
	case "schema-wrong-version":
		_, _ = fmt.Fprintln(os.Stdout, `{"version":"v2","config_type":"Config","fields":[]}`)
	case "validate-valid":
		_, _ = fmt.Fprintln(os.Stdout, `{"valid":true,"errors":[]}`)
	case "validate-invalid":
		_, _ = fmt.Fprintln(os.Stdout, `{"valid":false,"errors":[{"path":"storage.mode","message":"unsupported storage mode"}]}`)
		exitCode = 1
	case "validate-contradiction":
		_, _ = fmt.Fprintln(os.Stdout, `{"valid":true,"errors":[]}`)
		exitCode = 1
	case "garbage":
		_, _ = fmt.Fprintln(os.Stdout, "not-json")
	case "exit-seven":
		_, _ = fmt.Fprintln(os.Stderr, "api_key=do-not-leak-super-secret")
		exitCode = 7
	case "validate-exit-three":
		_, _ = fmt.Fprintln(os.Stdout, `{"valid":false,"errors":[{"path":"storage.mode","message":"invalid"}]}`)
		exitCode = 3
	case "oversized":
		_, _ = fmt.Fprintln(os.Stdout, strings.Repeat("x", commandOutputLimit+32))
	case "sleep":
		time.Sleep(time.Second)
	case "invalid-json-array":
		_, _ = fmt.Fprintln(os.Stdout, `{"version":"v1","config_type":"Config","fields":null}`)
	default:
		exitCode = 91
	}
	os.Exit(exitCode)
}

// TestSchemaUsesExplicitProcessAndDecodesRuntimeFields verifies schema parsing and fixed command arguments.
// TestSchemaUsesExplicitProcessAndDecodesRuntimeFields 验证 schema 解码和固定命令参数。
func TestSchemaUsesExplicitProcessAndDecodesRuntimeFields(t *testing.T) {
	client, calls := newFixtureClient(t, "schema")
	schema, err := client.Schema(context.Background())
	if err != nil {
		t.Fatalf("Schema() failed: %v", err)
	}
	if schema.Version != "v1" || schema.ConfigType != "Config" || len(schema.Fields) != 2 {
		t.Fatalf("Schema() = %#v, want v1 Config with two fields", schema)
	}
	if schema.Fields[0].Path != "storage.mode" || string(schema.Fields[0].Default) != `"native"` {
		t.Fatalf("first schema field = %#v, want storage.mode with native default", schema.Fields[0])
	}
	if !schema.Fields[1].Sensitive || schema.Fields[1].ItemType != "string" {
		t.Fatalf("second schema field = %#v, want sensitive string array", schema.Fields[1])
	}
	if len(*calls) != 1 || !reflect.DeepEqual((*calls)[0], []string{"config", "schema", "--json"}) {
		t.Fatalf("schema process arguments = %#v", *calls)
	}
}

// TestValidateReturnsBothValidAndInvalidResults verifies exit code 1 is represented as diagnostics.
// TestValidateReturnsBothValidAndInvalidResults 验证合法与不合法校验结果都按诊断结构返回。
func TestValidateReturnsBothValidAndInvalidResults(t *testing.T) {
	configRoot := filepath.Join(t.TempDir(), "custom config.yaml")
	validClient, validCalls := newFixtureClientAt(t, configRoot, "validate-valid")
	validResult, err := validClient.Validate(context.Background())
	if err != nil || !validResult.Valid || len(validResult.Errors) != 0 {
		t.Fatalf("Validate(valid) = %#v, %v", validResult, err)
	}
	if !reflect.DeepEqual((*validCalls)[0], []string{"config", "validate", "--config", configRoot, "--json"}) {
		t.Fatalf("validate process arguments = %#v", *validCalls)
	}

	invalidClient, _ := newFixtureClientAt(t, configRoot, "validate-invalid")
	invalidResult, err := invalidClient.Validate(context.Background())
	if err != nil {
		t.Fatalf("Validate(invalid) returned process error: %v", err)
	}
	if invalidResult.Valid || len(invalidResult.Errors) != 1 || invalidResult.Errors[0].Path != "storage.mode" {
		t.Fatalf("Validate(invalid) = %#v, want one storage.mode diagnostic", invalidResult)
	}
}

// TestSchemaRejectsMalformedProtocolDocuments verifies strict JSON shape and protocol revision checks.
// TestSchemaRejectsMalformedProtocolDocuments 验证严格 JSON 结构和协议版本检查。
func TestSchemaRejectsMalformedProtocolDocuments(t *testing.T) {
	tests := []struct {
		name string
		mode string
	}{
		{name: "garbage", mode: "garbage"},
		{name: "duplicate member", mode: "schema-duplicate"},
		{name: "unknown member", mode: "schema-unknown-field"},
		{name: "unsupported revision", mode: "schema-wrong-version"},
		{name: "null fields array", mode: "invalid-json-array"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			client, _ := newFixtureClient(t, testCase.mode)
			if _, err := client.Schema(context.Background()); !errors.Is(err, ErrProtocol) {
				t.Fatalf("Schema() error = %v, want ErrProtocol", err)
			}
		})
	}
}

// TestCommandsRejectUnexpectedExitAndSuppressChildStderr verifies exit errors never expose child output.
// TestCommandsRejectUnexpectedExitAndSuppressChildStderr 验证异常退出不会暴露子进程 stderr。
func TestCommandsRejectUnexpectedExitAndSuppressChildStderr(t *testing.T) {
	client, _ := newFixtureClient(t, "exit-seven")
	if _, err := client.Schema(context.Background()); err == nil || !strings.Contains(err.Error(), "code 7") {
		t.Fatalf("Schema() error = %v, want explicit exit-code error", err)
	} else if strings.Contains(err.Error(), "do-not-leak-super-secret") {
		t.Fatalf("Schema() leaked subprocess stderr: %v", err)
	}

	validateClient, _ := newFixtureClient(t, "validate-exit-three")
	if _, err := validateClient.Validate(context.Background()); err == nil || !strings.Contains(err.Error(), "code 3") {
		t.Fatalf("Validate() error = %v, want explicit unexpected exit-code error", err)
	}
}

// TestCommandsEnforceTimeoutAndOutputLimits protects process and memory bounds.
// TestCommandsEnforceTimeoutAndOutputLimits 保护子进程时限和输出内存上限。
func TestCommandsEnforceTimeoutAndOutputLimits(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		client, _ := newFixtureClient(t, "sleep")
		client.timeout = 25 * time.Millisecond
		if _, err := client.Schema(context.Background()); !errors.Is(err, ErrCommandTimeout) {
			t.Fatalf("Schema() error = %v, want ErrCommandTimeout", err)
		}
	})

	t.Run("output limit", func(t *testing.T) {
		client, _ := newFixtureClient(t, "oversized")
		client.outputLimit = 64
		if _, err := client.Schema(context.Background()); !errors.Is(err, ErrOutputLimit) {
			t.Fatalf("Schema() error = %v, want ErrOutputLimit", err)
		}
	})
}

// TestValidateRejectsExitAndResultContradictions prevents callers from accepting inconsistent CLI output.
// TestValidateRejectsExitAndResultContradictions 防止调用方接受退出码与 JSON 结果相互矛盾的响应。
func TestValidateRejectsExitAndResultContradictions(t *testing.T) {
	client, _ := newFixtureClient(t, "validate-contradiction")
	if _, err := client.Validate(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Validate() error = %v, want ErrProtocol", err)
	}
}

// newFixtureClient constructs a client whose executable is this test binary.
// newFixtureClient 创建一个将当前测试程序作为可执行文件的客户端。
func newFixtureClient(t *testing.T, mode string) (*Client, *[][]string) {
	t.Helper()
	return newFixtureClientAt(t, t.TempDir(), mode)
}

// newFixtureClientAt injects one deterministic test process and records its received argument vector.
// newFixtureClientAt 注入一个确定性测试进程，并记录其接收的参数数组。
func newFixtureClientAt(t *testing.T, configRoot string, mode string) (*Client, *[][]string) {
	t.Helper()
	binaryPath, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	client, err := New(binaryPath, configRoot)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	calls := make([][]string, 0, 1)
	client.commandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calls = append(calls, append([]string(nil), args...))
		command := exec.CommandContext(ctx, name, "-test.run=^TestConfigBridgeHelperProcess$")
		command.Env = []string{configBridgeHelperMode + "=" + mode}
		return command
	}
	return client, &calls
}
