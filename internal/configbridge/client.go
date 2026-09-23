// Package configbridge delegates configuration inspection to the installed VMM executable.
// configbridge 包通过已安装的 VMM 可执行文件执行权威配置检查。
// It belongs to the manager's runtime integration layer and never edits configuration files.
// 它属于管理器运行时集成层，且不会直接读写或修改配置文件。
package configbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// schemaProtocolVersion is the only schema document revision understood by this bridge.
	// schemaProtocolVersion 是本桥接层当前支持的唯一配置 schema 文档版本。
	schemaProtocolVersion = "v1"

	// schemaConfigType is the runtime configuration type exposed by the VMM CLI.
	// schemaConfigType 是 VMM CLI 暴露的运行时配置类型名称。
	schemaConfigType = "Config"

	// commandTimeout bounds each CLI process independently of the caller's context.
	// commandTimeout 为每个 CLI 子进程设置独立上限，同时仍遵守调用方更短的截止时间。
	commandTimeout = 30 * time.Second

	// commandOutputLimit bounds captured stdout and stderr separately.
	// commandOutputLimit 分别限制 stdout 与 stderr 的捕获大小，避免异常进程耗尽管理器内存。
	commandOutputLimit = 1 << 20
)

var (
	// ErrCommandTimeout identifies a VMM CLI process that exceeded its execution deadline.
	// ErrCommandTimeout 表示 VMM CLI 子进程超过了执行时限。
	ErrCommandTimeout = errors.New("VMM config command timed out")

	// ErrOutputLimit identifies output that exceeded the configured capture bound.
	// ErrOutputLimit 表示子进程输出超过了允许捕获的大小。
	ErrOutputLimit = errors.New("VMM config command output exceeded the limit")

	// ErrProtocol identifies malformed or unsupported machine-readable CLI responses.
	// ErrProtocol 表示 CLI 返回了格式错误或版本不受支持的机器可读响应。
	ErrProtocol = errors.New("VMM config command returned an invalid protocol response")
)

// Client invokes only the caller-selected VMM binary and configuration root.
// Client 只调用调用方明确指定的 VMM 可执行文件和配置根路径。
// Its command factory is private so production callers cannot bypass the fixed argument contract.
// 子进程工厂保持私有，避免生产调用方绕过固定的命令参数契约。
type Client struct {
	// binaryPath is the absolute path to the installed VMM executable.
	// binaryPath 是已安装 VMM 可执行文件的绝对路径。
	binaryPath string

	// configRoot is the absolute directory or YAML file passed to VMM validation.
	// configRoot 是传给 VMM 校验命令的绝对目录或 YAML 文件路径。
	configRoot string

	// timeout and outputLimit are copied from fixed defaults and narrowed only in package tests.
	// timeout 与 outputLimit 使用固定默认值，仅允许包内测试缩短边界。
	timeout     time.Duration
	outputLimit int

	// commandContext injects fixture processes in tests while production uses exec.CommandContext.
	// commandContext 用于测试注入 fixture 子进程，生产环境固定使用 exec.CommandContext。
	commandContext func(context.Context, string, ...string) *exec.Cmd
}

// Schema is the versioned, authoritative field inventory emitted by `vmm-local config schema --json`.
// Schema 是 `vmm-local config schema --json` 输出的带版本权威字段清单。
type Schema struct {
	// Version identifies the schema wire protocol.
	// Version 标识 schema 线协议版本。
	Version string `json:"version"`

	// ConfigType names the Go configuration root represented by the schema.
	// ConfigType 表示 schema 对应的 Go 配置根类型名称。
	ConfigType string `json:"config_type"`

	// Fields contains the complete runtime configuration field inventory.
	// Fields 包含运行时配置的完整字段清单。
	Fields []Field `json:"fields"`
}

// Field describes one configuration field without interpreting or rewriting its value.
// Field 描述一个配置字段，本桥接层不会解释或改写其配置值。
type Field struct {
	// Path is the stable dotted path emitted by the runtime schema.
	// Path 是运行时 schema 输出的稳定点分字段路径。
	Path string `json:"path"`

	// Type names the field's scalar or collection shape.
	// Type 表示字段的标量或集合形状。
	Type string `json:"type"`

	// ItemType names the element shape for arrays when present.
	// ItemType 在存在时表示数组元素形状。
	ItemType string `json:"item_type,omitempty"`

	// KeyType names the key shape for maps when present.
	// KeyType 在存在时表示 map 键形状。
	KeyType string `json:"key_type,omitempty"`

	// ValueType names the value shape for maps when present.
	// ValueType 在存在时表示 map 值形状。
	ValueType string `json:"value_type,omitempty"`

	// Nullable reports whether the runtime field accepts a null value.
	// Nullable 表示运行时字段是否接受 null 值。
	Nullable bool `json:"nullable,omitempty"`

	// Sensitive marks fields whose values must be treated as credentials or private data.
	// Sensitive 标记必须按凭据或私密数据处理的字段。
	Sensitive bool `json:"sensitive"`

	// Enum lists the values enforced by the runtime when this field has a constrained choice.
	// Enum 列出运行时对受限选择字段所强制的可选值。
	Enum []string `json:"enum,omitempty"`

	// Default preserves the runtime's JSON-safe default without converting its JSON type.
	// Default 保留运行时的 JSON 安全默认值，不转换其 JSON 类型。
	Default json.RawMessage `json:"default,omitempty"`
}

// ValidationResult is the stable JSON result returned by the VMM validation command.
// ValidationResult 是 VMM 配置校验命令返回的稳定 JSON 结果。
type ValidationResult struct {
	// Valid is true only when the runtime loader accepted the selected configuration root.
	// Valid 仅当运行时加载器接受指定配置根时为 true。
	Valid bool `json:"valid"`

	// Errors contains redacted diagnostics emitted by the runtime loader.
	// Errors 包含运行时加载器输出的脱敏诊断。
	Errors []ValidationError `json:"errors"`
}

// ValidationError contains one runtime diagnostic and its schema-confirmed field path when available.
// ValidationError 包含一条运行时诊断，以及可用时由 schema 确认的字段路径。
type ValidationError struct {
	// Path is empty when the runtime cannot attribute the issue to a known field.
	// 当运行时无法将问题归属到已知字段时，Path 为空。
	Path string `json:"path"`

	// Message is the runtime's redacted, user-displayable diagnostic.
	// Message 是运行时脱敏后可供用户查看的诊断文本。
	Message string `json:"message"`
}

// New creates a bridge bound to explicit absolute paths and the production exec.CommandContext runner.
// New 创建绑定到显式绝对路径并使用生产 exec.CommandContext 执行器的桥接客户端。
// binaryPath must name the installed VMM executable; configRoot must name a directory or YAML file.
// binaryPath 必须指向已安装的 VMM 可执行文件；configRoot 必须指向目录或 YAML 文件。
func New(binaryPath string, configRoot string) (*Client, error) {
	if err := validateAbsoluteArgument("VMM binary path", binaryPath); err != nil {
		return nil, err
	}
	if err := validateAbsoluteArgument("configuration root", configRoot); err != nil {
		return nil, err
	}
	return &Client{
		binaryPath:  binaryPath,
		configRoot:  configRoot,
		timeout:     commandTimeout,
		outputLimit: commandOutputLimit,
		commandContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, name, args...)
		},
	}, nil
}

// Schema retrieves and strictly decodes the authoritative configuration schema.
// Schema 获取并严格解码权威配置 schema。
// The VMM process runs with a fixed argument vector and no shell or implicit binary lookup.
// VMM 子进程使用固定参数数组执行，不经过 shell，也不进行隐式 PATH 查找。
func (c *Client) Schema(ctx context.Context) (Schema, error) {
	output, exitCode, err := c.run(ctx, "schema", "config", "schema", "--json")
	if err != nil {
		return Schema{}, err
	}
	if exitCode != 0 {
		return Schema{}, fmt.Errorf("VMM config schema command exited with code %d", exitCode)
	}

	var schema Schema
	if err := decodeStrictDocument(output, &schema, map[string]bool{
		"version": true, "config_type": true, "fields": true,
	}); err != nil {
		return Schema{}, protocolError("schema", err)
	}
	if schema.Version != schemaProtocolVersion {
		return Schema{}, protocolError("schema", fmt.Errorf("unsupported version %q", schema.Version))
	}
	if schema.ConfigType != schemaConfigType {
		return Schema{}, protocolError("schema", fmt.Errorf("unsupported config type %q", schema.ConfigType))
	}
	if err := validateSchemaFields(schema.Fields); err != nil {
		return Schema{}, protocolError("schema", err)
	}
	return schema, nil
}

// Validate asks the VMM runtime loader to validate the explicitly selected configuration root.
// Validate 调用 VMM 运行时加载器校验显式指定的配置根。
// Exit code 1 with a valid invalid-result document is returned as diagnostics, not as a process error.
// 退出码 1 且返回合法的无效结果文档时，会作为诊断返回，而不是进程错误。
func (c *Client) Validate(ctx context.Context) (ValidationResult, error) {
	output, exitCode, err := c.run(ctx, "validate", "config", "validate", "--config", c.configRoot, "--json")
	if err != nil {
		return ValidationResult{}, err
	}
	if exitCode != 0 && exitCode != 1 {
		return ValidationResult{}, fmt.Errorf("VMM config validate command exited with code %d", exitCode)
	}

	var result ValidationResult
	if err := decodeStrictDocument(output, &result, map[string]bool{
		"valid": true, "errors": true,
	}); err != nil {
		return ValidationResult{}, protocolError("validate", err)
	}
	if result.Errors == nil {
		return ValidationResult{}, protocolError("validate", errors.New("errors must be a JSON array"))
	}
	for index, item := range result.Errors {
		if strings.TrimSpace(item.Message) == "" {
			return ValidationResult{}, protocolError("validate", fmt.Errorf("errors[%d].message must not be empty", index))
		}
	}
	if exitCode == 0 {
		if !result.Valid || len(result.Errors) != 0 {
			return ValidationResult{}, protocolError("validate", errors.New("exit code 0 conflicts with validation result"))
		}
		return result, nil
	}
	if result.Valid || len(result.Errors) == 0 {
		return ValidationResult{}, protocolError("validate", errors.New("exit code 1 requires invalid result diagnostics"))
	}
	return result, nil
}

// run launches one fixed VMM config command with bounded runtime and output capture.
// run 在固定时限和输出上限内启动一条固定的 VMM 配置命令。
// Stderr is intentionally discarded after bounded capture so child output cannot leak credentials into manager errors.
// stderr 仅作有界捕获后丢弃，避免子进程输出中的凭据进入管理器错误信息。
func (c *Client) run(ctx context.Context, operation string, args ...string) ([]byte, int, error) {
	if c == nil || c.commandContext == nil || c.binaryPath == "" || c.configRoot == "" {
		return nil, -1, errors.New("VMM config bridge is not initialized")
	}
	if ctx == nil {
		return nil, -1, errors.New("VMM config command context is nil")
	}
	if c.timeout <= 0 || c.outputLimit <= 0 {
		return nil, -1, errors.New("VMM config bridge limits are invalid")
	}
	commandCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	command := c.commandContext(commandCtx, c.binaryPath, args...)
	if command == nil {
		return nil, -1, errors.New("VMM config command factory returned no process")
	}
	stdout := &boundedBuffer{limit: c.outputLimit}
	stderr := &boundedBuffer{limit: c.outputLimit}
	command.Stdout = stdout
	command.Stderr = stderr

	// Keep stderr out of returned errors; it is untrusted process output and may contain sensitive values.
	// 不把 stderr 放入返回错误；它属于不可信进程输出，可能包含敏感值。
	runErr := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return nil, -1, ErrOutputLimit
	}
	if runErr == nil {
		return stdout.Bytes(), 0, nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, -1, errors.New("VMM config command caller deadline exceeded")
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return nil, -1, errors.New("VMM config command canceled by caller")
	}
	if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
		return nil, -1, fmt.Errorf("VMM config %s command: %w", operation, ErrCommandTimeout)
	}
	if errors.Is(commandCtx.Err(), context.Canceled) {
		return nil, -1, fmt.Errorf("VMM config %s command canceled", operation)
	}
	var exitError *exec.ExitError
	if errors.As(runErr, &exitError) {
		return stdout.Bytes(), exitError.ExitCode(), nil
	}
	// Do not expose raw exec errors because platform messages may contain environment or command details.
	// 不暴露原始 exec 错误，因为平台错误文本可能包含环境或命令细节。
	return nil, -1, fmt.Errorf("VMM config %s command could not start", operation)
}

// validateSchemaFields rejects structurally incomplete, duplicated, or privacy-unsafe schema entries.
// validateSchemaFields 拒绝结构不完整、路径重复或违反敏感字段保护规则的 schema 项。
func validateSchemaFields(fields []Field) error {
	if fields == nil {
		return errors.New("fields must be a JSON array")
	}
	if len(fields) == 0 {
		return errors.New("fields must not be empty")
	}
	seen := make(map[string]struct{}, len(fields))
	for index, field := range fields {
		if strings.TrimSpace(field.Path) == "" || strings.TrimSpace(field.Path) != field.Path {
			return fmt.Errorf("fields[%d].path must be non-empty and trimmed", index)
		}
		if _, exists := seen[field.Path]; exists {
			return fmt.Errorf("fields[%d].path duplicates another field", index)
		}
		seen[field.Path] = struct{}{}
		if !isSchemaType(field.Type) {
			return fmt.Errorf("fields[%d].type is unsupported", index)
		}
		if field.Sensitive && len(field.Default) > 0 {
			return fmt.Errorf("fields[%d] exposes a default for a sensitive field", index)
		}
		if len(field.Default) > 0 && !json.Valid(field.Default) {
			return fmt.Errorf("fields[%d].default is invalid JSON", index)
		}
	}
	return nil
}

// isSchemaType recognizes the field shapes defined by the v1 runtime schema contract.
// isSchemaType 识别 v1 运行时 schema 契约定义的字段形状。
func isSchemaType(value string) bool {
	switch value {
	case "array", "any", "boolean", "duration", "integer", "map", "number", "object", "string", "unknown":
		return true
	default:
		return false
	}
}

// decodeStrictDocument checks duplicate keys, exact object shape, required members, and Go field types.
// decodeStrictDocument 检查重复键、对象精确结构、必需成员和 Go 字段类型。
func decodeStrictDocument(data []byte, destination any, required map[string]bool) error {
	if len(data) == 0 {
		return errors.New("response is empty")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return err
	}
	if members == nil {
		return errors.New("response must be a JSON object")
	}
	for name := range members {
		if _, known := required[name]; !known {
			return fmt.Errorf("unexpected field %q", name)
		}
	}
	for name := range required {
		if _, present := members[name]; !present {
			return fmt.Errorf("required field %q is missing", name)
		}
	}
	for name, raw := range members {
		if isJSONNull(raw) {
			return fmt.Errorf("field %q must not be null", name)
		}
	}
	if err := requireObjectArray(members, destination); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("response contains trailing JSON")
		}
		return err
	}
	return nil
}

// requireObjectArray verifies that collection-valued root members are arrays rather than null.
// requireObjectArray 确认根对象中的集合成员是数组，而不是 null。
func requireObjectArray(root map[string]json.RawMessage, destination any) error {
	switch destination.(type) {
	case *EffectiveConfig:
		var config map[string]json.RawMessage
		if err := json.Unmarshal(root["config"], &config); err != nil || len(config) == 0 {
			return errors.New("config must be a nonempty JSON object")
		}
	case *Schema:
		if !isJSONArray(root["fields"]) {
			return errors.New("fields must be a JSON array")
		}
		var fieldObjects []json.RawMessage
		if err := json.Unmarshal(root["fields"], &fieldObjects); err != nil {
			return err
		}
		for index, raw := range fieldObjects {
			if err := validateObjectKeys(raw, map[string]bool{
				"path": true, "type": true, "item_type": false, "key_type": false,
				"value_type": false, "nullable": false, "sensitive": true,
				"enum": false, "default": false,
			}, fmt.Sprintf("fields[%d]", index)); err != nil {
				return err
			}
		}
	case *ValidationResult:
		if !isJSONArray(root["errors"]) {
			return errors.New("errors must be a JSON array")
		}
		var errorObjects []json.RawMessage
		if err := json.Unmarshal(root["errors"], &errorObjects); err != nil {
			return err
		}
		for index, raw := range errorObjects {
			if err := validateObjectKeys(raw, map[string]bool{"path": true, "message": true}, fmt.Sprintf("errors[%d]", index)); err != nil {
				return err
			}
		}
	default:
		return errors.New("unsupported response type")
	}
	return nil
}

// validateObjectKeys enforces the allowed and required members of one nested JSON object.
// validateObjectKeys 强制检查嵌套 JSON 对象允许和必需的成员。
func validateObjectKeys(data []byte, allowed map[string]bool, label string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return fmt.Errorf("%s must be an object: %w", label, err)
	}
	if object == nil {
		return fmt.Errorf("%s must be an object", label)
	}
	for name := range object {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("%s has unexpected field %q", label, name)
		}
		if name != "default" && isJSONNull(object[name]) {
			return fmt.Errorf("%s.%s must not be null", label, name)
		}
	}
	for name, required := range allowed {
		if required {
			if _, ok := object[name]; !ok {
				return fmt.Errorf("%s is missing required field %q", label, name)
			}
		}
	}
	return nil
}

// isJSONArray reports whether a raw JSON value starts with an array delimiter after whitespace.
// isJSONArray 判断去除前导空白后的原始 JSON 值是否以数组分隔符开头。
func isJSONArray(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '['
}

// isJSONNull recognizes a JSON null value without interpreting the surrounding document.
// isJSONNull 在不解释外围文档的情况下识别 JSON null 值。
func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// rejectDuplicateKeys walks a JSON document before typed decoding so duplicate keys cannot be silently overwritten.
// rejectDuplicateKeys 在类型解码前遍历 JSON 文档，避免重复键被静默覆盖。
func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("response contains trailing JSON")
		}
		return err
	}
	return nil
}

// scanJSONValue recursively detects duplicate object keys while validating token boundaries.
// scanJSONValue 递归检测对象重复键，并验证 JSON token 边界。
func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object member name is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object member %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

// protocolError wraps an untrusted response failure without including its raw document.
// protocolError 包装不可信响应错误，但不包含原始响应文档。
func protocolError(operation string, _ error) error {
	// The detailed parse cause may contain attacker-controlled JSON member names, so expose only the protocol category.
	// 详细解析原因可能包含攻击者控制的 JSON 成员名，因此只向外暴露协议错误类别。
	return fmt.Errorf("VMM config %s command: %w", operation, ErrProtocol)
}

// validateAbsoluteArgument requires a caller-selected, trimmed absolute filesystem path.
// validateAbsoluteArgument 要求调用方提供去除首尾空白的绝对文件系统路径。
func validateAbsoluteArgument(label string, value string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must be explicitly provided without surrounding whitespace", label)
	}
	if !filepath.IsAbs(value) {
		return fmt.Errorf("%s must be an absolute path", label)
	}
	return nil
}

// boundedBuffer captures only the first limit bytes and drains the rest to avoid blocking the child process.
// boundedBuffer 只捕获前 limit 字节，并继续排空剩余输出，避免子进程因管道阻塞。
type boundedBuffer struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

// Write captures a bounded prefix and reports full consumption while marking overflow.
// Write 捕获有界前缀，并在标记溢出的同时报告已消费全部输入。
func (b *boundedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			_, _ = b.buffer.Write(data[:remaining])
			b.exceeded = true
		} else {
			_, _ = b.buffer.Write(data)
		}
	} else if len(data) > 0 {
		b.exceeded = true
	}
	return len(data), nil
}

// Bytes returns a defensive copy of the captured output prefix.
// Bytes 返回已捕获输出前缀的防御性副本。
func (b *boundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buffer.Bytes()...)
}
