// Package state persists the manager's versioned installation registration.
// state 包负责持久化管理器的版本化安装登记信息。
package state

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const (
	// ProtocolVersion is the only registration format currently understood by this package.
	// ProtocolVersion 是本包当前唯一支持的安装登记协议版本。
	ProtocolVersion = 1

	// maxStateBytes bounds parsing work before JSON decoding starts.
	// maxStateBytes 限制 JSON 解码开始前允许读取的最大状态文件大小。
	maxStateBytes int64 = 4 << 20
)

// State is the complete non-secret installation registration written by the manager.
// State 是管理器写入的完整非敏感安装登记信息。
//
// The schema deliberately has no API-key, password, or DSN field.
// 该协议刻意不包含 API Key、密码或 DSN 字段。
type State struct {
	// InstallationComplete is set only after all requested installation actions succeed; absence means repair is required.
	// InstallationComplete 仅在全部请求的安装步骤成功后设置；缺少标记时需要重新安装确认完整性。
	InstallationComplete bool `json:"installation_complete"`
	// ConfigValidatedAt records the last successful authoritative check, independently from installation or runtime status.
	// ConfigValidatedAt 记录最近一次权威配置检查通过时间，与安装完成及运行状态相互独立；旧登记可省略。
	ConfigValidatedAt string `json:"config_validated_at,omitempty"`
	// ProtocolVersion identifies the persisted JSON protocol.
	// ProtocolVersion 标识持久化 JSON 协议版本。
	ProtocolVersion int `json:"protocol_version"`

	// ManagerVersion records the standalone manager version that wrote the state.
	// ManagerVersion 记录写入该状态的独立管理器版本。
	ManagerVersion string `json:"manager_version"`

	// VMM records the installed Vulcan Memory Mesh identity and platform.
	// VMM 记录已安装 Vulcan Memory Mesh 的身份信息和平台。
	VMM VMMIdentity `json:"vmm"`

	// Paths records caller-selected installation roots.
	// Paths 记录调用方明确选择的安装根目录。
	Paths InstallPaths `json:"paths"`

	// DownloadSource records only source identity and an optional proxy prefix.
	// DownloadSource 只记录下载源身份和可选代理前缀。
	DownloadSource DownloadSource `json:"download_source"`

	// Service records the optional service registration.
	// Service 记录可选的系统服务注册状态。
	Service ServiceState `json:"service"`

	// PATH records ownership of entries changed by the manager.
	// PATH 记录管理器修改过的 PATH 条目的所有权。
	PATH PATHState `json:"path"`

	// ManagedFiles lists installed files relative to Paths.ProgramRoot.
	// ManagedFiles 列出相对于 Paths.ProgramRoot 的已安装受管文件。
	ManagedFiles []ManagedFile `json:"managed_files"`
}

// VMMIdentity records the exact runtime release selected by the installer.
// VMMIdentity 记录安装器选择的运行时版本。
type VMMIdentity struct {
	// Tag is the release tag used for the download.
	// Tag 是下载所使用的 Release 标签。
	Tag string `json:"tag"`

	// Commit is the immutable source commit associated with the release.
	// Commit 是该 Release 对应的不可变源代码提交。
	Commit string `json:"commit"`

	// Platform identifies the installed operating-system and architecture pair.
	// Platform 标识已安装的操作系统和架构组合。
	Platform string `json:"platform"`
}

// InstallPaths records explicit program, configuration, and data roots.
// InstallPaths 记录明确指定的程序、配置和数据根目录。
type InstallPaths struct {
	// ProgramRoot is the directory containing the installed executable and assets.
	// ProgramRoot 是包含可执行文件和资源的程序目录。
	ProgramRoot string `json:"program_root"`

	// ConfigRoot is the directory containing the user's configuration files.
	// ConfigRoot 是包含用户配置文件的配置目录。
	ConfigRoot string `json:"config_root"`

	// DataRoot contains VMM runtime data; manager registration lives in its separate control state root.
	// DataRoot 保存 VMM 运行时数据；管理器登记位于独立的控制状态根目录。
	DataRoot string `json:"data_root"`
}

// DownloadSource records a stable source identifier and an optional custom HTTPS prefix.
// DownloadSource 记录稳定的下载源标识和可选的自定义 HTTPS 前缀。
type DownloadSource struct {
	// ID is the source identifier shown and persisted by the manager.
	// ID 是管理器展示并持久化的下载源标识。
	ID string `json:"id"`

	// CustomPrefix is a credential-free HTTPS GitHub proxy prefix when one was selected.
	// CustomPrefix 是用户选择的无凭据 HTTPS GitHub 代理前缀。
	CustomPrefix string `json:"custom_prefix"`
}

// ServiceState records service name, selected local account, and automatic-start policy without secrets.
// ServiceState 记录服务名、选定的本机账户和自动启动策略，不包含敏感信息。
type ServiceState struct {
	// Name is empty when the runtime is not registered as a service.
	// Name 为空时表示运行时没有注册为系统服务。
	Name string `json:"name"`

	// User is the explicitly selected Unix account; empty preserves legacy and Windows records.
	// User 是明确选择的 Unix 账户；空值用于兼容旧登记和 Windows 登记。
	User string `json:"user,omitempty"`

	// AutoStart indicates whether the service is configured to start automatically.
	// AutoStart 表示服务是否配置为自动启动。
	AutoStart bool `json:"auto_start"`
}

// PATHOwner identifies who owns the recorded PATH entries.
// PATHOwner 标识登记 PATH 条目的所有者。
type PATHOwner string

const (
	// PATHOwnerNone means that the manager did not change PATH.
	// PATHOwnerNone 表示管理器没有修改 PATH。
	PATHOwnerNone PATHOwner = "none"

	// PATHOwnerManager means that the manager may remove the recorded entries.
	// PATHOwnerManager 表示管理器可以移除登记的 PATH 条目。
	PATHOwnerManager PATHOwner = "manager"

	// PATHOwnerExternal means that the entry is observed but must not be removed automatically.
	// PATHOwnerExternal 表示条目虽被观察到，但管理器不得自动移除。
	PATHOwnerExternal PATHOwner = "external"
)

// PATHScope identifies the environment in which PATH entries were changed.
// PATHScope 标识 PATH 条目被修改的环境范围。
type PATHScope string

const (
	// PATHScopeNone means no PATH modification is recorded.
	// PATHScopeNone 表示没有登记 PATH 修改。
	PATHScopeNone PATHScope = "none"

	// PATHScopeUser means the current user's PATH was changed.
	// PATHScopeUser 表示修改了当前用户的 PATH。
	PATHScopeUser PATHScope = "user"

	// PATHScopeSystem means the machine-wide PATH was changed.
	// PATHScopeSystem 表示修改了全局系统 PATH。
	PATHScopeSystem PATHScope = "system"
)

// PATHState records ownership and exact paths affected by the manager.
// PATHState 记录管理器影响的 PATH 条目及其所有权。
type PATHState struct {
	// Owner determines whether the manager owns the recorded entries.
	// Owner 决定登记条目是否归管理器所有。
	Owner PATHOwner `json:"owner"`

	// Scope identifies user-level or system-level PATH storage.
	// Scope 标识用户级或系统级 PATH 存储范围。
	Scope PATHScope `json:"scope"`

	// Entries contains absolute directories, never credentials or command arguments.
	// Entries 包含绝对目录，不包含凭据或命令参数。
	Entries []string `json:"entries"`
}

// ManagedFile records one installed file and its content summary.
// ManagedFile 记录一个已安装文件及其内容摘要。
type ManagedFile struct {
	// Path is a forward-slash relative path below Paths.ProgramRoot.
	// Path 是位于 Paths.ProgramRoot 下的正斜杠相对路径。
	Path string `json:"path"`

	// SHA256 is the lowercase hexadecimal SHA-256 digest of the file content.
	// SHA256 是文件内容的小写十六进制 SHA-256 摘要。
	SHA256 string `json:"sha256"`

	// Size is the file size in bytes.
	// Size 是文件大小，单位为字节。
	Size int64 `json:"size"`
}

// Validate checks the protocol version, required metadata, paths, and file summaries.
// Validate 检查协议版本、必需元数据、路径和文件摘要。
func (s State) Validate() error {
	if s.ConfigValidatedAt != "" {
		checked, err := time.Parse(time.RFC3339Nano, s.ConfigValidatedAt)
		if err != nil || checked.IsZero() {
			return errors.New("config validation time is invalid")
		}
	}
	if s.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("unsupported state protocol version %d", s.ProtocolVersion)
	}
	if err := validateRequiredText("manager_version", s.ManagerVersion); err != nil {
		return err
	}
	if err := validateRequiredText("vmm.tag", s.VMM.Tag); err != nil {
		return err
	}
	if err := validateRequiredText("vmm.commit", s.VMM.Commit); err != nil {
		return err
	}
	if err := validateRequiredText("vmm.platform", s.VMM.Platform); err != nil {
		return err
	}
	if err := validateAbsolutePath("paths.program_root", s.Paths.ProgramRoot); err != nil {
		return err
	}
	if err := validateAbsolutePath("paths.config_root", s.Paths.ConfigRoot); err != nil {
		return err
	}
	if err := validateAbsolutePath("paths.data_root", s.Paths.DataRoot); err != nil {
		return err
	}
	if err := validateDownloadSource(s.DownloadSource); err != nil {
		return err
	}
	if err := validateService(s.Service); err != nil {
		return err
	}
	if err := validatePATH(s.PATH); err != nil {
		return err
	}
	if s.ManagedFiles == nil {
		return errors.New("managed_files must be an array")
	}
	seen := make(map[string]struct{}, len(s.ManagedFiles))
	for index, file := range s.ManagedFiles {
		if err := file.validate(index); err != nil {
			return err
		}
		key := strings.ToLower(file.Path)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("managed_files[%d].path duplicates another path", index)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// Load reads and strictly validates a registration file at the caller-supplied path.
// Load 从调用方提供的路径读取并严格校验安装登记文件。
func Load(filePath string) (State, error) {
	if err := validateStateFilePath(filePath); err != nil {
		return State{}, fmt.Errorf("load state: %w", err)
	}
	file, err := os.Open(filePath)
	if err != nil {
		return State{}, fmt.Errorf("open state file: %w", err)
	}
	defer file.Close()

	data, err := readBounded(file)
	if err != nil {
		return State{}, fmt.Errorf("read state file: %w", err)
	}
	state, err := decodeStrict(data)
	if err != nil {
		return State{}, fmt.Errorf("decode state file: %w", err)
	}
	if err := state.Validate(); err != nil {
		return State{}, fmt.Errorf("validate state file: %w", err)
	}
	return state, nil
}

// Save validates and atomically persists a registration file at the caller-supplied path.
// Save 校验并以原子方式持久化调用方提供路径下的安装登记文件。
func Save(filePath string, state State) error {
	return saveWithReplace(filePath, state, atomicReplace)
}

// saveWithReplace keeps replacement injectable for deterministic failure-recovery tests.
// saveWithReplace 保留可注入的替换函数，以便确定性测试失败恢复逻辑。
func saveWithReplace(filePath string, state State, replace func(string, string) error) error {
	if err := validateStateFilePath(filePath); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	if replace == nil {
		return errors.New("save state: replacement function is nil")
	}

	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	payload = append(payload, '\n')

	directory := filepath.Dir(filePath)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(filePath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create state temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()

	// The temporary file is created beside the destination so replacement stays on one volume.
	// 临时文件与目标文件位于同一目录，确保替换发生在同一卷上。
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set state temporary permissions: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write state temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync state temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close state temporary file: %w", err)
	}

	// atomicReplace preserves the old destination when the platform replacement fails.
	// atomicReplace 在平台替换失败时保留旧目标文件。
	if err := replace(temporaryPath, filePath); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	removeTemporary = false
	return nil
}

// readBounded reads at most maxStateBytes plus one byte to enforce a hard file limit.
// readBounded 最多读取 maxStateBytes 加一个字节，以执行严格文件大小限制。
func readBounded(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxStateBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxStateBytes {
		return nil, fmt.Errorf("state file exceeds %d bytes", maxStateBytes)
	}
	return data, nil
}

// decodeStrict rejects duplicate keys, unknown fields, and trailing JSON values.
// decodeStrict 拒绝重复键、未知字段和尾随 JSON 值。
func decodeStrict(data []byte) (State, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return State{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return State{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return State{}, errors.New("state file contains multiple JSON values")
		}
		return State{}, fmt.Errorf("trailing JSON is invalid: %w", err)
	}
	return state, nil
}

// rejectDuplicateKeys walks every JSON object before struct decoding.
// rejectDuplicateKeys 在结构体解码前遍历每个 JSON 对象并拒绝重复键。
func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSON(decoder, "$", 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("JSON contains multiple top-level values")
		}
		return fmt.Errorf("JSON after top-level value is invalid: %w", err)
	}
	return nil
}

// walkJSON recursively consumes one JSON value and tracks object keys.
// walkJSON 递归消费一个 JSON 值并跟踪对象键。
func walkJSON(decoder *json.Decoder, location string, depth int) error {
	if depth > 128 {
		return errors.New("JSON nesting exceeds 128 levels")
	}
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
				return fmt.Errorf("JSON object key at %s is not a string", location)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q at %s", key, location)
			}
			seen[key] = struct{}{}
			if err := walkJSON(decoder, location+"."+key, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("JSON object at %s is not closed", location)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := walkJSON(decoder, fmt.Sprintf("%s[%d]", location, index), depth+1); err != nil {
				return err
			}
			index++
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("JSON array at %s is not closed", location)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, location)
	}
	return nil
}

// validateStateFilePath validates the explicit registration file path.
// validateStateFilePath 校验调用方明确提供的安装登记文件路径。
func validateStateFilePath(filePath string) error {
	if err := validateAbsolutePath("state_file", filePath); err != nil {
		return err
	}
	if filepath.Base(filepath.Clean(filePath)) == "." {
		return errors.New("state_file must name a file")
	}
	return nil
}

// validateRequiredText rejects empty, trimmed, or control-containing metadata.
// validateRequiredText 拒绝空值、首尾空白和包含控制字符的元数据。
func validateRequiredText(field string, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not contain surrounding whitespace", field)
	}
	if containsControl(value) {
		return fmt.Errorf("%s contains a control character", field)
	}
	return nil
}

// validateAbsolutePath accepts only explicit absolute paths without control characters.
// validateAbsolutePath 只接受调用方明确提供且不含控制字符的绝对路径。
func validateAbsolutePath(field string, value string) error {
	if err := validateRequiredText(field, value); err != nil {
		return err
	}
	if !filepath.IsAbs(value) {
		return fmt.Errorf("%s must be absolute", field)
	}
	if filepath.Clean(value) == "." {
		return fmt.Errorf("%s is not a usable path", field)
	}
	return nil
}

// validateDownloadSource rejects credential-bearing or ambiguous proxy prefixes.
// validateDownloadSource 拒绝携带凭据或含义不明确的代理前缀。
func validateDownloadSource(source DownloadSource) error {
	if err := validateRequiredText("download_source.id", source.ID); err != nil {
		return err
	}
	for _, character := range source.ID {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || strings.ContainsRune("-_", character) {
			continue
		}
		return fmt.Errorf("download_source.id contains forbidden character %q", character)
	}
	if source.CustomPrefix == "" {
		return nil
	}
	if strings.TrimSpace(source.CustomPrefix) != source.CustomPrefix || containsControl(source.CustomPrefix) || strings.ContainsRune(source.CustomPrefix, '\\') {
		return errors.New("download_source.custom_prefix contains invalid whitespace, control characters, or backslash")
	}
	parsed, err := url.Parse(source.CustomPrefix)
	if err != nil {
		return fmt.Errorf("download_source.custom_prefix is invalid: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Hostname() == "" {
		return errors.New("download_source.custom_prefix must be an HTTPS URL with a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("download_source.custom_prefix must not contain credentials, query, or fragment")
	}
	if !strings.HasSuffix(parsed.EscapedPath(), "/") {
		return errors.New("download_source.custom_prefix must end with /")
	}
	if hasTraversal(parsed.Path) || hasTraversal(parsed.RawPath) {
		return errors.New("download_source.custom_prefix must not contain path traversal")
	}
	return nil
}

// validateService validates the optional service name without interpreting platform-specific commands.
// validateService 校验可选服务名，但不解释平台相关命令。
func validateService(service ServiceState) error {
	if service.Name == "" {
		if service.AutoStart {
			return errors.New("service.auto_start cannot be true without service.name")
		}
		if service.User != "" {
			return errors.New("service.user cannot be set without service.name")
		}
		return nil
	}
	if err := validateRequiredText("service.name", service.Name); err != nil {
		return err
	}
	if len(service.Name) > 256 {
		return errors.New("service.name is too long")
	}
	if service.User != "" && !validServiceUser(service.User) {
		return errors.New("service.user is invalid")
	}
	return nil
}

// validServiceUser applies the VMM service account token contract to persisted identities.
// validServiceUser 对持久化账户标识应用 VMM 服务账户令牌契约。
func validServiceUser(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		if index > 0 && (character == '.' || character == '-') {
			continue
		}
		return false
	}
	return true
}

// validatePATH validates ownership, scope, and absolute PATH entries.
// validatePATH 校验 PATH 条目的所有权、范围和绝对路径。
func validatePATH(pathState PATHState) error {
	switch pathState.Owner {
	case PATHOwnerNone:
		if pathState.Scope != PATHScopeNone || len(pathState.Entries) != 0 {
			return errors.New("path scope and entries must be empty when path owner is none")
		}
	case PATHOwnerManager, PATHOwnerExternal:
		if pathState.Scope != PATHScopeUser && pathState.Scope != PATHScopeSystem {
			return errors.New("path scope must be user or system when path entries are owned")
		}
		if pathState.Entries == nil || len(pathState.Entries) == 0 {
			return errors.New("path entries must not be empty when path owner is set")
		}
	default:
		return fmt.Errorf("unsupported path owner %q", pathState.Owner)
	}
	seen := make(map[string]struct{}, len(pathState.Entries))
	for index, entry := range pathState.Entries {
		if err := validateAbsolutePath(fmt.Sprintf("path.entries[%d]", index), entry); err != nil {
			return err
		}
		key := strings.ToLower(filepath.Clean(entry))
		if _, exists := seen[key]; exists {
			return fmt.Errorf("path.entries[%d] duplicates another entry", index)
		}
		seen[key] = struct{}{}
	}
	if pathState.Entries == nil {
		return errors.New("path.entries must be an array")
	}
	return nil
}

// validate checks a managed file path, digest, and size.
// validate 校验受管文件路径、摘要和大小。
func (file ManagedFile) validate(index int) error {
	field := fmt.Sprintf("managed_files[%d]", index)
	if file.Path == "" || strings.ContainsRune(file.Path, '\\') || strings.ContainsRune(file.Path, '\x00') || strings.ContainsAny(file.Path, "\r\n\t") {
		return fmt.Errorf("%s.path must be a non-empty forward-slash path", field)
	}
	if filepath.IsAbs(filepath.FromSlash(file.Path)) || filepath.VolumeName(filepath.FromSlash(file.Path)) != "" {
		return fmt.Errorf("%s.path must be relative", field)
	}
	if file.Path != pathpkg.Clean(file.Path) || strings.HasPrefix(file.Path, "/") {
		return fmt.Errorf("%s.path must be normalized and relative", field)
	}
	for _, segment := range strings.Split(file.Path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("%s.path contains an invalid component", field)
		}
	}
	if len(file.SHA256) != 64 || strings.ToLower(file.SHA256) != file.SHA256 {
		return fmt.Errorf("%s.sha256 must be lowercase hexadecimal SHA-256", field)
	}
	if _, err := hex.DecodeString(file.SHA256); err != nil {
		return fmt.Errorf("%s.sha256 is invalid: %w", field, err)
	}
	if file.Size < 0 {
		return fmt.Errorf("%s.size must not be negative", field)
	}
	return nil
}

// containsControl detects characters that could alter file or service handling.
// containsControl 检测可能改变文件或服务处理行为的控制字符。
func containsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

// hasTraversal detects literal and escaped dot path components in a URL prefix.
// hasTraversal 检测 URL 前缀中的字面和转义点路径组件。
func hasTraversal(value string) bool {
	if value == "" {
		return false
	}
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return true
	}
	for _, candidate := range []string{value, decoded} {
		for _, segment := range strings.Split(candidate, "/") {
			if segment == "." || segment == ".." {
				return true
			}
		}
	}
	return false
}
