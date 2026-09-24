// Package pathctl owns user-level PATH integration and its reversible records.
// pathctl 负责用户级 PATH 集成以及可安全撤销的变更登记。
//
// The package deliberately keeps the persisted PATH portion aligned with state.PATHState.
// 本包刻意让持久化的 PATH 部分与 state.PATHState 保持一致。
// Platform-specific metadata records the exact profile or link that can be removed.
// 平台元数据记录可以精确删除的 profile 片段或链接。
package pathctl

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
)

// Method identifies the user-level integration selected by the installer.
// Method 标识安装器选择的用户级集成方式。
type Method string

const (
	// MethodWindowsUserPath updates the current user's HKCU Environment PATH value.
	// MethodWindowsUserPath 更新当前用户 HKCU Environment 中的 PATH 值。
	MethodWindowsUserPath Method = "windows-user-path"

	// MethodUnixProfile adds a marked export block to one explicitly selected profile.
	// MethodUnixProfile 将带标记的 export 片段加入用户明确选择的 profile。
	MethodUnixProfile Method = "unix-profile"

	// MethodUnixLocalBin creates one user-selected local-bin command link.
	// MethodUnixLocalBin 创建一个用户选择的 local-bin 命令链接。
	MethodUnixLocalBin Method = "unix-local-bin"

	// MethodUnixSystemBin creates a root-owned /usr/local/bin entry for the system manager.
	// MethodUnixSystemBin 为系统管理器创建 root 持有的 /usr/local/bin 命令入口。
	MethodUnixSystemBin Method = "unix-system-bin"

	// MethodDarwinPathsD exposes the root-owned manager through macOS path_helper's system path directory.
	// MethodDarwinPathsD 通过 macOS path_helper 的系统路径目录暴露 root 所有的管理器。
	MethodDarwinPathsD Method = "darwin-paths-d"
	// DarwinPathsFile uses the canonical system directory instead of macOS's /etc symlink.
	// DarwinPathsFile 使用规范系统目录，避免跟随 macOS 的 /etc 链接。
	DarwinPathsFile = "/private/etc/paths.d/vmmm"
)

const (
	// RecordVersion is the version of the pathctl record exchanged with the installer state layer.
	// RecordVersion 是 pathctl 与安装器状态层交换的登记记录版本。
	RecordVersion = 1
)

var (
	// ErrConflict means an existing user value prevents an unambiguous change.
	// ErrConflict 表示现有用户值阻止了可无歧义执行的变更。
	ErrConflict = errors.New("path integration conflicts with existing user state")

	// ErrChanged means a managed value was edited after the manager created it.
	// ErrChanged 表示管理器创建的值后来被用户编辑过。
	ErrChanged = errors.New("managed path integration was changed by the user")
)

// Options describes one explicit user-level PATH integration request.
// Options 描述一次明确的用户级 PATH 集成请求。
type Options struct {
	// Directory is the absolute manager installation directory to expose.
	// Directory 是要暴露的管理器安装绝对目录。
	Directory string

	// Method selects the platform-specific integration mechanism.
	// Method 选择平台相关的集成机制。
	Method Method

	// ProfilePath is the explicitly selected POSIX shell profile for MethodUnixProfile.
	// ProfilePath 是 MethodUnixProfile 使用的用户明确选择的 POSIX shell profile。
	ProfilePath string

	// LinkPath is the complete user-selected command link path for MethodUnixLocalBin.
	// LinkPath 是 MethodUnixLocalBin 使用的用户选择的完整命令链接路径。
	LinkPath string

	// TargetPath is the absolute executable path linked by MethodUnixLocalBin.
	// TargetPath 是 MethodUnixLocalBin 创建链接时指向的绝对可执行文件路径。
	TargetPath string
}

// Record combines state.PATHState with the exact data required for safe reversal.
// Record 将 state.PATHState 与安全撤销所需的精确数据组合在一起。
type Record struct {
	// Version identifies this record format.
	// Version 标识本登记记录格式。
	Version int `json:"version"`

	// Path is the state-layer ownership record consumed by installation state persistence.
	// Path 是安装状态持久化层使用的所有权登记。
	Path state.PATHState `json:"path"`

	// Method identifies the platform operation that produced this record.
	// Method 标识生成该记录的平台操作。
	Method Method `json:"method"`

	// Directory is the exposed manager installation directory.
	// Directory 是被暴露的管理器安装目录。
	Directory string `json:"directory"`

	// ProfilePath identifies the managed profile or the fixed macOS paths.d file.
	// ProfilePath 标识受管 profile 或固定的 macOS paths.d 文件。
	ProfilePath string `json:"profile_path,omitempty"`

	// LinkPath identifies the command link created for local-bin integration.
	// LinkPath 标识 local-bin 集成创建的命令链接。
	LinkPath string `json:"link_path,omitempty"`

	// TargetPath identifies the executable target expected by a managed link.
	// TargetPath 标识受管链接应当指向的可执行文件。
	TargetPath string `json:"target_path,omitempty"`

	// AfterSHA256 records the exact Windows PATH value or owned macOS paths.d file content.
	// AfterSHA256 记录 Windows PATH 完整值或受管 macOS paths.d 文件内容的摘要。
	AfterSHA256 string `json:"after_sha256,omitempty"`

	// AfterType records the Windows registry type observed after manager modification.
	// AfterType 记录管理器修改后观察到的 Windows 注册表类型。
	AfterType uint32 `json:"after_type,omitempty"`

	// BlockSHA256 records the exact bytes of the managed profile block.
	// BlockSHA256 记录受管 profile 片段原始字节的摘要。
	BlockSHA256 string `json:"block_sha256,omitempty"`
}

// Validate checks record shape before a platform implementation performs a removal.
// Validate 在平台实现执行撤销前检查登记记录的结构。
func (r Record) Validate() error {
	if r.Version != RecordVersion {
		return fmt.Errorf("unsupported path record version %d", r.Version)
	}
	if err := validatePATHState(r.Path); err != nil {
		return fmt.Errorf("path state is invalid: %w", err)
	}
	if r.Path.Owner != state.PATHOwnerManager && r.Path.Owner != state.PATHOwnerExternal {
		return fmt.Errorf("path record owner must be manager or external")
	}
	if r.Method == MethodUnixSystemBin || r.Method == MethodDarwinPathsD {
		if r.Path.Scope != state.PATHScopeSystem {
			return fmt.Errorf("system command record scope must be system")
		}
	} else if r.Path.Scope != state.PATHScopeUser {
		return fmt.Errorf("path record scope must be user")
	}
	if err := validateAbsoluteText("directory", r.Directory); err != nil {
		return err
	}
	switch r.Method {
	case MethodDarwinPathsD:
		if r.ProfilePath != DarwinPathsFile || r.LinkPath != "" || r.TargetPath != "" || r.BlockSHA256 != "" || r.AfterType != 0 || !validSHA256(r.AfterSHA256) {
			return errors.New("macOS path record metadata is invalid")
		}
		if len(r.Path.Entries) != 1 || r.Path.Entries[0] != filepath.Clean(r.Directory) {
			return errors.New("macOS path record entry does not match directory")
		}
		if _, err := darwinPathContent(r.Directory); err != nil {
			return err
		}
	case MethodWindowsUserPath:
		if strings.ContainsRune(r.Directory, ';') {
			return errors.New("windows directory must not contain the PATH separator")
		}
		if r.ProfilePath != "" || r.LinkPath != "" || r.TargetPath != "" || r.BlockSHA256 != "" {
			return errors.New("windows path record contains POSIX metadata")
		}
		if r.Path.Owner == state.PATHOwnerManager && r.AfterType != 1 && r.AfterType != 2 {
			return errors.New("windows manager record requires a supported registry type")
		}
		if r.Path.Owner == state.PATHOwnerExternal && r.AfterType != 0 {
			return errors.New("windows external record must not contain a registry type")
		}
		if r.Path.Entries[0] != filepath.Clean(r.Directory) {
			return errors.New("windows path record entry does not match directory")
		}
		if r.Path.Owner == state.PATHOwnerManager && !validSHA256(r.AfterSHA256) {
			return errors.New("windows manager record requires after_sha256")
		}
	case MethodUnixProfile:
		if err := validateAbsoluteText("profile_path", r.ProfilePath); err != nil {
			return err
		}
		if r.LinkPath != "" || r.TargetPath != "" || r.AfterSHA256 != "" || r.AfterType != 0 {
			return errors.New("profile path record contains unrelated metadata")
		}
		if r.Path.Entries[0] != filepath.Clean(r.Directory) {
			return errors.New("profile path record entry does not match directory")
		}
		if r.Path.Owner == state.PATHOwnerManager && !validSHA256(r.BlockSHA256) {
			return errors.New("profile manager record requires block_sha256")
		}
	case MethodUnixLocalBin, MethodUnixSystemBin:
		if err := validateAbsoluteText("link_path", r.LinkPath); err != nil {
			return err
		}
		if r.Method == MethodUnixSystemBin && filepath.Clean(r.LinkPath) != "/usr/local/bin/vmmm" {
			return errors.New("system command record has an unexpected link path")
		}
		if err := validateAbsoluteText("target_path", r.TargetPath); err != nil {
			return err
		}
		if r.ProfilePath != "" || r.AfterSHA256 != "" || r.AfterType != 0 || r.BlockSHA256 != "" {
			return errors.New("local-bin path record contains unrelated metadata")
		}
		if !pathWithin(r.Directory, r.TargetPath) {
			return errors.New("local-bin target must be below the manager directory")
		}
		if len(r.Path.Entries) != 1 || r.Path.Entries[0] != filepath.Clean(filepath.Dir(r.LinkPath)) {
			return errors.New("local-bin path record entry does not match link directory")
		}
	default:
		return fmt.Errorf("unsupported path method %q", r.Method)
	}
	return nil
}

// validatePATHState mirrors the state package's PATH invariants without changing that package.
// validatePATHState 在不修改 state 包的前提下复核其 PATH 不变量。
func validatePATHState(pathState state.PATHState) error {
	if pathState.Scope != state.PATHScopeUser && pathState.Scope != state.PATHScopeSystem {
		return fmt.Errorf("path scope must be user or system")
	}
	if pathState.Owner != state.PATHOwnerManager && pathState.Owner != state.PATHOwnerExternal {
		return fmt.Errorf("path owner must be manager or external")
	}
	if len(pathState.Entries) == 0 {
		return errors.New("path entries must not be empty")
	}
	seen := make(map[string]struct{}, len(pathState.Entries))
	for index, entry := range pathState.Entries {
		if err := validateAbsoluteText(fmt.Sprintf("path.entries[%d]", index), entry); err != nil {
			return err
		}
		key := strings.ToLower(filepath.Clean(entry))
		if _, exists := seen[key]; exists {
			return fmt.Errorf("path.entries[%d] duplicates another entry", index)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// validateOptions validates explicit paths before any filesystem or registry mutation.
// validateOptions 在任何文件系统或注册表变更前检查用户明确提供的路径。
func validateOptions(options Options) error {
	if err := validateAbsoluteText("directory", options.Directory); err != nil {
		return err
	}
	switch options.Method {
	case MethodDarwinPathsD:
		if options.ProfilePath != DarwinPathsFile || options.LinkPath != "" || options.TargetPath != "" {
			return errors.New("macOS paths.d options require the fixed system file only")
		}
		if _, err := darwinPathContent(options.Directory); err != nil {
			return err
		}
	case MethodWindowsUserPath:
		if options.ProfilePath != "" || options.LinkPath != "" || options.TargetPath != "" {
			return errors.New("windows path options contain POSIX fields")
		}
	case MethodUnixProfile:
		if err := validateAbsoluteText("profile_path", options.ProfilePath); err != nil {
			return err
		}
		if options.LinkPath != "" || options.TargetPath != "" {
			return errors.New("profile path options contain local-bin fields")
		}
	case MethodUnixLocalBin, MethodUnixSystemBin:
		if err := validateAbsoluteText("link_path", options.LinkPath); err != nil {
			return err
		}
		if err := validateAbsoluteText("target_path", options.TargetPath); err != nil {
			return err
		}
		if options.ProfilePath != "" {
			return errors.New("local-bin path options contain profile fields")
		}
		if !pathWithin(options.Directory, options.TargetPath) {
			return errors.New("local-bin target must be below the manager directory")
		}
		if options.Method == MethodUnixSystemBin && filepath.Clean(options.LinkPath) != "/usr/local/bin/vmmm" {
			return errors.New("system command link must be /usr/local/bin/vmmm")
		}
	default:
		return fmt.Errorf("unsupported path method %q", options.Method)
	}
	return nil
}

// darwinPathContent returns one path_helper entry and rejects shell-active or PATH-separator characters.
// darwinPathContent 返回单条 path_helper 路径，拒绝 shell 活跃字符和 PATH 分隔符，避免登录脚本解释路径内容。
func darwinPathContent(directory string) ([]byte, error) {
	if err := validateAbsoluteText("directory", directory); err != nil {
		return nil, err
	}
	if strings.ContainsAny(directory, ":\\`$\"'") {
		return nil, errors.New("macOS manager directory contains unsupported path_helper characters")
	}
	return []byte(filepath.Clean(directory) + "\n"), nil
}

// validateAbsoluteText rejects relative paths and control characters.
// validateAbsoluteText 拒绝相对路径、控制字符以及 PATH 分隔符歧义。
func validateAbsoluteText(field string, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not contain surrounding whitespace", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	if !filepath.IsAbs(value) {
		return fmt.Errorf("%s must be absolute", field)
	}
	if filepath.Clean(value) == "." {
		return fmt.Errorf("%s is not a usable path", field)
	}
	return nil
}

// validSHA256 checks the canonical lowercase hexadecimal digest form used by records.
// validSHA256 检查记录使用的小写十六进制摘要格式。
func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// digest returns a lowercase SHA-256 digest for exact bytes or text.
// digest 为精确字节或文本返回小写 SHA-256 摘要。
func digest(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

// pathWithin accepts a target only when it is rooted below the selected manager directory.
// pathWithin 仅在目标路径位于选定管理器目录下时接受它。
func pathWithin(root string, target string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil || relative == "" || relative == "." || filepath.IsAbs(relative) {
		return false
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}
