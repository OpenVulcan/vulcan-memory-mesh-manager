//go:build !windows

// This file implements explicit user-level POSIX profile and local-bin integration.
// 本文件实现用户明确选择的 POSIX profile 与 local-bin 集成。
// It never writes system profiles and never replaces an existing command path.
// 它不会写系统 profile，也不会替换已有命令路径。
package pathctl

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
)

const (
	// profileStart marks the beginning of the manager-owned export block.
	// profileStart 标识管理器受管 export 片段的开始。
	profileStart = "# >>> vmmm managed PATH >>>"

	// profileEnd marks the end of the manager-owned export block.
	// profileEnd 标识管理器受管 export 片段的结束。
	profileEnd = "# <<< vmmm managed PATH <<<"
)

// fileOps isolates filesystem mutation so tests can use temporary files or injected failures.
// fileOps 隔离文件系统变更，使测试可以使用临时文件或注入失败。
type fileOps interface {
	// Lstat inspects a path without following its final symlink.
	// Lstat 不跟随最后一级符号链接检查路径。
	Lstat(path string) (os.FileInfo, error)

	// ReadFile reads file bytes exactly as stored.
	// ReadFile 按文件实际内容读取字节。
	ReadFile(path string) ([]byte, error)

	// WriteAtomic replaces a regular file atomically after an optional expected-content check.
	// WriteAtomic 在可选的预期内容检查后原子替换普通文件。
	WriteAtomic(path string, before []byte, beforeExists bool, after []byte, mode fs.FileMode) error

	// MkdirAll creates user-selected parent directories with the requested mode.
	// MkdirAll 按请求权限创建用户选择的父目录。
	MkdirAll(path string, mode fs.FileMode) error

	// Symlink creates a new link and must fail if the link path already exists.
	// Symlink 创建新链接，且链接路径已存在时必须失败。
	Symlink(target string, linkPath string) error

	// Readlink reads the stored target text of a symlink.
	// Readlink 读取符号链接中储存的目标文本。
	Readlink(path string) (string, error)

	// Remove removes one path after the caller has verified its identity.
	// Remove 在调用方确认对象身份后删除一个路径。
	Remove(path string) error
}

// Controller applies and reverses explicit user-level POSIX PATH integration.
// Controller 执行和撤销明确的用户级 POSIX PATH 集成。
type Controller struct {
	// files is the filesystem boundary used by profile and local-bin operations.
	// files 是 profile 与 local-bin 操作使用的文件系统边界。
	files fileOps
}

// New returns a controller backed by ordinary POSIX filesystem operations.
// New 返回使用普通 POSIX 文件系统操作的控制器。
func New() *Controller {
	return &Controller{files: osFileOps{}}
}

// newController creates an injectable controller for package-local tests.
// newController 创建供包内测试使用的可注入控制器。
func newController(files fileOps) *Controller {
	return &Controller{files: files}
}

// Install applies the explicitly selected profile or local-bin method.
// Install 应用用户明确选择的 profile 或 local-bin 方法。
func (c *Controller) Install(options Options) (Record, error) {
	if c == nil || c.files == nil {
		return Record{}, errors.New("path controller is not initialized")
	}
	if err := validateOptions(options); err != nil {
		return Record{}, fmt.Errorf("validate POSIX PATH options: %w", err)
	}
	switch options.Method {
	case MethodDarwinPathsD:
		return c.installDarwinPaths(options)
	case MethodUnixProfile:
		return c.installProfile(options)
	case MethodUnixLocalBin, MethodUnixSystemBin:
		return c.installLocalBin(options)
	case MethodWindowsUserPath:
		return Record{}, fmt.Errorf("method %q is not supported on POSIX", options.Method)
	default:
		return Record{}, fmt.Errorf("unsupported POSIX path method %q", options.Method)
	}
}

// Remove reverses only manager-owned profile or link content that still matches its record.
// Remove 只撤销仍与登记记录匹配的管理器 profile 或链接内容。
func (c *Controller) Remove(record Record) error {
	if c == nil || c.files == nil {
		return errors.New("path controller is not initialized")
	}
	if err := record.Validate(); err != nil {
		return fmt.Errorf("validate POSIX PATH record: %w", err)
	}
	if record.Path.Owner == state.PATHOwnerExternal {
		return nil
	}
	switch record.Method {
	case MethodDarwinPathsD:
		return c.removeDarwinPaths(record)
	case MethodUnixProfile:
		return c.removeProfile(record)
	case MethodUnixLocalBin, MethodUnixSystemBin:
		return c.removeLocalBin(record)
	case MethodWindowsUserPath:
		return fmt.Errorf("path method %q is not supported on POSIX", record.Method)
	default:
		return fmt.Errorf("unsupported POSIX path method %q", record.Method)
	}
}

// installProfile appends one marked export block without touching user bytes outside the block.
// installProfile 追加一个带标记的 export 片段，不改动片段之外的用户字节。
func (c *Controller) installProfile(options Options) (Record, error) {
	if err := requireDirectory(options.Directory); err != nil {
		return Record{}, err
	}
	before, mode, exists, err := c.readRegularProfile(options.ProfilePath)
	if err != nil {
		return Record{}, err
	}
	if exists {
		if start, end, block, blockErr := managedBlock(before); blockErr == nil {
			if !bytes.Equal(block, buildProfileBlock(options.Directory)) {
				return Record{}, fmt.Errorf("%w: profile already contains a different vmmm block", ErrConflict)
			}
			_ = start
			_ = end
			return externalProfileRecord(options, block)
		} else if !errors.Is(blockErr, errNoManagedBlock) {
			return Record{}, fmt.Errorf("inspect profile markers: %w", blockErr)
		}
		if bytes.Contains(before, []byte(options.Directory)) {
			return Record{}, fmt.Errorf("%w: profile already mentions the manager directory", ErrConflict)
		}
	}

	block := buildProfileBlock(options.Directory)
	after := append([]byte(nil), before...)
	if len(after) > 0 && after[len(after)-1] != '\n' {
		after = append(after, '\n')
	}
	after = append(after, block...)
	if !exists {
		mode = 0o600
	}
	if err := c.files.WriteAtomic(options.ProfilePath, before, exists, after, mode); err != nil {
		return Record{}, fmt.Errorf("write selected profile: %w", err)
	}
	record := Record{
		Version:     RecordVersion,
		Path:        state.PATHState{Owner: state.PATHOwnerManager, Scope: state.PATHScopeUser, Entries: []string{filepath.Clean(options.Directory)}},
		Method:      MethodUnixProfile,
		Directory:   filepath.Clean(options.Directory),
		ProfilePath: filepath.Clean(options.ProfilePath),
		BlockSHA256: digest(block),
	}
	return record, nil
}

// installLocalBin creates a user-selected command link only when its path is absent.
// installLocalBin 仅在用户选择的命令链接路径不存在时创建链接。
func (c *Controller) installLocalBin(options Options) (Record, error) {
	if err := requireDirectory(options.Directory); err != nil {
		return Record{}, err
	}
	if err := requireRegularTarget(c.files, options.TargetPath); err != nil {
		return Record{}, err
	}
	if options.Method == MethodUnixSystemBin {
		if err := validateSystemCommandTarget(options.TargetPath); err != nil {
			return Record{}, err
		}
	}
	linkInfo, err := c.files.Lstat(options.LinkPath)
	if err == nil {
		if options.Method == MethodUnixSystemBin {
			if err := validateSystemCommandLinkParent(filepath.Dir(options.LinkPath)); err != nil {
				return Record{}, err
			}
		}
		if linkInfo.Mode()&os.ModeSymlink == 0 {
			return Record{}, fmt.Errorf("%w: local-bin path is an existing non-symlink", ErrConflict)
		}
		existingTarget, readErr := c.files.Readlink(options.LinkPath)
		if readErr != nil {
			return Record{}, fmt.Errorf("read existing local-bin link: %w", readErr)
		}
		if resolveLinkTarget(options.LinkPath, existingTarget) != filepath.Clean(options.TargetPath) {
			return Record{}, fmt.Errorf("%w: local-bin link points to another executable", ErrConflict)
		}
		return externalLocalBinRecord(options)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Record{}, fmt.Errorf("inspect local-bin path: %w", err)
	}
	parent := filepath.Dir(options.LinkPath)
	mode := os.FileMode(0o700)
	if options.Method == MethodUnixSystemBin {
		mode = 0o755
	}
	if err := c.files.MkdirAll(parent, mode); err != nil {
		return Record{}, fmt.Errorf("create local-bin directory: %w", err)
	}
	if options.Method == MethodUnixSystemBin {
		if err := validateSystemCommandLinkParent(parent); err != nil {
			return Record{}, err
		}
	}
	if err := c.files.Symlink(filepath.Clean(options.TargetPath), options.LinkPath); err != nil {
		return Record{}, fmt.Errorf("create local-bin link: %w", err)
	}
	scope := state.PATHScopeUser
	if options.Method == MethodUnixSystemBin {
		scope = state.PATHScopeSystem
	}
	record := Record{
		Version:    RecordVersion,
		Path:       state.PATHState{Owner: state.PATHOwnerManager, Scope: scope, Entries: []string{filepath.Clean(parent)}},
		Method:     options.Method,
		Directory:  filepath.Clean(options.Directory),
		LinkPath:   filepath.Clean(options.LinkPath),
		TargetPath: filepath.Clean(options.TargetPath),
	}
	return record, nil
}

// requireDirectory ensures the exposed manager directory exists before user integration.
// requireDirectory 确保用户集成前被暴露的管理器目录已经存在。
func requireDirectory(directory string) error {
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("stat manager directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("manager PATH entry is not a directory")
	}
	return nil
}

// removeProfile deletes only an unchanged marked block and preserves surrounding user edits.
// removeProfile 只删除未被改动的带标记片段，并保留周围的用户编辑。
func (c *Controller) removeProfile(record Record) error {
	before, mode, exists, err := c.readRegularProfile(record.ProfilePath)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	start, end, block, blockErr := managedBlock(before)
	if errors.Is(blockErr, errNoManagedBlock) {
		return nil
	}
	if blockErr != nil {
		return fmt.Errorf("inspect profile markers during removal: %w", blockErr)
	}
	if digest(block) != record.BlockSHA256 {
		return fmt.Errorf("%w: managed profile block bytes differ", ErrChanged)
	}
	after := make([]byte, 0, len(before)-(end-start))
	after = append(after, before[:start]...)
	after = append(after, before[end:]...)
	if err := c.files.WriteAtomic(record.ProfilePath, before, true, after, mode); err != nil {
		return fmt.Errorf("remove managed profile block: %w", err)
	}
	return nil
}

// removeLocalBin removes a link only when it still points to the recorded target.
// removeLocalBin 仅在链接仍指向登记目标时删除链接。
func (c *Controller) removeLocalBin(record Record) error {
	if record.Method == MethodUnixSystemBin {
		if err := validateSystemCommandLinkParent(filepath.Dir(record.LinkPath)); err != nil {
			return err
		}
	}
	linkInfo, err := c.files.Lstat(record.LinkPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect local-bin link during removal: %w", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("%w: local-bin path is no longer a symlink", ErrChanged)
	}
	existingTarget, err := c.files.Readlink(record.LinkPath)
	if err != nil {
		return fmt.Errorf("read local-bin link during removal: %w", err)
	}
	if resolveLinkTarget(record.LinkPath, existingTarget) != filepath.Clean(record.TargetPath) {
		return fmt.Errorf("%w: local-bin link target differs", ErrChanged)
	}
	if err := c.files.Remove(record.LinkPath); err != nil {
		return fmt.Errorf("remove local-bin link: %w", err)
	}
	return nil
}

// readRegularProfile reads an existing regular profile and returns its mode for preservation.
// readRegularProfile 读取现有普通 profile，并返回用于保留的权限模式。
func (c *Controller) readRegularProfile(path string) ([]byte, fs.FileMode, bool, error) {
	info, err := c.files.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0o600, false, nil
	}
	if err != nil {
		return nil, 0, false, fmt.Errorf("inspect selected profile: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, false, fmt.Errorf("%w: selected profile is a symlink", ErrConflict)
	}
	if !info.Mode().IsRegular() {
		return nil, 0, false, fmt.Errorf("%w: selected profile is not a regular file", ErrConflict)
	}
	content, err := c.files.ReadFile(path)
	if err != nil {
		return nil, 0, false, fmt.Errorf("read selected profile: %w", err)
	}
	return content, info.Mode().Perm(), true, nil
}

// requireRegularTarget ensures a link target is an existing regular executable file.
// requireRegularTarget 确保链接目标是现有普通可执行文件。
func requireRegularTarget(files fileOps, path string) error {
	info, err := files.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect local-bin target: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("local-bin target must be a regular file")
	}
	return nil
}

// buildProfileBlock creates a shell-safe POSIX export block for one absolute directory.
// buildProfileBlock 为一个绝对目录创建 shell 安全的 POSIX export 片段。
func buildProfileBlock(directory string) []byte {
	quoted := shellQuote(directory)
	return []byte(profileStart + "\nexport PATH=" + quoted + ":\"$PATH\"\n" + profileEnd + "\n")
}

// shellQuote uses POSIX single-quote escaping so paths cannot expand shell syntax.
// shellQuote 使用 POSIX 单引号转义，防止路径展开 shell 语法。
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

// errNoManagedBlock distinguishes a profile with no manager markers from a malformed block.
// errNoManagedBlock 区分没有管理器标记的 profile 与格式损坏的片段。
var errNoManagedBlock = errors.New("profile contains no vmmm managed block")

// managedBlock locates exactly one complete marked block on line boundaries.
// managedBlock 在行边界上定位唯一完整的带标记片段。
func managedBlock(data []byte) (int, int, []byte, error) {
	startCount := bytes.Count(data, []byte(profileStart))
	endCount := bytes.Count(data, []byte(profileEnd))
	if startCount == 0 && endCount == 0 {
		return 0, 0, nil, errNoManagedBlock
	}
	if startCount != 1 || endCount != 1 {
		return 0, 0, nil, fmt.Errorf("%w: expected one start and end marker", ErrConflict)
	}
	start := bytes.Index(data, []byte(profileStart))
	endMarker := bytes.Index(data, []byte(profileEnd))
	if start > 0 && data[start-1] != '\n' {
		return 0, 0, nil, fmt.Errorf("%w: start marker is not at a line boundary", ErrConflict)
	}
	if endMarker < start {
		return 0, 0, nil, fmt.Errorf("%w: end marker appears before start marker", ErrConflict)
	}
	if endMarker > 0 && data[endMarker-1] != '\n' {
		return 0, 0, nil, fmt.Errorf("%w: end marker is not at a line boundary", ErrConflict)
	}
	end := endMarker + len(profileEnd)
	if end < len(data) && data[end] != '\r' && data[end] != '\n' {
		return 0, 0, nil, fmt.Errorf("%w: end marker is not complete", ErrConflict)
	}
	if end < len(data) && data[end] == '\r' {
		end++
	}
	if end < len(data) && data[end] == '\n' {
		end++
	}
	return start, end, data[start:end], nil
}

// resolveLinkTarget converts a symlink's raw target to the normalized absolute target path.
// resolveLinkTarget 将符号链接原始目标转换为规范化绝对目标路径。
func resolveLinkTarget(linkPath string, target string) string {
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(linkPath), target)
	}
	return filepath.Clean(target)
}

// osFileOps implements fileOps with local operating-system primitives.
// osFileOps 使用本地操作系统原语实现 fileOps。
type osFileOps struct{}

// Lstat delegates to os.Lstat so final symlinks remain visible to safety checks.
// Lstat 调用 os.Lstat，使安全检查可以看到最后一级符号链接。
func (osFileOps) Lstat(path string) (os.FileInfo, error) { return os.Lstat(path) }

// ReadFile delegates to os.ReadFile.
// ReadFile 调用 os.ReadFile。
func (osFileOps) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// WriteAtomic writes a temporary sibling, verifies unchanged input, then renames it into place.
// WriteAtomic 写入同目录临时文件，核对输入未变化后原子替换目标。
func (osFileOps) WriteAtomic(path string, before []byte, beforeExists bool, after []byte, mode fs.FileMode) error {
	current, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if beforeExists {
			return ErrChanged
		}
	} else if !beforeExists || !bytes.Equal(current, before) {
		return ErrChanged
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".vmmm-path-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(after); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

// MkdirAll delegates to os.MkdirAll for user-selected local-bin parents.
// MkdirAll 调用 os.MkdirAll 创建用户选择的 local-bin 父目录。
func (osFileOps) MkdirAll(path string, mode fs.FileMode) error { return os.MkdirAll(path, mode) }

// Symlink delegates to os.Symlink and inherits its no-overwrite behavior.
// Symlink 调用 os.Symlink，并继承其不覆盖已有路径的行为。
func (osFileOps) Symlink(target string, linkPath string) error { return os.Symlink(target, linkPath) }

// Readlink delegates to os.Readlink.
// Readlink 调用 os.Readlink。
func (osFileOps) Readlink(path string) (string, error) { return os.Readlink(path) }

// Remove delegates to os.Remove after caller identity checks.
// Remove 在调用方完成身份检查后调用 os.Remove。
func (osFileOps) Remove(path string) error { return os.Remove(path) }

// externalProfileRecord records an existing identical block without taking ownership of it.
// externalProfileRecord 记录已有的相同片段，但不取得它的所有权。
func externalProfileRecord(options Options, block []byte) (Record, error) {
	record := Record{
		Version:     RecordVersion,
		Path:        state.PATHState{Owner: state.PATHOwnerExternal, Scope: state.PATHScopeUser, Entries: []string{filepath.Clean(options.Directory)}},
		Method:      MethodUnixProfile,
		Directory:   filepath.Clean(options.Directory),
		ProfilePath: filepath.Clean(options.ProfilePath),
		BlockSHA256: digest(block),
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

// externalLocalBinRecord records an existing identical link without taking ownership of it.
// externalLocalBinRecord 记录已有的相同链接，但不取得它的所有权。
func externalLocalBinRecord(options Options) (Record, error) {
	scope := state.PATHScopeUser
	if options.Method == MethodUnixSystemBin {
		scope = state.PATHScopeSystem
	}
	record := Record{
		Version:    RecordVersion,
		Path:       state.PATHState{Owner: state.PATHOwnerExternal, Scope: scope, Entries: []string{filepath.Clean(filepath.Dir(options.LinkPath))}},
		Method:     options.Method,
		Directory:  filepath.Clean(options.Directory),
		LinkPath:   filepath.Clean(options.LinkPath),
		TargetPath: filepath.Clean(options.TargetPath),
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}
