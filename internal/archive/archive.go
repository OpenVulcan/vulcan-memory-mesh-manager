// Package archive authenticates, safely extracts, and verifies VMM release archives.
// archive 包负责认证、受限解包并校验 VMM 发行压缩包。
// It is called after signed release metadata selects one platform artifact and before installation staging is consumed.
// 它在签名发行清单选定平台资产后、安装暂存内容被使用前调用。
package archive

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// ManifestSchemaVersion identifies the VMM receipt schema accepted by this manager release.
	// ManifestSchemaVersion 标识此管理器版本接受的 VMM 包内清单结构版本。
	ManifestSchemaVersion uint = 2

	// maxArchiveBytes bounds the immutable archive snapshot before parsing begins.
	// maxArchiveBytes 限制开始解析前复制的不可变压缩包快照大小。
	maxArchiveBytes int64 = 2 << 30

	// maxExpandedBytes prevents a compressed archive from expanding without a practical upper bound.
	// maxExpandedBytes 为解压后数据总量设置实用上限，阻止压缩炸弹无限展开。
	maxExpandedBytes int64 = 2 << 30

	// maxArchiveEntries bounds metadata work and filesystem object creation.
	// maxArchiveEntries 限制元数据处理量和文件系统对象创建数量。
	maxArchiveEntries = 100_000

	// maxReceiptBytes limits the package receipt before strict JSON parsing.
	// maxReceiptBytes 限制严格解析前包内清单的最大字节数。
	maxReceiptBytes int64 = 16 << 20

	// maxReceiptJSONDepth bounds recursive object scanning against adversarial nesting.
	// maxReceiptJSONDepth 限制递归对象扫描深度，防止恶意嵌套。
	maxReceiptJSONDepth = 32

	// maxTarOverhead allows bounded tar headers and padding beyond the payload-size limit.
	// maxTarOverhead 为 tar 文件头和填充预留有界空间。
	maxTarOverhead int64 = 64 << 20
)

var (
	// releaseVersionPattern accepts immutable semantic release tags used in VMM package names.
	// releaseVersionPattern 接受用于 VMM 包名的不可变语义版本标签。
	releaseVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$`)

	// digestPattern accepts lowercase SHA-256 digests from the verified outer release manifest.
	// digestPattern 接受已验证外层发行清单中的小写 SHA-256 摘要。
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

	// platformTargets maps the closed VMM release matrix to its canonical compilation targets.
	// platformTargets 将封闭的 VMM 发行平台矩阵映射到规范编译目标。
	platformTargets = map[string]string{
		"windows-x64": "x86_64-pc-windows-msvc",
		"linux-x64":   "x86_64-unknown-linux-gnu",
		"linux-arm64": "aarch64-unknown-linux-gnu",
		"macos-intel": "x86_64-apple-darwin",
		"macos-arm64": "aarch64-apple-darwin",
	}
)

// StorageMode identifies one storage configuration the VMM package can support.
// StorageMode 标识 VMM 安装包支持的一种存储配置。
type StorageMode string

const (
	// StorageModeSplit selects separate relation and vector stores.
	// StorageModeSplit 选择分离的关系存储和向量存储。
	StorageModeSplit StorageMode = "split"

	// StorageModeController selects the VLDB controller for storage operations.
	// StorageModeController 选择 VLDB 控制器执行存储操作。
	StorageModeController StorageMode = "controller"

	// StorageModeNative selects the native in-process storage implementation.
	// StorageModeNative 选择进程内原生存储实现。
	StorageModeNative StorageMode = "native"

	// StorageModeCombined selects a combined PostgreSQL-compatible storage provider.
	// StorageModeCombined 选择组合式 PostgreSQL 兼容存储提供方。
	StorageModeCombined StorageMode = "combined"
)

// ExpectedRelease binds extraction to the artifact identity and digest from a verified outer manifest.
// ExpectedRelease 将解包绑定到已验证外层清单中的资产身份与摘要。
type ExpectedRelease struct {
	// Version is the signed release tag expected inside the package receipt.
	// Version 是包内清单必须匹配的签名发行标签。
	Version string

	// Commit is the signed source commit expected inside the package receipt.
	// Commit 是包内清单必须匹配的签名源代码提交。
	Commit string

	// Platform is the signed platform identifier selected by the installer.
	// Platform 是安装器选定的签名平台标识。
	Platform string

	// Target is the canonical compilation target for Platform.
	// Target 是 Platform 对应的规范编译目标。
	Target string

	// ArchiveBytes is the exact artifact length from the verified outer manifest.
	// ArchiveBytes 是已验证外层清单给出的精确资产字节数。
	ArchiveBytes int64

	// ArchiveSHA256 is the lowercase digest from the verified outer manifest.
	// ArchiveSHA256 是已验证外层清单给出的小写压缩包摘要。
	ArchiveSHA256 string
}

// Capabilities contains the strictly validated storage capabilities advertised by a VMM package.
// Capabilities 包含 VMM 安装包声明且经过严格校验的存储能力。
type Capabilities struct {
	// SchemaVersion identifies the capability-object schema.
	// SchemaVersion 标识能力对象结构版本。
	SchemaVersion uint `json:"schema_version"`

	// StorageModes lists the supported top-level storage modes.
	// StorageModes 列出支持的顶层存储模式。
	StorageModes []StorageMode `json:"storage_modes"`

	// Combined describes the optional PostgreSQL-compatible combined provider.
	// Combined 描述可选的 PostgreSQL 兼容组合式存储提供方。
	Combined *CombinedCapability `json:"combined,omitempty"`
}

// CombinedCapability lists the supported provider and its selectable flavors.
// CombinedCapability 列出组合式存储支持的提供方和可选类型。
type CombinedCapability struct {
	// Provider is the supported combined storage provider.
	// Provider 是支持的组合式存储提供方。
	Provider string `json:"provider"`

	// Flavors lists the provider-specific implementation choices.
	// Flavors 列出提供方对应的实现类型。
	Flavors []string `json:"flavors"`
}

// Receipt is the authenticated file inventory and runtime identity embedded in a VMM archive.
// Receipt 是 VMM 压缩包内经过外层摘要认证的文件清单和运行时身份。
type Receipt struct {
	// ManifestSchema is the package receipt schema version.
	// ManifestSchema 是包内清单结构版本。
	ManifestSchema uint `json:"manifest_schema"`

	// Version is the immutable release tag recorded by the VMM packager.
	// Version 是 VMM 打包器记录的不可变发行标签。
	Version string `json:"version"`

	// Commit is the source commit recorded by the VMM packager.
	// Commit 是 VMM 打包器记录的源代码提交。
	Commit string `json:"commit"`

	// Platform is the platform identifier recorded by the VMM packager.
	// Platform 是 VMM 打包器记录的平台标识。
	Platform string `json:"platform"`

	// Target is the compilation target recorded by the VMM packager.
	// Target 是 VMM 打包器记录的编译目标。
	Target string `json:"target"`

	// StorageMode is the package's default storage mode.
	// StorageMode 是安装包默认存储模式。
	StorageMode StorageMode `json:"storage_mode"`

	// StorageProfile identifies which dependency profile is included in the package.
	// StorageProfile 标识安装包包含的依赖配置集合。
	StorageProfile string `json:"storage_profile"`

	// Capabilities describes supported storage modes and provider choices.
	// Capabilities 描述支持的存储模式和提供方选项。
	Capabilities Capabilities `json:"capabilities"`

	// Files maps package-relative paths to lowercase SHA-256 digests; the receipt excludes itself.
	// Files 将包内相对路径映射到小写 SHA-256 摘要；清单本身不包含在映射中。
	Files map[string]string `json:"files"`
}

// Package describes the verified package directory promoted into the caller's staging root.
// Package 描述已校验并移入调用方暂存根目录的安装包目录。
type Package struct {
	// Root is the absolute path to the package's single top-level directory.
	// Root 是安装包唯一顶层目录的绝对路径。
	Root string

	// Receipt is the validated package identity and capability inventory.
	// Receipt 是经过校验的包身份和能力清单。
	Receipt Receipt
}

// Extract verifies the signed artifact digest, extracts into an empty staging root, and validates every package file.
// Extract 校验签名资产摘要，将内容解到空暂存根目录，并逐个校验包内文件。
// The expected byte count and digest must come from a successfully verified outer release manifest.
// expected 中的字节数和摘要必须来自已经成功验签的外层发行清单。
// A failed operation removes its private temporary tree and leaves the caller's staging root empty.
// 操作失败时会清理私有临时目录，并保持调用方暂存根目录为空。
func Extract(ctx context.Context, archivePath string, stagingRoot string, expected ExpectedRelease) (Package, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateExpected(expected); err != nil {
		return Package{}, err
	}

	stagePath, err := validateEmptyStagingRoot(stagingRoot)
	if err != nil {
		return Package{}, err
	}
	stageRoot, err := os.OpenRoot(stagePath)
	if err != nil {
		return Package{}, fmt.Errorf("open staging root: %w", err)
	}
	defer stageRoot.Close()

	snapshot, cleanupSnapshot, err := snapshotVerifiedArchive(ctx, archivePath, expected)
	if err != nil {
		return Package{}, err
	}
	defer cleanupSnapshot()

	temporaryPath, err := os.MkdirTemp(stagePath, ".vmmm-extract-")
	if err != nil {
		return Package{}, fmt.Errorf("create private extraction directory: %w", err)
	}
	temporaryName := filepath.Base(temporaryPath)
	temporaryExists := true
	defer func() {
		if temporaryExists {
			_ = stageRoot.RemoveAll(temporaryName)
		}
	}()

	packageName := packageDirectoryName(expected)
	receipt, err := extractAndVerify(ctx, snapshot, temporaryPath, packageName, expected)
	if err != nil {
		return Package{}, err
	}

	if _, err := stageRoot.Lstat(packageName); err == nil {
		return Package{}, fmt.Errorf("package destination %q already exists", packageName)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Package{}, fmt.Errorf("inspect package destination: %w", err)
	}
	if err := stageRoot.Rename(path.Join(temporaryName, packageName), packageName); err != nil {
		return Package{}, fmt.Errorf("promote verified package into staging root: %w", err)
	}
	if err := stageRoot.Remove(temporaryName); err != nil {
		_ = stageRoot.Rename(packageName, path.Join(temporaryName, packageName))
		return Package{}, fmt.Errorf("remove private extraction directory: %w", err)
	}
	temporaryExists = false
	return Package{Root: filepath.Join(stagePath, packageName), Receipt: receipt}, nil
}

// validateExpected checks signed artifact metadata before it is used in paths or extraction limits.
// validateExpected 在将签名资产元数据用于路径或解包限制前进行校验。
func validateExpected(expected ExpectedRelease) error {
	if !releaseVersionPattern.MatchString(expected.Version) {
		return fmt.Errorf("expected release version %q is invalid", expected.Version)
	}
	if len(expected.Commit) != 40 || !isLowerHex(expected.Commit) {
		return errors.New("expected commit must be a 40-character lowercase hexadecimal SHA-1")
	}
	target, ok := platformTargets[expected.Platform]
	if !ok {
		return fmt.Errorf("unsupported VMM platform %q", expected.Platform)
	}
	if expected.Target != target {
		return fmt.Errorf("expected target %q does not match platform %q target %q", expected.Target, expected.Platform, target)
	}
	if expected.ArchiveBytes <= 0 || expected.ArchiveBytes > maxArchiveBytes {
		return fmt.Errorf("expected archive size %d is outside the supported range", expected.ArchiveBytes)
	}
	if !digestPattern.MatchString(expected.ArchiveSHA256) {
		return errors.New("expected archive SHA-256 must be 64 lowercase hexadecimal characters")
	}
	return nil
}

// isLowerHex reports whether a string contains only lowercase hexadecimal characters.
// isLowerHex 检查字符串是否仅包含小写十六进制字符。
func isLowerHex(value string) bool {
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return value != ""
}

// validateEmptyStagingRoot resolves and checks the caller-provided empty directory.
// validateEmptyStagingRoot 解析并检查调用方提供的空目录。
func validateEmptyStagingRoot(stagingRoot string) (string, error) {
	if strings.TrimSpace(stagingRoot) == "" {
		return "", errors.New("staging root must not be empty")
	}
	absolute, err := filepath.Abs(stagingRoot)
	if err != nil {
		return "", fmt.Errorf("resolve staging root: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", fmt.Errorf("inspect staging root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("staging root must be a real directory, not a symlink")
	}
	entries, err := os.ReadDir(absolute)
	if err != nil {
		return "", fmt.Errorf("read staging root: %w", err)
	}
	if len(entries) != 0 {
		return "", errors.New("staging root must be empty")
	}
	return absolute, nil
}

// snapshotVerifiedArchive copies a regular input file into a private immutable snapshot while checking its signed digest.
// snapshotVerifiedArchive 将普通输入文件复制到私有不可变快照，并核对其签名摘要。
func snapshotVerifiedArchive(ctx context.Context, archivePath string, expected ExpectedRelease) (*os.File, func(), error) {
	absolute, err := filepath.Abs(archivePath)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve archive path: %w", err)
	}
	pathInfo, err := os.Lstat(absolute)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect archive: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, nil, errors.New("archive input must be a regular file, not a symlink or special file")
	}
	if pathInfo.Size() != expected.ArchiveBytes {
		return nil, nil, fmt.Errorf("archive size is %d bytes, expected %d", pathInfo.Size(), expected.ArchiveBytes)
	}

	source, err := os.Open(absolute)
	if err != nil {
		return nil, nil, fmt.Errorf("open archive: %w", err)
	}
	defer source.Close()
	openedInfo, err := source.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat opened archive: %w", err)
	}
	if !os.SameFile(pathInfo, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Size() != expected.ArchiveBytes {
		return nil, nil, errors.New("archive changed while it was being opened")
	}

	snapshot, err := os.CreateTemp("", "vmmm-verified-archive-*.tmp")
	if err != nil {
		return nil, nil, fmt.Errorf("create verified archive snapshot: %w", err)
	}
	cleanup := func() {
		name := snapshot.Name()
		_ = snapshot.Close()
		_ = os.Remove(name)
	}
	if err := snapshot.Chmod(0o600); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("restrict archive snapshot permissions: %w", err)
	}

	hasher := sha256.New()
	limited := io.LimitReader(&contextReader{ctx: ctx, reader: source}, expected.ArchiveBytes+1)
	written, err := io.Copy(io.MultiWriter(snapshot, hasher), limited)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("copy archive into verified snapshot: %w", err)
	}
	if written != expected.ArchiveBytes {
		cleanup()
		return nil, nil, fmt.Errorf("archive snapshot contains %d bytes, expected %d", written, expected.ArchiveBytes)
	}
	actualDigest := hex.EncodeToString(hasher.Sum(nil))
	if actualDigest != expected.ArchiveSHA256 {
		cleanup()
		return nil, nil, fmt.Errorf("archive SHA-256 mismatch: got %s, want %s", actualDigest, expected.ArchiveSHA256)
	}
	if err := snapshot.Sync(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("sync archive snapshot: %w", err)
	}
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("rewind archive snapshot: %w", err)
	}
	return snapshot, cleanup, nil
}

// contextReader checks cancellation between reads of a large local archive or expanded file.
// contextReader 在读取大型本地压缩包或解压文件时检查取消状态。
type contextReader struct {
	// ctx is the caller's cancellation scope.
	// ctx 是调用方提供的取消上下文。
	ctx context.Context

	// reader is the underlying archive or entry stream.
	// reader 是底层压缩包或条目数据流。
	reader io.Reader
}

// Read forwards one read unless the caller has canceled extraction.
// Read 在调用方取消解包时停止，否则转发一次读取。
func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

// packageDirectoryName returns the sole top-level directory required in a VMM archive.
// packageDirectoryName 返回 VMM 压缩包必须使用的唯一顶层目录名。
func packageDirectoryName(expected ExpectedRelease) string {
	return "vulcan-memory-mesh-" + expected.Version + "-" + expected.Platform
}

// extractAndVerify populates a private package tree, then authenticates its receipt and exact file inventory.
// extractAndVerify 填充私有安装包目录，再认证包内清单和完整文件清单。
func extractAndVerify(ctx context.Context, snapshot *os.File, temporaryPath string, packageName string, expected ExpectedRelease) (Receipt, error) {
	temporaryRoot, err := os.OpenRoot(temporaryPath)
	if err != nil {
		return Receipt{}, fmt.Errorf("open private extraction root: %w", err)
	}
	defer temporaryRoot.Close()
	if err := temporaryRoot.Mkdir(packageName, 0o755); err != nil {
		return Receipt{}, fmt.Errorf("create package directory: %w", err)
	}
	packageRoot, err := temporaryRoot.OpenRoot(packageName)
	if err != nil {
		return Receipt{}, fmt.Errorf("open package directory: %w", err)
	}
	defer packageRoot.Close()

	var inventory map[string]string
	switch expected.Platform {
	case "windows-x64":
		inventory, err = extractZIP(ctx, snapshot, packageRoot, packageName)
	default:
		inventory, err = extractTarGzip(ctx, snapshot, packageRoot, packageName)
	}
	if err != nil {
		return Receipt{}, err
	}

	receiptBytes, err := readReceipt(packageRoot)
	if err != nil {
		return Receipt{}, err
	}
	receipt, err := decodeReceipt(receiptBytes)
	if err != nil {
		return Receipt{}, err
	}
	if err := validateReceipt(receipt, expected); err != nil {
		return Receipt{}, err
	}
	if err := verifyInventory(inventory, receipt.Files); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// readReceipt reads the bounded package receipt through the scoped package root.
// readReceipt 通过受限包根目录读取有大小上限的包内清单。
func readReceipt(root *os.Root) ([]byte, error) {
	info, err := root.Lstat("release-manifest.json")
	if err != nil {
		return nil, fmt.Errorf("package receipt is missing: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxReceiptBytes {
		return nil, errors.New("package receipt must be a non-empty regular file within the size limit")
	}
	file, err := root.Open("release-manifest.json")
	if err != nil {
		return nil, fmt.Errorf("open package receipt: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened package receipt: %w", err)
	}
	if !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() {
		return nil, errors.New("package receipt changed while it was being opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxReceiptBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read package receipt: %w", err)
	}
	if int64(len(data)) > maxReceiptBytes {
		return nil, errors.New("package receipt grew beyond the size limit while being read")
	}
	if int64(len(data)) != info.Size() {
		return nil, errors.New("package receipt changed while it was being read")
	}
	return data, nil
}

// decodeReceipt rejects duplicate JSON keys, unknown fields, and trailing documents before returning a typed receipt.
// decodeReceipt 在返回类型化清单前拒绝重复 JSON 键、未知字段和尾随文档。
func decodeReceipt(data []byte) (Receipt, error) {
	if !utf8.Valid(data) {
		return Receipt{}, errors.New("package receipt is not valid UTF-8")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return Receipt{}, fmt.Errorf("invalid package receipt JSON: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode package receipt: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// rejectDuplicateJSONKeys scans every object so duplicate receipt or files-map keys cannot be hidden by JSON decoding.
// rejectDuplicateJSONKeys 扫描所有对象，避免通过 JSON 解码覆盖重复清单字段或文件映射键。
func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("contains trailing JSON data")
		}
		return err
	}
	return nil
}

// scanJSONValue recursively checks JSON object keys while consuming exactly one JSON value.
// scanJSONValue 递归检查 JSON 对象键，并精确消费一个 JSON 值。
func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxReceiptJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxReceiptJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
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
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		return consumeClosingDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		return consumeClosingDelimiter(decoder, ']')
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

// consumeClosingDelimiter verifies the closing token for a JSON object or array.
// consumeClosingDelimiter 校验 JSON 对象或数组的结束标记。
func consumeClosingDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != expected {
		return fmt.Errorf("unexpected JSON delimiter %v, want %q", token, expected)
	}
	return nil
}

// ensureJSONEnd rejects any second JSON value after the decoded receipt.
// ensureJSONEnd 拒绝已解码清单之后出现的第二个 JSON 值。
func ensureJSONEnd(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("package receipt contains trailing JSON data")
		}
		return fmt.Errorf("read package receipt end: %w", err)
	}
	return nil
}

// validateReceipt matches package identity and enforces the manager-supported receipt and capability contract.
// validateReceipt 匹配包身份，并强制执行管理器支持的清单和能力契约。
func validateReceipt(receipt Receipt, expected ExpectedRelease) error {
	if receipt.ManifestSchema != ManifestSchemaVersion {
		return fmt.Errorf("package receipt schema is %d, want %d", receipt.ManifestSchema, ManifestSchemaVersion)
	}
	if receipt.Version != expected.Version || receipt.Commit != expected.Commit || receipt.Platform != expected.Platform {
		return fmt.Errorf("package receipt identity does not match expected release %s at %s for %s", expected.Version, expected.Commit, expected.Platform)
	}
	if receipt.Target != expected.Target {
		return fmt.Errorf("package receipt target %q does not match expected target %q", receipt.Target, expected.Target)
	}
	if receipt.StorageMode != StorageModeNative {
		return fmt.Errorf("package default storage mode is %q, want %q", receipt.StorageMode, StorageModeNative)
	}
	if receipt.StorageProfile != "all" {
		return fmt.Errorf("package storage profile is %q, want all", receipt.StorageProfile)
	}
	if err := validateCapabilities(receipt.Capabilities); err != nil {
		return err
	}
	if len(receipt.Files) == 0 {
		return errors.New("package receipt files map must not be empty")
	}
	return validateReceiptFiles(receipt.Files)
}

// validateCapabilities accepts only known modes, providers, flavors, and consistent combined-mode metadata.
// validateCapabilities 仅接受已知模式、提供方、类型以及一致的组合模式元数据。
func validateCapabilities(capabilities Capabilities) error {
	if capabilities.SchemaVersion != 1 {
		return fmt.Errorf("unsupported storage capability schema version %d", capabilities.SchemaVersion)
	}
	if len(capabilities.StorageModes) == 0 {
		return errors.New("storage capabilities must list at least one mode")
	}
	allowedModes := map[StorageMode]struct{}{
		StorageModeSplit: {}, StorageModeController: {}, StorageModeNative: {}, StorageModeCombined: {},
	}
	seenModes := make(map[StorageMode]struct{}, len(capabilities.StorageModes))
	combinedListed := false
	for _, mode := range capabilities.StorageModes {
		if _, ok := allowedModes[mode]; !ok {
			return fmt.Errorf("unsupported storage mode capability %q", mode)
		}
		if _, exists := seenModes[mode]; exists {
			return fmt.Errorf("duplicate storage mode capability %q", mode)
		}
		seenModes[mode] = struct{}{}
		combinedListed = combinedListed || mode == StorageModeCombined
	}
	if combinedListed != (capabilities.Combined != nil) {
		return errors.New("combined capability metadata must exist exactly when combined mode is listed")
	}
	if capabilities.Combined == nil {
		return nil
	}
	if capabilities.Combined.Provider != "postgres" {
		return fmt.Errorf("unsupported combined storage provider %q", capabilities.Combined.Provider)
	}
	if len(capabilities.Combined.Flavors) == 0 {
		return errors.New("combined storage capabilities must list at least one flavor")
	}
	allowedFlavors := map[string]struct{}{"standard": {}, "paradedb": {}}
	seenFlavors := make(map[string]struct{}, len(capabilities.Combined.Flavors))
	for _, flavor := range capabilities.Combined.Flavors {
		if _, ok := allowedFlavors[flavor]; !ok {
			return fmt.Errorf("unsupported combined storage flavor %q", flavor)
		}
		if _, exists := seenFlavors[flavor]; exists {
			return fmt.Errorf("duplicate combined storage flavor %q", flavor)
		}
		seenFlavors[flavor] = struct{}{}
	}
	return nil
}

// validateReceiptFiles checks portable relative paths and lowercase SHA-256 values from the receipt.
// validateReceiptFiles 校验清单中的可移植相对路径和小写 SHA-256 摘要。
func validateReceiptFiles(files map[string]string) error {
	if len(files) > maxArchiveEntries {
		return fmt.Errorf("package receipt lists more than %d files", maxArchiveEntries)
	}
	folded := make(map[string]string, len(files))
	for name, digest := range files {
		if err := validateRelativeFilePath(name); err != nil {
			return fmt.Errorf("invalid receipt file path %q: %w", name, err)
		}
		if name == "release-manifest.json" {
			return errors.New("package receipt must not list itself in files")
		}
		key := strings.ToLower(name)
		if previous, exists := folded[key]; exists && previous != name {
			return fmt.Errorf("receipt file paths %q and %q collide by case", previous, name)
		}
		folded[key] = name
		if !digestPattern.MatchString(digest) {
			return fmt.Errorf("receipt file %q has an invalid SHA-256 digest", name)
		}
	}
	return nil
}

// verifyInventory requires an exact path set and digest match between extracted files and the package receipt.
// verifyInventory 要求解出文件集合及摘要与包内清单完全一致。
func verifyInventory(actual map[string]string, expected map[string]string) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("package contains %d payload files, receipt lists %d", len(actual), len(expected))
	}
	for name, expectedDigest := range expected {
		actualDigest, ok := actual[name]
		if !ok {
			return fmt.Errorf("receipt file %q is missing from the archive", name)
		}
		if actualDigest != expectedDigest {
			return fmt.Errorf("package file %q SHA-256 mismatch: got %s, want %s", name, actualDigest, expectedDigest)
		}
	}
	for name := range actual {
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("archive contains unlisted package file %q", name)
		}
	}
	return nil
}

// entryTracker rejects duplicate, conflicting, and case-colliding archive paths while accounting expanded bytes.
// entryTracker 在累计解压字节时拒绝重复、冲突和大小写碰撞路径。
type entryTracker struct {
	// packageName is the required exact top-level directory.
	// packageName 是必须精确匹配的顶层目录。
	packageName string

	// explicit records archive entries to reject repeated directory and file headers.
	// explicit 记录压缩包条目，用于拒绝重复的目录和文件头。
	explicit map[string]struct{}

	// nodes records file and directory kinds, including directories implied by child files.
	// nodes 记录文件和目录类型，包括由子文件隐含的目录。
	nodes map[string]bool

	// folded records canonical ASCII lowercase paths to detect Windows case collisions.
	// folded 记录规范化 ASCII 小写路径，用于检测 Windows 大小写碰撞。
	folded map[string]string

	// count is the number of archive entries already inspected.
	// count 是已经检查的压缩包条目数。
	count int

	// expanded is the total uncompressed file payload size.
	// expanded 是文件负载的解压后总字节数。
	expanded uint64
}

// newEntryTracker creates the path inventory for one archive.
// newEntryTracker 为一个压缩包创建路径清单校验器。
func newEntryTracker(packageName string) *entryTracker {
	return &entryTracker{
		packageName: packageName,
		explicit:    make(map[string]struct{}),
		nodes:       make(map[string]bool),
		folded:      make(map[string]string),
	}
}

// addPath validates one normalized package-relative path and its directory or file type.
// addPath 校验一个规范化包内相对路径及其目录或文件类型。
func (tracker *entryTracker) addPath(relative string, isDirectory bool, expandedSize uint64) error {
	tracker.count++
	if tracker.count > maxArchiveEntries {
		return fmt.Errorf("archive has more than %d entries", maxArchiveEntries)
	}
	if expandedSize > uint64(maxExpandedBytes) || tracker.expanded > uint64(maxExpandedBytes)-expandedSize {
		return fmt.Errorf("archive expands beyond %d bytes", maxExpandedBytes)
	}
	tracker.expanded += expandedSize

	if relative == "" {
		if !isDirectory {
			return errors.New("archive top-level package entry must be a directory")
		}
		if _, exists := tracker.explicit[""]; exists {
			return errors.New("archive contains a duplicate top-level directory entry")
		}
		tracker.explicit[""] = struct{}{}
		return tracker.recordFolded(tracker.packageName, tracker.packageName)
	}
	if err := validateRelativeFilePath(relative); err != nil {
		return err
	}
	if _, exists := tracker.explicit[relative]; exists {
		return fmt.Errorf("archive contains duplicate path %q", relative)
	}
	tracker.explicit[relative] = struct{}{}

	parts := strings.Split(relative, "/")
	for index := 1; index < len(parts); index++ {
		parent := strings.Join(parts[:index], "/")
		if err := tracker.recordFolded(path.Join(tracker.packageName, parent), path.Join(tracker.packageName, parent)); err != nil {
			return err
		}
		if isFile, exists := tracker.nodes[parent]; exists && isFile {
			return fmt.Errorf("archive path %q is nested below a file", relative)
		}
		tracker.nodes[parent] = false
	}
	fullName := path.Join(tracker.packageName, relative)
	if err := tracker.recordFolded(fullName, fullName); err != nil {
		return err
	}
	if existingFile, exists := tracker.nodes[relative]; exists {
		if existingFile || !isDirectory {
			return fmt.Errorf("archive path %q is duplicated or both a file and directory", relative)
		}
	}
	tracker.nodes[relative] = !isDirectory
	return nil
}

// recordFolded stores one path and rejects another spelling with the same ASCII case-insensitive form.
// recordFolded 记录路径并拒绝 ASCII 大小写不敏感形式相同的其他拼写。
func (tracker *entryTracker) recordFolded(key string, display string) error {
	folded := strings.ToLower(key)
	if previous, exists := tracker.folded[folded]; exists && previous != display {
		return fmt.Errorf("archive paths %q and %q collide by case", previous, display)
	}
	tracker.folded[folded] = display
	return nil
}

// normalizeArchivePath validates one archive name and strips the required top-level directory.
// normalizeArchivePath 校验压缩包条目名并去掉要求的顶层目录。
func normalizeArchivePath(name string, isDirectory bool, packageName string) (string, error) {
	if !utf8.ValidString(name) {
		return "", errors.New("archive path is not valid UTF-8")
	}
	if name == "" || len(name) > 4096 {
		return "", errors.New("archive path is empty or too long")
	}
	if strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("archive path %q contains an absolute, backslash, or colon form", name)
	}
	if strings.HasSuffix(name, "/") {
		if !isDirectory {
			return "", fmt.Errorf("regular file path %q has a trailing slash", name)
		}
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" || strings.Contains(name, "//") {
		return "", fmt.Errorf("archive path %q contains an empty component", name)
	}
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("archive path %q contains a traversal component", name)
		}
		if len(part) > 255 || !safePathComponent(part) {
			return "", fmt.Errorf("archive path component %q is not portable", part)
		}
		if isWindowsDeviceName(part) {
			return "", fmt.Errorf("archive path component %q is a reserved Windows device name", part)
		}
	}
	if parts[0] != packageName {
		return "", fmt.Errorf("archive path %q is outside the expected top-level directory %q", name, packageName)
	}
	if len(parts) == 1 {
		if !isDirectory {
			return "", errors.New("archive package root entry must be a directory")
		}
		return "", nil
	}
	return strings.Join(parts[1:], "/"), nil
}

// safePathComponent permits portable ASCII names while excluding control, separator, and platform-specific syntax.
// safePathComponent 仅允许可移植 ASCII 名称，并排除控制字符、分隔符和平台专用语法。
func safePathComponent(component string) bool {
	if strings.HasSuffix(component, ".") {
		return false
	}
	for _, char := range component {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

// isWindowsDeviceName rejects reserved Windows device basenames on every host platform.
// isWindowsDeviceName 在所有宿主平台上拒绝 Windows 保留设备名称。
func isWindowsDeviceName(component string) bool {
	base := strings.ToUpper(strings.SplitN(component, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return true
	}
	return false
}

// validateRelativeFilePath applies archive portability rules to a receipt path without a package-root prefix.
// validateRelativeFilePath 对不带包根目录前缀的清单路径应用压缩包可移植性规则。
func validateRelativeFilePath(relative string) error {
	if relative == "" || len(relative) > 4096 || strings.ContainsAny(relative, "\\:\x00") || strings.HasPrefix(relative, "/") || strings.Contains(relative, "//") {
		return errors.New("path is empty, too long, absolute, or contains a forbidden separator")
	}
	for _, component := range strings.Split(relative, "/") {
		if component == "" || component == "." || component == ".." || len(component) > 255 || !safePathComponent(component) {
			return fmt.Errorf("path component %q is not portable", component)
		}
		if isWindowsDeviceName(component) {
			return fmt.Errorf("path component %q is a reserved Windows device name", component)
		}
	}
	if path.Clean(relative) != relative {
		return errors.New("path is not in canonical slash-separated form")
	}
	return nil
}

// extractZIP validates ZIP metadata before writing any entry into the private package tree.
// extractZIP 在向私有安装包目录写入条目前先校验 ZIP 元数据。
func extractZIP(ctx context.Context, snapshot *os.File, root *os.Root, packageName string) (map[string]string, error) {
	info, err := snapshot.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat ZIP snapshot: %w", err)
	}
	reader, err := zip.NewReader(snapshot, info.Size())
	if err != nil {
		return nil, fmt.Errorf("open ZIP archive: %w", err)
	}
	if len(reader.File) == 0 || len(reader.File) > maxArchiveEntries {
		return nil, fmt.Errorf("ZIP archive entry count %d is outside the supported range", len(reader.File))
	}
	tracker := newEntryTracker(packageName)
	for _, entry := range reader.File {
		if err := validateZIPEntry(entry, tracker, packageName); err != nil {
			return nil, err
		}
	}

	inventory := make(map[string]string, len(reader.File))
	for _, entry := range reader.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		isDirectory := entry.FileInfo().IsDir()
		relative, err := normalizeArchivePath(entry.Name, isDirectory, packageName)
		if err != nil {
			return nil, err
		}
		if relative == "" {
			continue
		}
		if isDirectory {
			if err := root.MkdirAll(relative, 0o755); err != nil {
				return nil, fmt.Errorf("create archive directory %q: %w", relative, err)
			}
			continue
		}
		stream, err := entry.Open()
		if err != nil {
			return nil, fmt.Errorf("open ZIP entry %q: %w", relative, err)
		}
		digest, extractErr := writeRegularFile(ctx, root, relative, int64(entry.UncompressedSize64), entry.Mode(), stream)
		closeErr := stream.Close()
		if extractErr != nil {
			return nil, fmt.Errorf("extract ZIP entry %q: %w", relative, extractErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close ZIP entry %q: %w", relative, closeErr)
		}
		if relative != "release-manifest.json" {
			inventory[relative] = digest
		}
	}
	return inventory, nil
}

// validateZIPEntry checks ZIP type, encryption, compression, path, and expanded-size metadata.
// validateZIPEntry 校验 ZIP 条目类型、加密、压缩方式、路径和展开大小元数据。
func validateZIPEntry(entry *zip.File, tracker *entryTracker, packageName string) error {
	if entry.Flags&1 != 0 {
		return fmt.Errorf("ZIP entry %q is encrypted", entry.Name)
	}
	if entry.Method != zip.Store && entry.Method != zip.Deflate {
		return fmt.Errorf("ZIP entry %q uses unsupported compression method %d", entry.Name, entry.Method)
	}
	isDirectory := entry.FileInfo().IsDir()
	if strings.HasSuffix(entry.Name, "/") != isDirectory {
		return fmt.Errorf("ZIP entry %q has inconsistent directory metadata", entry.Name)
	}
	mode := entry.Mode()
	if isDirectory {
		if entry.UncompressedSize64 != 0 || entry.CompressedSize64 != 0 {
			return fmt.Errorf("ZIP directory %q contains data", entry.Name)
		}
		if mode&os.ModeType != 0 && !mode.IsDir() {
			return fmt.Errorf("ZIP directory %q has a special file type", entry.Name)
		}
	} else if mode&os.ModeType != 0 && !mode.IsRegular() {
		return fmt.Errorf("ZIP entry %q is not a regular file", entry.Name)
	}
	if entry.UncompressedSize64 > uint64(maxExpandedBytes) {
		return fmt.Errorf("ZIP entry %q exceeds the expanded-size limit", entry.Name)
	}
	relative, err := normalizeArchivePath(entry.Name, isDirectory, packageName)
	if err != nil {
		return err
	}
	return tracker.addPath(relative, isDirectory, entry.UncompressedSize64)
}

// extractTarGzip streams a bounded gzip-compressed tar archive and rejects all non-file entry types.
// extractTarGzip 流式处理有界 gzip tar 压缩包，并拒绝所有非普通文件条目类型。
func extractTarGzip(ctx context.Context, snapshot *os.File, root *os.Root, packageName string) (map[string]string, error) {
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind tar.gz snapshot: %w", err)
	}
	buffered := bufio.NewReader(snapshot)
	gzipReader, err := gzip.NewReader(buffered)
	if err != nil {
		return nil, fmt.Errorf("open gzip archive: %w", err)
	}
	gzipReader.Multistream(false)
	limited := &io.LimitedReader{R: gzipReader, N: maxExpandedBytes + maxTarOverhead}
	tarReader := tar.NewReader(limited)
	tracker := newEntryTracker(packageName)
	inventory := make(map[string]string)

	for {
		if err := ctx.Err(); err != nil {
			_ = gzipReader.Close()
			return nil, err
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = gzipReader.Close()
			return nil, fmt.Errorf("read tar entry: %w", err)
		}
		isDirectory := header.Typeflag == tar.TypeDir
		isRegular := header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA
		if !isDirectory && !isRegular {
			_ = gzipReader.Close()
			return nil, fmt.Errorf("tar entry %q has unsupported type %d", header.Name, header.Typeflag)
		}
		if header.Linkname != "" {
			_ = gzipReader.Close()
			return nil, fmt.Errorf("tar entry %q has an unexpected link target", header.Name)
		}
		if header.Size < 0 || (isDirectory && header.Size != 0) {
			_ = gzipReader.Close()
			return nil, fmt.Errorf("tar entry %q has invalid size %d", header.Name, header.Size)
		}
		if header.Size > maxExpandedBytes {
			_ = gzipReader.Close()
			return nil, fmt.Errorf("tar entry %q exceeds the expanded-size limit", header.Name)
		}
		relative, err := normalizeArchivePath(header.Name, isDirectory, packageName)
		if err != nil {
			_ = gzipReader.Close()
			return nil, err
		}
		if err := tracker.addPath(relative, isDirectory, uint64(header.Size)); err != nil {
			_ = gzipReader.Close()
			return nil, err
		}
		if relative == "" {
			continue
		}
		if isDirectory {
			if err := root.MkdirAll(relative, 0o755); err != nil {
				_ = gzipReader.Close()
				return nil, fmt.Errorf("create tar directory %q: %w", relative, err)
			}
			continue
		}
		digest, err := writeRegularFile(ctx, root, relative, header.Size, os.FileMode(header.Mode), tarReader)
		if err != nil {
			_ = gzipReader.Close()
			return nil, fmt.Errorf("extract tar entry %q: %w", relative, err)
		}
		if relative != "release-manifest.json" {
			inventory[relative] = digest
		}
	}

	if limited.N == 0 {
		_ = gzipReader.Close()
		return nil, errors.New("tar stream exceeds the expanded metadata limit")
	}
	trailing, err := io.ReadAll(io.LimitReader(gzipReader, maxTarOverhead+1))
	if err != nil {
		_ = gzipReader.Close()
		return nil, fmt.Errorf("verify gzip trailer: %w", err)
	}
	if int64(len(trailing)) > maxTarOverhead {
		_ = gzipReader.Close()
		return nil, errors.New("tar archive has excessive trailing data")
	}
	for _, value := range trailing {
		if value != 0 {
			_ = gzipReader.Close()
			return nil, errors.New("tar archive has non-zero data after its end markers")
		}
	}
	if _, err := buffered.Peek(1); !errors.Is(err, io.EOF) {
		_ = gzipReader.Close()
		if err == nil {
			return nil, errors.New("tar archive contains trailing compressed data or a second gzip member")
		}
		return nil, fmt.Errorf("inspect gzip trailing bytes: %w", err)
	}
	if err := gzipReader.Close(); err != nil {
		return nil, fmt.Errorf("close gzip archive: %w", err)
	}
	return inventory, nil
}

// writeRegularFile creates one exclusive file, hashes bytes while writing, and preserves safe executable permission bits.
// writeRegularFile 以独占方式创建文件，边写入边计算摘要，并保留安全的可执行权限位。
func writeRegularFile(ctx context.Context, root *os.Root, relative string, size int64, archivedMode os.FileMode, source io.Reader) (string, error) {
	if size < 0 || size > maxExpandedBytes {
		return "", fmt.Errorf("file size %d is outside the supported range", size)
	}
	parent := path.Dir(relative)
	if parent != "." {
		if err := root.MkdirAll(parent, 0o755); err != nil {
			return "", fmt.Errorf("create parent directory: %w", err)
		}
	}
	file, err := root.OpenFile(relative, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create output file: %w", err)
	}
	removePartial := func() { _ = root.Remove(relative) }
	hasher := sha256.New()
	written, copyErr := io.CopyN(io.MultiWriter(file, hasher), &contextReader{ctx: ctx, reader: source}, size)
	if copyErr != nil {
		_ = file.Close()
		removePartial()
		return "", fmt.Errorf("write %d of %d bytes: %w", written, size, copyErr)
	}
	var extra [1]byte
	read, extraErr := io.ReadFull(&contextReader{ctx: ctx, reader: source}, extra[:])
	if read != 0 || !errors.Is(extraErr, io.EOF) {
		_ = file.Close()
		removePartial()
		if extraErr == nil {
			return "", errors.New("entry contains bytes beyond its declared size")
		}
		return "", fmt.Errorf("verify entry end: %w", extraErr)
	}
	// Keep executable bits for Unix binaries while ensuring the packaged service account can read staged assets.
	// 保留 Unix 二进制的可执行位，同时确保安装后的服务账户可以读取暂存资源。
	mode := (archivedMode.Perm() & 0o111) | 0o644
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		removePartial()
		return "", fmt.Errorf("set safe output permissions: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		removePartial()
		return "", fmt.Errorf("sync output file: %w", err)
	}
	if err := file.Close(); err != nil {
		removePartial()
		return "", fmt.Errorf("close output file: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
