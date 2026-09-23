// Package download defines trusted GitHub release sources and exact release URL construction.
// download 包负责定义受信任的 GitHub Release 源，并按唯一规则构造 Release URL。
package download

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// SourceKind identifies how a source reaches an OpenVulcan GitHub release.
// SourceKind 标识下载源访问 OpenVulcan GitHub Release 的方式。
type SourceKind string

const (
	// SourceKindOfficial addresses GitHub directly without a proxy prefix.
	// SourceKindOfficial 表示直接访问 GitHub，不使用代理前缀。
	SourceKindOfficial SourceKind = "github-official"

	// SourceKindProxy prepends an HTTPS GitHub proxy prefix to an exact URL.
	// SourceKindProxy 表示把 HTTPS GitHub 代理前缀拼接到固定 URL 前面。
	SourceKindProxy SourceKind = "github-proxy"
)

// SourceID is the stable identifier used by configuration and TUI selections.
// SourceID 是配置和 TUI 选择项使用的稳定标识符。
type SourceID string

const (
	// SourceIDGitHubOfficial identifies the official GitHub source.
	// SourceIDGitHubOfficial 标识 GitHub 官方源。
	SourceIDGitHubOfficial SourceID = "github-official"

	// SourceIDGhproxyNet identifies the ghproxy.net source.
	// SourceIDGhproxyNet 标识 ghproxy.net 源。
	SourceIDGhproxyNet SourceID = "github-proxy-ghproxy-net"

	// SourceIDGhProxyOrg identifies the gh-proxy.org source.
	// SourceIDGhProxyOrg 标识 gh-proxy.org 源。
	SourceIDGhProxyOrg SourceID = "github-proxy-gh-proxy-org"

	// SourceIDGhfastTop identifies the ghfast.top source.
	// SourceIDGhfastTop 标识 ghfast.top 源。
	SourceIDGhfastTop SourceID = "github-proxy-ghfast-top"
)

// Repository is an allowlisted OpenVulcan GitHub repository.
// Repository 是允许访问的 OpenVulcan GitHub 仓库。
type Repository string

const (
	// RepositoryManager is the standalone manager repository.
	// RepositoryManager 是独立管理器仓库。
	RepositoryManager Repository = "vulcan-memory-mesh-manager"

	// RepositoryVMM is the Vulcan Memory Mesh runtime repository.
	// RepositoryVMM 是 Vulcan Memory Mesh 运行时仓库。
	RepositoryVMM Repository = "vulcan-memory-mesh"
)

const (
	// GitHubOwner is the only GitHub owner accepted by release URL construction.
	// GitHubOwner 是 Release URL 构造唯一接受的 GitHub 所有者。
	GitHubOwner = "OpenVulcan"

	// VMMProbeTag is the immutable VMM release used for source health probing.
	// VMMProbeTag 是下载源健康探测使用的固定 VMM 版本。
	VMMProbeTag = "v0.1.0"

	// VMMProbeChecksumAsset is the fixed checksum asset used by source probes.
	// VMMProbeChecksumAsset 是下载源探测使用的固定摘要文件名。
	VMMProbeChecksumAsset = "SHA256SUMS"

	// VMMProbeArchiveAsset is the fixed Windows archive sampled by source probes.
	// VMMProbeArchiveAsset 是下载源探测抽样的固定 Windows 压缩包文件名。
	VMMProbeArchiveAsset = "vulcan-memory-mesh-v0.1.0-windows-x64.zip"
)

const (
	// OfficialGitHubPrefix is the canonical direct GitHub release prefix.
	// OfficialGitHubPrefix 是直接访问 GitHub Release 的规范前缀。
	OfficialGitHubPrefix = "https://github.com/"

	// GhproxyNetPrefix is the configured ghproxy.net GitHub proxy prefix.
	// GhproxyNetPrefix 是配置的 ghproxy.net GitHub 代理前缀。
	GhproxyNetPrefix = "https://ghproxy.net/"

	// GhProxyOrgPrefix is the configured gh-proxy.org GitHub proxy prefix.
	// GhProxyOrgPrefix 是配置的 gh-proxy.org GitHub 代理前缀。
	GhProxyOrgPrefix = "https://gh-proxy.org/"

	// GhfastTopPrefix is the configured ghfast.top GitHub proxy prefix.
	// GhfastTopPrefix 是配置的 ghfast.top GitHub 代理前缀。
	GhfastTopPrefix = "https://ghfast.top/"
)

const (
	// expectedProbeChecksumSHA256 is the official SHA-256 of the fixed VMM checksum asset.
	// expectedProbeChecksumSHA256 是固定 VMM 摘要文件的官方 SHA-256。
	expectedProbeChecksumSHA256 = "ca8101f845b10dfd0e60d02b6f88abc89143e12ea20cc1968873bd8822bc6763"

	// expectedProbeChecksumSize is the exact byte size of the fixed VMM checksum asset.
	// expectedProbeChecksumSize 是固定 VMM 摘要文件的精确字节数。
	expectedProbeChecksumSize int64 = 1093

	// expectedProbeArchiveSize is the exact byte size advertised for the fixed Windows archive.
	// expectedProbeArchiveSize 是固定 Windows 压缩包应声明的精确字节数。
	expectedProbeArchiveSize int64 = 123238027

	// probeArchiveSampleSize is the byte count used to check an archive header.
	// probeArchiveSampleSize 是检查压缩包文件头使用的字节数。
	probeArchiveSampleSize int64 = 1024
)

// Source describes one exact download source and its stable configuration identity.
// Source 描述一个精确下载源及其稳定的配置标识。
type Source struct {
	// ID is the stable identifier persisted by the manager.
	// ID 是管理器持久化使用的稳定标识符。
	ID SourceID

	// Name is the display name shown by the TUI.
	// Name 是 TUI 展示的名称。
	Name string

	// Kind selects direct GitHub or proxy URL construction.
	// Kind 选择直接 GitHub 访问或代理 URL 构造方式。
	Kind SourceKind

	// Prefix is the exact HTTPS prefix used for this source.
	// Prefix 是该源使用的精确 HTTPS 前缀。
	Prefix string
}

// DefaultSources returns the built-in official source and three observed proxy sources.
// DefaultSources 返回内置官方源和三个已探测代理源。
func DefaultSources() []Source {
	return []Source{
		{ID: SourceIDGitHubOfficial, Name: "GitHub 官方", Kind: SourceKindOfficial, Prefix: OfficialGitHubPrefix},
		{ID: SourceIDGhproxyNet, Name: "ghproxy.net", Kind: SourceKindProxy, Prefix: GhproxyNetPrefix},
		{ID: SourceIDGhProxyOrg, Name: "gh-proxy.org", Kind: SourceKindProxy, Prefix: GhProxyOrgPrefix},
		{ID: SourceIDGhfastTop, Name: "ghfast.top", Kind: SourceKindProxy, Prefix: GhfastTopPrefix},
	}
}

// NewCustomProxy validates an HTTPS GitHub proxy prefix and assigns a stable derived ID.
// NewCustomProxy 校验 HTTPS GitHub 代理前缀，并为其分配稳定的派生 ID。
func NewCustomProxy(prefix string) (Source, error) {
	if err := validateProxyPrefix(prefix); err != nil {
		return Source{}, err
	}

	digest := sha256.Sum256([]byte(prefix))
	return Source{
		ID:     SourceID("github-proxy-custom-" + hex.EncodeToString(digest[:])[:12]),
		Name:   "自定义 GitHub 代理",
		Kind:   SourceKindProxy,
		Prefix: prefix,
	}, nil
}

// Validate checks that a source has a safe, internally consistent URL construction policy.
// Validate 检查下载源是否具有安全且内部一致的 URL 构造策略。
func (s Source) Validate() error {
	if err := validateSourceID(s.ID); err != nil {
		return err
	}
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("download source name must not be empty")
	}

	switch s.Kind {
	case SourceKindOfficial:
		if s.Prefix != OfficialGitHubPrefix {
			return fmt.Errorf("official source must use prefix %q", OfficialGitHubPrefix)
		}
	case SourceKindProxy:
		if err := validateProxyPrefix(s.Prefix); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported download source kind %q", s.Kind)
	}
	return nil
}

// BuildReleaseURL constructs exactly one allowlisted GitHub release URL for a source.
// BuildReleaseURL 为下载源精确构造唯一一个允许的 GitHub Release URL。
func BuildReleaseURL(source Source, repository Repository, tag string, filename string) (string, error) {
	if err := source.Validate(); err != nil {
		return "", err
	}
	if repository != RepositoryManager && repository != RepositoryVMM {
		return "", fmt.Errorf("repository %q is not allowlisted", repository)
	}
	if err := validateReleaseComponent("tag", tag); err != nil {
		return "", err
	}
	if err := validateReleaseComponent("filename", filename); err != nil {
		return "", err
	}

	releasePath := GitHubOwner + "/" + string(repository) + "/releases/download/" + tag + "/" + filename
	if source.Kind == SourceKindOfficial {
		return source.Prefix + releasePath, nil
	}
	return source.Prefix + OfficialGitHubPrefix + releasePath, nil
}

// ExpectedProbeChecksumSHA256 exposes the immutable checksum expected by source probes.
// ExpectedProbeChecksumSHA256 暴露下载源探测使用的固定摘要值。
func ExpectedProbeChecksumSHA256() string {
	return expectedProbeChecksumSHA256
}

// ExpectedProbeChecksumSize exposes the immutable checksum asset size expected by probes.
// ExpectedProbeChecksumSize 暴露下载源探测使用的固定摘要文件大小。
func ExpectedProbeChecksumSize() int64 {
	return expectedProbeChecksumSize
}

// ExpectedProbeArchiveSize exposes the immutable archive size expected by source probes.
// ExpectedProbeArchiveSize 暴露下载源探测使用的固定压缩包大小。
func ExpectedProbeArchiveSize() int64 {
	return expectedProbeArchiveSize
}

// validateProxyPrefix enforces the single accepted custom proxy URL spelling.
// validateProxyPrefix 强制执行唯一接受的自定义代理 URL 写法。
func validateProxyPrefix(prefix string) error {
	if prefix == "" || strings.TrimSpace(prefix) != prefix {
		return errors.New("proxy prefix must not be empty or contain surrounding whitespace")
	}
	if strings.ContainsAny(prefix, "\\\r\n\t") {
		return errors.New("proxy prefix contains forbidden control characters or backslash")
	}

	parsed, err := url.Parse(prefix)
	if err != nil {
		return fmt.Errorf("invalid proxy prefix: %w", err)
	}
	if parsed.Scheme != "https" {
		return errors.New("proxy prefix must use HTTPS")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return errors.New("proxy prefix must include a host")
	}
	if parsed.User != nil {
		return errors.New("proxy prefix must not contain user information")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("proxy prefix must not contain a query or fragment")
	}
	if !strings.HasSuffix(parsed.EscapedPath(), "/") {
		return errors.New("proxy prefix must end with /")
	}
	if hasPathTraversal(parsed.Path) || hasPathTraversal(parsed.RawPath) {
		return errors.New("proxy prefix must not contain path traversal")
	}
	return nil
}

// validateSourceID keeps persisted source identifiers deterministic and path-safe.
// validateSourceID 保证持久化源标识符确定且不会成为路径片段。
func validateSourceID(id SourceID) error {
	value := string(id)
	if value == "" {
		return errors.New("download source ID must not be empty")
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("-_", r) {
			continue
		}
		return fmt.Errorf("download source ID contains forbidden character %q", r)
	}
	return nil
}

// validateReleaseComponent rejects ambiguous path components before exact concatenation.
// validateReleaseComponent 在精确拼接前拒绝含糊的路径片段。
func validateReleaseComponent(name string, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if value == "." || value == ".." || strings.Contains(value, "..") {
		return fmt.Errorf("%s must not contain path traversal", name)
	}
	if strings.ContainsAny(value, "/\\?#%") {
		return fmt.Errorf("%s must be one URL path component", name)
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%s must not contain whitespace or control characters", name)
		}
	}
	return nil
}

// hasPathTraversal detects literal and percent-decoded dot path components.
// hasPathTraversal 检查字面和百分号解码后的点路径片段。
func hasPathTraversal(path string) bool {
	if path == "" {
		return false
	}
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return true
	}
	for _, candidate := range []string{path, decoded} {
		for _, segment := range strings.Split(candidate, "/") {
			if segment == "." || segment == ".." {
				return true
			}
		}
	}
	return false
}
