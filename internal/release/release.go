// Package release discovers and authenticates VMMM and VMM releases.
// release 包负责发现并认证 VMMM 与 VMM 的发行版本。
// It is called before an artifact is downloaded, extracted, or installed.
// 它在任何发行资产下载、解包或安装之前被调用。
package release

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/download"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/manifest"
)

const (
	// manifestFilename is the signed release metadata filename shared by both products.
	// manifestFilename 是两个产品共用的已签名发行元数据文件名。
	manifestFilename = "manifest.json"

	// signatureFilename is the detached signature filename paired with manifestFilename.
	// signatureFilename 是与 manifestFilename 配对的分离签名文件名。
	signatureFilename = "manifest.sig"

	// maxManifestBytes bounds untrusted metadata before JSON parsing can allocate more memory.
	// maxManifestBytes 在解析 JSON 前限制不可信元数据的大小，避免无界内存分配。
	maxManifestBytes int64 = 1 << 20

	// maxSignatureBytes bounds the detached signature envelope received from a source.
	// maxSignatureBytes 限制从下载源接收的分离签名封装大小。
	maxSignatureBytes int64 = 64 << 10

	// perRequestTimeout bounds each metadata request even when the caller gives no deadline.
	// perRequestTimeout 即使调用方没有设置截止时间，也限制每个元数据请求。
	perRequestTimeout = 30 * time.Second

	// discoveryTimeout bounds the complete manifest and signature pair acquisition.
	// discoveryTimeout 限制清单与签名这一对元数据的完整获取过程。
	discoveryTimeout = 60 * time.Second
)

// SelectorKind identifies whether a release lookup uses latest or one exact tag.
// SelectorKind 标识发行版本查询使用 latest 还是一个精确标签。
type SelectorKind string

const (
	// SelectorLatest asks the selected source for its latest release assets.
	// SelectorLatest 要求选定下载源返回 latest 发行资产。
	SelectorLatest SelectorKind = "latest"

	// SelectorTag asks the selected source for assets belonging to one exact tag.
	// SelectorTag 要求选定下载源返回一个精确标签对应的资产。
	SelectorTag SelectorKind = "tag"
)

// Selector describes the immutable release selection requested by the caller.
// Selector 描述调用方请求的不可变发行版本选择。
type Selector struct {
	// Kind selects latest or exact-tag URL construction.
	// Kind 选择 latest 或精确标签的 URL 构造方式。
	Kind SelectorKind

	// Tag is required for SelectorTag and must be empty for SelectorLatest.
	// Tag 在 SelectorTag 时必填，在 SelectorLatest 时必须为空。
	Tag string
}

// Latest returns a selector that resolves the selected source's latest release.
// Latest 返回解析选定下载源最新发行版本的选择器。
func Latest() Selector {
	return Selector{Kind: SelectorLatest}
}

// ExactTag returns a selector for one release tag.
// ExactTag 返回一个发行标签的精确选择器。
func ExactTag(tag string) Selector {
	return Selector{Kind: SelectorTag, Tag: tag}
}

// Request contains all caller-provided inputs for one authenticated lookup.
// Request 包含一次已认证发行版本查询所需的全部调用方输入。
type Request struct {
	// Product fixes the product-to-repository mapping before any URL is built.
	// Product 在构造 URL 前固定产品到代码仓库的映射。
	Product string

	// Selector chooses latest or one exact tag from Source.
	// Selector 从 Source 中选择 latest 或一个精确标签。
	Selector Selector

	// Source is the one user-selected source; discovery never falls back to another source.
	// Source 是用户选定的唯一下载源；发现流程不会自动回退到其他源。
	Source download.Source

	// TrustKeys is the injected fixed trust root for detached Ed25519 signatures.
	// TrustKeys 是调用方注入的固定 Ed25519 分离签名信任根。
	TrustKeys map[string]ed25519.PublicKey

	// HTTPClient optionally supplies a certificate-validating client or a test client.
	// HTTPClient 可选，用于提供证书校验客户端或测试客户端。
	HTTPClient *http.Client
}

// Result is an authenticated release snapshot pinned to one tag and commit.
// Result 是已经钉住一个标签和提交的已认证发行版本快照。
type Result struct {
	// Manifest is the verified release manifest returned by the trust boundary.
	// Manifest 是由信任边界返回的已验证发行清单。
	Manifest manifest.VerifiedManifest

	// Product is the requested product identifier after signed metadata matching.
	// Product 是签名元数据匹配后的请求产品标识。
	Product string

	// Repository is the only allowlisted repository for Product.
	// Repository 是 Product 唯一允许使用的代码仓库。
	Repository download.Repository

	// Source is the exact source used for both metadata requests.
	// Source 是两次元数据请求实际共同使用的精确下载源。
	Source download.Source

	// Selector records whether the request used latest or an exact tag.
	// Selector 记录本次请求使用 latest 还是精确标签。
	Selector Selector

	// Tag is the authenticated release tag pinned by the result.
	// Tag 是结果钉住的已认证发行标签。
	Tag string

	// Commit is the authenticated source commit pinned by the result.
	// Commit 是结果钉住的已认证源代码提交。
	Commit string

	// ManifestURL is the source URL used to request manifest.json.
	// ManifestURL 是请求 manifest.json 时使用的下载源 URL。
	ManifestURL string

	// SignatureURL is the source URL used to request manifest.sig.
	// SignatureURL 是请求 manifest.sig 时使用的下载源 URL。
	SignatureURL string
}

// Discover fetches and verifies a release manifest from exactly one selected source.
// Discover 仅从一个选定下载源获取并验证发行清单。
//
// The trust map is mandatory: an empty map fails before network access so a source
// can never introduce its own public key or silently downgrade verification.
// 信任映射必须存在：空映射会在联网前失败，因此下载源无法引入自己的公钥或静默降级校验。
func Discover(ctx context.Context, request Request) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("release discovery context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := validateRequest(request); err != nil {
		return Result{}, err
	}
	repository, err := repositoryForProduct(request.Product)
	if err != nil {
		return Result{}, err
	}
	manifestURL, signatureURL, err := buildMetadataURLs(request.Source, repository, request.Selector)
	if err != nil {
		return Result{}, err
	}
	trustKeys, err := cloneTrustKeys(request.TrustKeys)
	if err != nil {
		return Result{}, err
	}

	// One pair deadline prevents two sequential source requests from extending forever.
	// 这一对截止时间防止两个串行下载请求无限延长整个发现流程。
	discoveryContext, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	manifestDocument, err := fetchDocument(discoveryContext, request.HTTPClient, manifestURL, maxManifestBytes)
	if err != nil {
		return Result{}, fmt.Errorf("fetch release manifest: %w", err)
	}
	signatureDocument, err := fetchDocument(discoveryContext, request.HTTPClient, signatureURL, maxSignatureBytes)
	if err != nil {
		return Result{}, fmt.Errorf("fetch release signature: %w", err)
	}
	if err := validateResolvedVersions(request.Selector, manifestDocument.releaseTag, signatureDocument.releaseTag); err != nil {
		return Result{}, err
	}

	verified, err := manifest.Verify(manifestDocument.bytes, signatureDocument.bytes, trustKeys)
	if err != nil {
		return Result{}, fmt.Errorf("verify release manifest: %w", err)
	}
	product, err := verified.Product()
	if err != nil {
		return Result{}, fmt.Errorf("read verified product: %w", err)
	}
	if product != request.Product {
		return Result{}, fmt.Errorf("manifest product %q does not match requested product %q", product, request.Product)
	}
	tag, err := verified.Tag()
	if err != nil {
		return Result{}, fmt.Errorf("read verified release tag: %w", err)
	}
	if request.Selector.Kind == SelectorTag && tag != request.Selector.Tag {
		return Result{}, fmt.Errorf("manifest tag %q does not match requested tag %q", tag, request.Selector.Tag)
	}
	if manifestDocument.releaseTag != "" && manifestDocument.releaseTag != tag {
		return Result{}, fmt.Errorf("manifest URL resolved to tag %q but signed manifest declares %q", manifestDocument.releaseTag, tag)
	}
	if signatureDocument.releaseTag != "" && signatureDocument.releaseTag != tag {
		return Result{}, fmt.Errorf("signature URL resolved to tag %q but signed manifest declares %q", signatureDocument.releaseTag, tag)
	}
	commit, err := verified.Commit()
	if err != nil {
		return Result{}, fmt.Errorf("read verified release commit: %w", err)
	}

	return Result{
		Manifest:     verified,
		Product:      product,
		Repository:   repository,
		Source:       request.Source,
		Selector:     request.Selector,
		Tag:          tag,
		Commit:       commit,
		ManifestURL:  manifestURL,
		SignatureURL: signatureURL,
	}, nil
}

// validateRequest rejects unsupported products, selectors, sources, and trust roots.
// validateRequest 拒绝不支持的产品、选择器、下载源和信任根。
func validateRequest(request Request) error {
	if _, err := repositoryForProduct(request.Product); err != nil {
		return err
	}
	if err := request.Source.Validate(); err != nil {
		return fmt.Errorf("validate release source: %w", err)
	}
	if err := request.Selector.validate(); err != nil {
		return err
	}
	if len(request.TrustKeys) == 0 {
		return errors.New("release trust keys must not be empty")
	}
	return nil
}

// validate checks the exact URL mode before an untrusted tag can enter a path.
// validate 在不可信标签进入路径前检查精确 URL 模式。
func (selector Selector) validate() error {
	switch selector.Kind {
	case SelectorLatest:
		if selector.Tag != "" {
			return errors.New("latest release selector must not include a tag")
		}
	case SelectorTag:
		if err := validateTag(selector.Tag); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported release selector kind %q", selector.Kind)
	}
	return nil
}

// validateTag allows only one non-ambiguous release path component.
// validateTag 只允许一个无歧义的发行路径片段。
func validateTag(tag string) error {
	if tag == "" || strings.TrimSpace(tag) != tag {
		return errors.New("release tag must not be empty or contain surrounding whitespace")
	}
	if tag == "." || tag == ".." || strings.Contains(tag, "..") {
		return errors.New("release tag must not contain path traversal")
	}
	if strings.ContainsAny(tag, `/\\?#%`) {
		return errors.New("release tag must be one URL path component")
	}
	for _, character := range tag {
		if character < 0x20 || character == 0x7f || (character <= 0x7f && (character == ' ' || character == '\t')) {
			return errors.New("release tag must not contain whitespace or control characters")
		}
	}
	return nil
}

// repositoryForProduct fixes each product to the only repository it may read.
// repositoryForProduct 将每个产品固定到它唯一允许读取的代码仓库。
func repositoryForProduct(product string) (download.Repository, error) {
	switch product {
	case manifest.ProductVMMM:
		return download.RepositoryManager, nil
	case manifest.ProductVMM:
		return download.RepositoryVMM, nil
	default:
		return "", fmt.Errorf("unsupported release product %q", product)
	}
}

// buildMetadataURLs creates the manifest/signature pair from the same source and selector.
// buildMetadataURLs 使用同一个下载源和选择器构造清单与签名这一对 URL。
func buildMetadataURLs(source download.Source, repository download.Repository, selector Selector) (string, string, error) {
	if err := source.Validate(); err != nil {
		return "", "", err
	}
	buildURL := func(filename string) (string, error) {
		if selector.Kind == SelectorTag {
			return download.BuildReleaseURL(source, repository, selector.Tag, filename)
		}
		path := download.GitHubOwner + "/" + string(repository) + "/releases/latest/download/" + filename
		if source.Kind == download.SourceKindOfficial {
			return source.Prefix + path, nil
		}
		return source.Prefix + download.OfficialGitHubPrefix + path, nil
	}
	manifestURL, err := buildURL(manifestFilename)
	if err != nil {
		return "", "", fmt.Errorf("build manifest URL: %w", err)
	}
	signatureURL, err := buildURL(signatureFilename)
	if err != nil {
		return "", "", fmt.Errorf("build signature URL: %w", err)
	}
	if err := validateHTTPSURL(manifestURL); err != nil {
		return "", "", fmt.Errorf("manifest URL is invalid: %w", err)
	}
	if err := validateHTTPSURL(signatureURL); err != nil {
		return "", "", fmt.Errorf("signature URL is invalid: %w", err)
	}
	return manifestURL, signatureURL, nil
}

// cloneTrustKeys snapshots the injected trust root before any network operation.
// cloneTrustKeys 在联网前复制调用方注入的信任根快照。
func cloneTrustKeys(keys map[string]ed25519.PublicKey) (map[string]ed25519.PublicKey, error) {
	if len(keys) == 0 {
		return nil, errors.New("release trust keys must not be empty")
	}
	cloned := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, key := range keys {
		if strings.TrimSpace(keyID) != keyID || keyID == "" {
			return nil, errors.New("release trust key ID must not be empty or contain surrounding whitespace")
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release trust key %q has invalid length %d", keyID, len(key))
		}
		cloned[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	return cloned, nil
}

// fetchedDocument holds bounded bytes and the release tag observed in redirects.
// fetchedDocument 保存有界响应字节以及重定向中观察到的发行标签。
type fetchedDocument struct {
	bytes      []byte
	releaseTag string
}

// fetchDocument downloads one bounded HTTPS document without accepting downgrade redirects.
// fetchDocument 下载一个有界 HTTPS 文档，并拒绝降级重定向。
func fetchDocument(ctx context.Context, client *http.Client, rawURL string, limit int64) (fetchedDocument, error) {
	if err := validateHTTPSURL(rawURL); err != nil {
		return fetchedDocument{}, err
	}
	if limit <= 0 {
		return fetchedDocument{}, errors.New("release metadata size limit must be positive")
	}
	if client == nil {
		client = &http.Client{}
	}
	clientCopy := *client
	originalCheckRedirect := client.CheckRedirect
	var redirectTag string
	clientCopy.CheckRedirect = func(redirectRequest *http.Request, previousRequests []*http.Request) error {
		if redirectRequest == nil || redirectRequest.URL == nil {
			return errors.New("release redirect has no URL")
		}
		if err := validateHTTPSURL(redirectRequest.URL.String()); err != nil {
			return fmt.Errorf("release redirect rejected: %w", err)
		}
		if observed := releaseTagFromURL(redirectRequest.URL); observed != "" {
			if redirectTag != "" && redirectTag != observed {
				return fmt.Errorf("release redirect changed tag from %q to %q", redirectTag, observed)
			}
			redirectTag = observed
		}
		if originalCheckRedirect != nil {
			if err := originalCheckRedirect(redirectRequest, previousRequests); err != nil {
				return err
			}
			if err := validateHTTPSURL(redirectRequest.URL.String()); err != nil {
				return fmt.Errorf("release redirect policy attempted to leave HTTPS: %w", err)
			}
		} else if len(previousRequests) >= 10 {
			return errors.New("release redirect limit exceeded")
		}
		return nil
	}

	requestContext, cancel := context.WithTimeout(ctx, perRequestTimeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(requestContext, http.MethodGet, rawURL, nil)
	if err != nil {
		return fetchedDocument{}, fmt.Errorf("create release metadata request: %w", err)
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Accept-Encoding", "identity")
	httpRequest.Header.Set("User-Agent", "vmmm-installer/1")
	response, err := clientCopy.Do(httpRequest)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fetchedDocument{}, err
		}
		return fetchedDocument{}, errors.New("release metadata HTTP request failed")
	}
	if response == nil || response.Body == nil {
		return fetchedDocument{}, errors.New("release metadata HTTP response is incomplete")
	}
	defer response.Body.Close()
	if response.Request == nil || response.Request.URL == nil {
		return fetchedDocument{}, errors.New("release metadata response has no final URL")
	}
	if err := validateHTTPSURL(response.Request.URL.String()); err != nil {
		return fetchedDocument{}, fmt.Errorf("release metadata final response rejected: %w", err)
	}
	if observed := releaseTagFromURL(response.Request.URL); observed != "" {
		if redirectTag != "" && redirectTag != observed {
			return fetchedDocument{}, fmt.Errorf("release response changed tag from %q to %q", redirectTag, observed)
		}
		redirectTag = observed
	}
	if response.StatusCode != http.StatusOK {
		return fetchedDocument{}, fmt.Errorf("release metadata response status is %s; want 200 OK", response.Status)
	}
	if response.ContentLength > limit {
		return fetchedDocument{}, fmt.Errorf("release metadata response exceeds %d bytes", limit)
	}
	contentEncoding := strings.TrimSpace(response.Header.Get("Content-Encoding"))
	if contentEncoding != "" && !strings.EqualFold(contentEncoding, "identity") {
		return fetchedDocument{}, fmt.Errorf("unsupported release metadata content encoding %q", contentEncoding)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return fetchedDocument{}, errors.New("read release metadata response failed")
	}
	if int64(len(data)) > limit {
		return fetchedDocument{}, fmt.Errorf("release metadata response exceeds %d bytes", limit)
	}
	if err := requestContext.Err(); err != nil {
		return fetchedDocument{}, err
	}
	return fetchedDocument{bytes: data, releaseTag: redirectTag}, nil
}

// validateResolvedVersions rejects a latest pair whose source redirects to two releases.
// validateResolvedVersions 拒绝下载源将 latest 的清单和签名重定向到两个版本的情况。
func validateResolvedVersions(selector Selector, manifestTag string, signatureTag string) error {
	if selector.Kind != SelectorLatest {
		return nil
	}
	if manifestTag != "" && signatureTag != "" && manifestTag != signatureTag {
		return fmt.Errorf("latest manifest and signature resolved to different tags %q and %q", manifestTag, signatureTag)
	}
	return nil
}

// releaseTagFromURL extracts an exact tag only from a GitHub releases/download path.
// releaseTagFromURL 仅从 GitHub releases/download 路径中提取精确标签。
func releaseTagFromURL(value *url.URL) string {
	if value == nil {
		return ""
	}
	segments := strings.Split(strings.Trim(value.Path, "/"), "/")
	for index := 0; index+2 < len(segments); index++ {
		if segments[index] == "releases" && segments[index+1] == "download" && segments[index+2] != "latest" {
			return segments[index+2]
		}
	}
	return ""
}

// validateHTTPSURL accepts only absolute credential-free HTTPS URLs.
// validateHTTPSURL 只接受绝对、无凭据且使用 HTTPS 的 URL。
func validateHTTPSURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" || parsed.User != nil {
		return errors.New("URL must be HTTPS with a host and without user information")
	}
	return nil
}
