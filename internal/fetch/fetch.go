// Package fetch downloads authenticated VMM and VMMM release artifacts into a staging directory.
// fetch 包负责将已认证的 VMM 与 VMMM 发行资产安全下载到暂存目录。
// It is the byte-transfer boundary used after manifest verification and before installation.
// 它位于清单验证之后、正式安装之前，负责可信发行资产的字节传输边界。
package fetch

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/download"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/manifest"
)

const (
	// defaultTotalTimeout bounds the entire request, body transfer, and verification interval.
	// defaultTotalTimeout 限制完整请求、响应传输与完整性校验的总耗时。
	defaultTotalTimeout = 30 * time.Minute

	// transferBufferSize bounds the memory used while copying an artifact stream.
	// transferBufferSize 限制流式复制资产时使用的内存。
	transferBufferSize = 64 * 1024

	// temporaryNameAttempts limits collisions when creating an unpredictable same-directory file.
	// temporaryNameAttempts 限制创建同目录随机临时文件时的重试次数。
	temporaryNameAttempts = 8
)

var (
	// ErrTargetExists reports that the requested staging filename is already occupied.
	// ErrTargetExists 表示请求的暂存文件名已经被占用。
	ErrTargetExists = errors.New("staging target already exists")

	// ErrArtifactSize reports that the response did not match the signed artifact byte length.
	// ErrArtifactSize 表示响应长度与签名清单中的资产大小不符。
	ErrArtifactSize = errors.New("downloaded artifact size does not match the signed manifest")

	// ErrArtifactDigest reports that the response did not match the signed artifact SHA-256.
	// ErrArtifactDigest 表示响应摘要与签名清单中的 SHA-256 不符。
	ErrArtifactDigest = errors.New("downloaded artifact digest does not match the signed manifest")
)

// ProgressFunc receives the number of artifact bytes written and the signed total size.
// ProgressFunc 接收已经写入的资产字节数以及签名清单中的总大小。
// The callback never receives a source URL, redirect URL, or credential-bearing value.
// 回调不会收到下载源 URL、重定向 URL 或任何凭据信息。
type ProgressFunc func(downloaded int64, total int64)

// URLResolver builds one asset URL from the signed release identity and the selected source.
// URLResolver 根据签名发行身份和用户选择的下载源构造单个资产 URL。
// A resolver must return an absolute HTTPS URL; FetchWithResolver enforces that requirement.
// resolver 必须返回绝对 HTTPS URL；FetchWithResolver 会强制执行此要求。
type URLResolver func(source download.Source, repository download.Repository, tag string, filename string) (string, error)

// Request identifies one product artifact and its exact staging destination.
// Request 指定一个产品资产以及它的确切暂存目标路径。
// Product and Repository are checked against the fixed product-to-repository mapping.
// Product 与 Repository 会按固定的产品到仓库映射进行交叉校验。
type Request struct {
	// Source is the one source selected by the caller; fetch never falls back to another source.
	// Source 是调用方选定的唯一下载源；fetch 不会自动切换到其他源。
	Source download.Source

	// Manifest is the release manifest returned by successful signature verification.
	// Manifest 是经签名验证成功后返回的发行清单。
	Manifest manifest.VerifiedManifest

	// Product is either manifest.ProductVMM or manifest.ProductVMMM.
	// Product 必须是 manifest.ProductVMM 或 manifest.ProductVMMM。
	Product string

	// Repository must match the fixed repository assigned to Product.
	// Repository 必须与 Product 对应的固定仓库一致。
	Repository download.Repository

	// Platform selects the signed artifact for the current operating system and architecture.
	// Platform 选择当前操作系统与处理器架构对应的签名资产。
	Platform string

	// StagingPath is the absolute destination filename, including the signed artifact filename.
	// StagingPath 是包含签名资产文件名的绝对暂存目标路径。
	StagingPath string

	// Progress optionally reports bounded byte counts without exposing request metadata.
	// Progress 可选地报告有界字节进度，不会暴露请求元数据。
	Progress ProgressFunc
}

// Result describes the verified artifact atomically published at the requested staging path.
// Result 描述已校验并原子放入指定暂存路径的发行资产。
type Result struct {
	// Path is the absolute path of the completed artifact.
	// Path 是已完成资产的绝对路径。
	Path string

	// Filename is the signed artifact filename.
	// Filename 是签名清单中的资产文件名。
	Filename string

	// Bytes is the number of bytes received and verified.
	// Bytes 是接收并校验通过的字节数。
	Bytes int64

	// SHA256 is the lowercase digest authenticated by the release manifest.
	// SHA256 是发行清单认证的小写十六进制摘要。
	SHA256 string
}

// Fetch downloads one authenticated artifact with the default certificate-validating HTTP client.
// Fetch 使用默认校验证书的 HTTP 客户端下载一个已认证的发行资产。
// It requires an absolute staging path and publishes only after size and SHA-256 checks pass.
// 它要求传入绝对暂存路径，并仅在大小与 SHA-256 校验通过后发布文件。
// ctx cancels the request; request supplies the exact product, repository, platform, source, and path.
// ctx 用于取消请求；request 提供确切产品、仓库、平台、下载源和暂存路径。
// The returned result describes the published file; any validation or transfer failure returns an error.
// 返回结果描述已发布的文件；任一校验或传输失败都会返回错误。
func Fetch(ctx context.Context, request Request) (Result, error) {
	return FetchWithResolver(ctx, request, resolveGitHubReleaseURL)
}

// FetchWithResolver downloads through an injected URL layout using the standard verified HTTP client.
// FetchWithResolver 使用注入的 URL 结构和标准证书校验 HTTP 客户端执行下载。
// ctx and request have the same meanings as Fetch; resolver receives authenticated release fields.
// ctx 与 request 含义同 Fetch；resolver 接收已认证的发行字段。
// The result is returned only after digest verification and atomic publication both succeed.
// 仅当摘要验证与原子发布均成功时才返回结果。
func FetchWithResolver(ctx context.Context, request Request, resolver URLResolver) (Result, error) {
	return fetchWithResolver(ctx, &http.Client{}, request, resolver)
}

// fetchWithClient is the test seam that keeps production callers on the standard verified transport.
// fetchWithClient 是仅供测试注入 HTTP 客户端的内部入口，生产调用固定使用标准证书校验传输。
func fetchWithClient(ctx context.Context, client *http.Client, request Request) (Result, error) {
	return fetchWithResolver(ctx, client, request, resolveGitHubReleaseURL)
}

// releaseURLResolver builds the exact URL for one repository release asset.
// releaseURLResolver 为一个仓库发行资产构造确切 URL。
// fetchWithResolver keeps transfer, verification, and atomic publication independent from URL layout.
// fetchWithResolver 将传输、校验和原子发布流程与 URL 结构解耦。
// resolver constructs the selected source URL; every failure is returned before successful publication.
// resolver 构造所选下载源 URL；所有失败都会在成功发布前返回。
func fetchWithResolver(ctx context.Context, client *http.Client, request Request, resolver URLResolver) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("download context must not be nil")
	}
	if client == nil {
		return Result{}, errors.New("HTTP client must not be nil")
	}
	if resolver == nil {
		return Result{}, errors.New("artifact URL resolver must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	// Bind product identity to one repository before constructing a release URL.
	// 先将产品身份绑定到唯一仓库，再构造发行 URL，避免跨产品清单混用。
	repository, err := repositoryForProduct(request.Product)
	if err != nil {
		return Result{}, err
	}
	if request.Repository != repository {
		return Result{}, fmt.Errorf("repository %q does not match product %q repository %q", request.Repository, request.Product, repository)
	}
	artifact, err := request.Manifest.FindArtifact(request.Product, request.Platform)
	if err != nil {
		return Result{}, fmt.Errorf("select signed artifact: %w", err)
	}
	if err := validateArtifact(artifact); err != nil {
		return Result{}, err
	}
	tag, err := request.Manifest.Tag()
	if err != nil {
		return Result{}, fmt.Errorf("read verified release tag: %w", err)
	}
	releaseURL, err := resolver(request.Source, repository, tag, artifact.Filename)
	if err != nil {
		return Result{}, errors.New("resolve artifact URL failed")
	}
	if err := validateHTTPSURL(releaseURL); err != nil {
		return Result{}, errors.New("resolved artifact URL is invalid")
	}
	stagingDirectory, destinationName, absoluteDestination, err := validateStagingPath(request.StagingPath, artifact.Filename)
	if err != nil {
		return Result{}, err
	}

	// Walk and pin every directory component so later filesystem operations cannot follow a swapped path.
	// 逐级检查并固定目录句柄，避免后续文件操作跟随被替换的路径组件。
	root, err := openStagingDirectory(stagingDirectory)
	if err != nil {
		return Result{}, fmt.Errorf("open staging directory: %w", err)
	}
	defer root.Close()
	if _, err := root.Lstat(destinationName); err == nil {
		return Result{}, ErrTargetExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, fmt.Errorf("inspect staging target: %w", err)
	}

	// Add one deadline for the whole operation; the caller's earlier deadline remains authoritative.
	// 为整个下载流程设置一个总截止时间；调用方更早的截止时间仍然优先。
	transferContext, cancel := context.WithTimeout(ctx, defaultTotalTimeout)
	defer cancel()

	requestMessage, err := http.NewRequestWithContext(transferContext, http.MethodGet, releaseURL, nil)
	if err != nil {
		return Result{}, errors.New("create artifact request failed")
	}
	requestMessage.Header.Set("Accept", "application/octet-stream")
	requestMessage.Header.Set("Accept-Encoding", "identity")
	requestMessage.Header.Set("User-Agent", "vmmm-installer/1")

	// Clone the client so every redirect remains HTTPS without mutating caller-owned global state.
	// 克隆客户端并强制所有重定向保持 HTTPS，同时不修改调用方持有的全局客户端。
	response, err := doHTTPSOnly(client, requestMessage)
	if err != nil {
		return Result{}, sanitizedRequestError(err)
	}
	if response == nil {
		return Result{}, errors.New("HTTP client returned a nil response")
	}
	if response.Body == nil {
		return Result{}, errors.New("HTTP response body is nil")
	}
	defer response.Body.Close()
	if response.Request == nil || response.Request.URL == nil || !strings.EqualFold(response.Request.URL.Scheme, "https") {
		return Result{}, errors.New("final download response did not use HTTPS")
	}
	if response.TLS == nil {
		return Result{}, errors.New("artifact response did not establish a verified TLS connection")
	}
	if response.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("artifact response status is %d; want 200", response.StatusCode)
	}
	if response.ContentLength >= 0 && response.ContentLength != artifact.Bytes {
		return Result{}, fmt.Errorf("%w: response declares %d bytes, want %d", ErrArtifactSize, response.ContentLength, artifact.Bytes)
	}
	contentEncoding := strings.TrimSpace(response.Header.Get("Content-Encoding"))
	if contentEncoding != "" && !strings.EqualFold(contentEncoding, "identity") {
		return Result{}, errors.New("artifact response uses unsupported content encoding")
	}
	if transferContext.Err() != nil {
		return Result{}, transferContext.Err()
	}

	// Stream into a fresh sibling file so failed transfers cannot affect an existing target.
	// 流式写入同目录新临时文件，确保失败传输不会触碰已有目标。
	temporaryName, temporaryFile, err := createTemporaryFile(root)
	if err != nil {
		return Result{}, fmt.Errorf("create staging temporary file: %w", err)
	}
	temporaryOwned := true
	defer func() {
		if temporaryOwned {
			_ = root.Remove(temporaryName)
		}
	}()

	digest := sha256.New()
	progressWriter := progressWriter{callback: request.Progress, total: artifact.Bytes}
	limitedBody := &io.LimitedReader{R: response.Body, N: artifact.Bytes + 1}
	written, copyErr := io.CopyBuffer(io.MultiWriter(temporaryFile, digest, &progressWriter), limitedBody, make([]byte, transferBufferSize))
	if copyErr != nil {
		_ = temporaryFile.Close()
		if transferContext.Err() != nil {
			return Result{}, transferContext.Err()
		}
		return Result{}, fmt.Errorf("receive artifact stream: %w", copyErr)
	}
	if written > artifact.Bytes || limitedBody.N == 0 {
		_ = temporaryFile.Close()
		return Result{}, fmt.Errorf("%w: received more than %d bytes", ErrArtifactSize, artifact.Bytes)
	}
	if written != artifact.Bytes {
		_ = temporaryFile.Close()
		return Result{}, fmt.Errorf("%w: received %d bytes, want %d", ErrArtifactSize, written, artifact.Bytes)
	}

	// Compare the complete stream digest before syncing or publishing the file.
	// 在同步或发布文件前，对完整响应流的摘要进行比较。
	actualDigest := digest.Sum(nil)
	expectedDigest, _ := hex.DecodeString(artifact.SHA256)
	if subtle.ConstantTimeCompare(actualDigest, expectedDigest) != 1 {
		_ = temporaryFile.Close()
		return Result{}, ErrArtifactDigest
	}
	if err := transferContext.Err(); err != nil {
		_ = temporaryFile.Close()
		return Result{}, err
	}
	if err := temporaryFile.Sync(); err != nil {
		_ = temporaryFile.Close()
		return Result{}, fmt.Errorf("sync verified staging file: %w", err)
	}
	fileInfo, err := temporaryFile.Stat()
	if err != nil {
		_ = temporaryFile.Close()
		return Result{}, fmt.Errorf("inspect verified staging file: %w", err)
	}
	if !fileInfo.Mode().IsRegular() || fileInfo.Size() != artifact.Bytes {
		_ = temporaryFile.Close()
		return Result{}, errors.New("staging temporary file changed before publication")
	}
	if err := temporaryFile.Close(); err != nil {
		return Result{}, fmt.Errorf("close verified staging file: %w", err)
	}
	linkedInfo, err := root.Lstat(temporaryName)
	if err != nil || !linkedInfo.Mode().IsRegular() || !os.SameFile(fileInfo, linkedInfo) {
		return Result{}, errors.New("staging temporary file changed before publication")
	}
	if err := transferContext.Err(); err != nil {
		return Result{}, err
	}

	// Link is an atomic create-if-absent operation; it never replaces another file.
	// Link 是原子的“仅当目标不存在时创建”操作，绝不会覆盖其他文件。
	if err := root.Link(temporaryName, destinationName); err != nil {
		if _, statErr := root.Lstat(destinationName); statErr == nil {
			return Result{}, ErrTargetExists
		}
		return Result{}, fmt.Errorf("atomically publish verified artifact: %w", err)
	}
	publishedInfo, err := root.Lstat(destinationName)
	if err != nil || !publishedInfo.Mode().IsRegular() || !os.SameFile(fileInfo, publishedInfo) {
		return Result{}, errors.New("published staging file does not match the verified temporary file")
	}
	if err := root.Remove(temporaryName); err != nil {
		if currentInfo, statErr := root.Lstat(destinationName); statErr == nil && os.SameFile(fileInfo, currentInfo) {
			_ = root.Remove(destinationName)
		}
		return Result{}, fmt.Errorf("remove temporary staging link after publication: %w", err)
	}
	temporaryOwned = false
	return Result{
		Path:     absoluteDestination,
		Filename: artifact.Filename,
		Bytes:    written,
		SHA256:   artifact.SHA256,
	}, nil
}

// repositoryForProduct returns the only repository allowed for a product identifier.
// repositoryForProduct 返回指定产品标识唯一允许使用的仓库。
// product is the signed product name; unsupported values return an error instead of selecting a repository.
// product 是签名产品名；不支持的值会返回错误，不会选择任何仓库。
func repositoryForProduct(product string) (download.Repository, error) {
	switch product {
	case manifest.ProductVMM:
		return download.RepositoryVMM, nil
	case manifest.ProductVMMM:
		return download.RepositoryManager, nil
	default:
		return "", fmt.Errorf("unsupported release product %q", product)
	}
}

// resolveGitHubReleaseURL constructs one allowlisted GitHub release asset URL.
// resolveGitHubReleaseURL 为一个资产构造唯一允许的 GitHub Release URL。
func resolveGitHubReleaseURL(source download.Source, repository download.Repository, tag string, filename string) (string, error) {
	return download.BuildReleaseURL(source, repository, tag, filename)
}

// validateHTTPSURL rejects resolver results without an HTTPS scheme and host or with user-info or fragments.
// validateHTTPSURL 拒绝缺少 HTTPS 协议或主机、包含用户信息或片段的 resolver 结果。
// value is the resolved asset URL; nil is returned only when every URL safety check passes.
// value 是解析后的资产 URL；只有全部 URL 安全检查通过时才返回 nil。
func validateHTTPSURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return errors.New("URL is malformed")
	}
	if !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("URL must be HTTPS with a host, no user information, and no fragment")
	}
	return nil
}

// validateArtifact rejects unsafe names and malformed signed size or digest metadata.
// validateArtifact 拒绝不安全文件名以及格式错误的签名大小或摘要元数据。
// artifact is the selected signed entry; validation errors stop processing before any download is written.
// artifact 是选中的签名条目；校验错误会阻止下载写入。
func validateArtifact(artifact manifest.Artifact) error {
	if artifact.Filename == "" || artifact.Filename == "." || artifact.Filename == ".." || strings.Contains(artifact.Filename, "..") {
		return errors.New("signed artifact filename is empty or contains traversal")
	}
	if filepath.Base(artifact.Filename) != artifact.Filename || filepath.IsAbs(artifact.Filename) || strings.ContainsAny(artifact.Filename, `/\\:*?"<>|`) {
		return errors.New("signed artifact filename is not a safe basename")
	}
	if strings.HasSuffix(artifact.Filename, ".") || isWindowsDeviceName(artifact.Filename) {
		return errors.New("signed artifact filename is not portable across supported filesystems")
	}
	for _, character := range artifact.Filename {
		if character < 0x20 || character == 0x7f {
			return errors.New("signed artifact filename contains a control character")
		}
	}
	if artifact.Bytes <= 0 || artifact.Bytes >= math.MaxInt64 {
		return errors.New("signed artifact size is outside the supported range")
	}
	if len(artifact.SHA256) != sha256.Size*2 || strings.ToLower(artifact.SHA256) != artifact.SHA256 {
		return errors.New("signed artifact SHA-256 must be 64 lowercase hexadecimal characters")
	}
	decoded, err := hex.DecodeString(artifact.SHA256)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("signed artifact SHA-256 is invalid")
	}
	return nil
}

// isWindowsDeviceName recognizes reserved device basenames independent of extension and case.
// isWindowsDeviceName 不区分大小写地识别带扩展名的 Windows 保留设备名。
func isWindowsDeviceName(filename string) bool {
	basename := filename
	if extension := strings.IndexByte(basename, '.'); extension >= 0 {
		basename = basename[:extension]
	}
	basename = strings.ToUpper(basename)
	if basename == "CON" || basename == "PRN" || basename == "AUX" || basename == "NUL" {
		return true
	}
	if len(basename) == 4 && (strings.HasPrefix(basename, "COM") || strings.HasPrefix(basename, "LPT")) && basename[3] >= '1' && basename[3] <= '9' {
		return true
	}
	return false
}

// validateStagingPath confines the target to an existing symlink-free parent directory.
// validateStagingPath 将目标约束在已存在且不含符号链接的父目录中。
// stagingPath must end in filename; the return values are its parent, child name, and normalized absolute path.
// stagingPath 必须以 filename 结尾；返回值依次是父目录、子文件名和规范化绝对路径。
func validateStagingPath(stagingPath string, filename string) (string, string, string, error) {
	if stagingPath == "" || strings.ContainsAny(stagingPath, "\x00\r\n") || !filepath.IsAbs(stagingPath) {
		return "", "", "", errors.New("staging path must be an absolute path without control characters")
	}
	for _, component := range strings.FieldsFunc(stagingPath, func(character rune) bool { return character == '/' || character == '\\' }) {
		if component == ".." {
			return "", "", "", errors.New("staging path must not contain parent traversal")
		}
	}
	cleanPath := filepath.Clean(stagingPath)
	if filepath.Base(cleanPath) != filename {
		return "", "", "", fmt.Errorf("staging filename %q must match signed artifact filename %q", filepath.Base(cleanPath), filename)
	}
	absolutePath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve staging path: %w", err)
	}
	parentPath := filepath.Dir(absolutePath)
	relativePath, err := filepath.Rel(parentPath, absolutePath)
	if err != nil || relativePath != filename {
		return "", "", "", errors.New("staging target escapes its parent directory")
	}
	return parentPath, filename, absolutePath, nil
}

// openStagingDirectory walks from the filesystem root and pins each symlink-free directory component.
// openStagingDirectory 从文件系统根目录逐级打开并固定每个不含符号链接的目录组件。
// directory must already exist; the returned root handle remains anchored to the inspected directory.
// directory 必须已存在；返回的根句柄会固定到已检查的目录。
func openStagingDirectory(directory string) (openedRoot *os.Root, err error) {
	absolutePath, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve staging directory: %w", err)
	}
	volume := filepath.VolumeName(absolutePath)
	rootPath := string(os.PathSeparator)
	if volume != "" {
		rootPath = volume + string(os.PathSeparator)
	}
	openedRoot, err = os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root for staging: %w", err)
	}
	rootToClose := openedRoot
	defer func() {
		if err != nil && rootToClose != nil {
			_ = rootToClose.Close()
		}
	}()
	rootInfo, err := openedRoot.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("inspect filesystem root for staging: %w", err)
	}
	if !rootInfo.IsDir() {
		return nil, errors.New("staging filesystem root is not a directory")
	}
	remaining := strings.TrimLeft(absolutePath[len(rootPath):], `/\\`)
	if remaining == "" {
		return openedRoot, nil
	}
	currentPath := rootPath
	for _, component := range strings.FieldsFunc(remaining, func(character rune) bool { return character == '/' || character == '\\' }) {
		entryInfo, err := openedRoot.Lstat(component)
		if err != nil {
			return nil, fmt.Errorf("inspect staging path component: %w", err)
		}
		currentPath = filepath.Join(currentPath, component)
		isReparsePoint, err := pathIsReparsePoint(currentPath, entryInfo)
		if err != nil {
			return nil, fmt.Errorf("inspect staging path component type: %w", err)
		}
		if isReparsePoint {
			return nil, errors.New("staging path must not contain symbolic links or reparse points")
		}
		if !entryInfo.IsDir() {
			return nil, errors.New("staging path parent component is not a directory")
		}
		nextRoot, err := openedRoot.OpenRoot(component)
		if err != nil {
			return nil, fmt.Errorf("open staging path component: %w", err)
		}
		openedInfo, err := nextRoot.Stat(".")
		if err != nil {
			_ = nextRoot.Close()
			return nil, fmt.Errorf("inspect opened staging path component: %w", err)
		}
		if !os.SameFile(entryInfo, openedInfo) {
			_ = nextRoot.Close()
			return nil, errors.New("staging path changed while it was being opened")
		}
		previousRoot := openedRoot
		openedRoot = nextRoot
		rootToClose = nextRoot
		_ = previousRoot.Close()
	}
	return openedRoot, nil
}

// createTemporaryFile creates an unpredictable exclusive file relative to the staging root.
// createTemporaryFile 在暂存根目录中创建不可预测且独占的临时文件。
func createTemporaryFile(root *os.Root) (string, *os.File, error) {
	for attempt := 0; attempt < temporaryNameAttempts; attempt++ {
		var randomBytes [16]byte
		if _, err := rand.Read(randomBytes[:]); err != nil {
			return "", nil, fmt.Errorf("generate temporary filename: %w", err)
		}
		name := ".vmmm-fetch-" + hex.EncodeToString(randomBytes[:]) + ".tmp"
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return name, file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, errors.New("could not allocate a unique staging temporary file")
}

// doHTTPSOnly follows redirects only when their destination also uses HTTPS.
// doHTTPSOnly 仅在重定向目标同样使用 HTTPS 时才继续请求。
// client is cloned, request is sent once, and the response or a sanitized transport error is returned.
// client 会被克隆，request 仅发送一次，并返回响应或经过净化的传输错误。
func doHTTPSOnly(client *http.Client, request *http.Request) (*http.Response, error) {
	clonedClient := *client
	originalCheckRedirect := client.CheckRedirect
	clonedClient.CheckRedirect = func(redirectRequest *http.Request, previousRequests []*http.Request) error {
		if redirectRequest.URL == nil || !strings.EqualFold(redirectRequest.URL.Scheme, "https") || redirectRequest.URL.User != nil {
			return errors.New("redirect target must use HTTPS and must not contain user information")
		}
		if originalCheckRedirect == nil {
			if len(previousRequests) >= 10 {
				return errors.New("stopped after 10 HTTPS redirects")
			}
			return nil
		}
		if err := originalCheckRedirect(redirectRequest, previousRequests); err != nil {
			return err
		}
		if redirectRequest.URL == nil || !strings.EqualFold(redirectRequest.URL.Scheme, "https") || redirectRequest.URL.User != nil {
			return errors.New("redirect policy attempted to leave HTTPS")
		}
		return nil
	}
	response, err := clonedClient.Do(request)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// sanitizedRequestError hides URLs because secure object-store redirects may contain temporary query tokens.
// sanitizedRequestError 隐藏 URL，因为安全对象存储重定向可能带有临时查询令牌。
func sanitizedRequestError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return errors.New("artifact HTTP request failed")
}

// progressWriter reports copied byte counts while forwarding no request metadata.
// progressWriter 在转发数据时报告字节数，不传递任何请求元数据。
type progressWriter struct {
	callback ProgressFunc
	total    int64
	written  int64
}

// Write records the latest bounded progress and accepts all bytes supplied by io.CopyBuffer.
// Write 记录最新的有界进度，并接收 io.CopyBuffer 提供的全部字节。
func (writer *progressWriter) Write(data []byte) (int, error) {
	writer.written += int64(len(data))
	if writer.callback != nil {
		downloaded := writer.written
		if downloaded > writer.total {
			downloaded = writer.total
		}
		writer.callback(downloaded, writer.total)
	}
	return len(data), nil
}
