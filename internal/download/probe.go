// Package download contains bounded source health probes for fixed VMM release assets.
// download 包含针对固定 VMM Release 资产的有界下载源健康探测。
package download

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// HTTPDoer is the injectable subset of http.Client needed by Probe.
// HTTPDoer 是 Probe 需要的可注入 http.Client 最小接口。
type HTTPDoer interface {
	// Do sends one HTTP request and returns its response.
	// Do 发送一个 HTTP 请求并返回响应。
	Do(request *http.Request) (*http.Response, error)
}

// ProbeStatus describes whether a source passed the full probe or only download checks.
// ProbeStatus 描述下载源是通过完整探测，还是仅通过可下载性检查。
type ProbeStatus string

const (
	// ProbeStatusPassed means checksum and ranged archive checks both passed.
	// ProbeStatusPassed 表示摘要和带范围压缩包检查均通过。
	ProbeStatusPassed ProbeStatus = "passed"

	// ProbeStatusDownloadableNoRange means content is valid but Range support is unproven.
	// ProbeStatusDownloadableNoRange 表示内容有效，但未证明支持 Range 续传。
	ProbeStatusDownloadableNoRange ProbeStatus = "downloadable-no-range"

	// ProbeStatusFailed means the source failed before content checks completed.
	// ProbeStatusFailed 表示下载源在内容检查完成前失败。
	ProbeStatusFailed ProbeStatus = "failed"
)

// ProbeStage identifies the bounded stage that produced a failure.
// ProbeStage 标识产生失败的有界探测阶段。
type ProbeStage string

const (
	// ProbeStageNone means no failure was recorded.
	// ProbeStageNone 表示没有记录失败。
	ProbeStageNone ProbeStage = ""

	// ProbeStageSource validates the source before network access.
	// ProbeStageSource 表示网络访问前的源校验阶段。
	ProbeStageSource ProbeStage = "source"

	// ProbeStageChecksumRequest covers checksum URL construction and HTTP execution.
	// ProbeStageChecksumRequest 表示摘要 URL 构造和 HTTP 执行阶段。
	ProbeStageChecksumRequest ProbeStage = "checksum-request"

	// ProbeStageChecksumStatus covers the checksum HTTP status code.
	// ProbeStageChecksumStatus 表示摘要 HTTP 状态码阶段。
	ProbeStageChecksumStatus ProbeStage = "checksum-status"

	// ProbeStageChecksumSize covers the exact checksum response size.
	// ProbeStageChecksumSize 表示摘要响应精确大小阶段。
	ProbeStageChecksumSize ProbeStage = "checksum-size"

	// ProbeStageChecksumDigest covers the official checksum digest comparison.
	// ProbeStageChecksumDigest 表示官方摘要值比较阶段。
	ProbeStageChecksumDigest ProbeStage = "checksum-digest"

	// ProbeStageArchiveRequest covers archive URL construction and HTTP execution.
	// ProbeStageArchiveRequest 表示压缩包 URL 构造和 HTTP 执行阶段。
	ProbeStageArchiveRequest ProbeStage = "archive-request"

	// ProbeStageArchiveStatus covers the archive HTTP status code.
	// ProbeStageArchiveStatus 表示压缩包 HTTP 状态码阶段。
	ProbeStageArchiveStatus ProbeStage = "archive-status"

	// ProbeStageArchiveSize covers the advertised archive size.
	// ProbeStageArchiveSize 表示压缩包声明大小阶段。
	ProbeStageArchiveSize ProbeStage = "archive-size"

	// ProbeStageArchiveRange covers the exact Content-Range response.
	// ProbeStageArchiveRange 表示精确 Content-Range 响应阶段。
	ProbeStageArchiveRange ProbeStage = "archive-range"

	// ProbeStageArchiveBody covers bounded archive sample reading.
	// ProbeStageArchiveBody 表示有界压缩包样本读取阶段。
	ProbeStageArchiveBody ProbeStage = "archive-body"

	// ProbeStageArchiveMagic covers the ZIP magic check.
	// ProbeStageArchiveMagic 表示 ZIP 文件头检查阶段。
	ProbeStageArchiveMagic ProbeStage = "archive-magic"
)

const (
	// zipMagic is the local-file ZIP signature expected from the VMM archive.
	// zipMagic 是 VMM 压缩包应有的本地文件 ZIP 签名。
	zipMagic = "PK\x03\x04"

	// defaultProbeUserAgent identifies bounded manager health probes.
	// defaultProbeUserAgent 标识管理器的有界健康探测请求。
	defaultProbeUserAgent = "vmmm-source-probe/1"

	// probeTimeout caps one complete source probe while preserving a shorter caller deadline.
	// probeTimeout 限制一次完整源探测的最长时间，同时保留调用方更短的 deadline。
	probeTimeout = 15 * time.Second

	// maxProbeRedirects bounds HTTPS-to-HTTPS redirect chains for the default client.
	// maxProbeRedirects 限制默认客户端的 HTTPS 到 HTTPS 重定向链长度。
	maxProbeRedirects = 5
)

// contentRangePattern parses the only Content-Range form accepted by the probe.
// contentRangePattern 解析探测唯一接受的 Content-Range 格式。
var contentRangePattern = regexp.MustCompile(`^bytes ([0-9]+)-([0-9]+)/([0-9]+)$`)

// ProbeResult records source status, URLs, timing, and the first failing stage.
// ProbeResult 记录下载源状态、URL、时间以及第一个失败阶段。
type ProbeResult struct {
	// Source is the source checked by this result.
	// Source 是本次结果检查的下载源。
	Source Source

	// Status is the final bounded probe classification.
	// Status 是最终的有界探测分类。
	Status ProbeStatus

	// Downloadable is true when the fixed checksum and archive content checks pass.
	// Downloadable 表示固定摘要和压缩包内容检查均通过。
	Downloadable bool

	// RangeSupported is true only after an exact HTTP 206 range response.
	// RangeSupported 仅在收到精确 HTTP 206 范围响应后为 true。
	RangeSupported bool

	// ChecksumURL is the exact checksum URL probed.
	// ChecksumURL 是实际探测的精确摘要 URL。
	ChecksumURL string

	// ArchiveURL is the exact archive URL probed.
	// ArchiveURL 是实际探测的精确压缩包 URL。
	ArchiveURL string

	// FailureStage identifies the first failing stage, if any.
	// FailureStage 标识第一个失败阶段（如有）。
	FailureStage ProbeStage

	// Failure contains a concise error suitable for TUI display and logs.
	// Failure 包含适合 TUI 展示和日志记录的简短错误。
	Failure string

	// CheckedAt is the UTC time at which the probe started.
	// CheckedAt 是探测开始时的 UTC 时间。
	CheckedAt time.Time
}

// Probe performs a bounded, deterministic health check without downloading a full archive.
// Probe 执行有界且确定的健康检查，不下载完整压缩包。
func Probe(ctx context.Context, client HTTPDoer, source Source) ProbeResult {
	result := ProbeResult{
		Source:    source,
		Status:    ProbeStatusFailed,
		CheckedAt: time.Now().UTC(),
	}
	if err := source.Validate(); err != nil {
		return failProbe(result, ProbeStageSource, err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	probeContext, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if client == nil {
		client = newProbeHTTPClient()
	}

	checksumURL, err := BuildReleaseURL(source, RepositoryVMM, VMMProbeTag, VMMProbeChecksumAsset)
	if err != nil {
		return failProbe(result, ProbeStageChecksumRequest, err)
	}
	result.ChecksumURL = checksumURL
	checksumResponse, err := doGET(probeContext, client, checksumURL)
	if err != nil {
		return failProbe(result, ProbeStageChecksumRequest, err)
	}
	if err := validateFinalResponseHTTPS(checksumResponse); err != nil {
		closeResponse(checksumResponse)
		return failProbe(result, ProbeStageChecksumRequest, err)
	}
	if checksumResponse.StatusCode != http.StatusOK {
		closeResponse(checksumResponse)
		return failProbe(result, ProbeStageChecksumStatus, fmt.Errorf("checksum response status is %s", checksumResponse.Status))
	}
	checksumBody, err := readExactBounded(checksumResponse.Body, expectedProbeChecksumSize)
	closeResponse(checksumResponse)
	if err != nil {
		return failProbe(result, ProbeStageChecksumSize, err)
	}
	if int64(len(checksumBody)) != expectedProbeChecksumSize {
		return failProbe(result, ProbeStageChecksumSize, fmt.Errorf("checksum response is %d bytes, want %d", len(checksumBody), expectedProbeChecksumSize))
	}
	checksumDigest := sha256.Sum256(checksumBody)
	if !strings.EqualFold(hex.EncodeToString(checksumDigest[:]), expectedProbeChecksumSHA256) {
		return failProbe(result, ProbeStageChecksumDigest, fmt.Errorf("checksum digest is %s, want %s", hex.EncodeToString(checksumDigest[:]), expectedProbeChecksumSHA256))
	}

	archiveURL, err := BuildReleaseURL(source, RepositoryVMM, VMMProbeTag, VMMProbeArchiveAsset)
	if err != nil {
		return failProbe(result, ProbeStageArchiveRequest, err)
	}
	result.ArchiveURL = archiveURL
	archiveResponse, err := doRangeGET(probeContext, client, archiveURL)
	if err != nil {
		return failProbe(result, ProbeStageArchiveRequest, err)
	}
	if err := validateFinalResponseHTTPS(archiveResponse); err != nil {
		closeResponse(archiveResponse)
		return failProbe(result, ProbeStageArchiveRequest, err)
	}
	if archiveResponse.StatusCode != http.StatusPartialContent && archiveResponse.StatusCode != http.StatusOK {
		closeResponse(archiveResponse)
		return failProbe(result, ProbeStageArchiveStatus, fmt.Errorf("archive response status is %s", archiveResponse.Status))
	}
	if archiveResponse.StatusCode == http.StatusPartialContent {
		if err := validatePartialContentHeaders(archiveResponse); err != nil {
			closeResponse(archiveResponse)
			return failProbe(result, ProbeStageArchiveRange, err)
		}
		archiveSample, err := readExactBounded(archiveResponse.Body, probeArchiveSampleSize)
		closeResponse(archiveResponse)
		if err != nil {
			return failProbe(result, ProbeStageArchiveBody, err)
		}
		if int64(len(archiveSample)) != probeArchiveSampleSize {
			return failProbe(result, ProbeStageArchiveBody, fmt.Errorf("partial archive sample is %d bytes, want %d", len(archiveSample), probeArchiveSampleSize))
		}
		if err := validateArchiveMagic(archiveSample); err != nil {
			return failProbe(result, ProbeStageArchiveMagic, err)
		}
		result.Downloadable = true
		result.RangeSupported = true
		result.Status = ProbeStatusPassed
		return result
	}

	if archiveResponse.ContentLength != expectedProbeArchiveSize {
		closeResponse(archiveResponse)
		return failProbe(result, ProbeStageArchiveSize, fmt.Errorf("archive response advertises %d bytes, want %d", archiveResponse.ContentLength, expectedProbeArchiveSize))
	}
	archiveSample, err := readSample(archiveResponse.Body, probeArchiveSampleSize)
	closeResponse(archiveResponse)
	if err != nil {
		return failProbe(result, ProbeStageArchiveBody, err)
	}
	if err := validateArchiveMagic(archiveSample); err != nil {
		return failProbe(result, ProbeStageArchiveMagic, err)
	}
	result.Downloadable = true
	result.Status = ProbeStatusDownloadableNoRange
	return result
}

// newProbeHTTPClient creates the default client with bounded HTTPS redirects and timeout.
// newProbeHTTPClient 创建带有界 HTTPS 重定向和超时策略的默认客户端。
func newProbeHTTPClient() *http.Client {
	return &http.Client{
		Timeout: probeTimeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= maxProbeRedirects {
				return fmt.Errorf("probe redirect chain exceeds %d redirects", maxProbeRedirects)
			}
			if request == nil || request.URL == nil || !strings.EqualFold(request.URL.Scheme, "https") {
				return errors.New("probe redirect must remain on HTTPS")
			}
			return nil
		},
	}
}

// validateFinalResponseHTTPS rejects an observable HTTP downgrade before body processing.
// validateFinalResponseHTTPS 在处理响应体前拒绝可观察到的 HTTP 降级。
func validateFinalResponseHTTPS(response *http.Response) error {
	if response == nil || response.Request == nil || response.Request.URL == nil {
		return nil
	}
	if !strings.EqualFold(response.Request.URL.Scheme, "https") {
		return fmt.Errorf("final probe response URL must use HTTPS, got %q", response.Request.URL.Scheme)
	}
	return nil
}

// doGET sends a bounded probe GET request with a stable request policy.
// doGET 按稳定请求策略发送有界探测 GET 请求。
func doGET(ctx context.Context, client HTTPDoer, requestURL string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", defaultProbeUserAgent)
	response, err := client.Do(request)
	if err != nil {
		closeResponse(response)
		return nil, err
	}
	if response == nil {
		return nil, errors.New("HTTP client returned a nil response")
	}
	if response.Body == nil {
		response.Body = io.NopCloser(strings.NewReader(""))
	}
	return response, nil
}

// doRangeGET sends the fixed archive sample request used to assess resumability.
// doRangeGET 发送用于判断续传能力的固定压缩包样本请求。
func doRangeGET(ctx context.Context, client HTTPDoer, requestURL string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Range", "bytes=0-1023")
	request.Header.Set("User-Agent", defaultProbeUserAgent)
	response, err := client.Do(request)
	if err != nil {
		closeResponse(response)
		return nil, err
	}
	if response == nil {
		return nil, errors.New("HTTP client returned a nil response")
	}
	if response.Body == nil {
		response.Body = io.NopCloser(strings.NewReader(""))
	}
	return response, nil
}

// validatePartialContentHeaders accepts only the requested 1024-byte range and total size.
// validatePartialContentHeaders 只接受请求的 1024 字节范围和精确总大小。
func validatePartialContentHeaders(response *http.Response) error {
	value := response.Header.Get("Content-Range")
	matches := contentRangePattern.FindStringSubmatch(value)
	if len(matches) != 4 {
		return fmt.Errorf("archive Content-Range %q is invalid", value)
	}
	start, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return fmt.Errorf("archive Content-Range start is invalid: %w", err)
	}
	end, err := strconv.ParseInt(matches[2], 10, 64)
	if err != nil {
		return fmt.Errorf("archive Content-Range end is invalid: %w", err)
	}
	total, err := strconv.ParseInt(matches[3], 10, 64)
	if err != nil {
		return fmt.Errorf("archive Content-Range total is invalid: %w", err)
	}
	if start != 0 || end != probeArchiveSampleSize-1 || total != expectedProbeArchiveSize {
		return fmt.Errorf("archive Content-Range is bytes %d-%d/%d, want bytes 0-%d/%d", start, end, total, probeArchiveSampleSize-1, expectedProbeArchiveSize)
	}
	if response.ContentLength >= 0 && response.ContentLength != probeArchiveSampleSize {
		return fmt.Errorf("partial archive response advertises %d bytes, want %d", response.ContentLength, probeArchiveSampleSize)
	}
	return nil
}

// readExactBounded reads at most expected bytes plus one sentinel byte.
// readExactBounded 最多读取 expected 字节加一个哨兵字节。
func readExactBounded(body io.Reader, expected int64) ([]byte, error) {
	if body == nil {
		return nil, errors.New("response body is nil")
	}
	data, err := io.ReadAll(io.LimitReader(body, expected+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > expected {
		return nil, fmt.Errorf("response body exceeds bounded size of %d bytes", expected)
	}
	return data, nil
}

// readSample reads exactly the archive prefix needed for a ZIP magic check.
// readSample 精确读取 ZIP 文件头检查所需的压缩包前缀。
func readSample(body io.Reader, expected int64) ([]byte, error) {
	if body == nil {
		return nil, errors.New("response body is nil")
	}
	data := make([]byte, expected)
	if _, err := io.ReadFull(body, data); err != nil {
		return nil, err
	}
	return data, nil
}

// validateArchiveMagic checks the fixed Windows artifact is a ZIP archive.
// validateArchiveMagic 检查固定 Windows 资产是否为 ZIP 压缩包。
func validateArchiveMagic(sample []byte) error {
	if len(sample) < len(zipMagic) || string(sample[:len(zipMagic)]) != zipMagic {
		return errors.New("archive sample does not start with ZIP magic PK\\x03\\x04")
	}
	return nil
}

// closeResponse closes a response body after a bounded read.
// closeResponse 在有界读取后关闭响应体。
func closeResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

// failProbe records a stable failure stage and a display-safe error string.
// failProbe 记录稳定失败阶段和适合展示的错误字符串。
func failProbe(result ProbeResult, stage ProbeStage, err error) ProbeResult {
	result.Status = ProbeStatusFailed
	result.FailureStage = stage
	if err != nil {
		result.Failure = err.Error()
	}
	return result
}
