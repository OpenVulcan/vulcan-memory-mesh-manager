// Package download contains deterministic tests for source construction and probing.
// download 包包含下载源构造和探测逻辑的确定性测试。
package download

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDefaultSourcesAndURLConstruction protects stable source IDs and exact URL spelling.
// TestDefaultSourcesAndURLConstruction 保护稳定源 ID 和精确 URL 写法。
func TestDefaultSourcesAndURLConstruction(t *testing.T) {
	sources := DefaultSources()
	if len(sources) != 4 {
		t.Fatalf("DefaultSources() returned %d sources, want 4", len(sources))
	}
	wantIDs := []SourceID{SourceIDGitHubOfficial, SourceIDGhproxyNet, SourceIDGhProxyOrg, SourceIDGhfastTop}
	for index, source := range sources {
		if source.ID != wantIDs[index] {
			t.Fatalf("source %d ID = %q, want %q", index, source.ID, wantIDs[index])
		}
		if err := source.Validate(); err != nil {
			t.Fatalf("source %q failed validation: %v", source.ID, err)
		}
	}

	officialURL, err := BuildReleaseURL(sources[0], RepositoryVMM, VMMProbeTag, VMMProbeChecksumAsset)
	if err != nil {
		t.Fatalf("BuildReleaseURL(official) failed: %v", err)
	}
	if want := "https://github.com/OpenVulcan/vulcan-memory-mesh/releases/download/v0.1.0/SHA256SUMS"; officialURL != want {
		t.Fatalf("official URL = %q, want %q", officialURL, want)
	}

	proxyURL, err := BuildReleaseURL(sources[1], RepositoryVMM, VMMProbeTag, VMMProbeChecksumAsset)
	if err != nil {
		t.Fatalf("BuildReleaseURL(proxy) failed: %v", err)
	}
	if want := "https://ghproxy.net/https://github.com/OpenVulcan/vulcan-memory-mesh/releases/download/v0.1.0/SHA256SUMS"; proxyURL != want {
		t.Fatalf("proxy URL = %q, want %q", proxyURL, want)
	}
}

// TestCustomProxyValidationRejectsAmbiguousPrefixes verifies the custom input boundary.
// TestCustomProxyValidationRejectsAmbiguousPrefixes 验证自定义输入边界。
func TestCustomProxyValidationRejectsAmbiguousPrefixes(t *testing.T) {
	invalid := []string{
		"",
		"http://proxy.example/",
		"https://proxy.example",
		"https://proxy.example/?token=secret",
		"https://user:pass@proxy.example/",
		"https://proxy.example/#fragment",
		"https://proxy.example/a/../",
		"https://proxy.example/a/%2e%2e/",
		"https://proxy.example/a\\b/",
	}
	for _, prefix := range invalid {
		if _, err := NewCustomProxy(prefix); err == nil {
			t.Errorf("NewCustomProxy(%q) succeeded, want error", prefix)
		}
	}

	first, err := NewCustomProxy("https://proxy.example/path/")
	if err != nil {
		t.Fatalf("NewCustomProxy(valid) failed: %v", err)
	}
	second, err := NewCustomProxy("https://proxy.example/path/")
	if err != nil {
		t.Fatalf("NewCustomProxy(valid second call) failed: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("custom source IDs differ: %q vs %q", first.ID, second.ID)
	}
	if !strings.HasPrefix(string(first.ID), "github-proxy-custom-") {
		t.Fatalf("custom source ID = %q, want github-proxy-custom- prefix", first.ID)
	}
}

// TestBuildReleaseURLRejectsUnallowlistedRepositoriesAndPathTraversal protects URL scope.
// TestBuildReleaseURLRejectsUnallowlistedRepositoriesAndPathTraversal 保护 URL 访问范围。
func TestBuildReleaseURLRejectsUnallowlistedRepositoriesAndPathTraversal(t *testing.T) {
	source := DefaultSources()[0]
	cases := []struct {
		name       string
		repository Repository
		tag        string
		filename   string
	}{
		{name: "repository", repository: Repository("other-repository"), tag: VMMProbeTag, filename: VMMProbeChecksumAsset},
		{name: "tag traversal", repository: RepositoryVMM, tag: "../v0.1.0", filename: VMMProbeChecksumAsset},
		{name: "filename query", repository: RepositoryVMM, tag: VMMProbeTag, filename: "SHA256SUMS?x=1"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := BuildReleaseURL(source, testCase.repository, testCase.tag, testCase.filename); err == nil {
				t.Fatal("BuildReleaseURL succeeded, want error")
			}
		})
	}
}

// TestProbeWithRangeUsesInjectedHTTPFixture verifies the complete successful probe without network access.
// TestProbeWithRangeUsesInjectedHTTPFixture 验证无网络时通过注入 HTTP fixture 完成完整探测。
func TestProbeWithRangeUsesInjectedHTTPFixture(t *testing.T) {
	checksumBody := checksumFixture(t)
	archiveSample := makeArchiveSample()
	var sawRange bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/SHA256SUMS") {
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(checksumBody)
			return
		}
		if !strings.HasSuffix(request.URL.Path, "/"+VMMProbeArchiveAsset) {
			http.NotFound(writer, request)
			return
		}
		if request.Header.Get("Range") != "bytes=0-1023" {
			http.Error(writer, "missing range", http.StatusBadRequest)
			return
		}
		sawRange = true
		writer.Header().Set("Content-Range", "bytes 0-1023/123238027")
		writer.Header().Set("Content-Length", "1024")
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write(archiveSample)
	}))
	defer server.Close()

	source, err := NewCustomProxy(server.URL + "/")
	if err != nil {
		t.Fatalf("NewCustomProxy(httptest) failed: %v", err)
	}
	result := Probe(context.Background(), server.Client(), source)
	if result.Status != ProbeStatusPassed || !result.Downloadable || !result.RangeSupported {
		t.Fatalf("probe result = %+v, want passed/downloadable/range-supported", result)
	}
	if result.FailureStage != ProbeStageNone || result.Failure != "" {
		t.Fatalf("successful probe recorded failure: %+v", result)
	}
	if !sawRange {
		t.Fatal("probe did not send the required Range header")
	}
}

// TestProbeRejectsTruncatedPartialArchive rejects a ZIP header without the requested full sample.
// TestProbeRejectsTruncatedPartialArchive 拒绝只有 ZIP 文件头而没有完整样本的响应。
func TestProbeRejectsTruncatedPartialArchive(t *testing.T) {
	checksumBody := checksumFixture(t)
	client := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/SHA256SUMS") {
			return fixtureResponse(http.StatusOK, checksumBody, int64(len(checksumBody)), nil), nil
		}
		return fixtureResponse(
			http.StatusPartialContent,
			[]byte(zipMagic),
			probeArchiveSampleSize,
			map[string]string{"Content-Range": "bytes 0-1023/123238027"},
		), nil
	})
	result := Probe(context.Background(), client, DefaultSources()[0])
	if result.Status != ProbeStatusFailed || result.FailureStage != ProbeStageArchiveBody {
		t.Fatalf("probe result = %+v, want archive-body failure", result)
	}
}

// TestProbeDefaultClientRejectsHTTPSDowngrade verifies the default redirect policy with real TLS fixtures.
// TestProbeDefaultClientRejectsHTTPSDowngrade 使用真实 TLS fixture 验证默认重定向策略。
func TestProbeDefaultClientRejectsHTTPSDowngrade(t *testing.T) {
	var insecureHits int
	insecureServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		insecureHits++
		http.Error(writer, "insecure endpoint must not be reached", http.StatusInternalServerError)
	}))
	defer insecureServer.Close()

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, insecureServer.URL+"/downgrade", http.StatusFound)
	}))
	defer tlsServer.Close()

	client := newProbeHTTPClient()
	client.Transport = tlsServer.Client().Transport
	source, err := NewCustomProxy(tlsServer.URL + "/")
	if err != nil {
		t.Fatalf("NewCustomProxy(TLS fixture) failed: %v", err)
	}
	result := Probe(context.Background(), client, source)
	if result.Status != ProbeStatusFailed || result.FailureStage != ProbeStageChecksumRequest {
		t.Fatalf("probe result = %+v, want checksum-request failure", result)
	}
	if !strings.Contains(result.Failure, "HTTPS") {
		t.Fatalf("probe failure = %q, want HTTPS downgrade detail", result.Failure)
	}
	if insecureHits != 0 {
		t.Fatalf("insecure redirect target was reached %d times", insecureHits)
	}
}

// TestProbeRejectsInjectedHTTPFinalResponse verifies the final URL guard for injected clients.
// TestProbeRejectsInjectedHTTPFinalResponse 验证注入客户端的最终 URL 防降级检查。
func TestProbeRejectsInjectedHTTPFinalResponse(t *testing.T) {
	client := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		response := fixtureResponse(http.StatusOK, checksumFixture(t), expectedProbeChecksumSize, nil)
		response.Request = httptest.NewRequest(http.MethodGet, "http://proxy.example/SHA256SUMS", nil)
		return response, nil
	})
	result := Probe(context.Background(), client, DefaultSources()[0])
	if result.Status != ProbeStatusFailed || result.FailureStage != ProbeStageChecksumRequest {
		t.Fatalf("probe result = %+v, want checksum-request failure", result)
	}
}

// TestProbeRedirectPolicyAllowsHTTPSCDN verifies HTTPS-to-HTTPS redirects remain allowed.
// TestProbeRedirectPolicyAllowsHTTPSCDN 验证 HTTPS 到 HTTPS 的 CDN 重定向仍然允许。
func TestProbeRedirectPolicyAllowsHTTPSCDN(t *testing.T) {
	client := newProbeHTTPClient()
	previous := httptest.NewRequest(http.MethodGet, "https://github.com/OpenVulcan/vulcan-memory-mesh", nil)
	cdn := httptest.NewRequest(http.MethodGet, "https://objects.githubusercontent.com/vmm.zip", nil)
	if err := client.CheckRedirect(cdn, []*http.Request{previous}); err != nil {
		t.Fatalf("HTTPS redirect rejected: %v", err)
	}
	insecure := httptest.NewRequest(http.MethodGet, "http://proxy.example/vmm.zip", nil)
	if err := client.CheckRedirect(insecure, []*http.Request{previous}); err == nil {
		t.Fatal("HTTP downgrade redirect was accepted")
	}
	via := make([]*http.Request, maxProbeRedirects)
	if err := client.CheckRedirect(cdn, via); err == nil {
		t.Fatal("redirect chain beyond configured limit was accepted")
	}
}

// TestProbeAcceptsValidHTTP200AsDownloadableOnly verifies the explicit no-resume classification.
// TestProbeAcceptsValidHTTP200AsDownloadableOnly 验证 HTTP 200 的明确不可证明续传分类。
func TestProbeAcceptsValidHTTP200AsDownloadableOnly(t *testing.T) {
	checksumBody := checksumFixture(t)
	archiveSample := makeArchiveSample()
	client := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/SHA256SUMS") {
			return fixtureResponse(http.StatusOK, checksumBody, int64(len(checksumBody)), nil), nil
		}
		return fixtureResponse(http.StatusOK, archiveSample, expectedProbeArchiveSize, nil), nil
	})
	source, err := NewCustomProxy("https://proxy.example/")
	if err != nil {
		t.Fatalf("NewCustomProxy failed: %v", err)
	}
	result := Probe(context.Background(), client, source)
	if result.Status != ProbeStatusDownloadableNoRange || !result.Downloadable || result.RangeSupported {
		t.Fatalf("probe result = %+v, want downloadable-no-range only", result)
	}
}

// TestProbeRecordsChecksumDigestFailure verifies the first failing stage is preserved.
// TestProbeRecordsChecksumDigestFailure 验证首个失败阶段会被保留。
func TestProbeRecordsChecksumDigestFailure(t *testing.T) {
	badChecksum := []byte(strings.Repeat("x", int(expectedProbeChecksumSize)))
	client := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return fixtureResponse(http.StatusOK, badChecksum, int64(len(badChecksum)), nil), nil
	})
	source := DefaultSources()[0]
	result := Probe(context.Background(), client, source)
	if result.Status != ProbeStatusFailed || result.FailureStage != ProbeStageChecksumDigest {
		t.Fatalf("probe result = %+v, want checksum-digest failure", result)
	}
}

// TestProbeRejectsOversizedChecksum verifies response-body bounds are enforced before digest use.
// TestProbeRejectsOversizedChecksum 验证摘要响应体会在计算摘要前执行大小上限。
func TestProbeRejectsOversizedChecksum(t *testing.T) {
	oversized := append(make([]byte, expectedProbeChecksumSize), 'x')
	client := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return fixtureResponse(http.StatusOK, oversized, int64(len(oversized)), nil), nil
	})
	result := Probe(context.Background(), client, DefaultSources()[0])
	if result.Status != ProbeStatusFailed || result.FailureStage != ProbeStageChecksumSize {
		t.Fatalf("probe result = %+v, want checksum-size failure", result)
	}
}

// roundTripFunc adapts a fixture function to the injected HTTPDoer interface.
// roundTripFunc 将 fixture 函数适配为可注入的 HTTPDoer 接口。
type roundTripFunc func(*http.Request) (*http.Response, error)

// Do executes the fixture callback for one request.
// Do 为一个请求执行 fixture 回调。
func (fixture roundTripFunc) Do(request *http.Request) (*http.Response, error) {
	return fixture(request)
}

// fixtureResponse creates an in-memory HTTP response for deterministic probe tests.
// fixtureResponse 创建用于确定性探测测试的内存 HTTP 响应。
func fixtureResponse(status int, body []byte, contentLength int64, headers map[string]string) *http.Response {
	header := make(http.Header)
	for key, value := range headers {
		header.Set(key, value)
	}
	return &http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(string(body))),
		ContentLength: contentLength,
	}
}

// checksumFixture decodes the checked-in official checksum fixture.
// checksumFixture 解码已固定的官方摘要 fixture。
func checksumFixture(t *testing.T) []byte {
	t.Helper()
	const encoded = "MGM0ODQ2ZGRiMGQxMzAwMDFiZjhiM2MyNTE3NTg1ZTNkY2QwOWU4ZDAxNjQyOTcwYmY4MjRjN2E3MzIyNTMzNiAgdnVsY2FuLW1lbW9yeS1tZXNoLXYwLjEuMC1tYWNvcy1hcm02NC50YXIuZ3oKMGY1ODNlYWVkMDMyM2JkOTZlZGQwY2Y0MWIwNDEyYzdhYzcwNTI4NzBlMzg2Mzk2MWEyNjYyYTEyOTc0ZDNhZSAgdnVsY2FuLW1lbW9yeS1tZXNoLXYwLjEuMC13aW5kb3dzLXg2NC56aXAKMWFjYjk5MmIzYjk2ZDIxZmJkYTQ5MmJjMGFjNzdiNjFjNDBkNTZiZmQxNTEyYjQ4ZWNiYWUxYzhjMzk5MGQ3YiAgdnVsY2FuLW1lbW9yeS1tZXNoLXYwLjEuMC1tYWNvcy1hcm02NC5qc29uCjNjYjQzODIyYWQ3MTkzYTMyZjRlYWU4YWI2MDUzNGM2YTNjZDEyMDg0ZWY2ZGE1YTgzYzQ5MmU3N2JhZGU0MjIgIHZ1bGNhbi1tZW1vcnktbWVzaC12MC4xLjAtbWFjb3MtaW50ZWwuanNvbgozZGU4MzlmOWE3YmMyNTA4NDk3YmQ5YWZjYWE0ODYxZjA0Y2YxNmVhZDAxYjM1NzBmYWQ2M2RkODU5NzllYzM1ICB2dWxjYW4tbWVtb3J5LW1lc2gtdjAuMS4wLWxpbnV4LXg2NC5qc29uCjQwZjc3NDAwMDUzYzZmMjA3ZDVjYzllMDBkZWU2NzFiNDkxMjE2NmIzNWQ4N2MwN2E0OTQ2NDhmMjAyMDcyY2QgIHZ1bGNhbi1tZW1vcnktbWVzaC12MC4xLjAtbWFjb3MtaW50ZWwudGFyLmd6CjQ5MGRlMTQ0OWY0M2RiYWM5ZGVkYjkyMjJiZjgzNzFkNzQ0NmIzMDk1OTIzNDIyNTZjMjU1Y2E5NmRjZjRhNzEgIHZ1bGNhbi1tZW1vcnktbWVzaC12MC4xLjAtbGludXgteDY0LnRhci5negpjMTg1NWRkZmQ1ZDQ2NDUzZDM3NmI1ZDk3NTU0ZTE0ZjExNDIwMjIzMjNhNGRjNzJkOGFkZDEyMzE5MDlkNjkwICB2dWxjYW4tbWVtb3J5LW1lc2gtdjAuMS4wLXdpbmRvd3MteDY0Lmpzb24KZmJjMDIzOTI1OWVkMDAwYWYwMzVmNGFhMDQxOGUyMmRjNWM4YTQwZjk1NmNjMmViNDRkNDMyMmY3ZjYzMmE1NCAgdnVsY2FuLW1lbW9yeS1tZXNoLXYwLjEuMC1saW51eC1hcm02NC50YXIuZ3oKZmRjZmU4MjkwMWQ3YTczMjNiNjg3ZmNiYzkzYmMxYzFiOTRmNWZiYmM1ODY4Yzk1ODE3MDIzOTY5YzY1ODdkMCAgdnVsY2FuLW1lbW9yeS1tZXNoLXYwLjEuMC1saW51eC1hcm02NC5qc29uCg=="
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode checksum fixture: %v", err)
	}
	digest := sha256.Sum256(data)
	if got := hex.EncodeToString(digest[:]); got != expectedProbeChecksumSHA256 {
		t.Fatalf("checksum fixture digest = %s, want %s", got, expectedProbeChecksumSHA256)
	}
	if int64(len(data)) != expectedProbeChecksumSize {
		t.Fatalf("checksum fixture size = %d, want %d", len(data), expectedProbeChecksumSize)
	}
	return data
}

// makeArchiveSample creates the bounded ZIP prefix used by fixture responses.
// makeArchiveSample 创建 fixture 响应使用的有界 ZIP 前缀。
func makeArchiveSample() []byte {
	sample := make([]byte, probeArchiveSampleSize)
	copy(sample, []byte(zipMagic))
	return sample
}
