// Package fetch tests the signed release byte-transfer boundary without network access outside httptest.
// fetch 包通过 httptest 测试签名发行文件传输边界，不访问外部网络。
// These tests cover exact URL selection, bounded streaming, integrity checks, and atomic publication.
// 这些测试覆盖 URL 精确选择、有界流式传输、完整性校验以及原子发布。
package fetch

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/download"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/manifest"
)

// testArtifactFilename is the fixed test-only release asset basename.
// testArtifactFilename 是仅用于测试的固定发行资产文件名。
const testArtifactFilename = "vulcan-memory-mesh-v1.2.3-windows-x64.zip"

// TestFetchStreamsAndPublishesVerifiedArtifact checks the exact GitHub proxy URL and final digest.
// TestFetchStreamsAndPublishesVerifiedArtifact 检查精确 GitHub 代理 URL 与最终文件摘要。
func TestFetchStreamsAndPublishesVerifiedArtifact(t *testing.T) {
	artifactBytes := []byte(strings.Repeat("verified-vmm-artifact-", 4096))
	receivedPath := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		receivedPath <- request.URL.Path
		response.Header().Set("Content-Type", "application/octet-stream")
		_, _ = response.Write(artifactBytes)
	}))
	defer server.Close()

	request := testRequest(t, server, artifactBytes, filepath.Join(t.TempDir(), testArtifactFilename))
	var lastProgress int64
	request.Progress = func(downloaded int64, total int64) {
		if total != int64(len(artifactBytes)) || downloaded < lastProgress || downloaded > total {
			t.Errorf("progress = (%d, %d), previous = %d", downloaded, total, lastProgress)
		}
		lastProgress = downloaded
	}
	result, err := fetchWithClient(context.Background(), server.Client(), request)
	if err != nil {
		t.Fatalf("Fetch() failed: %v", err)
	}
	wantURLPath := "/https://github.com/OpenVulcan/vulcan-memory-mesh/releases/download/v1.2.3/" + testArtifactFilename
	select {
	case gotURLPath := <-receivedPath:
		if gotURLPath != wantURLPath {
			t.Fatalf("request path = %q, want %q", gotURLPath, wantURLPath)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not receive the release request")
	}
	stored, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatalf("read published artifact: %v", err)
	}
	if string(stored) != string(artifactBytes) || result.Bytes != int64(len(artifactBytes)) {
		t.Fatalf("published artifact size = %d, result bytes = %d", len(stored), result.Bytes)
	}
	expectedDigest := sha256.Sum256(artifactBytes)
	if result.SHA256 != hex.EncodeToString(expectedDigest[:]) {
		t.Fatalf("result SHA256 = %q, want %x", result.SHA256, expectedDigest)
	}
}

// TestFetchUsesInjectedURLResolver proves transfer and verification do not depend on GitHub path layout.
// TestFetchUsesInjectedURLResolver 证明传输与校验流程不依赖 GitHub 路径结构。
func TestFetchUsesInjectedURLResolver(t *testing.T) {
	artifactBytes := []byte("verified artifact from a static HTTPS layout")
	receivedPath := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		receivedPath <- request.URL.Path
		_, _ = response.Write(artifactBytes)
	}))
	defer server.Close()
	request := testRequest(t, server, artifactBytes, filepath.Join(t.TempDir(), testArtifactFilename))
	resolver := URLResolver(func(_ download.Source, repository download.Repository, tag string, filename string) (string, error) {
		if repository != download.RepositoryVMM || tag != "v1.2.3" || filename != testArtifactFilename {
			t.Errorf("resolver identity = (%q, %q, %q)", repository, tag, filename)
		}
		return server.URL + "/static/releases/" + filename, nil
	})
	result, err := fetchWithResolver(context.Background(), server.Client(), request, resolver)
	if err != nil {
		t.Fatalf("FetchWithResolver() failed: %v", err)
	}
	select {
	case path := <-receivedPath:
		if path != "/static/releases/"+testArtifactFilename {
			t.Fatalf("request path = %q, want static HTTPS layout", path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not receive the static release request")
	}
	if result.Bytes != int64(len(artifactBytes)) {
		t.Fatalf("result bytes = %d, want %d", result.Bytes, len(artifactBytes))
	}
}

// TestFetchRejectsProxyErrorPage rejects an HTML error page even when the proxy returns HTTP 200.
// TestFetchRejectsProxyErrorPage 拒绝代理以 HTTP 200 返回的 HTML 错误页。
func TestFetchRejectsProxyErrorPage(t *testing.T) {
	artifactBytes := []byte("verified bytes expected from release")
	secretBody := []byte("<html>proxy error secret response</html>")
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/html")
		_, _ = response.Write(secretBody)
	}))
	defer server.Close()
	request := testRequest(t, server, artifactBytes, filepath.Join(t.TempDir(), testArtifactFilename))
	_, err := fetchWithClient(context.Background(), server.Client(), request)
	if err == nil {
		t.Fatalf("Fetch() accepted a proxy error page: %v", err)
	}
	if strings.Contains(err.Error(), "secret response") {
		t.Fatalf("error exposed response content: %v", err)
	}
	assertDirectoryEmpty(t, filepath.Dir(request.StagingPath))
}

// TestFetchRejectsWrongLength rejects a complete response whose size differs from the manifest.
// TestFetchRejectsWrongLength 拒绝完整响应长度与签名清单不一致的情况。
func TestFetchRejectsWrongLength(t *testing.T) {
	artifactBytes := []byte("expected artifact body")
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write(artifactBytes[:len(artifactBytes)-1])
	}))
	defer server.Close()
	request := testRequest(t, server, artifactBytes, filepath.Join(t.TempDir(), testArtifactFilename))
	_, err := fetchWithClient(context.Background(), server.Client(), request)
	if !errors.Is(err, ErrArtifactSize) {
		t.Fatalf("Fetch() error = %v, want ErrArtifactSize", err)
	}
	assertDirectoryEmpty(t, filepath.Dir(request.StagingPath))
}

// TestFetchBoundsOversizedResponse stops reading after the signed length plus one sentinel byte.
// TestFetchBoundsOversizedResponse 在签名长度加一个哨兵字节后停止读取超大响应。
func TestFetchBoundsOversizedResponse(t *testing.T) {
	artifactBytes := []byte("expected artifact body")
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
		response.(http.Flusher).Flush()
		_, _ = response.Write(append(append([]byte(nil), artifactBytes...), []byte("overflow")...))
	}))
	defer server.Close()
	request := testRequest(t, server, artifactBytes, filepath.Join(t.TempDir(), testArtifactFilename))
	_, err := fetchWithClient(context.Background(), server.Client(), request)
	if !errors.Is(err, ErrArtifactSize) {
		t.Fatalf("Fetch() error = %v, want ErrArtifactSize", err)
	}
	assertDirectoryEmpty(t, filepath.Dir(request.StagingPath))
}

// TestFetchRejectsWrongDigest rejects a full-size artifact that differs from the signed digest.
// TestFetchRejectsWrongDigest 拒绝长度正确但内容摘要与签名不符的资产。
func TestFetchRejectsWrongDigest(t *testing.T) {
	artifactBytes := []byte("expected artifact body")
	wrongBytes := []byte(strings.Repeat("x", len(artifactBytes)))
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write(wrongBytes)
	}))
	defer server.Close()
	request := testRequest(t, server, artifactBytes, filepath.Join(t.TempDir(), testArtifactFilename))
	_, err := fetchWithClient(context.Background(), server.Client(), request)
	if !errors.Is(err, ErrArtifactDigest) {
		t.Fatalf("Fetch() error = %v, want ErrArtifactDigest", err)
	}
	assertDirectoryEmpty(t, filepath.Dir(request.StagingPath))
}

// TestFetchRejectsTruncatedResponse rejects a stream that ends before its declared content length.
// TestFetchRejectsTruncatedResponse 拒绝在声明长度之前中断的响应流。
func TestFetchRejectsTruncatedResponse(t *testing.T) {
	artifactBytes := []byte("expected artifact body")
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Length", strconv.Itoa(len(artifactBytes)))
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(artifactBytes[:4])
		response.(http.Flusher).Flush()
	}))
	defer server.Close()
	request := testRequest(t, server, artifactBytes, filepath.Join(t.TempDir(), testArtifactFilename))
	_, err := fetchWithClient(context.Background(), server.Client(), request)
	if err == nil {
		t.Fatal("Fetch() succeeded with a truncated response")
	}
	assertDirectoryEmpty(t, filepath.Dir(request.StagingPath))
}

// TestFetchRejectsHTTPSDowngrade ensures the client never follows an HTTPS redirect to HTTP.
// TestFetchRejectsHTTPSDowngrade 确保客户端绝不跟随从 HTTPS 降级到 HTTP 的重定向。
func TestFetchRejectsHTTPSDowngrade(t *testing.T) {
	var insecureRequests atomic.Int32
	insecureServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		insecureRequests.Add(1)
	}))
	defer insecureServer.Close()
	secureServer := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, insecureServer.URL+"/asset?token=redirect-secret", http.StatusFound)
	}))
	defer secureServer.Close()
	artifactBytes := []byte("verified artifact body")
	request := testRequest(t, secureServer, artifactBytes, filepath.Join(t.TempDir(), testArtifactFilename))
	_, err := fetchWithClient(context.Background(), secureServer.Client(), request)
	if err == nil {
		t.Fatal("Fetch() succeeded after an HTTPS-to-HTTP redirect")
	}
	if strings.Contains(err.Error(), "redirect-secret") {
		t.Fatalf("error exposed a redirect token: %v", err)
	}
	if insecureRequests.Load() != 0 {
		t.Fatalf("HTTP redirect destination received %d requests", insecureRequests.Load())
	}
	assertDirectoryEmpty(t, filepath.Dir(request.StagingPath))
}

// TestFetchRejectsDuplicateTarget preserves an existing destination and avoids the network request.
// TestFetchRejectsDuplicateTarget 保留已有目标文件，并确保冲突时不发起网络请求。
func TestFetchRejectsDuplicateTarget(t *testing.T) {
	var requests atomic.Int32
	artifactBytes := []byte("signed release artifact")
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = response.Write(artifactBytes)
	}))
	defer server.Close()
	request := testRequest(t, server, artifactBytes, filepath.Join(t.TempDir(), testArtifactFilename))
	priorBytes := []byte("previous verified artifact")
	if err := os.WriteFile(request.StagingPath, priorBytes, 0o600); err != nil {
		t.Fatalf("create preexisting artifact: %v", err)
	}
	_, err := fetchWithClient(context.Background(), server.Client(), request)
	if !errors.Is(err, ErrTargetExists) {
		t.Fatalf("Fetch() error = %v, want ErrTargetExists", err)
	}
	stored, readErr := os.ReadFile(request.StagingPath)
	if readErr != nil || string(stored) != string(priorBytes) {
		t.Fatalf("existing target changed: bytes=%q error=%v", stored, readErr)
	}
	if requests.Load() != 0 {
		t.Fatalf("duplicate target caused %d network requests", requests.Load())
	}
}

// TestFetchCancellationCleansTemporaryFile verifies context cancellation leaves no partial target or temp file.
// TestFetchCancellationCleansTemporaryFile 验证取消上下文后不会遗留半成品或临时文件。
func TestFetchCancellationCleansTemporaryFile(t *testing.T) {
	artifactBytes := []byte(strings.Repeat("slow artifact ", 1024))
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Length", strconv.Itoa(len(artifactBytes)))
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(artifactBytes[:16])
		response.(http.Flusher).Flush()
		close(started)
		<-request.Context().Done()
	}))
	defer server.Close()
	request := testRequest(t, server, artifactBytes, filepath.Join(t.TempDir(), testArtifactFilename))
	ctx, cancel := context.WithCancel(context.Background())
	resultChannel := make(chan error, 1)
	go func() {
		_, err := fetchWithClient(ctx, server.Client(), request)
		resultChannel <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("server did not start streaming")
	}
	cancel()
	select {
	case err := <-resultChannel:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Fetch() error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Fetch() did not return after cancellation")
	}
	assertDirectoryEmpty(t, filepath.Dir(request.StagingPath))
}

// TestFetchBindsProductToRepository prevents a VMM manifest from selecting the manager repository.
// TestFetchBindsProductToRepository 阻止 VMM 清单被用于选择管理器仓库。
func TestFetchBindsProductToRepository(t *testing.T) {
	var requests atomic.Int32
	artifactBytes := []byte("signed release artifact")
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = response.Write(artifactBytes)
	}))
	defer server.Close()
	request := testRequest(t, server, artifactBytes, filepath.Join(t.TempDir(), testArtifactFilename))
	request.Product = manifest.ProductVMMM
	request.Repository = download.RepositoryManager
	_, err := fetchWithClient(context.Background(), server.Client(), request)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Fetch() error = %v, want product/manifest mismatch", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("mismatched product caused %d network requests", requests.Load())
	}
}

// TestFetchRejectsPathTraversal rejects a target that attempts to leave the selected staging directory.
// TestFetchRejectsPathTraversal 拒绝试图离开所选暂存目录的目标路径。
func TestFetchRejectsPathTraversal(t *testing.T) {
	artifactBytes := []byte("signed release artifact")
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write(artifactBytes)
	}))
	defer server.Close()
	stagingDirectory := t.TempDir()
	traversingPath := stagingDirectory + string(os.PathSeparator) + ".." + string(os.PathSeparator) + testArtifactFilename
	request := testRequest(t, server, artifactBytes, traversingPath)
	_, err := fetchWithClient(context.Background(), server.Client(), request)
	if err == nil || !strings.Contains(err.Error(), "parent traversal") {
		t.Fatalf("Fetch() error = %v, want traversal rejection", err)
	}
	assertDirectoryEmpty(t, stagingDirectory)
}

// TestFetchRejectsSymlinkedStagingPath rejects a parent symlink or Windows reparse point.
// TestFetchRejectsSymlinkedStagingPath 拒绝父目录中的符号链接或 Windows 重解析点。
func TestFetchRejectsSymlinkedStagingPath(t *testing.T) {
	artifactBytes := []byte("signed release artifact")
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write(artifactBytes)
	}))
	defer server.Close()
	baseDirectory := t.TempDir()
	outsideDirectory := t.TempDir()
	linkPath := filepath.Join(baseDirectory, "staging-link")
	if err := os.Symlink(outsideDirectory, linkPath); err != nil {
		t.Skipf("symbolic links are unavailable in this environment: %v", err)
	}
	request := testRequest(t, server, artifactBytes, filepath.Join(linkPath, testArtifactFilename))
	_, err := fetchWithClient(context.Background(), server.Client(), request)
	if err == nil || !strings.Contains(err.Error(), "symbolic links or reparse points") {
		t.Fatalf("Fetch() error = %v, want symlink rejection", err)
	}
	assertDirectoryEmpty(t, outsideDirectory)
}

// testRequest builds a request from a locally signed manifest and one HTTPS test server.
// testRequest 使用本地测试密钥和 HTTPS 测试服务器构造下载请求。
func testRequest(t *testing.T, server *httptest.Server, artifactBytes []byte, stagingPath string) Request {
	t.Helper()
	digest := sha256.Sum256(artifactBytes)
	manifestDocument := manifest.Manifest{
		ProtocolVersion: manifest.ProtocolVersion,
		Product:         manifest.ProductVMM,
		Tag:             "v1.2.3",
		Commit:          "0123456789abcdef0123456789abcdef01234567",
		Artifacts: []manifest.Artifact{{
			Platform: "windows-x64",
			Filename: testArtifactFilename,
			Bytes:    int64(len(artifactBytes)),
			SHA256:   hex.EncodeToString(digest[:]),
		}},
	}
	manifestBytes, err := json.Marshal(manifestDocument)
	if err != nil {
		t.Fatalf("marshal test manifest: %v", err)
	}
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	signature := ed25519.Sign(privateKey, manifestBytes)
	signatureBytes, err := json.Marshal(manifest.SignatureEnvelope{
		Version:   manifest.SignatureVersion,
		KeyID:     "fetch-test",
		Signature: base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatalf("marshal test signature: %v", err)
	}
	verified, err := manifest.Verify(manifestBytes, signatureBytes, map[string]ed25519.PublicKey{
		"fetch-test": privateKey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatalf("verify test manifest: %v", err)
	}
	source, err := download.NewCustomProxy(server.URL + "/")
	if err != nil {
		t.Fatalf("create test proxy source: %v", err)
	}
	return Request{
		Source:      source,
		Manifest:    verified,
		Product:     manifest.ProductVMM,
		Repository:  download.RepositoryVMM,
		Platform:    "windows-x64",
		StagingPath: stagingPath,
	}
}

// assertDirectoryEmpty ensures failed transfers leave neither targets nor temporary files behind.
// assertDirectoryEmpty 确认失败传输不会留下目标文件或临时文件。
func assertDirectoryEmpty(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read staging directory: %v", err)
	}
	if len(entries) != 0 {
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("staging directory is not empty: %s", strings.Join(names, ", "))
	}
}
