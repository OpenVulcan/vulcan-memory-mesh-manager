// This file verifies the release trust boundary with local HTTPS test servers.
// 本文件使用本地 HTTPS 测试服务器验证发行信任边界。
package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/download"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/manifest"
)

// TestDiscoverLatestPinsTheSignedRelease verifies latest resolution and source binding.
// TestDiscoverLatestPinsTheSignedRelease 验证 latest 解析和下载源绑定行为。
func TestDiscoverLatestPinsTheSignedRelease(t *testing.T) {
	manifestBytes, signatureBytes, publicKey := signedManifest(t, manifest.ProductVMMM, "v1.2.3")
	var manifestRequests atomic.Int32
	var signatureRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/releases/latest/download/manifest.json"):
			manifestRequests.Add(1)
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(manifestBytes)
		case strings.HasSuffix(request.URL.Path, "/releases/latest/download/manifest.sig"):
			signatureRequests.Add(1)
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(signatureBytes)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	result, err := Discover(t.Context(), Request{
		Product:  manifest.ProductVMMM,
		Selector: Latest(),
		Source: download.Source{
			ID:     "test-source",
			Name:   "test",
			Kind:   download.SourceKindProxy,
			Prefix: server.URL + "/",
		},
		TrustKeys:  map[string]ed25519.PublicKey{"test-key": publicKey},
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if result.Tag != "v1.2.3" || result.Commit == "" {
		t.Fatalf("unexpected pinned release: tag=%q commit=%q", result.Tag, result.Commit)
	}
	if result.ManifestURL == result.SignatureURL || !strings.HasSuffix(result.ManifestURL, "manifest.json") || !strings.HasSuffix(result.SignatureURL, "manifest.sig") {
		t.Fatalf("unexpected metadata URLs: manifest=%q signature=%q", result.ManifestURL, result.SignatureURL)
	}
	if manifestRequests.Load() != 1 || signatureRequests.Load() != 1 {
		t.Fatalf("unexpected metadata request counts: manifest=%d signature=%d", manifestRequests.Load(), signatureRequests.Load())
	}
}

// TestDiscoverExactTagRejectsSignedTagMismatch prevents exact selector downgrade.
// TestDiscoverExactTagRejectsSignedTagMismatch 防止精确选择器被签名标签降级。
func TestDiscoverExactTagRejectsSignedTagMismatch(t *testing.T) {
	manifestBytes, signatureBytes, publicKey := signedManifest(t, manifest.ProductVMM, "v1.0.0")
	server := newMetadataServer(t, manifestBytes, signatureBytes)
	defer server.Close()

	_, err := Discover(t.Context(), Request{
		Product:    manifest.ProductVMM,
		Selector:   ExactTag("v2.0.0"),
		Source:     testSource(server.URL),
		TrustKeys:  map[string]ed25519.PublicKey{"test-key": publicKey},
		HTTPClient: server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "does not match requested tag") {
		t.Fatalf("Discover() error = %v, want exact tag mismatch", err)
	}
}

// TestDiscoverRequiresInjectedTrustRoot rejects network access without production trust.
// TestDiscoverRequiresInjectedTrustRoot 在没有生产信任根时拒绝联网校验。
func TestDiscoverRequiresInjectedTrustRoot(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		http.Error(writer, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := Discover(t.Context(), Request{
		Product:    manifest.ProductVMMM,
		Selector:   Latest(),
		Source:     testSource(server.URL),
		HTTPClient: server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "trust keys must not be empty") {
		t.Fatalf("Discover() error = %v, want empty trust root error", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("network requests = %d, want zero", requests.Load())
	}
}

// TestDiscoverRejectsHTTPSDowngrade rejects a redirect from the selected HTTPS source to HTTP.
// TestDiscoverRejectsHTTPSDowngrade 拒绝选定 HTTPS 源降级重定向到 HTTP。
func TestDiscoverRejectsHTTPSDowngrade(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, httpServer.URL, http.StatusFound)
	}))
	defer server.Close()

	_, err := Discover(t.Context(), Request{
		Product:    manifest.ProductVMMM,
		Selector:   Latest(),
		Source:     testSource(server.URL),
		TrustKeys:  map[string]ed25519.PublicKey{"test-key": make(ed25519.PublicKey, ed25519.PublicKeySize)},
		HTTPClient: server.Client(),
	})
	if err == nil {
		t.Fatalf("Discover() error = %v, want downgrade rejection", err)
	}
}

// TestDiscoverRejectsLatestVersionMixup rejects manifest and signature redirects to different tags.
// TestDiscoverRejectsLatestVersionMixup 拒绝清单与签名 latest 重定向到不同标签。
func TestDiscoverRejectsLatestVersionMixup(t *testing.T) {
	manifestBytes, signatureBytes, publicKey := signedManifest(t, manifest.ProductVMMM, "v1.0.0")
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/releases/latest/download/manifest.json"):
			http.Redirect(writer, request, "/OpenVulcan/vulcan-memory-mesh-manager/releases/download/v1.0.0/manifest.json", http.StatusFound)
		case strings.HasSuffix(request.URL.Path, "/releases/latest/download/manifest.sig"):
			http.Redirect(writer, request, "/OpenVulcan/vulcan-memory-mesh-manager/releases/download/v2.0.0/manifest.sig", http.StatusFound)
		case strings.HasSuffix(request.URL.Path, "/releases/download/v1.0.0/manifest.json"):
			_, _ = writer.Write(manifestBytes)
		case strings.HasSuffix(request.URL.Path, "/releases/download/v2.0.0/manifest.sig"):
			_, _ = writer.Write(signatureBytes)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	_, err := Discover(t.Context(), Request{
		Product:    manifest.ProductVMMM,
		Selector:   Latest(),
		Source:     testSource(server.URL),
		TrustKeys:  map[string]ed25519.PublicKey{"test-key": publicKey},
		HTTPClient: server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "different tags") {
		t.Fatalf("Discover() error = %v, want version mix-up rejection", err)
	}
}

// signedManifest creates a strict manifest and detached test signature.
// signedManifest 创建严格发行清单及其测试用分离签名。
func signedManifest(t *testing.T, product string, tag string) ([]byte, []byte, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	metadata := manifest.Manifest{
		ProtocolVersion: manifest.ProtocolVersion,
		Product:         product,
		Tag:             tag,
		Commit:          "0123456789012345678901234567890123456789",
		Artifacts: []manifest.Artifact{{
			Platform: "windows-x64",
			Filename: "release.zip",
			Bytes:    1,
			SHA256:   strings.Repeat("0", sha256.Size*2),
		}},
	}
	manifestBytes, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	signature := ed25519.Sign(privateKey, manifestBytes)
	signatureEnvelope, err := json.Marshal(manifest.SignatureEnvelope{
		Version:   manifest.SignatureVersion,
		KeyID:     "test-key",
		Signature: base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatalf("Marshal(signature) error = %v", err)
	}
	return manifestBytes, signatureEnvelope, publicKey
}

// newMetadataServer serves one fixed metadata pair for exact-tag tests.
// newMetadataServer 为精确标签测试提供一对固定元数据。
func newMetadataServer(t *testing.T, manifestBytes []byte, signatureBytes []byte) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/manifest.json") {
			_, _ = writer.Write(manifestBytes)
			return
		}
		if strings.HasSuffix(request.URL.Path, "/manifest.sig") {
			_, _ = writer.Write(signatureBytes)
			return
		}
		http.NotFound(writer, request)
	}))
}

// testSource maps the allowlisted proxy form to a local HTTPS test server.
// testSource 将允许的代理形式映射到本地 HTTPS 测试服务器。
func testSource(prefix string) download.Source {
	return download.Source{
		ID:     "test-source",
		Name:   "test",
		Kind:   download.SourceKindProxy,
		Prefix: prefix + "/",
	}
}
