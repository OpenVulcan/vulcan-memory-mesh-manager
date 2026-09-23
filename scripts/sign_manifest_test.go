// Test the Go standard-library release signing boundary.
// 测试 Go 标准库发行签名边界。
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestRFC8032EmptyMessageVector verifies the standard Ed25519 implementation against RFC 8032.
// TestRFC8032EmptyMessageVector 使用 RFC 8032 验证标准 Ed25519 实现。
func TestRFC8032EmptyMessageVector(t *testing.T) {
	seed := mustHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	expectedPublic := mustHex(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	expectedSignature := mustHex(t, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	privateKey := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), expectedPublic) {
		t.Fatal("RFC public key mismatch")
	}
	if signature := ed25519.Sign(privateKey, nil); !bytes.Equal(signature, expectedSignature) {
		t.Fatal("RFC signature mismatch")
	}
	if !ed25519.Verify(ed25519.PublicKey(expectedPublic), nil, expectedSignature) {
		t.Fatal("RFC signature did not verify")
	}
}

// TestManifestEnvelopeRoundTrip verifies exact bytes, envelope fields, and tamper rejection.
// TestManifestEnvelopeRoundTrip 验证原始字节、封装字段与篡改拒绝。
func TestManifestEnvelopeRoundTrip(t *testing.T) {
	temporary := t.TempDir()
	manifestPath := filepath.Join(temporary, "manifest.json")
	signaturePath := filepath.Join(temporary, "manifest.sig")
	seed := mustHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	private := ed25519.NewKeyFromSeed(seed)
	t.Setenv("TEST_PRIVATE", base64.StdEncoding.EncodeToString(seed))
	t.Setenv("TEST_KEY_ID", "release-test")
	t.Setenv("TEST_PUBLIC", base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)))
	manifestBytes := []byte(`{"protocol_version":1,"product":"vmmm"}` + "\n")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	publicKey, err := signManifest(manifestPath, signaturePath, "TEST_PRIVATE", "TEST_KEY_ID")
	if err != nil {
		t.Fatalf("signManifest: %v", err)
	}
	if !bytes.Equal(publicKey, private.Public().(ed25519.PublicKey)) {
		t.Fatal("signManifest returned the wrong public key")
	}
	if err := verifyManifest(manifestPath, signaturePath, "TEST_PUBLIC"); err != nil {
		t.Fatalf("verifyManifest: %v", err)
	}
	var envelope signatureEnvelope
	signatureBytes, err := os.ReadFile(signaturePath)
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}
	if err := json.Unmarshal(signatureBytes, &envelope); err != nil {
		t.Fatalf("decode signature envelope: %v", err)
	}
	if envelope.Version != signatureVersion || envelope.KeyID != "release-test" {
		t.Fatalf("unexpected envelope: %#v", envelope)
	}
	if err := os.WriteFile(manifestPath, []byte(`{"protocol_version":1,"product":"vmmm","tag":"tampered"}`), 0o644); err != nil {
		t.Fatalf("tamper manifest: %v", err)
	}
	if err := verifyManifest(manifestPath, signaturePath, "TEST_PUBLIC"); err == nil {
		t.Fatal("tampered manifest verified")
	}
}

// TestSignatureEnvelopeRejectsDuplicateKeys rejects the JSON ambiguity accepted by generic decoders.
// TestSignatureEnvelopeRejectsDuplicateKeys 拒绝通用解码器可能接受的 JSON 重复键歧义。
func TestSignatureEnvelopeRejectsDuplicateKeys(t *testing.T) {
	duplicate := []byte(`{"version":1,"version":1,"key_id":"release-test","signature":""}`)
	if _, _, err := decodeSignatureEnvelope(duplicate); err == nil {
		t.Fatal("duplicate signature key was accepted")
	}
}

// TestMissingSecretFailsClosed refuses signing without the configured environment secret.
// TestMissingSecretFailsClosed 在缺少配置环境密钥时拒绝签名。
func TestMissingSecretFailsClosed(t *testing.T) {
	t.Setenv("TEST_PRIVATE_MISSING", "")
	if _, err := privateKeyFromEnvironment("TEST_PRIVATE_MISSING"); err == nil {
		t.Fatal("missing private key was accepted")
	}
}

// mustHex decodes deterministic test bytes and stops the test on malformed fixtures.
// mustHex 解码确定性测试字节，并在样例损坏时终止测试。
func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode test hex: %v", err)
	}
	return decoded
}
