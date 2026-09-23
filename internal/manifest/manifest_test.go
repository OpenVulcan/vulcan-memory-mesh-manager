// Package manifest tests the signed-release trust boundary without network or production keys.
// manifest 包测试签名发行信任边界，不访问网络，也不使用生产密钥。
// These tests are called by the manifest package validation suite.
// 这些测试由 manifest 包的校验套件调用。
package manifest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// validManifestJSON is a deterministic test-only manifest fixture.
// validManifestJSON 是确定性的仅测试清单样例。
const validManifestJSON = `{"protocol_version":1,"product":"vmmm","tag":"v0.1.0","commit":"0123456789abcdef","artifacts":[{"platform":"windows-x64","filename":"vmmm-v0.1.0-windows-x64.exe","bytes":123,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}`

// TestVerifyAcceptsSignedManifest verifies the complete trusted-manifest path.
// TestVerifyAcceptsSignedManifest 验证完整的可信清单流程。
func TestVerifyAcceptsSignedManifest(t *testing.T) {
	manifestBytes, signatureBytes, keys := signedFixture(t, validManifestJSON)
	verified, err := Verify(manifestBytes, signatureBytes, keys)
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}
	keyID, err := verified.KeyID()
	if err != nil {
		t.Fatalf("KeyID() failed: %v", err)
	}
	if keyID != "release-test" {
		t.Fatalf("KeyID() = %q, want release-test", keyID)
	}
	artifact, err := verified.FindArtifact(ProductVMMM, "windows-x64")
	if err != nil {
		t.Fatalf("FindArtifact() failed: %v", err)
	}
	if artifact.Filename != "vmmm-v0.1.0-windows-x64.exe" || artifact.Bytes != 123 {
		t.Fatalf("artifact = %#v, want signed windows artifact", artifact)
	}
}

// TestVerifiedManifestAccessorsAreReadOnly verifies zero-value rejection and defensive artifact copies.
// TestVerifiedManifestAccessorsAreReadOnly 验证零值拒绝和资产副本隔离。
func TestVerifiedManifestAccessorsAreReadOnly(t *testing.T) {
	var zero VerifiedManifest
	if zero.IsVerified() {
		t.Fatal("zero VerifiedManifest reports verified")
	}
	if _, err := zero.Tag(); err == nil {
		t.Fatal("zero VerifiedManifest Tag() succeeded")
	}
	if _, err := zero.FindArtifact(ProductVMMM, "windows-x64"); err == nil {
		t.Fatal("zero VerifiedManifest FindArtifact() succeeded")
	}

	manifestBytes, signatureBytes, keys := signedFixture(t, validManifestJSON)
	verified, err := Verify(manifestBytes, signatureBytes, keys)
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}
	protocolVersion, err := verified.ProtocolVersion()
	if err != nil || protocolVersion != ProtocolVersion {
		t.Fatalf("ProtocolVersion() = %d, %v; want %d, nil", protocolVersion, err, ProtocolVersion)
	}
	product, err := verified.Product()
	if err != nil || product != ProductVMMM {
		t.Fatalf("Product() = %q, %v; want %q, nil", product, err, ProductVMMM)
	}
	tag, err := verified.Tag()
	if err != nil || tag != "v0.1.0" {
		t.Fatalf("Tag() = %q, %v; want v0.1.0, nil", tag, err)
	}
	commit, err := verified.Commit()
	if err != nil || commit != "0123456789abcdef" {
		t.Fatalf("Commit() = %q, %v; want fixture commit, nil", commit, err)
	}
	artifacts, err := verified.Artifacts()
	if err != nil {
		t.Fatalf("Artifacts() failed: %v", err)
	}
	artifacts[0].Filename = "mutated-by-caller.exe"
	artifact, err := verified.FindArtifact(ProductVMMM, "windows-x64")
	if err != nil {
		t.Fatalf("FindArtifact() after caller mutation failed: %v", err)
	}
	if artifact.Filename == "mutated-by-caller.exe" {
		t.Fatal("caller mutation changed the authenticated artifact")
	}
}

// TestVerifyRejectsSignatureTampering ensures a modified detached signature cannot authenticate a manifest.
// TestVerifyRejectsSignatureTampering 确保篡改分离签名后不能认证清单。
func TestVerifyRejectsSignatureTampering(t *testing.T) {
	manifestBytes, signatureBytes, keys := signedFixture(t, validManifestJSON)
	var envelope SignatureEnvelope
	if err := json.Unmarshal(signatureBytes, &envelope); err != nil {
		t.Fatalf("json.Unmarshal(signature) failed: %v", err)
	}
	envelope.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	tamperedSignature, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal(signature) failed: %v", err)
	}
	if _, err := Verify(manifestBytes, tamperedSignature, keys); err == nil {
		t.Fatal("Verify() succeeded with a tampered signature")
	}
}

// TestVerifyRejectsManifestTampering ensures the signature covers the exact original manifest bytes.
// TestVerifyRejectsManifestTampering 确保签名覆盖清单的原始字节。
func TestVerifyRejectsManifestTampering(t *testing.T) {
	manifestBytes, signatureBytes, keys := signedFixture(t, validManifestJSON)
	tamperedManifest := []byte(strings.Replace(string(manifestBytes), `"v0.1.0"`, `"v0.1.1"`, 1))
	if _, err := Verify(tamperedManifest, signatureBytes, keys); err == nil {
		t.Fatal("Verify() succeeded with a tampered manifest")
	}
}

// TestVerifyRejectsWrongTrustedKey ensures the injected key map controls the trust root.
// TestVerifyRejectsWrongTrustedKey 确保调用方注入的公钥映射控制信任根。
func TestVerifyRejectsWrongTrustedKey(t *testing.T) {
	manifestBytes, signatureBytes, keys := signedFixture(t, validManifestJSON)
	wrongPrivateKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("w", ed25519.SeedSize)))
	keys["release-test"] = wrongPrivateKey.Public().(ed25519.PublicKey)
	if _, err := Verify(manifestBytes, signatureBytes, keys); err == nil {
		t.Fatal("Verify() succeeded with the wrong trusted key")
	}
}

// TestRemovedTrustRootRejectsPreviouslyValidSignature verifies the fixed-key revocation boundary used by rebuilt managers.
// TestRemovedTrustRootRejectsPreviouslyValidSignature 验证重新发行管理器移除固定公钥后，曾有效的旧签名会被拒绝。
func TestRemovedTrustRootRejectsPreviouslyValidSignature(t *testing.T) {
	manifestBytes, signatureBytes, oldKeys := signedFixture(t, validManifestJSON)
	if _, err := Verify(manifestBytes, signatureBytes, oldKeys); err != nil {
		t.Fatal(err)
	}
	newPrivateKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("n", ed25519.SeedSize)))
	newKeys := map[string]ed25519.PublicKey{"replacement-test": newPrivateKey.Public().(ed25519.PublicKey)}
	if _, err := Verify(manifestBytes, signatureBytes, newKeys); err == nil {
		t.Fatal("removed signing key was still accepted")
	}
	newEnvelope, err := json.Marshal(SignatureEnvelope{
		Version: SignatureVersion, KeyID: "replacement-test",
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(newPrivateKey, manifestBytes)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(manifestBytes, newEnvelope, newKeys); err != nil {
		t.Fatalf("replacement signature rejected: %v", err)
	}
	if _, err := Verify(manifestBytes, newEnvelope, oldKeys); err == nil {
		t.Fatal("old manager silently trusted a new key")
	}
}

// TestVerifyRejectsMalformedJSONAndTrailingContent ensures syntax is checked after authentication and before decoding.
// TestVerifyRejectsMalformedJSONAndTrailingContent 确保认证后、解码前检查语法。
func TestVerifyRejectsMalformedJSONAndTrailingContent(t *testing.T) {
	tests := map[string]string{
		"malformed": `{"protocol_version":1,"product":"vmmm",}`,
		"trailing":  validManifestJSON + ` {"unexpected":true}`,
		"duplicate": `{"protocol_version":1,"protocol_version":1,"product":"vmmm","tag":"v0.1.0","commit":"0123456789abcdef","artifacts":[]}`,
		"unknown":   `{"protocol_version":1,"product":"vmmm","tag":"v0.1.0","commit":"0123456789abcdef","artifacts":[],"extra":true}`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			manifestBytes, signatureBytes, keys := signedFixture(t, input)
			if _, err := Verify(manifestBytes, signatureBytes, keys); err == nil {
				t.Fatal("Verify() succeeded with invalid JSON")
			}
		})
	}
}

// TestVerifyRejectsFilenameTraversal ensures an artifact filename cannot escape the install directory.
// TestVerifyRejectsFilenameTraversal 确保资产文件名不能逃逸安装目录。
func TestVerifyRejectsFilenameTraversal(t *testing.T) {
	input := strings.Replace(validManifestJSON, `vmmm-v0.1.0-windows-x64.exe`, `../vmmm.exe`, 1)
	manifestBytes, signatureBytes, keys := signedFixture(t, input)
	if _, err := Verify(manifestBytes, signatureBytes, keys); err == nil {
		t.Fatal("Verify() succeeded with a path-traversal filename")
	}
}

// TestVerifyRejectsDuplicatePlatforms ensures one platform maps to exactly one signed asset.
// TestVerifyRejectsDuplicatePlatforms 确保一个平台只映射到一个已签名资产。
func TestVerifyRejectsDuplicatePlatforms(t *testing.T) {
	input := strings.Replace(validManifestJSON, `}]}`, `},{"platform":"windows-x64","filename":"other.exe","bytes":123,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}`, 1)
	manifestBytes, signatureBytes, keys := signedFixture(t, input)
	if _, err := Verify(manifestBytes, signatureBytes, keys); err == nil {
		t.Fatal("Verify() succeeded with duplicate artifact platforms")
	}
}

// TestFindArtifactRejectsProductMismatch ensures a valid manifest cannot be used for another product.
// TestFindArtifactRejectsProductMismatch 确保有效清单不能用于另一个产品。
func TestFindArtifactRejectsProductMismatch(t *testing.T) {
	manifestBytes, signatureBytes, keys := signedFixture(t, validManifestJSON)
	verified, err := Verify(manifestBytes, signatureBytes, keys)
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}
	if _, err := verified.FindArtifact(ProductVMM, "windows-x64"); err == nil {
		t.Fatal("FindArtifact() succeeded with a mismatched product")
	}
}

// signedFixture signs test-only bytes with a deterministic key that is never a production trust root.
// signedFixture 使用确定性测试密钥签名测试字节，该密钥绝不作为生产信任根。
func signedFixture(t *testing.T, manifestJSON string) ([]byte, []byte, map[string]ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	signature := ed25519.Sign(privateKey, []byte(manifestJSON))
	envelope, err := json.Marshal(SignatureEnvelope{
		Version:   SignatureVersion,
		KeyID:     "release-test",
		Signature: base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatalf("json.Marshal(signature) failed: %v", err)
	}
	return []byte(manifestJSON), envelope, map[string]ed25519.PublicKey{
		"release-test": privateKey.Public().(ed25519.PublicKey),
	}
}
