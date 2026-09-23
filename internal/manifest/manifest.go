// Package manifest verifies signed VMMM and VMM release manifests.
// manifest 包负责验证已签名的 VMMM 与 VMM 发布清单。
// It belongs to the release trust boundary and is called before any artifact download or installation.
// 它属于发布信任边界，在任何资产下载或安装前被调用。
package manifest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// ProtocolVersion is the supported release-manifest protocol version.
	// ProtocolVersion 是当前支持的发布清单协议版本。
	ProtocolVersion uint = 1

	// SignatureVersion is the supported detached-signature envelope version.
	// SignatureVersion 是当前支持的分离签名封装版本。
	SignatureVersion uint = 1

	// ProductVMMM identifies the standalone manager product.
	// ProductVMMM 标识独立管理器产品。
	ProductVMMM = "vmmm"

	// ProductVMM identifies the Vulcan Memory Mesh runtime product.
	// ProductVMM 标识 Vulcan Memory Mesh 运行时产品。
	ProductVMM = "vmm"
)

// Manifest is the signed metadata used to select and verify one product release.
// Manifest 是用于选择并校验一个产品发行版的已签名元数据。
type Manifest struct {
	// ProtocolVersion is the manifest wire-protocol version.
	// ProtocolVersion 是清单线协议版本。
	ProtocolVersion uint `json:"protocol_version"`

	// Product identifies whether the release belongs to VMMM or VMM.
	// Product 标识发行版属于 VMMM 还是 VMM。
	Product string `json:"product"`

	// Tag is the immutable release tag selected by the publisher.
	// Tag 是发布方选定的不可变发行标签。
	Tag string `json:"tag"`

	// Commit is the source commit recorded for the release.
	// Commit 是发行版记录的源代码提交。
	Commit string `json:"commit"`

	// Artifacts lists the fixed platform assets available for this release.
	// Artifacts 列出该发行版可用的固定平台资产。
	Artifacts []Artifact `json:"artifacts"`
}

// Artifact describes one platform-specific release file.
// Artifact 描述一个特定平台的发行文件。
type Artifact struct {
	// Platform is the stable platform identifier used by the installer.
	// Platform 是安装器使用的稳定平台标识。
	Platform string `json:"platform"`

	// Filename is the single archive or executable filename downloaded for the platform.
	// Filename 是该平台下载的单个压缩包或可执行文件名。
	Filename string `json:"filename"`

	// Bytes is the exact expected byte length of the artifact.
	// Bytes 是资产预期的精确字节数。
	Bytes int64 `json:"bytes"`

	// SHA256 is the lowercase hexadecimal SHA-256 digest of the artifact.
	// SHA256 是资产的小写十六进制 SHA-256 摘要。
	SHA256 string `json:"sha256"`
}

// VerifiedManifest is an authenticated release snapshot that cannot be constructed or mutated outside this package.
// VerifiedManifest 是包外无法构造或修改的已认证发行快照。
type VerifiedManifest struct {
	// manifest stores the validated metadata behind read-only accessors.
	// manifest 在只读访问器之后保存已校验的元数据。
	manifest Manifest

	// keyID records the trusted key that authenticated the exact manifest bytes.
	// keyID 记录认证清单原始字节的可信密钥标识。
	keyID string

	// verified prevents the zero value from being mistaken for an authenticated snapshot.
	// verified 防止零值被误认为已认证快照。
	verified bool
}

// SignatureEnvelope is the JSON representation of a detached Ed25519 signature.
// SignatureEnvelope 是分离式 Ed25519 签名的 JSON 表示。
// The signature covers the exact original manifest.json bytes, including formatting and final newline.
// 签名覆盖 manifest.json 的原始字节，包括格式和末尾换行。
type SignatureEnvelope struct {
	// Version is the detached-signature envelope version.
	// Version 是分离签名封装版本。
	Version uint `json:"version"`

	// KeyID selects a public key from the caller-provided trust map.
	// KeyID 从调用方提供的信任映射中选择公钥。
	KeyID string `json:"key_id"`

	// Signature is the standard-base64 encoded 64-byte Ed25519 signature.
	// Signature 是标准 Base64 编码的 64 字节 Ed25519 签名。
	Signature string `json:"signature"`
}

// Verify authenticates and strictly decodes a release manifest.
// Verify 认证并严格解码一个发行清单。
// The keys map is the injected trust root; no key or trust decision is read from the download source.
// keys 映射由调用方注入，是唯一信任根；不会从下载源读取公钥或信任决策。
func Verify(manifestBytes []byte, signatureBytes []byte, keys map[string]ed25519.PublicKey) (VerifiedManifest, error) {
	signature, err := decodeSignature(signatureBytes)
	if err != nil {
		return VerifiedManifest{}, err
	}

	publicKey, ok := keys[signature.KeyID]
	if !ok {
		return VerifiedManifest{}, fmt.Errorf("manifest signature key ID %q is not trusted", signature.KeyID)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return VerifiedManifest{}, fmt.Errorf("trusted key %q has invalid length %d", signature.KeyID, len(publicKey))
	}
	if !ed25519.Verify(publicKey, manifestBytes, signature.signatureBytes) {
		return VerifiedManifest{}, errors.New("manifest signature verification failed")
	}

	decoded, err := decodeManifest(manifestBytes)
	if err != nil {
		return VerifiedManifest{}, err
	}
	return VerifiedManifest{manifest: decoded, keyID: signature.KeyID, verified: true}, nil
}

// IsVerified reports whether this value was created by successful signature verification.
// IsVerified 报告该值是否由成功的签名校验创建。
func (m VerifiedManifest) IsVerified() bool {
	return m.verified
}

// ProtocolVersion returns the authenticated manifest protocol version.
// ProtocolVersion 返回已认证清单的协议版本。
func (m VerifiedManifest) ProtocolVersion() (uint, error) {
	if err := m.ensureVerified(); err != nil {
		return 0, err
	}
	return m.manifest.ProtocolVersion, nil
}

// Product returns the authenticated product identifier.
// Product 返回已认证的产品标识。
func (m VerifiedManifest) Product() (string, error) {
	if err := m.ensureVerified(); err != nil {
		return "", err
	}
	return m.manifest.Product, nil
}

// Tag returns the authenticated release tag.
// Tag 返回已认证的发行标签。
func (m VerifiedManifest) Tag() (string, error) {
	if err := m.ensureVerified(); err != nil {
		return "", err
	}
	return m.manifest.Tag, nil
}

// Commit returns the authenticated source commit.
// Commit 返回已认证的源代码提交。
func (m VerifiedManifest) Commit() (string, error) {
	if err := m.ensureVerified(); err != nil {
		return "", err
	}
	return m.manifest.Commit, nil
}

// KeyID returns the trusted key identifier that authenticated this snapshot.
// KeyID 返回认证该快照的可信密钥标识。
func (m VerifiedManifest) KeyID() (string, error) {
	if err := m.ensureVerified(); err != nil {
		return "", err
	}
	return m.keyID, nil
}

// Artifacts returns a deep copy of the authenticated artifact list.
// Artifacts 返回已认证资产列表的深拷贝。
func (m VerifiedManifest) Artifacts() ([]Artifact, error) {
	if err := m.ensureVerified(); err != nil {
		return nil, err
	}
	artifacts := make([]Artifact, len(m.manifest.Artifacts))
	copy(artifacts, m.manifest.Artifacts)
	return artifacts, nil
}

// FindArtifact returns the artifact for an expected product and platform.
// FindArtifact 按预期产品和平台返回对应资产。
// It fails closed when the signed product or platform is not the requested one.
// 当已签名产品或平台不是请求目标时，它会显式失败而不会回退到其他资产。
func (m VerifiedManifest) FindArtifact(expectedProduct string, platform string) (Artifact, error) {
	if err := m.ensureVerified(); err != nil {
		return Artifact{}, err
	}
	return findArtifact(m.manifest, expectedProduct, platform)
}

// ensureVerified rejects zero values and any value not produced by Verify.
// ensureVerified 拒绝零值以及任何不是由 Verify 产生的值。
func (m VerifiedManifest) ensureVerified() error {
	if !m.verified {
		return errors.New("manifest has not been verified")
	}
	return nil
}

// findArtifact performs product and platform matching on already validated metadata.
// findArtifact 在已校验元数据上执行产品与平台匹配。
func findArtifact(m Manifest, expectedProduct string, platform string) (Artifact, error) {
	if !isProduct(expectedProduct) {
		return Artifact{}, fmt.Errorf("expected product %q is unsupported", expectedProduct)
	}
	if m.Product != expectedProduct {
		return Artifact{}, fmt.Errorf("manifest product %q does not match expected product %q", m.Product, expectedProduct)
	}
	if strings.TrimSpace(platform) == "" {
		return Artifact{}, errors.New("platform must not be empty")
	}
	for _, artifact := range m.Artifacts {
		if artifact.Platform == platform {
			return artifact, nil
		}
	}
	return Artifact{}, fmt.Errorf("manifest has no artifact for platform %q", platform)
}

type parsedSignature struct {
	// SignatureEnvelope contains the authenticated wire fields.
	// SignatureEnvelope 包含已解析的签名线协议字段。
	SignatureEnvelope

	// signatureBytes is the decoded raw Ed25519 signature used for verification.
	// signatureBytes 是用于校验的原始 Ed25519 签名字节。
	signatureBytes []byte
}

// decodeSignature parses the detached signature and enforces its exact JSON shape.
// decodeSignature 解析分离签名，并强制执行精确的 JSON 结构。
func decodeSignature(data []byte) (parsedSignature, error) {
	if err := validateJSONDocument(data); err != nil {
		return parsedSignature{}, fmt.Errorf("invalid signature JSON: %w", err)
	}
	object, err := decodeObject(data, "signature")
	if err != nil {
		return parsedSignature{}, err
	}
	if err := requireExactKeys(object, map[string]struct{}{"version": {}, "key_id": {}, "signature": {}}, "signature"); err != nil {
		return parsedSignature{}, err
	}

	var envelope SignatureEnvelope
	if err := decodeRequired(object, "version", &envelope.Version); err != nil {
		return parsedSignature{}, err
	}
	if err := decodeRequired(object, "key_id", &envelope.KeyID); err != nil {
		return parsedSignature{}, err
	}
	if err := decodeRequired(object, "signature", &envelope.Signature); err != nil {
		return parsedSignature{}, err
	}
	if envelope.Version != SignatureVersion {
		return parsedSignature{}, fmt.Errorf("unsupported signature version %d", envelope.Version)
	}
	if strings.TrimSpace(envelope.KeyID) == "" || strings.TrimSpace(envelope.KeyID) != envelope.KeyID {
		return parsedSignature{}, errors.New("signature key_id must not be empty or contain surrounding whitespace")
	}
	if strings.IndexFunc(envelope.KeyID, func(r rune) bool { return r < 0x20 || r == '\\' || r == '/' }) >= 0 {
		return parsedSignature{}, errors.New("signature key_id contains forbidden characters")
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return parsedSignature{}, fmt.Errorf("signature is not valid base64: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return parsedSignature{}, fmt.Errorf("signature has length %d, want %d", len(signatureBytes), ed25519.SignatureSize)
	}
	return parsedSignature{SignatureEnvelope: envelope, signatureBytes: signatureBytes}, nil
}

// decodeManifest validates the exact manifest object and its artifact entries.
// decodeManifest 校验清单对象及其资产条目的精确结构。
func decodeManifest(data []byte) (Manifest, error) {
	if err := validateJSONDocument(data); err != nil {
		return Manifest{}, fmt.Errorf("invalid manifest JSON: %w", err)
	}
	object, err := decodeObject(data, "manifest")
	if err != nil {
		return Manifest{}, err
	}
	if err := requireExactKeys(object, map[string]struct{}{
		"protocol_version": {},
		"product":          {},
		"tag":              {},
		"commit":           {},
		"artifacts":        {},
	}, "manifest"); err != nil {
		return Manifest{}, err
	}

	var manifest Manifest
	if err := decodeRequired(object, "protocol_version", &manifest.ProtocolVersion); err != nil {
		return Manifest{}, err
	}
	if err := decodeRequired(object, "product", &manifest.Product); err != nil {
		return Manifest{}, err
	}
	if err := decodeRequired(object, "tag", &manifest.Tag); err != nil {
		return Manifest{}, err
	}
	if err := decodeRequired(object, "commit", &manifest.Commit); err != nil {
		return Manifest{}, err
	}

	var artifactValues []json.RawMessage
	if err := decodeRequired(object, "artifacts", &artifactValues); err != nil {
		return Manifest{}, err
	}
	if len(artifactValues) == 0 {
		return Manifest{}, errors.New("manifest artifacts must not be empty")
	}
	manifest.Artifacts = make([]Artifact, 0, len(artifactValues))
	for index, rawArtifact := range artifactValues {
		artifact, err := decodeArtifact(rawArtifact, index)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Artifacts = append(manifest.Artifacts, artifact)
	}
	if err := validateManifest(&manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// decodeArtifact parses one artifact and rejects unknown or missing fields.
// decodeArtifact 解析一个资产并拒绝未知字段或缺失字段。
func decodeArtifact(data []byte, index int) (Artifact, error) {
	object, err := decodeObject(data, fmt.Sprintf("artifacts[%d]", index))
	if err != nil {
		return Artifact{}, err
	}
	if err := requireExactKeys(object, map[string]struct{}{
		"platform": {},
		"filename": {},
		"bytes":    {},
		"sha256":   {},
	}, fmt.Sprintf("artifacts[%d]", index)); err != nil {
		return Artifact{}, err
	}

	var artifact Artifact
	if err := decodeRequired(object, "platform", &artifact.Platform); err != nil {
		return Artifact{}, err
	}
	if err := decodeRequired(object, "filename", &artifact.Filename); err != nil {
		return Artifact{}, err
	}
	if err := decodeRequired(object, "bytes", &artifact.Bytes); err != nil {
		return Artifact{}, err
	}
	if err := decodeRequired(object, "sha256", &artifact.SHA256); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}

// validateManifest enforces protocol, identity, path, size, digest, and uniqueness rules.
// validateManifest 执行协议、身份、路径、大小、摘要和唯一性规则校验。
func validateManifest(manifest *Manifest) error {
	if manifest.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("unsupported manifest protocol version %d", manifest.ProtocolVersion)
	}
	if !isProduct(manifest.Product) {
		return fmt.Errorf("unsupported manifest product %q", manifest.Product)
	}
	if err := validateReleaseIdentity("tag", manifest.Tag); err != nil {
		return err
	}
	if err := validateReleaseIdentity("commit", manifest.Commit); err != nil {
		return err
	}

	seenPlatforms := make(map[string]struct{}, len(manifest.Artifacts))
	for index := range manifest.Artifacts {
		artifact := &manifest.Artifacts[index]
		if err := validatePlatform(artifact.Platform); err != nil {
			return fmt.Errorf("artifacts[%d]: %w", index, err)
		}
		if _, exists := seenPlatforms[artifact.Platform]; exists {
			return fmt.Errorf("artifacts contains duplicate platform %q", artifact.Platform)
		}
		seenPlatforms[artifact.Platform] = struct{}{}
		if err := validateFilename(artifact.Filename); err != nil {
			return fmt.Errorf("artifacts[%d]: %w", index, err)
		}
		if artifact.Bytes <= 0 {
			return fmt.Errorf("artifacts[%d].bytes must be positive", index)
		}
		if len(artifact.SHA256) != sha256HexLength || strings.ToLower(artifact.SHA256) != artifact.SHA256 {
			return fmt.Errorf("artifacts[%d].sha256 must be 64 lowercase hexadecimal characters", index)
		}
		if _, err := hex.DecodeString(artifact.SHA256); err != nil {
			return fmt.Errorf("artifacts[%d].sha256 is invalid: %w", index, err)
		}
	}
	return nil
}

// sha256HexLength is the exact number of hexadecimal characters in a SHA-256 digest.
// sha256HexLength 是 SHA-256 摘要十六进制表示的精确字符数。
const sha256HexLength = 32 * 2

// validateReleaseIdentity rejects empty or control-containing release identifiers.
// validateReleaseIdentity 拒绝空值或包含控制字符的发行标识。
func validateReleaseIdentity(name string, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("manifest %s must not be empty", name)
	}
	if strings.TrimSpace(value) != value || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return fmt.Errorf("manifest %s contains surrounding whitespace or control characters", name)
	}
	return nil
}

// validatePlatform keeps platform identifiers stable and independent of filesystem paths.
// validatePlatform 保证平台标识稳定且不依赖文件系统路径。
func validatePlatform(platform string) error {
	if strings.TrimSpace(platform) == "" {
		return errors.New("platform must not be empty")
	}
	if strings.TrimSpace(platform) != platform || strings.ContainsAny(platform, "/\\") || strings.IndexFunc(platform, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return fmt.Errorf("platform %q contains forbidden characters", platform)
	}
	return nil
}

// validateFilename rejects path separators, dot traversal, whitespace, and control characters.
// validateFilename 拒绝路径分隔符、点穿越、空白和控制字符。
func validateFilename(filename string) error {
	if strings.TrimSpace(filename) == "" {
		return errors.New("filename must not be empty")
	}
	if filename == "." || filename == ".." || strings.Contains(filename, "..") {
		return fmt.Errorf("filename %q contains path traversal", filename)
	}
	if strings.ContainsAny(filename, "/\\") || strings.TrimSpace(filename) != filename || strings.IndexFunc(filename, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return fmt.Errorf("filename %q contains forbidden characters", filename)
	}
	return nil
}

// decodeObject decodes one JSON object and rejects null or non-object values.
// decodeObject 解码一个 JSON 对象并拒绝 null 或非对象值。
func decodeObject(data []byte, name string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&object); err != nil {
		return nil, fmt.Errorf("%s must be a JSON object: %w", name, err)
	}
	if object == nil {
		return nil, fmt.Errorf("%s must be a JSON object", name)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s contains trailing JSON content starting with %v", name, token)
		}
		return nil, fmt.Errorf("%s contains invalid trailing JSON content: %w", name, err)
	}
	return object, nil
}

// decodeRequired decodes a required field and reports its JSON path on failure.
// decodeRequired 解码必需字段，并在失败时报告其 JSON 路径。
func decodeRequired(object map[string]json.RawMessage, field string, destination any) error {
	raw, ok := object[field]
	if !ok {
		return fmt.Errorf("missing required field %q", field)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("field %q has invalid value: %w", field, err)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("field %q contains trailing JSON content starting with %v", field, token)
		}
		return fmt.Errorf("field %q contains invalid trailing JSON content: %w", field, err)
	}
	return nil
}

// requireExactKeys rejects unknown fields while preserving case-sensitive wire names.
// requireExactKeys 拒绝未知字段，并保持线协议字段名区分大小写。
func requireExactKeys(object map[string]json.RawMessage, allowed map[string]struct{}, name string) error {
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("%s contains unknown field %q", name, key)
		}
	}
	return nil
}

// validateJSONDocument rejects malformed JSON, duplicate object keys, and trailing values.
// validateJSONDocument 拒绝畸形 JSON、对象重复键以及尾随值。
func validateJSONDocument(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := parseJSONValue(decoder, "$", true); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("JSON contains trailing content starting with %v", token)
		}
		return fmt.Errorf("JSON contains invalid trailing content: %w", err)
	}
	return nil
}

// parseJSONValue walks one JSON value to detect duplicate keys at every object depth.
// parseJSONValue 遍历一个 JSON 值，以检测所有对象层级的重复键。
func parseJSONValue(decoder *json.Decoder, path string, topLevel bool) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON at %s: %w", path, err)
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return fmt.Errorf("invalid JSON object at %s: %w", path, err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("JSON object key at %s is not a string", path)
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON field %q at %s", key, path)
				}
				seen[key] = struct{}{}
				if err := parseJSONValue(decoder, path+"."+key, false); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				if err == nil {
					return fmt.Errorf("JSON object at %s is not closed", path)
				}
				return fmt.Errorf("JSON object at %s is not closed: %w", path, err)
			}
		case '[':
			index := 0
			for decoder.More() {
				if err := parseJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index), false); err != nil {
					return err
				}
				index++
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				if err == nil {
					return fmt.Errorf("JSON array at %s is not closed", path)
				}
				return fmt.Errorf("JSON array at %s is not closed: %w", path, err)
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, path)
		}
	case nil, bool, string, json.Number:
		return nil
	default:
		return fmt.Errorf("unexpected JSON token %v at %s", token, path)
	}
	if topLevel {
		return nil
	}
	return nil
}

// isProduct reports whether a product identifier belongs to this protocol.
// isProduct 判断产品标识是否属于本协议。
func isProduct(product string) bool {
	return product == ProductVMMM || product == ProductVMM
}
