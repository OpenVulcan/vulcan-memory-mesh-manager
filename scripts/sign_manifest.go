// Sign and verify VMMM release manifests with Go's standard Ed25519 library.
// 使用 Go 标准库 Ed25519 对 VMMM 发行清单进行签名与验证。
// This file is the release trust-boundary implementation used by CI.
// 本文件是 CI 使用的发行信任边界实现。
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	// signatureVersion is the detached signature envelope version shared with internal/manifest.
	// signatureVersion 是与 internal/manifest 共用的分离签名封装版本。
	signatureVersion uint = 1

	// defaultPrivateKeyEnvironment identifies the CI-only signing secret.
	// defaultPrivateKeyEnvironment 标识仅供 CI 使用的签名密钥 Secret。
	defaultPrivateKeyEnvironment = "VMMM_RELEASE_ED25519_PRIVATE_KEY"

	// defaultKeyIDEnvironment identifies the trusted release-key ID.
	// defaultKeyIDEnvironment 标识受信发行密钥 ID。
	defaultKeyIDEnvironment = "VMMM_RELEASE_ED25519_KEY_ID"

	// defaultPublicKeyEnvironment identifies the verification key environment variable.
	// defaultPublicKeyEnvironment 标识验签公钥环境变量。
	defaultPublicKeyEnvironment = "VMMM_RELEASE_ED25519_PUBLIC_KEY"
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// signatureEnvelope is the exact JSON wire shape consumed by internal/manifest.Verify.
// signatureEnvelope 是 internal/manifest.Verify 消费的精确 JSON 线协议结构。
type signatureEnvelope struct {
	// Version identifies the detached signature protocol.
	// Version 标识分离签名协议。
	Version uint `json:"version"`

	// KeyID selects the trusted public key used by the manager.
	// KeyID 选择管理器使用的受信公钥。
	KeyID string `json:"key_id"`

	// Signature is the standard Base64 encoded Ed25519 signature.
	// Signature 是标准 Base64 编码的 Ed25519 签名。
	Signature string `json:"signature"`
}

// readManifest reads exact bytes and never normalizes the signed document.
// readManifest 读取原始字节，不标准化需要签名的文档。
func readManifest(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	if len(data) == 0 {
		return nil, errors.New("manifest is empty")
	}
	return data, nil
}

// decodeEncodedKey accepts strict hexadecimal or Base64 key text from CI environment variables.
// decodeEncodedKey 从 CI 环境变量接受严格十六进制或 Base64 密钥文本。
func decodeEncodedKey(value string, expected map[int]struct{}, label string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("%s is empty", label)
	}

	if decoded, err := hex.DecodeString(value); err == nil {
		if _, ok := expected[len(decoded)]; ok {
			return decoded, nil
		}
	}
	base64Decoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, decoder := range base64Decoders {
		decoded, err := decoder.DecodeString(value)
		if err == nil {
			if _, ok := expected[len(decoded)]; ok {
				return decoded, nil
			}
		}
	}
	return nil, fmt.Errorf("%s must decode to an allowed key length", label)
}

// privateKeyFromEnvironment loads only the configured GitHub Secret as an Ed25519 private key.
// privateKeyFromEnvironment 只从配置的 GitHub Secret 加载 Ed25519 私钥。
func privateKeyFromEnvironment(environmentName string) (ed25519.PrivateKey, error) {
	value, ok := os.LookupEnv(environmentName)
	if !ok || strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("required signing secret %s is missing", environmentName)
	}
	decoded, err := decodeEncodedKey(value, map[int]struct{}{ed25519.SeedSize: {}, ed25519.PrivateKeySize: {}}, environmentName)
	if err != nil {
		return nil, err
	}
	if len(decoded) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(decoded), nil
	}
	privateKey := ed25519.PrivateKey(decoded)
	derivedPublic := privateKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(derivedPublic, privateKey[ed25519.SeedSize:]) {
		return nil, fmt.Errorf("%s contains an inconsistent Ed25519 private key", environmentName)
	}
	return privateKey, nil
}

// publicKeyFromEnvironment loads one exact 32-byte Ed25519 public key.
// publicKeyFromEnvironment 加载一个精确的 32 字节 Ed25519 公钥。
func publicKeyFromEnvironment(environmentName string) (ed25519.PublicKey, error) {
	value, ok := os.LookupEnv(environmentName)
	if !ok || strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("required public key %s is missing", environmentName)
	}
	decoded, err := decodeEncodedKey(value, map[int]struct{}{ed25519.PublicKeySize: {}}, environmentName)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(decoded), nil
}

// keyIDFromEnvironment loads and validates the stable public-key identifier.
// keyIDFromEnvironment 加载并校验稳定的公钥标识。
func keyIDFromEnvironment(environmentName string) (string, error) {
	value, ok := os.LookupEnv(environmentName)
	if !ok || !keyIDPattern.MatchString(value) {
		return "", fmt.Errorf("required signing key ID %s is missing or invalid", environmentName)
	}
	return value, nil
}

// strictObject decodes an object while rejecting duplicate keys and trailing JSON values.
// strictObject 解码对象，同时拒绝重复键和尾随 JSON 值。
func strictObject(data []byte, label string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	first, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid %s JSON: %w", label, err)
	}
	if delimiter, ok := first.(json.Delim); !ok || delimiter != '{' {
		return nil, fmt.Errorf("%s must be a JSON object", label)
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid %s key: %w", label, err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("%s object key is not a string", label)
		}
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("%s contains duplicate key %q", label, key)
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("invalid %s field %q: %w", label, key, err)
		}
		fields[key] = raw
	}
	closing, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid %s closing delimiter: %w", label, err)
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' {
		return nil, fmt.Errorf("%s does not close as an object", label)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s contains trailing JSON content", label)
		}
		return nil, fmt.Errorf("invalid trailing %s JSON: %w", label, err)
	}
	return fields, nil
}

// decodeSignatureEnvelope validates the exact detached-signature wire protocol.
// decodeSignatureEnvelope 校验精确的分离签名线协议。
func decodeSignatureEnvelope(data []byte) (signatureEnvelope, []byte, error) {
	fields, err := strictObject(data, "signature")
	if err != nil {
		return signatureEnvelope{}, nil, err
	}
	if len(fields) != 3 {
		return signatureEnvelope{}, nil, errors.New("signature has unexpected fields")
	}
	for _, required := range []string{"version", "key_id", "signature"} {
		if _, ok := fields[required]; !ok {
			return signatureEnvelope{}, nil, fmt.Errorf("signature is missing field %q", required)
		}
	}
	var envelope signatureEnvelope
	for key, destination := range map[string]any{
		"version":   &envelope.Version,
		"key_id":    &envelope.KeyID,
		"signature": &envelope.Signature,
	} {
		if err := json.Unmarshal(fields[key], destination); err != nil {
			return signatureEnvelope{}, nil, fmt.Errorf("signature field %q is invalid: %w", key, err)
		}
	}
	if envelope.Version != signatureVersion {
		return signatureEnvelope{}, nil, fmt.Errorf("unsupported signature version %d", envelope.Version)
	}
	if !keyIDPattern.MatchString(envelope.KeyID) {
		return signatureEnvelope{}, nil, errors.New("signature key_id is invalid")
	}
	rawSignature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || len(rawSignature) != ed25519.SignatureSize {
		return signatureEnvelope{}, nil, errors.New("signature is not a valid Ed25519 Base64 value")
	}
	return envelope, rawSignature, nil
}

// writeNewFile atomically writes a new output without accepting an existing destination.
// writeNewFile 原子写入新输出，并拒绝覆盖已存在目标。
func writeNewFile(path string, data []byte) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("refusing to overwrite existing output %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryName := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return fmt.Errorf("set output permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("publish output: %w", err)
	}
	removeTemporary = false
	return nil
}

// signManifest creates an exact envelope over the manifest bytes.
// signManifest 对清单原始字节创建精确签名封装。
func signManifest(manifestPath string, signaturePath string, privateKeyEnvironment string, keyIDEnvironment string) ([]byte, error) {
	privateKey, err := privateKeyFromEnvironment(privateKeyEnvironment)
	if err != nil {
		return nil, err
	}
	keyID, err := keyIDFromEnvironment(keyIDEnvironment)
	if err != nil {
		return nil, err
	}
	manifestBytes, err := readManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	envelope := signatureEnvelope{
		Version:   signatureVersion,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestBytes)),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode signature: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := writeNewFile(signaturePath, encoded); err != nil {
		return nil, err
	}
	return privateKey.Public().(ed25519.PublicKey), nil
}

// verifyManifest validates a detached signature against exact manifest bytes.
// verifyManifest 使用清单原始字节校验分离签名。
func verifyManifest(manifestPath string, signaturePath string, publicKeyEnvironment string) error {
	manifestBytes, err := readManifest(manifestPath)
	if err != nil {
		return err
	}
	signatureBytes, err := os.ReadFile(signaturePath)
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	envelope, rawSignature, err := decodeSignatureEnvelope(signatureBytes)
	if err != nil {
		return err
	}
	publicKey, err := publicKeyFromEnvironment(publicKeyEnvironment)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, manifestBytes, rawSignature) {
		return fmt.Errorf("Ed25519 verification failed for key ID %s", envelope.KeyID)
	}
	return nil
}

// publicKey prints the public key derived from the signing secret for CI verification.
// publicKey 输出由签名 Secret 派生的公钥，供 CI 验签使用。
func publicKey(privateKeyEnvironment string) error {
	private, err := privateKeyFromEnvironment(privateKeyEnvironment)
	if err != nil {
		return err
	}
	_, err = fmt.Println(base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)))
	return err
}

// parseSignFlags parses the sign command without allowing unknown arguments.
// parseSignFlags 解析 sign 命令，并拒绝未知参数。
func parseSignFlags(arguments []string) (string, string, string, string, error) {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	manifest := flags.String("manifest", "", "path to manifest.json")
	signature := flags.String("signature", "", "path to manifest.sig")
	privateKeyEnvironment := flags.String("private-key-env", defaultPrivateKeyEnvironment, "environment variable containing the private key")
	keyIDEnvironment := flags.String("key-id-env", defaultKeyIDEnvironment, "environment variable containing the key ID")
	if err := flags.Parse(arguments); err != nil {
		return "", "", "", "", err
	}
	if flags.NArg() != 0 || *manifest == "" || *signature == "" {
		return "", "", "", "", errors.New("sign requires --manifest and --signature")
	}
	return *manifest, *signature, *privateKeyEnvironment, *keyIDEnvironment, nil
}

// parseVerifyFlags parses the verify command without allowing unknown arguments.
// parseVerifyFlags 解析 verify 命令，并拒绝未知参数。
func parseVerifyFlags(arguments []string) (string, string, string, error) {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	manifest := flags.String("manifest", "", "path to manifest.json")
	signature := flags.String("signature", "", "path to manifest.sig")
	publicKeyEnvironment := flags.String("public-key-env", defaultPublicKeyEnvironment, "environment variable containing the public key")
	if err := flags.Parse(arguments); err != nil {
		return "", "", "", err
	}
	if flags.NArg() != 0 || *manifest == "" || *signature == "" {
		return "", "", "", errors.New("verify requires --manifest and --signature")
	}
	return *manifest, *signature, *publicKeyEnvironment, nil
}

// parsePublicFlags parses the public command.
// parsePublicFlags 解析 public 命令。
func parsePublicFlags(arguments []string) (string, error) {
	flags := flag.NewFlagSet("public", flag.ContinueOnError)
	privateKeyEnvironment := flags.String("private-key-env", defaultPrivateKeyEnvironment, "environment variable containing the private key")
	if err := flags.Parse(arguments); err != nil {
		return "", err
	}
	if flags.NArg() != 0 {
		return "", errors.New("public does not accept positional arguments")
	}
	return *privateKeyEnvironment, nil
}

// run dispatches one CLI command and returns its process error.
// run 分发一个 CLI 命令并返回进程错误。
func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: sign_manifest.go sign|verify|public [options]")
	}
	switch arguments[0] {
	case "sign":
		manifest, signature, privateEnvironment, keyIDEnvironment, err := parseSignFlags(arguments[1:])
		if err != nil {
			return err
		}
		_, err = signManifest(manifest, signature, privateEnvironment, keyIDEnvironment)
		return err
	case "verify":
		manifest, signature, publicEnvironment, err := parseVerifyFlags(arguments[1:])
		if err != nil {
			return err
		}
		return verifyManifest(manifest, signature, publicEnvironment)
	case "public":
		privateEnvironment, err := parsePublicFlags(arguments[1:])
		if err != nil {
			return err
		}
		return publicKey(privateEnvironment)
	default:
		return fmt.Errorf("unsupported command %q", arguments[0])
	}
}

// main runs the release signing CLI and never prints private key material.
// main 运行发行签名 CLI，并且绝不输出私钥材料。
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "manifest signing failed: %v\n", err)
		os.Exit(1)
	}
}
