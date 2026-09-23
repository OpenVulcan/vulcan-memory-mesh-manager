// Package trust holds the fixed public roots for VMMM and VMM release signatures.
// trust 包保存 VMMM 与 VMM 发行签名使用的固定公钥信任根。
// Release discovery consumes these keys before accepting any downloaded manifest.
// 发行发现流程在接受任何下载清单前使用这些公钥。
package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

const (
	// VMMMKeyID identifies the manager release key stored in its GitHub Actions Secrets.
	// VMMMKeyID 标识存放在管理器 GitHub Actions Secrets 中的发行密钥。
	VMMMKeyID = "vmmm-2026-09-23-01"
	// VMMKeyID identifies the runtime release key stored in its GitHub Actions Secrets.
	// VMMKeyID 标识存放在运行时 GitHub Actions Secrets 中的发行密钥。
	VMMKeyID = "vmm-2026-09-23-01"
	// vmmmPublicKeyBase64 is the public half of the manager's release signing key.
	// vmmmPublicKeyBase64 是管理器发行签名密钥的公钥部分。
	vmmmPublicKeyBase64 = "S4zmW0F/BJA7MbvupEdD1jYuaA2tUlBfFRsuDBVjge0="
	// vmmPublicKeyBase64 is the public half of the runtime's release signing key.
	// vmmPublicKeyBase64 是运行时发行签名密钥的公钥部分。
	vmmPublicKeyBase64 = "h2906GgOkZSmkYGWy3tV6/sH0+zyCcnhTZKjKx06cpM="
)

// VMMMKeys returns a new trust map for manager self updates.
// VMMMKeys 返回供管理器自身更新使用的独立信任映射。
func VMMMKeys() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{VMMMKeyID: mustPublicKey(vmmmPublicKeyBase64)}
}

// VMMKeys returns a new trust map for runtime package installation and updates.
// VMMKeys 返回供运行时安装与更新使用的独立信任映射。
func VMMKeys() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{VMMKeyID: mustPublicKey(vmmPublicKeyBase64)}
}

// mustPublicKey decodes a compile-time trust root and panics if a release build carries an invalid key.
// mustPublicKey 解码编译期信任根；若发行构建携带无效公钥则立即终止。
func mustPublicKey(encoded string) ed25519.PublicKey {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize {
		panic(fmt.Sprintf("invalid compiled Ed25519 trust root: %v", err))
	}
	return ed25519.PublicKey(key)
}
