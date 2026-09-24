package trust

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// TestProductKeysAreSeparateAndImmutable verifies callers cannot alter a later trust lookup.
// TestProductKeysAreSeparateAndImmutable 验证调用方无法改变之后的信任根查询结果。
func TestProductKeysAreSeparateAndImmutable(t *testing.T) {
	manager := VMMMKeys()
	runtime := VMMKeys()
	if len(manager[VMMMKeyID]) != ed25519.PublicKeySize || len(runtime[VMMKeyID]) != ed25519.PublicKeySize {
		t.Fatal("invalid public key size")
	}
	if bytes.Equal(manager[VMMMKeyID], runtime[VMMKeyID]) {
		t.Fatal("manager and runtime must use distinct release keys")
	}
	manager[VMMMKeyID][0] ^= 0xff
	if bytes.Equal(manager[VMMMKeyID], VMMMKeys()[VMMMKeyID]) {
		t.Fatal("mutating one returned map changed the compiled trust root")
	}
}
