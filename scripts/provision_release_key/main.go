// Package main provisions product-specific Ed25519 release keys in GitHub Actions Secrets.
// main 包在 GitHub Actions Secrets 中配置产品专用的 Ed25519 发行密钥。
// It keeps private material in process memory and prints only the public trust root.
// 私钥材料仅留在进程内存中，程序只输出公开的信任根。
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// product identifies the fixed repository and secret names for one release stream.
// product 标识一个发行流的固定仓库和密钥名称。
type product struct {
	Repository string
	PrivateSecret string
	KeyIDSecret string
	KeyID string
}

// products is a closed allowlist so key material cannot be sent to an arbitrary repository.
// products 是封闭白名单，防止密钥材料被发送到任意仓库。
var products = map[string]product{
	"vmmm": {
		Repository: "OpenVulcan/vulcan-memory-mesh-manager",
		PrivateSecret: "VMMM_RELEASE_ED25519_PRIVATE_KEY",
		KeyIDSecret: "VMMM_RELEASE_ED25519_KEY_ID",
		KeyID: "vmmm-2026-09-23-01",
	},
	"vmm": {
		Repository: "OpenVulcan/vulcan-memory-mesh",
		PrivateSecret: "VMM_RELEASE_ED25519_PRIVATE_KEY",
		KeyIDSecret: "VMM_RELEASE_ED25519_KEY_ID",
		KeyID: "vmm-2026-09-23-01",
	},
}

// main provisions one requested key and reports its public half after both secrets are accepted.
// main 配置指定密钥，并仅在两个 Secret 均被接受后报告其公钥部分。
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./scripts/provision_release_key {vmmm|vmm}")
		os.Exit(2)
	}
	selected, ok := products[os.Args[1]]
	if !ok {
		fmt.Fprintln(os.Stderr, "unknown release product")
		os.Exit(2)
	}
	if err := provision(selected); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// provision generates a fresh key in memory, stores its seed in one Actions Secret, and prints only public metadata.
// provision 在内存中生成新密钥，将种子写入一个 Actions Secret，并只输出公开元数据。
func provision(selected product) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("generate Ed25519 key failed")
	}
	seed := append([]byte(nil), privateKey.Seed()...)
	defer clear(seed)
	defer clear(privateKey)
	privateText := base64.StdEncoding.EncodeToString(seed)
	defer func() { privateText = "" }()
	if err := setSecret(selected.Repository, selected.PrivateSecret, privateText); err != nil {
		return err
	}
	if err := setSecret(selected.Repository, selected.KeyIDSecret, selected.KeyID); err != nil {
		return err
	}
	fmt.Printf("product=%s key_id=%s public_key_base64=%s\n", selected.Repository, selected.KeyID, base64.StdEncoding.EncodeToString(publicKey))
	return nil
}

// setSecret passes a value to gh through stdin, keeping it out of process arguments, files, and logs.
// setSecret 通过标准输入向 gh 传值，避免写入进程参数、文件和日志。
func setSecret(repository, name, value string) error {
	command := exec.Command("gh", "secret", "set", name, "--repo", repository, "--app", "actions")
	command.Stdin = strings.NewReader(value)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("set GitHub Actions Secret %s in %s failed: %w", name, repository, err)
	}
	return nil
}
