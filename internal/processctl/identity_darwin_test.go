//go:build darwin

// This file checks Darwin kernel argument decoding used by foreground process identity verification.
// 此文件检验前台进程身份核对所用的 Darwin 内核参数解码。
package processctl

import (
	"encoding/binary"
	"reflect"
	"testing"
)

// TestParseDarwinArgumentsSeparatesExecutablePath verifies KERN_PROCARGS2 metadata is not mistaken for argv.
// TestParseDarwinArgumentsSeparatesExecutablePath 验证 KERN_PROCARGS2 元数据不会被误当作 argv。
func TestParseDarwinArgumentsSeparatesExecutablePath(t *testing.T) {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, 3)
	data = append(data, []byte("/private/tmp/vmm-local\x00\x00\x00/private/tmp/vmm-local\x00-config\x00/private/tmp/config\x00ENV=value\x00")...)
	got, err := parseDarwinArguments(data)
	if err != nil {
		t.Fatalf("parse Darwin arguments: %v", err)
	}
	want := []string{"/private/tmp/vmm-local", "-config", "/private/tmp/config"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("arguments = %#v, want %#v", got, want)
	}
}

// TestParseDarwinArgumentsRejectsTruncation ensures incomplete argv never becomes trusted process identity.
// TestParseDarwinArgumentsRejectsTruncation 确保不完整的 argv 不会被当作可信进程身份。
func TestParseDarwinArgumentsRejectsTruncation(t *testing.T) {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, 2)
	data = append(data, []byte("/private/tmp/vmm-local\x00\x00/private/tmp/vmm-local\x00-config")...)
	if _, err := parseDarwinArguments(data); err == nil {
		t.Fatal("truncated argv was accepted")
	}
}
