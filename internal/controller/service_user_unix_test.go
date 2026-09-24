//go:build !windows

// This file verifies Unix service-account path preflight before administrator-owned roots are created.
// 本文件验证管理员创建服务目录之前的 Unix 服务账户路径预检。
package controller

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/testpath"
)

// TestValidateServicePathAccessDefersMissingLeafWrite verifies a missing root can be prepared by the administrator.
// TestValidateServicePathAccessDefersMissingLeafWrite 验证缺失的根目录可由管理员后续创建和移交。
func TestValidateServicePathAccessDefersMissingLeafWrite(t *testing.T) {
	parent := testpath.CanonicalTempDir(t)
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(parent, "service-config")
	if err := validateServicePathAccess(missing, uint64(os.Getuid()), true, false); err != nil {
		t.Fatalf("missing administrator-prepared root rejected: %v", err)
	}
	if err := validateServicePathAccess(parent, uint64(os.Getuid()), true, false); err == nil {
		t.Fatal("existing service root without write permission was accepted")
	}
	// A known missing child needs traversal through its parent, not directory listing permission.
	// 已知的缺失子路径只需穿越父目录，无需列出父目录内容。
	if err := os.Chmod(parent, 0o100); err != nil {
		t.Fatal(err)
	}
	if err := validateServicePathAccess(missing, uint64(os.Getuid()), true, false); err != nil {
		t.Fatalf("traversable administrator-prepared root rejected: %v", err)
	}
	if err := validateServicePathAccess(parent, uint64(os.Getuid()), false, false); err == nil {
		t.Fatal("existing unreadable service root was accepted")
	}
}
