// This file verifies rollback data survives until runtime reconciliation finishes.
// 本文件验证回滚数据会保留到运行时协调完成。
package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
)

// TestPendingUpgradeRestoresFilesAndRegistration simulates a startup failure after file promotion.
// TestPendingUpgradeRestoresFilesAndRegistration 模拟文件推广之后启动失败，检查文件及登记恢复。
func TestPendingUpgradeRestoresFilesAndRegistration(t *testing.T) {
	request, paths, _ := newInstallRequest(t, "")
	request.ValidateConfig = validConfigValidator(t)
	first, err := Install(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(paths.ProgramRoot, "bin", vmmExecutableName())
	originalBinary := []byte("previous executable")
	if err := os.WriteFile(binary, originalBinary, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(originalBinary)
	previous := first.State
	for index := range previous.ManagedFiles {
		if previous.ManagedFiles[index].Path == "bin/"+vmmExecutableName() {
			previous.ManagedFiles[index].SHA256 = hex.EncodeToString(digest[:])
			previous.ManagedFiles[index].Size = int64(len(originalBinary))
		}
	}
	if err := state.Save(request.StatePath, previous); err != nil {
		t.Fatal(err)
	}
	request.Operation = OperationUpgrade
	request.ManagerVersion = "changed-manager"
	request.ConfigFiles[UserConfigFileName] = []byte("mode: changed\n")
	prepared, err := StagePackage(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	pending, err := prepared.BeginInstall(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(binary); err != nil || string(data) != "vmm executable" {
		t.Fatal("candidate binary was not promoted")
	}
	if err := pending.Finish(false); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(binary); err != nil || string(data) != string(originalBinary) {
		t.Fatal("old executable was not restored")
	}
	if data, err := os.ReadFile(filepath.Join(paths.ConfigRoot, UserConfigFileName)); err != nil || string(data) != "mode: native\n" {
		t.Fatal("old config was not restored")
	}
	restored, err := state.Load(request.StatePath)
	if err != nil || !reflect.DeepEqual(restored, previous) {
		t.Fatal("old registration was not restored")
	}
}

// TestPendingFirstInstallCanAbort removes newly managed files and registration while preserving persistent data.
// TestPendingFirstInstallCanAbort 移除首次安装新建的受管文件与登记，同时保留持久数据。
func TestPendingFirstInstallCanAbort(t *testing.T) {
	request, paths, _ := newInstallRequest(t, "")
	request.ValidateConfig = validConfigValidator(t)
	prepared, err := StagePackage(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	pending, err := prepared.BeginInstall(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(paths.DataRoot, "preserved.db")
	if err := os.WriteFile(data, []byte("preserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pending.Finish(false); err != nil {
		t.Fatal(err)
	}
	for _, removed := range []string{request.StatePath, filepath.Join(paths.ProgramRoot, "bin", vmmExecutableName())} {
		if _, err := os.Stat(removed); !os.IsNotExist(err) {
			t.Fatalf("aborted installation retained %s", removed)
		}
	}
	if bytes, err := os.ReadFile(data); err != nil || string(bytes) != "preserved" {
		t.Fatal("rollback changed persistent data")
	}
}
