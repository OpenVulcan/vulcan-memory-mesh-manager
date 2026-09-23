// These tests exercise effective configuration through the candidate and installed controller routes.
// 这些测试通过候选及已安装控制器链路验证生效配置查看，属于控制器回归测试。
package controller

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestEffectiveCandidateIsIsolatedAndSavedReadUsesInstalledRoot checks real staging and guards against accidentally committing inspection.
// TestEffectiveCandidateIsIsolatedAndSavedReadUsesInstalledRoot 检查真实暂存，并防止查看候选配置时意外提交安装。
func TestEffectiveCandidateIsIsolatedAndSavedReadUsesInstalledRoot(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	defer controller.discardStaged()
	if events := collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan}); terminalKind(events) != tui.OperationEventCompleted {
		t.Fatal(events)
	}
	var inspectedRoot string
	controller.options.Effective = func(_ context.Context, binary, root string) (configbridge.EffectiveConfig, error) {
		inspectedRoot = root
		if _, err := os.Stat(binary); err != nil {
			return configbridge.EffectiveConfig{}, err
		}
		if _, err := os.Stat(filepath.Join(root, "config.yaml")); err != nil {
			return configbridge.EffectiveConfig{}, err
		}
		return configbridge.EffectiveConfig{Version: "v2", Redacted: true, Config: map[string]json.RawMessage{"memory_pipeline": json.RawMessage(`{"min_similarity_score":null}`)}, Sources: map[string]configbridge.ConfigValueSource{"/memory_pipeline/min_similarity_score": {Kind: "file", File: filepath.Join(root, "config.yaml")}}}, nil
	}
	events := collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationEffective, Plan: plan})
	if terminalKind(events) != tui.OperationEventCompleted || inspectedRoot == plan.ConfigRoot {
		t.Fatal("candidate read used saved root or failed")
	}
	var projection *tui.EffectiveConfiguration
	for _, event := range events {
		if event.Effective != nil {
			projection = event.Effective
		}
	}
	if projection == nil || !projection.Candidate || len(projection.Fields) != 1 || projection.Fields[0].Value != "null" {
		t.Fatal("candidate projection lost null or context")
	}
	if _, err := os.Stat(inspectedRoot); !os.IsNotExist(err) {
		t.Fatal("candidate was not cleaned")
	}
	if _, err := os.Stat(controller.options.StatePath); !os.IsNotExist(err) {
		t.Fatal("inspection committed installation")
	}
	if events = collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan}); terminalKind(events) != tui.OperationEventCompleted {
		t.Fatal(events)
	}
	events = collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationEffective})
	if terminalKind(events) != tui.OperationEventCompleted || inspectedRoot != plan.ConfigRoot {
		t.Fatal("saved read did not use installed root")
	}
	for _, event := range events {
		if event.Effective != nil && event.Effective.Candidate {
			t.Fatal("saved read labeled candidate")
		}
	}
}
