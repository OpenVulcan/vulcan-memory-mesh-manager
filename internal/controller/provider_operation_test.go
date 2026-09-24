// provider_operation_test.go verifies candidate isolation and consent without sending external requests.
// provider_operation_test.go 验证候选隔离和用户确认，不发送外部请求。
package controller

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestProviderOperationKeepsCredentialsInCandidate checks consent, staged keys, cleanup and independent online failure reporting.
// TestProviderOperationKeepsCredentialsInCandidate 检查确认、暂存密钥、清理及独立在线失败报告。
func TestProviderOperationKeepsCredentialsInCandidate(t *testing.T) {
	c, plan, _ := newFixtureController(t)
	defer c.discardStaged()
	if err := os.MkdirAll(plan.ConfigRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("OLD_KEY=unchanged\n")
	if err := os.WriteFile(filepath.Join(plan.ConfigRoot, ".env"), original, 0o600); err != nil {
		t.Fatal(err)
	}
	plan.Providers = tui.ProviderPlan{
		LLMRoutes:         []tui.ProviderRoute{{Provider: "openrouter", Model: "test-model", APIKeyEnvironmentNames: []string{"PROBE_KEY"}}},
		CredentialPath:    filepath.Join(plan.ConfigRoot, ".env"),
		CredentialUpdates: []tui.CredentialUpdate{{EnvironmentName: "PROBE_KEY", Value: "candidate-secret"}},
	}
	calls, candidateRoot := 0, ""
	c.options.TestProvider = func(_ context.Context, binary, root, purpose string, route int, confirmed bool) (configbridge.ProviderTestResult, error) {
		calls++
		candidateRoot = root
		if !confirmed || root == plan.ConfigRoot || purpose != "llm" || route != 0 {
			t.Fatal("incorrect diagnostic selection or candidate root")
		}
		content, err := os.ReadFile(filepath.Join(root, ".env"))
		if err != nil || !bytes.Contains(content, []byte("candidate-secret")) || !bytes.Contains(content, []byte("unchanged")) {
			t.Fatal("candidate credentials missing")
		}
		return configbridge.ProviderTestResult{Version: "v1", Purpose: purpose, Route: route, Class: "request-failed"}, nil
	}
	request := tui.OperationRequest{Kind: tui.OperationTestProvider, Plan: plan, ProviderPurpose: tui.ProviderPurposeLLM}
	if terminalKind(collectOperation(t, c, request)) != tui.OperationEventFailed || calls != 0 {
		t.Fatal("unconfirmed test reached provider")
	}
	if terminalKind(collectOperation(t, c, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})) != tui.OperationEventCompleted {
		t.Fatal("stage failed")
	}
	request.ConfirmProviderNetwork = true
	events := collectOperation(t, c, request)
	if terminalKind(events) != tui.OperationEventFailed || calls != 1 {
		t.Fatal("online failure was not reported")
	}
	found := false
	for _, event := range events {
		if event.ProviderTest != nil && !event.ProviderTest.Success && event.ProviderTest.Class == "request-failed" {
			found = true
		}
		if event.Kind == tui.OperationEventFailed && event.Retryable {
			t.Fatal("paid retry bypasses confirmation page")
		}
		if event.Validation != nil {
			t.Fatal("online test rewrote static validation")
		}
	}
	if !found {
		t.Fatal("missing independent provider result")
	}
	if _, err := os.Stat(candidateRoot); !os.IsNotExist(err) {
		t.Fatal("candidate directory was retained")
	}
	content, err := os.ReadFile(filepath.Join(plan.ConfigRoot, ".env"))
	if err != nil || !bytes.Equal(content, original) {
		t.Fatal("provider test persisted credentials")
	}
	if _, err := os.Stat(c.options.StatePath); !os.IsNotExist(err) {
		t.Fatal("provider test wrote installation state")
	}
}
