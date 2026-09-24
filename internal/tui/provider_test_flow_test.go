// provider_test_flow_test.go verifies paid-test consent and independent online results in the terminal flow.
// provider_test_flow_test.go 验证终端流程中的收费测试确认与独立在线结果。
package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// TestProviderTestNeedsExplicitSelection ensures opening or leaving the warning page cannot trigger network diagnostics.
// TestProviderTestNeedsExplicitSelection 确保打开或离开警告页不会触发网络诊断。
func TestProviderTestNeedsExplicitSelection(t *testing.T) {
	controller := &testController{}
	m := NewModel(ModelConfig{Controller: controller, Language: LanguageChinese})
	m.setScreen(ScreenConfigCheck)
	m.cursor = 4
	m = update(t, m, press(tea.KeyEnter, ""))
	if m.Screen() != ScreenProviderTest || len(controller.requests) != 0 || m.cursor != 0 {
		t.Fatal("warning page sent a request or failed to default to return")
	}
	if !strings.Contains(strings.Join(m.renderProviderTest(), "\n"), "可能产生费用") {
		t.Fatal("cost disclosure is missing")
	}
	m = update(t, m, press(tea.KeyEnter, ""))
	if m.Screen() != ScreenConfigCheck || len(controller.requests) != 0 {
		t.Fatal("return option sent a request")
	}
	m.cursor = 4
	m = update(t, m, press(tea.KeyEnter, ""))
	m.cursor = 1
	m = update(t, m, press(tea.KeyEnter, ""))
	if len(controller.requests) != 1 || controller.requests[0].Kind != OperationTestProvider || !controller.requests[0].ConfirmProviderNetwork || controller.requests[0].ProviderPurpose != ProviderPurposeLLM {
		t.Fatal("explicit choice did not bind the paid request")
	}
}

// TestProviderFailureDoesNotInvalidateStaticConfig keeps failed network diagnostics visible without changing a valid YAML result.
// TestProviderFailureDoesNotInvalidateStaticConfig 保留网络失败诊断的显示，不改变有效 YAML 的校验结果。
func TestProviderFailureDoesNotInvalidateStaticConfig(t *testing.T) {
	m := NewModel(ModelConfig{Language: LanguageChinese})
	m.validation.Valid = true
	m.updateOperationEvent(operationEventMsg{id: m.operationID, event: OperationEvent{Kind: OperationEventProgress, ProviderTest: &ProviderTestSummary{Purpose: ProviderPurposeEmbedding, Class: "request-failed"}}})
	if !m.validation.Valid || !strings.Contains(strings.Join(m.renderConfigCheck(), "\n"), "网络、认证或供应商请求失败") {
		t.Fatal("online failure changed or hid static validation")
	}
	m.invalidateValidation()
	if m.providerTest != nil {
		t.Fatal("changed configuration retained a stale provider result")
	}
}
