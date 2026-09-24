// These tests exercise bilingual rendering of controller events without rerunning operations.
// 这些测试验证无需重新执行操作即可双语渲染控制器事件。
package tui

import (
	"strings"
	"testing"
)

// TestControllerEventLanguageSwitch retains the original event while rendering its current language.
// TestControllerEventLanguageSwitch 保留原始事件，并按当前语言显示进度和错误。
func TestControllerEventLanguageSwitch(t *testing.T) {
	model := NewModel(ModelConfig{Language: LanguageChinese})
	model.screen = ScreenDownload
	model.busy = true
	_, _ = model.Update(operationEventMsg{id: model.operationID, event: OperationEvent{
		Kind:     OperationEventProgress,
		Message:  "Downloading and verifying VMM package",
		Progress: Progress{Stage: "download", Message: "Downloading and verifying VMM package"},
	}})
	view := model.View().Content
	if !strings.Contains(view, "正在下载并验证 VMM 安装包") || strings.Contains(view, "Downloading") {
		t.Fatalf("Chinese progress: %q", view)
	}
	model.language = LanguageEnglish
	if !strings.Contains(model.View().Content, "Downloading and verifying VMM package") {
		t.Fatal("switching language lost the original progress")
	}
	model.language = LanguageChinese
	_, _ = model.Update(operationEventMsg{id: model.operationID, event: OperationEvent{
		Kind: OperationEventFailed, Message: "VMM runtime did not become healthy; run vmmm doctor for diagnostics",
	}})
	if !strings.Contains(model.View().Content, "VMM 未达到健康状态") {
		t.Fatal("health failure remained untranslated")
	}
	if got := model.operationText("custom_field: invalid value"); got != "custom_field: invalid value" {
		t.Fatal("runtime diagnostic was rewritten")
	}
}
