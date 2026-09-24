// Verify source selection after the controller returns a partial probe update.
// 验证控制器返回局部探测更新后，TUI 仍可选择全部下载来源。
package tui

import (
	"testing"

	"charm.land/bubbletea/v2"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/download"
)

// TestProbedSourceKeepsOtherDownloadChoices exercises probe, back, and source switching using real event semantics.
// TestProbedSourceKeepsOtherDownloadChoices 按真实事件语义覆盖探测、返回和切源流程。
func TestProbedSourceKeepsOtherDownloadChoices(t *testing.T) {
	controller := &testController{}
	model := NewModel(ModelConfig{Controller: controller, Localizer: testLocalizer{}, Language: LanguageEnglish})
	original := append([]SourceOption(nil), model.sources...)
	model = update(t, model, press(tea.KeyEnter, ""))
	model = update(t, model, press(tea.KeyEnter, ""))
	if len(model.sources) != len(original) {
		t.Fatalf("probing one source removed alternatives: got %d, want %d", len(model.sources), len(original))
	}
	for index, source := range original {
		if model.sources[index].Source != source.Source {
			t.Fatalf("source identity/order changed at %d", index)
		}
	}
	if !model.sources[0].Available || !model.selectedSource.Available || !model.plan.Source.Available {
		t.Fatal("selected source probe result was not retained")
	}
	model = update(t, model, press(tea.KeyEscape, ""))
	if model.Screen() != ScreenSource {
		t.Fatalf("back did not restore the source menu: %v", model.Screen())
	}
	model = update(t, model, press(tea.KeyDown, ""))
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.selectedSource.Source.ID != download.SourceIDGhproxyNet || len(model.sources) != len(original) {
		t.Fatal("the built-in proxy could not be selected after the official source probe")
	}
	if !model.sources[0].Available || !model.sources[1].Available {
		t.Fatal("a later probe discarded an earlier probe result")
	}
}
