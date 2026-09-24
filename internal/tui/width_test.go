// These tests measure real terminal columns for localized pages and long input.
// 这些测试按真实终端显示列检查本地化页面与长输入。
package tui

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"
)

// TestDisplayColumnBounds checks Chinese, emoji, combining marks, and very narrow terminals.
// TestDisplayColumnBounds 检查中文、表情符号、组合字符与极窄终端的显示列约束。
func TestDisplayColumnBounds(t *testing.T) {
	for _, value := range []string{"中文配置文件地址", "👨‍👩‍👧‍👦😀家庭", "e\u0301e\u0301组合"} {
		for width := 1; width <= 12; width++ {
			view := boundLines([]string{value}, width, 1)
			if !utf8.ValidString(view) || ansi.StringWidth(view) > width {
				t.Fatalf("width %d exceeded: %q", width, view)
			}
		}
	}
	model := NewModel(ModelConfig{Localizer: testLocalizer{}, Language: LanguageChinese})
	model.width, model.height = 80, 24
	model.screen = ScreenStorage
	for _, line := range strings.Split(model.View().Content, "\n") {
		if ansi.StringWidth(line) > 80 {
			t.Fatalf("localized screen overflow: %q", line)
		}
	}
}

// TestLongInputShowsTail verifies that text appended beyond one screen remains visible after resize.
// TestLongInputShowsTail 验证超过屏幕宽度的末尾输入在窗口尺寸变化后仍然可见。
func TestLongInputShowsTail(t *testing.T) {
	model := NewModel(ModelConfig{Localizer: testLocalizer{}, Language: LanguageChinese})
	model.screen = ScreenCustomSource
	model.input = "https://example.org/" + strings.Repeat("路径", 30) + "尾部"
	for _, width := range []int{80, 40, 12} {
		model.width = width
		view := model.View().Content
		if !strings.Contains(view, "尾部") {
			t.Fatalf("input tail hidden at %d columns: %q", width, view)
		}
		for _, line := range strings.Split(view, "\n") {
			if ansi.StringWidth(line) > width {
				t.Fatal("input exceeded width")
			}
		}
	}
}

// TestInstructionsWrapWithoutLosingText keeps replacement notices available on eighty-column screens.
// TestInstructionsWrapWithoutLosingText 保证八十列终端中的替换提示不会被截断丢失。
func TestInstructionsWrapWithoutLosingText(t *testing.T) {
	text := strings.Repeat("配置说明", 25)
	lines := wrapProse([]string{text, "> selected", "    > input"}, 80)
	if strings.Join(lines[:len(lines)-2], "") != text {
		t.Fatal("instruction text was lost")
	}
	if lines[len(lines)-2] != "> selected" || lines[len(lines)-1] != "    > input" {
		t.Fatal("focus markers changed")
	}
}
