// The i18n tests protect bilingual catalog parity, locale selection, and strict formatting.
// i18n 测试保护双语目录一致性、语言选择和严格格式化行为。
package i18n

import (
	"errors"
	"strings"
	"testing"
)

// TestCatalogsStayComplete verifies that both languages expose the same usable catalog.
// TestCatalogsStayComplete 验证两种语言暴露相同且可用的消息目录。
func TestCatalogsStayComplete(t *testing.T) {
	if err := ValidateCatalogs(); err != nil {
		t.Fatalf("catalog validation failed: %v", err)
	}
	keys := Keys()
	if len(keys) < 50 {
		t.Fatalf("catalog is unexpectedly small: %d keys", len(keys))
	}
	for _, language := range []Language{English, SimplifiedChinese} {
		catalog, err := New(language)
		if err != nil {
			t.Fatalf("New(%q): %v", language, err)
		}
		for _, key := range keys {
			message, err := catalog.Text(key)
			if err != nil || strings.TrimSpace(message) == "" {
				t.Fatalf("language %q key %q is unusable: %v", language, key, err)
			}
		}
	}
}

// TestLocaleSelection verifies explicit selection, POSIX locale parsing, and precedence.
// TestLocaleSelection 验证显式选择、POSIX 区域设置解析和优先级。
func TestLocaleSelection(t *testing.T) {
	tests := []struct {
		name     string
		explicit string
		env      map[string]string
		want     Language
		wantErr  error
	}{
		{name: "explicit Chinese", explicit: "zh", env: map[string]string{"LANG": "en_US.UTF-8"}, want: SimplifiedChinese},
		{name: "explicit locale", explicit: "zh-CN", want: SimplifiedChinese},
		{name: "LC_ALL wins", env: map[string]string{"LC_ALL": "en_US.UTF-8", "LC_MESSAGES": "zh_CN.UTF-8", "LANG": "zh"}, want: English},
		{name: "messages wins", env: map[string]string{"LC_MESSAGES": "zh_CN.UTF-8", "LANG": "en_US.UTF-8"}, want: SimplifiedChinese},
		{name: "default English", env: map[string]string{}, want: English},
		{name: "invalid explicit", explicit: "ja", wantErr: ErrUnsupportedLanguage},
		{name: "empty explicit is automatic", explicit: " ", env: map[string]string{"LANG": "zh"}, want: SimplifiedChinese},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := SelectLanguage(test.explicit, test.env)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("error %v does not wrap %v", err, test.wantErr)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("got language %q, error %v; want %q", got, err, test.want)
			}
		})
	}
}

// TestStrictFormatting verifies missing, extra, malformed, and data-only substitutions.
// TestStrictFormatting 验证缺失、多余、格式错误以及纯数据替换。
func TestStrictFormatting(t *testing.T) {
	catalog, err := New(English)
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := catalog.Format(KeyDownloadProgress, map[string]string{"current": "10%", "total": "100"})
	if err != nil || formatted != "Progress: 10%/100" {
		t.Fatalf("safe formatting returned %q, error %v", formatted, err)
	}
	if _, err := catalog.Format(KeyDownloadProgress, map[string]string{"current": "1"}); !errors.Is(err, ErrMissingPlaceholder) {
		t.Fatalf("missing placeholder error = %v", err)
	}
	if _, err := catalog.Format(KeyDownloadProgress, map[string]string{"current": "1", "total": "2", "extra": "3"}); !errors.Is(err, ErrUnexpectedPlaceholder) {
		t.Fatalf("extra placeholder error = %v", err)
	}
	if _, err := catalog.Format(KeyDownloadProgress, map[string]string{"bad key": "1", "current": "2", "total": "3"}); !errors.Is(err, ErrInvalidPlaceholder) {
		t.Fatalf("invalid placeholder error = %v", err)
	}
	if _, err := catalog.Text(MessageKey("missing.key")); !errors.Is(err, ErrMissingMessage) {
		t.Fatalf("missing key error = %v", err)
	}
	if _, err := catalog.Format(KeyDownloadProgress, map[string]string{"current": "{malicious}", "total": "%s"}); err != nil {
		t.Fatalf("replacement data should remain data: %v", err)
	}
}

// TestCatalogValidationDetectsMissingKeys proves that incomplete catalogs fail closed.
// TestCatalogValidationDetectsMissingKeys 证明不完整目录会安全失败。
func TestCatalogValidationDetectsMissingKeys(t *testing.T) {
	const removed = KeyAppTitle
	original := catalogs[SimplifiedChinese][removed]
	delete(catalogs[SimplifiedChinese], removed)
	t.Cleanup(func() { catalogs[SimplifiedChinese][removed] = original })
	if err := ValidateCatalogs(); !errors.Is(err, ErrCatalogMismatch) {
		t.Fatalf("missing key validation error = %v", err)
	}
}
