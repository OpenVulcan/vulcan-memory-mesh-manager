// This file adapts the shared bilingual catalog to the TUI rendering boundary.
// 本文件将共享双语目录适配到 TUI 渲染边界。
package tui

import "github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/i18n"

// CatalogLocalizer adapts the shared i18n catalogs to the TUI Localizer interface.
// CatalogLocalizer 将共享 i18n 目录适配到 TUI 的 Localizer 接口。
type CatalogLocalizer struct {
	// catalogs contains validated catalogs keyed by their supported language.
	// catalogs 保存按受支持语言索引的已校验目录。
	catalogs map[Language]i18n.Catalog
}

// NewCatalogLocalizer loads both supported catalogs and keeps failures fail-soft for rendering.
// NewCatalogLocalizer 加载两种受支持目录，并在渲染时对加载失败采取可见的降级行为。
func NewCatalogLocalizer() CatalogLocalizer {
	localizer := CatalogLocalizer{catalogs: make(map[Language]i18n.Catalog, 2)}
	for _, language := range []Language{LanguageEnglish, LanguageChinese} {
		catalog, err := i18n.New(language)
		if err == nil {
			localizer.catalogs[language] = catalog
		}
	}
	return localizer
}

// Text returns a translated message and safely substitutes named values.
// Text 返回翻译消息，并安全替换命名占位值。
func (l CatalogLocalizer) Text(language Language, key i18n.MessageKey, values map[string]string) string {
	catalog, ok := l.catalogs[language]
	if !ok {
		catalog, ok = l.catalogs[LanguageChinese]
	}
	if !ok {
		return string(key)
	}
	if len(values) == 0 {
		message, err := catalog.Text(key)
		if err == nil {
			return message
		}
		return string(key)
	}
	message, err := catalog.Format(key, values)
	if err == nil {
		return message
	}
	return string(key)
}
