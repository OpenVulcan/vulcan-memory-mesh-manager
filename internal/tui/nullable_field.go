// This file stages explicit null values for schema-declared optional scalar fields in the advanced editor.
// 本文件在高级编辑器中为 schema 声明的可选标量暂存显式空值，属于界面层。
package tui

// clearNullableField stages null for the selected editable scalar and invalidates the old validation and preview.
// clearNullableField 将选中且可编辑的标量暂存为空值，并使旧校验及预览失效；不写文件或返回结果。
func (m *Model) clearNullableField() {
	index := m.cursor
	if m.editingField >= 0 {
		index = m.editingField
	}
	if index < 0 || index >= len(m.configFields.Fields) {
		return
	}
	field := &m.configFields.Fields[index]
	if !field.Nullable || !field.Editable || field.RuleAsset {
		m.status = m.label("当前字段不支持显式空值", "This field does not support explicit null")
		return
	}
	switch field.Type {
	case "string", "boolean", "integer", "number", "duration":
		field.Null, field.Changed, field.Value = true, true, "null"
		m.configFields.Changed = true
		m.editingField = -1
		m.input = ""
		m.invalidateValidation()
		m.status = m.label("已暂存 null，保存后仍须通过 VMM 校验", "Null staged; saving still requires VMM validation")
	default:
		m.status = m.label("当前字段不是可为空的标量", "This field is not a nullable scalar")
	}
}
