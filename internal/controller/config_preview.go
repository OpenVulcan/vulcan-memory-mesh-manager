// This file builds a secret-safe write preview from the exact candidate configuration during validation.
// 本文件在校验期间从实际候选配置生成不泄露秘密的写入预览，属于控制器层。
package controller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configedit"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// configurationPreview compares the saved override with the validated candidate; errors never include configuration values.
// configurationPreview 比较已保存覆盖与已校验候选配置；错误不包含配置值，返回可安全展示的变更。
func (c *Controller) configurationPreview(ctx context.Context, binary string, plan tui.InstallPlan, files map[string][]byte) (*tui.ConfigPreview, error) {
	schema, err := c.options.Schema(ctx, binary, plan.ConfigRoot)
	if err != nil {
		return nil, errors.New("configuration preview schema is unavailable")
	}
	before, err := readConfigBytes(plan.ConfigRoot)
	if err != nil {
		return nil, errors.New("configuration preview could not read saved overrides")
	}
	changes, err := previewConfigChanges(schema, before, files[defaultConfigFileName])
	if err != nil {
		return nil, errors.New("configuration preview could not compare overrides")
	}
	// Rule bodies may contain user text; show their exact content digests instead of copying bodies into summaries.
	// 规则正文可能含用户文本；在摘要中显示精确内容摘要，避免复制正文。
	// Compare the user layer only: creating an override identical to a system rule is still a new file write.
	// 仅比较用户层：创建与系统规则相同的覆盖文件仍然属于新增写入。
	rules := make(map[string]tui.ConfigField)
	root, err := os.OpenRoot(plan.ConfigRoot)
	if err == nil {
		err = collectRuleAssets(root, rules)
		closeErr := root.Close()
		if err != nil || closeErr != nil {
			return nil, errors.New("configuration preview could not read rule assets")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("configuration preview could not open saved rules")
	}
	for name, content := range files {
		if name == defaultConfigFileName {
			continue
		}
		old, exists := rules[name]
		if exists && old.Value == string(content) {
			continue
		}
		change := tui.ConfigChange{Path: name, Kind: "rule", After: fmt.Sprintf("sha256:%x", sha256.Sum256(content))}
		if exists {
			change.Before = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(old.Value)))
		}
		changes = append(changes, change)
	}
	// Report explicit credential writes by variable name only, even when the YAML reference does not change.
	// 即使 YAML 引用不变，也按变量名报告明确的凭据写入，绝不携带凭据值。
	credentialNames := make(map[string]bool)
	for _, update := range plan.Providers.CredentialUpdates {
		if update.Value != "" {
			credentialNames[update.EnvironmentName] = true
		}
	}
	if plan.StorageSettings.PostgreSQLDSNValue != "" {
		name := plan.StorageSettings.PostgreSQLDSNVariable
		if name == "" {
			name = "VMM_POSTGRES_DSN"
		}
		credentialNames[name] = true
	}
	for name := range credentialNames {
		changes = append(changes, tui.ConfigChange{Path: ".env / " + name, Kind: "credential"})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return &tui.ConfigPreview{Changes: changes}, nil
}

// previewConfigChanges compares concrete schema paths on both sides, including removed array elements and masked changes.
// previewConfigChanges 比较两侧具体 schema 路径，覆盖数组元素删除及脱敏字段变化，返回安全变更列表或错误。
func previewConfigChanges(schema configbridge.Schema, before, after []byte) ([]tui.ConfigChange, error) {
	oldDraft, err := configedit.Parse(before)
	if err != nil {
		return nil, err
	}
	newDraft, err := configedit.Parse(after)
	if err != nil {
		return nil, err
	}
	fields := make(map[string]configbridge.Field)
	for _, draft := range []*configedit.Draft{oldDraft, newDraft} {
		expanded, err := expandSchemaFields(schema.Fields, draft)
		if err != nil {
			return nil, err
		}
		for _, field := range expanded {
			fields[field.Path] = field
		}
	}
	paths := make([]string, 0, len(fields))
	for path := range fields {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	changes := make([]tui.ConfigChange, 0)
	for index, path := range paths {
		field := fields[path]
		// Descendants provide precise changes; avoid repeating their whole parent object and its credentials.
		// 子字段提供精确变化，避免重复整个父对象及其凭据。
		if index+1 < len(paths) && (strings.HasPrefix(paths[index+1], path+".") || strings.HasPrefix(paths[index+1], path+"[")) {
			continue
		}
		if field.Type == "any" || field.Type == "unknown" {
			continue
		}
		oldValue, oldExists, err := previewFieldValue(oldDraft, field)
		if err != nil {
			return nil, err
		}
		newValue, newExists, err := previewFieldValue(newDraft, field)
		if err != nil {
			return nil, err
		}
		if oldExists == newExists && oldValue == newValue {
			continue
		}
		change := tui.ConfigChange{Path: path, Kind: "updated", Before: oldValue, After: newValue}
		if !oldExists {
			change.Kind = "added"
		} else if !newExists {
			change.Kind = "removed"
		}
		if previewFieldSensitive(schema.Fields, field) {
			change.Before, change.After = "", ""
			if oldExists {
				change.Before = "<redacted>"
			}
			if newExists {
				change.After = "<redacted>"
			}
		}
		changes = append(changes, change)
	}
	return changes, nil
}

// previewFieldValue reads one declared field for local comparison and distinguishes missing from empty values.
// previewFieldValue 读取一个已声明字段供本地比较，并区分不存在与空值；原值不得直接作为错误输出。
func previewFieldValue(draft *configedit.Draft, field configbridge.Field) (string, bool, error) {
	var value string
	var err error
	switch field.Type {
	case "object", "array", "map":
		kind := configedit.StructuredObject
		if field.Type == "array" {
			kind = configedit.StructuredArray
		}
		value, err = draft.GetStructured(field.Path, kind)
	default:
		var scalar configedit.Scalar
		scalar, err = draft.Get(field.Path)
		value = scalar.Value
	}
	// Paths are the union of both array expansions; a removed index is absent on the shorter side.
	// 路径来自两侧数组展开的并集；被移除的索引在较短一侧表示不存在。
	if errors.Is(err, configedit.ErrNotFound) || errors.Is(err, configedit.ErrOutOfRange) {
		return "", false, nil
	}
	return value, err == nil, err
}

// previewFieldSensitive propagates declared secrecy through parents and children before any value reaches the UI.
// previewFieldSensitive 在值进入界面前沿父级和子级传播 schema 声明的敏感属性，返回是否必须隐藏。
func previewFieldSensitive(fields []configbridge.Field, field configbridge.Field) bool {
	path := schemaPathForConcrete(field.Path)
	if field.Sensitive || hasSensitiveDescendant(fields, path) {
		return true
	}
	for _, parent := range fields {
		if parent.Sensitive && (strings.HasPrefix(path, parent.Path+".") || strings.HasPrefix(path, parent.Path+"[")) {
			return true
		}
	}
	return false
}
