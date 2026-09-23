// This file parses explicit field paths and applies mapping-only path creation rules.
// 本文件解析明确字段路径，并执行仅创建映射的路径规则。
package configedit

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// pathStep is one mapping key or concrete sequence index in a parsed path.
// pathStep 是已解析路径中的一个映射键或具体序列索引。
type pathStep struct {
	// key stores a mapping key when the path step is not an array index.
	// key 在路径步骤不是数组索引时保存映射键。
	key string
	// index stores the concrete sequence offset for an array path step.
	// index 保存数组路径步骤对应的具体序列偏移。
	index int
	// isIndex distinguishes sequence offsets from mapping key names.
	// isIndex 用于区分序列偏移和映射键名。
	isIndex bool
}

// nodeSlot identifies one existing node and the content range used to remove it.
// nodeSlot 标识一个已有节点及删除时对应的内容范围。
type nodeSlot struct {
	// parent owns the content slice containing the target node.
	// parent 持有包含目标节点的内容切片。
	parent *yaml.Node
	// index is the direct content offset of the target value.
	// index 是目标值在内容切片中的直接偏移。
	index int
	// deleteStart is the first content offset removed by a delete operation.
	// deleteStart 是删除操作移除的首个内容偏移。
	deleteStart int
	// deleteWidth is one for arrays and two for mapping key/value pairs.
	// deleteWidth 在数组中为一，在映射键值对中为二。
	deleteWidth int
}

// mutationLocation describes either an existing node or a safe missing mapping suffix.
// mutationLocation 描述已有节点或可安全创建的缺失映射后缀。
type mutationLocation struct {
	// slot identifies an existing terminal node when the path already exists.
	// slot 在路径已存在时标识末端节点。
	slot *nodeSlot
	// parent is the existing mapping that owns a missing key suffix.
	// parent 是持有缺失键后缀的已有映射。
	parent *yaml.Node
	// missing contains the suffix that may be safely created as mappings.
	// missing 保存可安全创建为映射的缺失后缀。
	missing []pathStep
}

// contentBackup retains a mapping's prior child slice for failed structured edits.
// contentBackup 保存映射旧子节点切片，以便结构化编辑失败时恢复。
type contentBackup struct {
	// node is the mapping whose child slice was changed.
	// node 是子节点切片被修改的映射。
	node *yaml.Node
	// content is the exact prior child slice restored after validation failure.
	// content 是校验失败后恢复的原子节点切片。
	content []*yaml.Node
	// style is the prior presentation style restored if structured validation fails.
	// style 是结构化校验失败时恢复的原节点展示样式。
	style yaml.Style
}

// parsePath accepts ASCII key segments joined by dots and concrete non-negative array indices.
// parsePath 接受由点连接的 ASCII 键名段和具体非负数组索引。
func parsePath(path string) ([]pathStep, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: path is empty", ErrInvalidPath)
	}
	steps := make([]pathStep, 0, 4)
	position := 0
	for {
		key, next, err := parseKey(path, position)
		if err != nil {
			return nil, err
		}
		steps = append(steps, pathStep{key: key})
		position = next
		for position < len(path) && path[position] == '[' {
			closeAt := strings.IndexByte(path[position+1:], ']')
			if closeAt < 0 {
				return nil, fmt.Errorf("%w: unterminated array index", ErrInvalidPath)
			}
			closeAt += position + 1
			indexText := path[position+1 : closeAt]
			if indexText == "" {
				return nil, fmt.Errorf("%w: empty array index", ErrInvalidPath)
			}
			for _, digit := range indexText {
				if digit < '0' || digit > '9' {
					return nil, fmt.Errorf("%w: array index must be decimal", ErrInvalidPath)
				}
			}
			index, err := strconv.Atoi(indexText)
			if err != nil {
				return nil, fmt.Errorf("%w: array index overflows", ErrInvalidPath)
			}
			steps = append(steps, pathStep{index: index, isIndex: true})
			position = closeAt + 1
		}
		if position == len(path) {
			return steps, nil
		}
		if path[position] != '.' {
			return nil, fmt.Errorf("%w near byte %d", ErrInvalidPath, position)
		}
		position++
		if position == len(path) || path[position] == '.' || path[position] == '[' {
			return nil, fmt.Errorf("%w: empty key segment", ErrInvalidPath)
		}
	}
}

// parseKey reads one restricted key segment and returns its end byte offset.
// parseKey 读取一个受限键名段并返回结束字节偏移。
func parseKey(path string, start int) (string, int, error) {
	if start >= len(path) || !isKeyStart(path[start]) {
		return "", start, fmt.Errorf("%w: key must start with an ASCII letter or underscore", ErrInvalidPath)
	}
	end := start + 1
	for end < len(path) && isKeyPart(path[end]) {
		end++
	}
	return path[start:end], end, nil
}

// isKeyStart reports whether one byte is allowed at the beginning of a path key.
// isKeyStart 判断字节是否可以作为路径键名的首字符。
func isKeyStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

// isKeyPart reports whether one byte is allowed after a path key's first character.
// isKeyPart 判断字节是否可以出现在路径键名的首字符之后。
func isKeyPart(value byte) bool {
	return isKeyStart(value) || value >= '0' && value <= '9' || value == '-'
}

// locateForMutation resolves an existing node or a safely creatable chain of missing mappings.
// locateForMutation 解析已有节点，或可安全创建的一串缺失映射。
func locateForMutation(root *yaml.Node, steps []pathStep, path string) (mutationLocation, error) {
	current := root
	for index, step := range steps {
		if current == nil {
			return mutationLocation{}, fmt.Errorf("%w at %q", ErrNotFound, path)
		}
		if current.Kind == yaml.AliasNode {
			return mutationLocation{}, fmt.Errorf("%w at %q", ErrAliasTraversal, path)
		}
		last := index == len(steps)-1
		if step.isIndex {
			if current.Kind != yaml.SequenceNode {
				return mutationLocation{}, fmt.Errorf("%w at %q: expected array", ErrNotFound, path)
			}
			if step.index < 0 || step.index >= len(current.Content) {
				return mutationLocation{}, fmt.Errorf("%w: %q", ErrOutOfRange, path)
			}
			if last {
				return mutationLocation{slot: &nodeSlot{
					parent: current, index: step.index, deleteStart: step.index, deleteWidth: 1,
				}}, nil
			}
			current = current.Content[step.index]
			continue
		}
		if current.Kind != yaml.MappingNode {
			return mutationLocation{}, fmt.Errorf("%w at %q: expected mapping", ErrNotFound, path)
		}
		pairIndex, value, found := findMapEntry(current, step.key)
		if !found {
			for _, remaining := range steps[index+1:] {
				if remaining.isIndex {
					return mutationLocation{}, fmt.Errorf("%w at %q: missing arrays must be supplied explicitly", ErrUnknownPosition, path)
				}
			}
			return mutationLocation{parent: current, missing: steps[index:]}, nil
		}
		if last {
			valueIndex := pairIndex*2 + 1
			return mutationLocation{slot: &nodeSlot{
				parent: current, index: valueIndex, deleteStart: pairIndex * 2, deleteWidth: 2,
			}}, nil
		}
		current = value
	}
	return mutationLocation{}, fmt.Errorf("%w: %q", ErrInvalidPath, path)
}

// findMapEntry returns the first string-keyed mapping value and its pair index.
// findMapEntry 返回第一个字符串键映射值及其键值对索引。
func findMapEntry(mapping *yaml.Node, key string) (int, *yaml.Node, bool) {
	for pair := 0; pair+1 < len(mapping.Content); pair += 2 {
		candidate := mapping.Content[pair]
		if candidate.Kind == yaml.ScalarNode && candidate.Tag == "!!str" && candidate.Value == key {
			return pair / 2, mapping.Content[pair+1], true
		}
	}
	return 0, nil, false
}

// appendMissingKeys adds mapping-only suffixes in existing insertion order.
// appendMissingKeys 按现有插入顺序添加仅由映射键组成的缺失后缀。
func appendMissingKeys(parent *yaml.Node, missing []pathStep, value *yaml.Node) error {
	_, err := appendMissingKeysWithBackup(parent, missing, value)
	return err
}

// appendMissingKeysWithBackup appends mapping nodes and records content snapshots for rollback.
// appendMissingKeysWithBackup 添加映射节点并保存内容快照以便回滚。
func appendMissingKeysWithBackup(parent *yaml.Node, missing []pathStep, value *yaml.Node) ([]contentBackup, error) {
	if parent == nil || parent.Kind != yaml.MappingNode || len(missing) == 0 {
		return nil, fmt.Errorf("%w: missing mapping parent", ErrUnknownPosition)
	}
	for _, step := range missing {
		if step.isIndex {
			return nil, ErrUnknownPosition
		}
	}
	backups := make([]contentBackup, 0, len(missing))
	current := parent
	for index, step := range missing {
		backups = append(backups, contentBackup{
			node:    current,
			content: append([]*yaml.Node(nil), current.Content...),
			style:   current.Style,
		})
		// Expanding a flow mapping into an editable configuration should render as readable block YAML.
		// 将流式映射扩展为可编辑配置时，输出应切换为易读的块状 YAML。
		current.Style &^= yaml.FlowStyle
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: step.key}
		child := value
		if index != len(missing)-1 {
			child = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		current.Content = append(current.Content, keyNode, child)
		current = child
	}
	return backups, nil
}

// restoreContents restores mapping content snapshots in reverse mutation order.
// restoreContents 按变更逆序恢复映射内容快照。
func restoreContents(backups []contentBackup) {
	for index := len(backups) - 1; index >= 0; index-- {
		backups[index].node.Content = backups[index].content
		backups[index].node.Style = backups[index].style
	}
}
