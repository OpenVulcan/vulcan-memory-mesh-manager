// Package configedit edits VMM YAML drafts while retaining comments and unknown nodes.
// configedit 包负责编辑 VMM YAML 草稿，并保留注释和未知节点。
package configedit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	// ErrInvalidDocument marks malformed, empty, or non-mapping configuration documents.
	// ErrInvalidDocument 表示配置文档格式错误、为空或根节点不是映射。
	ErrInvalidDocument = errors.New("invalid YAML configuration document")

	// ErrMultipleDocuments marks an input containing more than one YAML document.
	// ErrMultipleDocuments 表示输入包含多个 YAML 文档。
	ErrMultipleDocuments = errors.New("multiple YAML documents are not supported")

	// ErrDuplicateKey marks a duplicate key found anywhere in the YAML node tree.
	// ErrDuplicateKey 表示 YAML 节点树中存在重复键。
	ErrDuplicateKey = errors.New("duplicate YAML mapping key")

	// ErrInvalidPath marks a path that does not match the supported dotted-key and array-index grammar.
	// ErrInvalidPath 表示路径不符合支持的点分键名和数组索引语法。
	ErrInvalidPath = errors.New("invalid configuration path")

	// ErrNotFound marks a path component that does not exist in the draft.
	// ErrNotFound 表示草稿中不存在指定路径。
	ErrNotFound = errors.New("configuration path not found")

	// ErrOutOfRange marks an array index that is outside the existing sequence.
	// ErrOutOfRange 表示数组索引超出已有序列范围。
	ErrOutOfRange = errors.New("configuration array index out of range")

	// ErrNotScalar marks a scalar operation applied to a mapping or sequence node.
	// ErrNotScalar 表示标量操作的目标实际为映射或序列节点。
	ErrNotScalar = errors.New("configuration value is not a scalar")

	// ErrInvalidValue marks a value that does not validate as its caller-selected scalar type.
	// ErrInvalidValue 表示值不符合调用方明确指定的标量类型。
	ErrInvalidValue = errors.New("invalid value for selected scalar type")

	// ErrUnknownPosition marks a missing path position whose container type cannot be inferred safely.
	// ErrUnknownPosition 表示缺失路径位置的容器类型无法安全确定。
	ErrUnknownPosition = errors.New("cannot infer missing YAML container position")

	// ErrAliasTraversal prevents writes through aliases from silently mutating shared anchor targets.
	// ErrAliasTraversal 阻止写操作沿别名路径隐式修改共享锚点目标。
	ErrAliasTraversal = errors.New("cannot edit through a YAML alias")

	// ErrAliasReference marks a mutation that would leave an alias pointing to a removed node.
	// ErrAliasReference 表示变更会使别名继续指向已移除的节点。
	ErrAliasReference = errors.New("YAML alias would reference a removed node")

	// ErrAnchorConflict marks a replacement whose anchor name conflicts with the existing target anchor.
	// ErrAnchorConflict 表示替换节点的锚点名与目标现有锚点冲突。
	ErrAnchorConflict = errors.New("replacement YAML anchor conflicts with existing anchor")
)

// ScalarType selects the exact scalar representation to validate and emit.
// ScalarType 指定需要校验并输出的精确标量类型。
type ScalarType string

const (
	// ScalarString emits a quoted YAML string.
	// ScalarString 输出带引号的 YAML 字符串。
	ScalarString ScalarType = "string"

	// ScalarBool emits a canonical YAML boolean.
	// ScalarBool 输出规范形式的 YAML 布尔值。
	ScalarBool ScalarType = "bool"

	// ScalarInt emits a base-ten signed 64-bit integer.
	// ScalarInt 输出十进制有符号 64 位整数。
	ScalarInt ScalarType = "int"

	// ScalarNumber emits a finite decimal floating-point value.
	// ScalarNumber 输出有限的十进制浮点数。
	ScalarNumber ScalarType = "number"

	// ScalarDuration validates Go duration syntax and emits a quoted YAML string.
	// ScalarDuration 校验 Go duration 语法并输出带引号的 YAML 字符串。
	ScalarDuration ScalarType = "duration"
)

// StructuredType restricts a parsed replacement to an object or array node.
// StructuredType 将解析后的替换内容限制为对象或数组节点。
type StructuredType string

const (
	// StructuredObject permits a YAML mapping replacement.
	// StructuredObject 允许 YAML 映射替换。
	StructuredObject StructuredType = "object"

	// StructuredArray permits a YAML sequence replacement.
	// StructuredArray 允许 YAML 序列替换。
	StructuredArray StructuredType = "array"
)

// Scalar is the exact YAML tag and text returned by a read-only scalar lookup.
// Scalar 是只读标量查询返回的 YAML 标签和原始文本。
type Scalar struct {
	// Tag is the YAML scalar tag, such as !!str or !!bool.
	// Tag 是 YAML 标量标签，例如 !!str 或 !!bool。
	Tag string

	// Value is the scalar's decoded text without YAML quoting.
	// Value 是去除 YAML 引号后的标量解码文本。
	Value string
}

// Draft holds one parsed YAML configuration and its untouched source bytes.
// Draft 保存一份已解析的 YAML 配置及未经修改的原始字节。
type Draft struct {
	// root is the mutable YAML document tree used for reads and draft edits.
	// root 是读取和草稿编辑使用的可变 YAML 文档树。
	root *yaml.Node
	// original holds exact input bytes independently of later tree edits.
	// original 独立保存精确输入字节，不随之后的树编辑变化。
	original []byte
}

// decimalNumber restricts floating-point input to the YAML-friendly decimal grammar.
// decimalNumber 将浮点输入限制为适用于 YAML 的十进制语法。
var decimalNumber = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

// Parse validates one mapping-root YAML document and retains its source for advanced editing.
// Parse 校验单个映射根 YAML 文档，并保留原文供高级编辑使用。
func Parse(data []byte) (*Draft, error) {
	root, err := parseSingleDocument(data)
	if err != nil {
		return nil, err
	}
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: root must be a mapping", ErrInvalidDocument)
	}
	if err := validateDocument(root); err != nil {
		return nil, err
	}
	return &Draft{root: root, original: bytes.Clone(data)}, nil
}

// Original returns a defensive copy of the exact source bytes used to create the draft.
// Original 返回创建草稿时使用的原始字节副本，调用方无法修改内部状态。
func (d *Draft) Original() []byte {
	if d == nil {
		return nil
	}
	return bytes.Clone(d.original)
}

// Get reads a scalar at a concrete dotted-key and array-index path.
// Get 按具体点分键名和数组索引路径读取标量。
func (d *Draft) Get(path string) (Scalar, error) {
	if d == nil || d.root == nil {
		return Scalar{}, ErrInvalidDocument
	}
	steps, err := parsePath(path)
	if err != nil {
		return Scalar{}, err
	}
	node, err := locateForRead(d.root.Content[0], steps, path)
	if err != nil {
		return Scalar{}, err
	}
	if node.Kind != yaml.ScalarNode {
		return Scalar{}, fmt.Errorf("%w: %q", ErrNotScalar, path)
	}
	return Scalar{Tag: node.Tag, Value: node.Value}, nil
}

// GetStructured returns the YAML fragment at a concrete object or array path for TUI editing.
// GetStructured 返回具体对象或数组路径的 YAML 片段，供 TUI 编辑。
func (d *Draft) GetStructured(path string, expected StructuredType) (string, error) {
	if d == nil || d.root == nil {
		return "", ErrInvalidDocument
	}
	steps, err := parsePath(path)
	if err != nil {
		return "", err
	}
	node, err := locateForRead(d.root.Content[0], steps, path)
	if err != nil {
		return "", err
	}
	wantKind := yaml.MappingNode
	if expected == StructuredArray {
		wantKind = yaml.SequenceNode
	} else if expected != StructuredObject {
		return "", fmt.Errorf("%w: unsupported structured type %q", ErrInvalidValue, expected)
	}
	if node.Kind != wantKind {
		return "", fmt.Errorf("%w: %q", ErrInvalidDocument, path)
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(node); err != nil {
		return "", fmt.Errorf("render structured field %q: %w", path, err)
	}
	if err := encoder.Close(); err != nil {
		return "", fmt.Errorf("close structured field %q: %w", path, err)
	}
	return strings.TrimSuffix(output.String(), "\n"), nil
}

// ArrayLength returns the number of existing elements at one concrete sequence path.
// ArrayLength 返回一个具体序列路径下现有元素的数量。
func (d *Draft) ArrayLength(path string) (int, error) {
	if d == nil || d.root == nil {
		return 0, ErrInvalidDocument
	}
	steps, err := parsePath(path)
	if err != nil {
		return 0, err
	}
	node, err := locateForRead(d.root.Content[0], steps, path)
	if err != nil {
		return 0, err
	}
	if node.Kind != yaml.SequenceNode {
		return 0, fmt.Errorf("%w: %q is not an array", ErrInvalidDocument, path)
	}
	return len(node.Content), nil
}

// Set validates and writes a scalar using only the explicitly selected scalar type.
// Set 仅按调用方明确选择的标量类型校验并写入值。
func (d *Draft) Set(path string, scalarType ScalarType, value string) error {
	if d == nil || d.root == nil {
		return ErrInvalidDocument
	}
	valueNode, err := makeScalar(scalarType, value)
	if err != nil {
		return fmt.Errorf("%w at %q: %v", ErrInvalidValue, path, err)
	}
	steps, err := parsePath(path)
	if err != nil {
		return err
	}
	location, err := locateForMutation(d.root.Content[0], steps, path)
	if err != nil {
		return err
	}
	if location.slot == nil {
		return appendMissingKeys(location.parent, location.missing, valueNode)
	}
	old := location.slot.parent.Content[location.slot.index]
	if old.Kind == yaml.ScalarNode {
		// In-place updates preserve anchor identity so existing aliases still point at this scalar.
		// 原位更新可保留锚点身份，使已有别名继续指向该标量。
		valueNode.Anchor = old.Anchor
		valueNode.HeadComment = old.HeadComment
		valueNode.LineComment = old.LineComment
		valueNode.FootComment = old.FootComment
		*old = *valueNode
		return nil
	}
	if old.Kind != yaml.AliasNode {
		return fmt.Errorf("%w: %q", ErrNotScalar, path)
	}
	copyComments(valueNode, old)
	location.slot.parent.Content[location.slot.index] = valueNode
	if err := validateDocument(d.root); err != nil {
		location.slot.parent.Content[location.slot.index] = old
		return err
	}
	return nil
}

// SetStructured replaces or creates one object or array from a strict single-document YAML fragment.
// SetStructured 使用严格单文档 YAML 片段替换或创建一个对象或数组。
func (d *Draft) SetStructured(path string, expected StructuredType, yamlBytes []byte) error {
	if d == nil || d.root == nil {
		return ErrInvalidDocument
	}
	replacementDocument, err := parseSingleDocument(yamlBytes)
	if err != nil {
		return err
	}
	if len(replacementDocument.Content) != 1 {
		return fmt.Errorf("%w: structured fragment has no root", ErrInvalidDocument)
	}
	replacement := replacementDocument.Content[0]
	wantKind := yaml.MappingNode
	if expected == StructuredArray {
		wantKind = yaml.SequenceNode
	} else if expected != StructuredObject {
		return fmt.Errorf("%w: unsupported structured type %q", ErrInvalidValue, expected)
	}
	if replacement.Kind != wantKind {
		return fmt.Errorf("%w: expected %s node", ErrInvalidDocument, expected)
	}
	if err := validateDocument(replacementDocument); err != nil {
		return err
	}
	steps, err := parsePath(path)
	if err != nil {
		return err
	}
	location, err := locateForMutation(d.root.Content[0], steps, path)
	if err != nil {
		return err
	}
	if location.slot == nil {
		backups, err := appendMissingKeysWithBackup(location.parent, location.missing, replacement)
		if err != nil {
			return err
		}
		if err := validateDocument(d.root); err != nil {
			restoreContents(backups)
			return err
		}
		return nil
	}
	old := location.slot.parent.Content[location.slot.index]
	if err := inheritReplacementMetadata(replacement, old); err != nil {
		return fmt.Errorf("%w at %q: %v", ErrAnchorConflict, path, err)
	}
	oldValue := *old
	*old = *replacement
	changedAliases := retargetAliases(d.root, replacement, old)
	if err := validateDocument(d.root); err != nil {
		*old = oldValue
		restoreAliasTargets(changedAliases)
		return err
	}
	return nil
}

// Delete removes an existing mapping entry or array element without leaving dangling aliases.
// Delete 删除已有映射项或数组元素，并阻止留下悬空别名。
func (d *Draft) Delete(path string) error {
	if d == nil || d.root == nil {
		return ErrInvalidDocument
	}
	steps, err := parsePath(path)
	if err != nil {
		return err
	}
	location, err := locateForMutation(d.root.Content[0], steps, path)
	if err != nil {
		return err
	}
	if location.slot == nil {
		return fmt.Errorf("%w: %q", ErrNotFound, path)
	}
	parent := location.slot.parent
	oldContent := append([]*yaml.Node(nil), parent.Content...)
	start := location.slot.deleteStart
	width := location.slot.deleteWidth
	parent.Content = append(parent.Content[:start], parent.Content[start+width:]...)
	if err := validateDocument(d.root); err != nil {
		parent.Content = oldContent
		return err
	}
	return nil
}

// Render serializes the current in-memory draft and never writes files or environment data.
// Render 序列化当前内存草稿，不写入文件或环境数据。
func (d *Draft) Render() ([]byte, error) {
	if d == nil || d.root == nil {
		return nil, ErrInvalidDocument
	}
	if err := validateDocument(d.root); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(d.root); err != nil {
		return nil, fmt.Errorf("render YAML draft: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("close YAML encoder: %w", err)
	}
	return output.Bytes(), nil
}

// parseSingleDocument decodes exactly one YAML document and validates its structural invariants.
// parseSingleDocument 解码且仅接受一个 YAML 文档，并校验其结构约束。
func parseSingleDocument(data []byte) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: decode YAML: %v", ErrInvalidDocument, err)
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, fmt.Errorf("%w: expected one non-empty document", ErrInvalidDocument)
	}
	var extra yaml.Node
	err := decoder.Decode(&extra)
	if err == nil && extra.Kind != 0 {
		return nil, ErrMultipleDocuments
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: decode trailing YAML: %v", ErrInvalidDocument, err)
	}
	if err := validateDocument(&document); err != nil {
		return nil, err
	}
	return &document, nil
}

// makeScalar validates one explicit type and constructs its canonical YAML scalar node.
// makeScalar 校验明确指定的类型并构造规范 YAML 标量节点。
func makeScalar(scalarType ScalarType, value string) (*yaml.Node, error) {
	node := &yaml.Node{Kind: yaml.ScalarNode}
	switch scalarType {
	case ScalarString:
		node.Tag = "!!str"
		node.Value = value
		node.Style = yaml.DoubleQuotedStyle
	case ScalarBool:
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return nil, err
		}
		node.Tag = "!!bool"
		node.Value = strconv.FormatBool(parsed)
	case ScalarInt:
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil, err
		}
		node.Tag = "!!int"
		node.Value = strconv.FormatInt(parsed, 10)
	case ScalarNumber:
		if !decimalNumber.MatchString(value) {
			return nil, errors.New("expected a decimal number")
		}
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil || math.IsInf(parsed, 0) || math.IsNaN(parsed) {
			return nil, errors.New("expected a finite decimal number")
		}
		node.Tag = "!!float"
		node.Value = strconv.FormatFloat(parsed, 'g', -1, 64)
	case ScalarDuration:
		if _, err := time.ParseDuration(value); err != nil {
			return nil, err
		}
		node.Tag = "!!str"
		node.Value = value
		node.Style = yaml.DoubleQuotedStyle
	default:
		return nil, fmt.Errorf("unsupported scalar type %q", scalarType)
	}
	return node, nil
}

// locateForRead follows aliases only for observation and resolves a concrete path.
// locateForRead 仅在只读查询中跟随别名，并解析具体路径。
func locateForRead(root *yaml.Node, steps []pathStep, path string) (*yaml.Node, error) {
	current := root
	for _, step := range steps {
		var err error
		current, err = dereference(current)
		if err != nil {
			return nil, fmt.Errorf("%w at %q: %v", ErrInvalidDocument, path, err)
		}
		if step.isIndex {
			if current.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("%w: expected array at %q", ErrNotFound, path)
			}
			if step.index < 0 || step.index >= len(current.Content) {
				return nil, fmt.Errorf("%w: %q", ErrOutOfRange, path)
			}
			current = current.Content[step.index]
			continue
		}
		if current.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%w: expected mapping at %q", ErrNotFound, path)
		}
		_, value, ok := findMapEntry(current, step.key)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrNotFound, path)
		}
		current = value
	}
	return dereference(current)
}

// dereference follows an alias chain while detecting malformed cycles.
// dereference 跟随别名链，并检测无效循环。
func dereference(node *yaml.Node) (*yaml.Node, error) {
	visited := make(map[*yaml.Node]struct{})
	for node != nil && node.Kind == yaml.AliasNode {
		if _, ok := visited[node]; ok {
			return nil, errors.New("alias cycle")
		}
		visited[node] = struct{}{}
		if node.Alias == nil {
			return nil, errors.New("alias has no target")
		}
		node = node.Alias
	}
	if node == nil {
		return nil, errors.New("nil YAML node")
	}
	return node, nil
}

// copyComments carries comments from a replaced node when the replacement has none.
// copyComments 在替换节点未提供注释时沿用旧节点注释。
func copyComments(destination, source *yaml.Node) {
	if destination.HeadComment == "" {
		destination.HeadComment = source.HeadComment
	}
	if destination.LineComment == "" {
		destination.LineComment = source.LineComment
	}
	if destination.FootComment == "" {
		destination.FootComment = source.FootComment
	}
}

// inheritReplacementMetadata keeps an existing node's anchor and comments through structured replacement.
// inheritReplacementMetadata 在结构化替换时保留旧节点的锚点和注释。
func inheritReplacementMetadata(replacement, old *yaml.Node) error {
	if old.Anchor != "" && replacement.Anchor != "" && replacement.Anchor != old.Anchor {
		return fmt.Errorf("old anchor %q cannot be replaced by %q", old.Anchor, replacement.Anchor)
	}
	if old.Anchor != "" {
		replacement.Anchor = old.Anchor
	}
	copyComments(replacement, old)
	return nil
}

// aliasChange stores one alias target update so a rejected edit can be rolled back.
// aliasChange 保存一次别名目标更新，以便拒绝编辑后回滚。
type aliasChange struct {
	// node is the alias node whose target was temporarily changed.
	// node 是目标指针被临时修改的别名节点。
	node *yaml.Node
	// old is the alias target that must be restored after a rejected edit.
	// old 是编辑被拒绝后必须恢复的原别名目标。
	old *yaml.Node
}

// retargetAliases reconnects fragment self-aliases to the stable destination node identity.
// retargetAliases 将片段内指向自身的别名重新连接到稳定的目标节点身份。
func retargetAliases(root, source, destination *yaml.Node) []aliasChange {
	var changes []aliasChange
	var visit func(*yaml.Node)
	visit = func(node *yaml.Node) {
		if node == nil {
			return
		}
		if node.Kind == yaml.AliasNode {
			if node.Alias == source {
				changes = append(changes, aliasChange{node: node, old: node.Alias})
				node.Alias = destination
			}
			return
		}
		for _, child := range node.Content {
			visit(child)
		}
	}
	visit(root)
	return changes
}

// restoreAliasTargets rolls back alias pointer changes after a rejected replacement.
// restoreAliasTargets 在替换失败时回滚别名指针变更。
func restoreAliasTargets(changes []aliasChange) {
	for _, change := range changes {
		change.node.Alias = change.old
	}
}

// validateDocument rejects duplicate mapping keys, duplicate anchors, and dangling aliases.
// validateDocument 拒绝重复映射键、重复锚点和悬空别名。
func validateDocument(document *yaml.Node) error {
	if document == nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return fmt.Errorf("%w: expected one document root", ErrInvalidDocument)
	}
	reachable := make(map[*yaml.Node]struct{})
	anchors := make(map[string]*yaml.Node)
	var aliases []*yaml.Node
	var visit func(*yaml.Node) error
	visit = func(node *yaml.Node) error {
		if node == nil {
			return fmt.Errorf("%w: nil node", ErrInvalidDocument)
		}
		if _, ok := reachable[node]; ok {
			return nil
		}
		reachable[node] = struct{}{}
		if node.Anchor != "" {
			if existing, ok := anchors[node.Anchor]; ok && existing != node {
				return fmt.Errorf("%w: duplicate anchor %q", ErrInvalidDocument, node.Anchor)
			}
			anchors[node.Anchor] = node
		}
		if node.Kind == yaml.AliasNode {
			aliases = append(aliases, node)
			if node.Alias == nil {
				return fmt.Errorf("%w: alias has no target", ErrInvalidDocument)
			}
			return nil
		}
		if node.Kind == yaml.MappingNode {
			if len(node.Content)%2 != 0 {
				return fmt.Errorf("%w: mapping has an unmatched key", ErrInvalidDocument)
			}
			seen := make(map[string]struct{}, len(node.Content)/2)
			for index := 0; index < len(node.Content); index += 2 {
				fingerprint, err := nodeFingerprint(node.Content[index], make(map[*yaml.Node]bool))
				if err != nil {
					return fmt.Errorf("%w: invalid mapping key: %v", ErrInvalidDocument, err)
				}
				if _, exists := seen[fingerprint]; exists {
					return fmt.Errorf("%w: %q", ErrDuplicateKey, node.Content[index].Value)
				}
				seen[fingerprint] = struct{}{}
			}
		}
		for _, child := range node.Content {
			if err := visit(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(document); err != nil {
		return err
	}
	for _, alias := range aliases {
		if _, ok := reachable[alias.Alias]; !ok || alias.Alias.Anchor == "" {
			return fmt.Errorf("%w: %q", ErrAliasReference, alias.Value)
		}
	}
	return nil
}

// nodeFingerprint creates a stable structural identity for a YAML mapping key.
// nodeFingerprint 为 YAML 映射键生成稳定的结构身份。
func nodeFingerprint(node *yaml.Node, active map[*yaml.Node]bool) (string, error) {
	if node == nil {
		return "", errors.New("nil mapping key")
	}
	if active[node] {
		return "", errors.New("cyclic mapping key")
	}
	active[node] = true
	defer delete(active, node)
	if node.Kind == yaml.AliasNode {
		return nodeFingerprint(node.Alias, active)
	}
	if node.Kind == yaml.ScalarNode {
		return "S" + strconv.Itoa(len(node.Tag)) + ":" + node.Tag + strconv.Itoa(len(node.Value)) + ":" + node.Value, nil
	}
	children := make([]string, 0, len(node.Content))
	for _, child := range node.Content {
		fingerprint, err := nodeFingerprint(child, active)
		if err != nil {
			return "", err
		}
		children = append(children, fingerprint)
	}
	if node.Kind == yaml.MappingNode {
		pairs := make([]string, 0, len(children)/2)
		for index := 0; index+1 < len(children); index += 2 {
			pairs = append(pairs, children[index]+"="+children[index+1])
		}
		sort.Strings(pairs)
		children = pairs
	}
	return fmt.Sprintf("N%d:%s[%s]", node.Kind, node.Tag, strings.Join(children, ",")), nil
}
