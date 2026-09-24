// Package credentials manages the value-bearing .env file used beside a VMM configuration.
// credentials 包负责管理 VMM 配置旁边的、包含密钥值的 .env 文件。
//
// The package deliberately accepts a small, documented dotenv subset and writes only
// quoted values. This keeps the manager independent from godotenv while matching the
// syntax that VMM uses for environment references.
// 本包刻意采用一个有明确边界的 dotenv 子集，并始终写入带引号的值；这样管理器不
// 引入 godotenv，同时保持与 VMM 环境引用所使用语法的一致性。
package credentials

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// maxDocumentBytes bounds parsing work for a user-controlled dotenv file.
	// maxDocumentBytes 限制用户可控制的 dotenv 文件解析规模。
	maxDocumentBytes int64 = 1 << 20

	// defaultNewline is used when a new file has no existing line-ending style.
	// defaultNewline 用于没有现有换行风格的新文件。
	defaultNewline = "\n"
)

var (
	// ErrInvalidPath reports a path that is not an absolute .env file path.
	// ErrInvalidPath 表示路径不是绝对的 .env 文件路径。
	ErrInvalidPath = errors.New("credentials path must be an absolute .env file")

	// ErrDuplicateName reports duplicate environment names, including case variants.
	// ErrDuplicateName 表示环境变量名称重复，包括仅大小写不同的变体。
	ErrDuplicateName = errors.New("dotenv contains duplicate environment names")

	// ErrInvalidSyntax reports syntax outside the supported dotenv subset.
	// ErrInvalidSyntax 表示语法超出支持的 dotenv 子集。
	ErrInvalidSyntax = errors.New("dotenv contains unsupported syntax")

	// ErrInvalidName reports an environment name that cannot be used portably.
	// ErrInvalidName 表示不能跨平台使用的环境变量名称。
	ErrInvalidName = errors.New("environment name is invalid")

	// ErrInvalidValue reports a value that could inject a new dotenv line.
	// ErrInvalidValue 表示可能注入新的 dotenv 行的值。
	ErrInvalidValue = errors.New("environment value contains unsupported control characters")

	// ErrOwnerUnsupported reports that target Unix ownership is unavailable on this platform.
	// ErrOwnerUnsupported 表示当前平台不支持目标 Unix 所有权设置。
	ErrOwnerUnsupported = errors.New("target Unix credential ownership is unsupported on this platform")

	// ErrOwnerConflict reports an unsafe existing owner, directory, or permission boundary.
	// ErrOwnerConflict 表示现有所有者、目录或权限边界不安全。
	ErrOwnerConflict = errors.New("credential owner or permission boundary is unsafe")
)

// Owner identifies the exact Unix UID and GID that must own a protected .env file.
// Owner 标识受保护 .env 文件必须使用的 Unix UID 和 GID。
//
// The manager passes numeric identities after resolving the selected local service
// account. The credentials package never accepts a shell account string for chown.
// 管理器在解析本机服务账户后传入数字身份；凭据包不会接受用于 chown 的 shell 账户字符串。
type Owner struct {
	// UID is the target Unix user identifier.
	// UID 是目标 Unix 用户标识符。
	UID uint32

	// GID is the target Unix group identifier.
	// GID 是目标 Unix 组标识符。
	GID uint32
}

// Action identifies the secret-file operation shown by a dry-run plan.
// Action 标识 dry-run 计划中展示的密钥文件操作。
type Action string

const (
	// ActionSet means an environment value will be created or replaced.
	// ActionSet 表示创建或替换环境变量值。
	ActionSet Action = "set"

	// ActionDelete means an environment value will be removed.
	// ActionDelete 表示删除环境变量值。
	ActionDelete Action = "delete"
)

// ChangeSummary is a value-free description of one requested update.
// ChangeSummary 是一项请求更新的无值描述，不包含密钥明文。
type ChangeSummary struct {
	// Name is the environment variable name affected by the operation.
	// Name 是本次操作影响的环境变量名称。
	Name string

	// Action identifies whether the name is set or deleted.
	// Action 标识该名称将被设置还是删除。
	Action Action
}

// Plan is the value-free result returned by dry-run and apply operations.
// Plan 是 dry-run 和实际应用操作返回的无值结果。
type Plan struct {
	// Path is the validated .env path used by the operation.
	// Path 是本次操作使用并已校验的 .env 路径。
	Path string

	// Changes contains stable, name-only operation descriptions.
	// Changes 包含稳定排序且仅含名称的操作描述。
	Changes []ChangeSummary
}

// Document is a parsed dotenv document that preserves comments, order, and untouched lines.
// Document 是保留注释、顺序和未修改行的 dotenv 文档。
type Document struct {
	lines    []documentLine
	newline  string
	original []byte
}

// documentLine stores one line without exposing any secret value through errors or plans.
// documentLine 保存一行内容，避免通过错误或计划暴露密钥值。
type documentLine struct {
	text          string
	ending        string
	kind          lineKind
	name          string
	value         string
	prefix        string
	commentSuffix string
	modified      bool
}

// lineKind identifies the supported line categories.
// lineKind 标识支持的行类型。
type lineKind uint8

const (
	lineBlank lineKind = iota
	lineComment
	lineAssignment
)

// Load reads and strictly parses one absolute .env path.
// Load 读取并严格解析一个绝对路径的 .env 文件。
//
// A missing file is represented as an empty document so the first credential can
// be written atomically by Apply. Symlinks are rejected before reading.
// 缺少文件时返回空文档，以便 Apply 原子地写入第一项凭据；读取前会拒绝符号链接。
func Load(path string) (*Document, error) {
	data, _, _, err := ReadSnapshot(path)
	if err != nil {
		return nil, err
	}
	document, err := Parse(data)
	if err != nil {
		return nil, err
	}
	document.original = append([]byte(nil), data...)
	return document, nil
}

// Restore atomically restores a captured dotenv document with protected credential permissions.
// Restore 使用受保护的凭据权限原子恢复已捕获的 dotenv 文档，返回写入或权限错误。
func Restore(path string, data []byte) error {
	if _, err := Parse(data); err != nil {
		return err
	}
	return writeAtomic(path, data)
}

// Parse validates and parses dotenv bytes while retaining the original line layout.
// Parse 校验并解析 dotenv 字节，同时保留原始行布局。
func Parse(data []byte) (*Document, error) {
	if int64(len(data)) > maxDocumentBytes {
		return nil, errors.New("dotenv file is too large")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("dotenv file is not valid UTF-8")
	}
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, ErrInvalidSyntax
	}
	document := &Document{
		newline:  detectNewline(data),
		original: append([]byte(nil), data...),
	}
	document.lines = splitLines(data)
	seen := make(map[string]struct{}, len(document.lines))
	for index := range document.lines {
		ending := document.lines[index].ending
		parsed, err := parseLine(document.lines[index].text)
		if err != nil {
			return nil, fmt.Errorf("dotenv line %d: %w", index+1, err)
		}
		parsed.ending = ending
		document.lines[index] = parsed
		if parsed.kind != lineAssignment {
			continue
		}
		key := canonicalName(parsed.name)
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("dotenv line %d: %w", index+1, ErrDuplicateName)
		}
		seen[key] = struct{}{}
	}
	return document, nil
}

// Names returns assignment names in document order without returning their values.
// Names 按文档顺序返回变量名，但不返回变量值。
func (d *Document) Names() []string {
	if d == nil {
		return nil
	}
	names := make([]string, 0, len(d.lines))
	for _, line := range d.lines {
		if line.kind == lineAssignment {
			names = append(names, line.name)
		}
	}
	return names
}

// Has reports whether the document contains an assignment with the supplied name.
// Has 报告文档是否包含给定名称的赋值。
func (d *Document) Has(name string) bool {
	if err := validateName(name); err != nil || d == nil {
		return false
	}
	for _, line := range d.lines {
		if line.kind == lineAssignment && canonicalName(line.name) == canonicalName(name) {
			return true
		}
	}
	return false
}

// Value returns one decoded value and intentionally exposes it only to the direct caller.
// Value 返回一个已解码的值，仅向直接调用方暴露该值。
func (d *Document) Value(name string) (string, bool, error) {
	if err := validateName(name); err != nil {
		return "", false, err
	}
	if d == nil {
		return "", false, errors.New("dotenv document is nil")
	}
	for _, line := range d.lines {
		if line.kind == lineAssignment && canonicalName(line.name) == canonicalName(name) {
			return line.value, true, nil
		}
	}
	return "", false, nil
}

// Get is the concise alias used by configuration editors when reading one value.
// Get 是配置编辑器读取单项值时使用的简洁别名。
func (d *Document) Get(name string) (string, bool, error) {
	return d.Value(name)
}

// Set changes one value in memory and validates the name and value before mutation.
// Set 在内存中修改一项值，并在变更前校验名称和值。
func (d *Document) Set(name string, value string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if err := validateValue(value); err != nil {
		return err
	}
	if d == nil {
		return errors.New("dotenv document is nil")
	}
	key := canonicalName(name)
	for index := range d.lines {
		line := &d.lines[index]
		if line.kind != lineAssignment || canonicalName(line.name) != key {
			continue
		}
		if line.value == value {
			return nil
		}
		line.value = value
		line.text = line.prefix + line.name + "=" + encodeValue(value) + line.commentSuffix
		line.modified = true
		return nil
	}
	if len(d.lines) > 0 && d.lines[len(d.lines)-1].ending == "" {
		d.lines[len(d.lines)-1].ending = d.newline
	}
	d.lines = append(d.lines, documentLine{
		text:     name + "=" + encodeValue(value),
		ending:   d.newline,
		kind:     lineAssignment,
		name:     name,
		value:    value,
		modified: true,
	})
	return nil
}

// Delete removes one assignment while preserving an inline comment as a comment line.
// Delete 删除一项赋值，并把行尾内联注释保留为注释行。
func (d *Document) Delete(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if d == nil {
		return errors.New("dotenv document is nil")
	}
	key := canonicalName(name)
	for index := range d.lines {
		line := d.lines[index]
		if line.kind != lineAssignment || canonicalName(line.name) != key {
			continue
		}
		if comment := strings.TrimLeft(line.commentSuffix, " \t"); comment != "" {
			d.lines[index] = documentLine{text: comment, ending: line.ending, kind: lineComment}
		} else {
			d.lines = append(d.lines[:index], d.lines[index+1:]...)
		}
		return nil
	}
	return nil
}

// Render serializes the document without writing the filesystem.
// Render 序列化文档但不写入文件系统。
func (d *Document) Render() []byte {
	if d == nil {
		return nil
	}
	var buffer bytes.Buffer
	for _, line := range d.lines {
		buffer.WriteString(line.text)
		buffer.WriteString(line.ending)
	}
	return buffer.Bytes()
}

// DryRun validates changes and returns only affected variable names.
// DryRun 校验变更并只返回受影响的变量名。
func DryRun(path string, values map[string]string, deletes []string) (Plan, error) {
	return prepare(path, values, deletes, false, nil)
}

// Apply atomically writes validated changes and returns a value-free operation plan.
// Apply 原子写入已校验的变更，并返回不包含值的操作计划。
func Apply(path string, values map[string]string, deletes []string) (Plan, error) {
	return prepare(path, values, deletes, true, nil)
}

// DryRunAs validates a credential update against an explicit Unix service owner without writing.
// DryRunAs 使用明确的 Unix 服务账户所有者校验凭据变更，但不写入文件。
func DryRunAs(path string, values map[string]string, deletes []string, owner Owner) (Plan, error) {
	return prepare(path, values, deletes, false, &owner)
}

// ApplyAs atomically writes credentials owned by the explicit Unix service account.
// ApplyAs 原子写入由明确 Unix 服务账户拥有的凭据。
//
// On Unix, the target file is validated before it is read, the existing directory
// boundary is checked, and the temporary file is fchown'ed and chmod'ed before any
// secret byte is written. On Windows this operation fails closed; Apply keeps its
// existing Windows ACL behavior.
// 在 Unix 上，目标文件会在读取前校验，现有目录边界会被检查，临时文件会在写入任何
// 密钥字节前执行 fchown 和 chmod。Windows 上该操作明确失败；Apply 保持原有 Windows ACL 行为。
func ApplyAs(path string, values map[string]string, deletes []string, owner Owner) (Plan, error) {
	return prepare(path, values, deletes, true, &owner)
}

// CheckOwner validates a service-owned .env path before a separate read operation.
// CheckOwner 在单独读取凭据之前校验服务账户持有的 .env 路径。
func CheckOwner(path string, owner Owner) error {
	return validateOwnerTarget(path, owner)
}

// RestoreAs atomically restores exact pre-transaction bytes under the same service owner.
// RestoreAs 在相同服务所有者下原子恢复事务前的原始字节。
func RestoreAs(path string, data []byte, owner Owner) error {
	if err := validateOwnerTarget(path, owner); err != nil {
		return err
	}
	return writeAtomicForOwner(path, data, &owner)
}

// prepare validates and applies in-memory changes, optionally replacing the file atomically.
// prepare 校验并应用内存变更，并按需原子替换文件。
func prepare(path string, values map[string]string, deletes []string, write bool, owner *Owner) (Plan, error) {
	if err := validatePath(path); err != nil {
		return Plan{}, err
	}
	if owner != nil {
		if err := validateOwnerTarget(path, *owner); err != nil {
			return Plan{}, err
		}
	}
	document, err := Load(path)
	if err != nil {
		return Plan{}, err
	}
	changes, err := normalizeChanges(values, deletes)
	if err != nil {
		return Plan{}, err
	}
	for _, change := range changes {
		if change.Action == ActionSet {
			if err := document.Set(change.Name, values[change.Name]); err != nil {
				return Plan{}, err
			}
			continue
		}
		if err := document.Delete(change.Name); err != nil {
			return Plan{}, err
		}
	}
	plan := Plan{Path: path, Changes: append([]ChangeSummary(nil), changes...)}
	if !write || len(changes) == 0 {
		return plan, nil
	}
	if owner != nil {
		// Recheck the ownership boundary after parsing and immediately before replacement.
		// 解析后、替换前再次检查所有权边界，缩短检查与写入之间的窗口。
		if err := validateOwnerTarget(path, *owner); err != nil {
			return Plan{}, err
		}
	}
	if err := writeAtomicForOwner(path, document.Render(), owner); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// normalizeChanges validates all names and returns deterministic, value-free summaries.
// normalizeChanges 校验全部名称，并返回确定排序且不含值的摘要。
func normalizeChanges(values map[string]string, deletes []string) ([]ChangeSummary, error) {
	seen := make(map[string]ChangeSummary, len(values)+len(deletes))
	for rawName := range values {
		if err := validateName(rawName); err != nil {
			return nil, err
		}
		if err := validateValue(values[rawName]); err != nil {
			return nil, err
		}
		key := canonicalName(rawName)
		if _, exists := seen[key]; exists {
			return nil, ErrDuplicateName
		}
		seen[key] = ChangeSummary{Name: rawName, Action: ActionSet}
	}
	for _, rawName := range deletes {
		if err := validateName(rawName); err != nil {
			return nil, err
		}
		key := canonicalName(rawName)
		if _, exists := seen[key]; exists {
			return nil, ErrDuplicateName
		}
		seen[key] = ChangeSummary{Name: rawName, Action: ActionDelete}
	}
	changes := make([]ChangeSummary, 0, len(seen))
	for _, change := range seen {
		changes = append(changes, change)
	}
	sort.Slice(changes, func(left, right int) bool {
		return canonicalName(changes[left].Name) < canonicalName(changes[right].Name)
	})
	return changes, nil
}

// parseLine parses the supported dotenv syntax without copying raw values into errors.
// parseLine 解析支持的 dotenv 语法，并避免把原始值复制进错误信息。
func parseLine(text string) (documentLine, error) {
	for _, char := range text {
		if char == '\r' || char == 0 || (unicode.IsControl(char) && char != '\t') || char == '\u2028' || char == '\u2029' {
			return documentLine{}, ErrInvalidSyntax
		}
	}
	line := documentLine{text: text, kind: lineBlank}
	leading := len(text) - len(strings.TrimLeft(text, " \t"))
	trimmed := text[leading:]
	if trimmed == "" {
		return line, nil
	}
	if strings.HasPrefix(trimmed, "#") {
		line.kind = lineComment
		return line, nil
	}
	prefix := text[:leading]
	rest := trimmed
	if strings.HasPrefix(rest, "export") && len(rest) > len("export") && isHorizontalSpace(rest[len("export")]) {
		index := len("export")
		for index < len(rest) && isHorizontalSpace(rest[index]) {
			index++
		}
		prefix += rest[:index]
		rest = rest[index:]
	}
	equal := strings.IndexByte(rest, '=')
	if equal < 0 {
		return documentLine{}, ErrInvalidSyntax
	}
	left := strings.TrimRight(rest[:equal], " \t")
	if err := validateName(left); err != nil {
		return documentLine{}, ErrInvalidSyntax
	}
	value, suffix, err := parseValue(rest[equal+1:])
	if err != nil {
		return documentLine{}, err
	}
	return documentLine{
		text:          text,
		kind:          lineAssignment,
		name:          left,
		value:         value,
		prefix:        prefix,
		commentSuffix: suffix,
	}, nil
}

// parseValue decodes unquoted, single-quoted, and double-quoted dotenv values.
// parseValue 解码无引号、单引号和双引号 dotenv 值。
func parseValue(input string) (string, string, error) {
	start := 0
	for start < len(input) && isHorizontalSpace(input[start]) {
		start++
	}
	if start == len(input) {
		return "", "", nil
	}
	switch input[start] {
	case '\'':
		for index := start + 1; index < len(input); index++ {
			if input[index] != '\'' {
				continue
			}
			// godotenv preserves backslashes in single-quoted values; only the quote
			// terminator is skipped when immediately preceded by a backslash.
			// godotenv 会保留单引号值中的反斜杠；只有反斜杠紧邻时才跳过结束引号。
			value := input[start+1 : index]
			suffix, err := parseQuoteSuffix(input[index+1:])
			return value, suffix, err
		}
		return "", "", ErrInvalidSyntax
	case '"':
		var value strings.Builder
		for index := start + 1; index < len(input); index++ {
			switch input[index] {
			case '"':
				suffix, err := parseQuoteSuffix(input[index+1:])
				return value.String(), suffix, err
			case '\\':
				index++
				if index >= len(input) {
					return "", "", ErrInvalidSyntax
				}
				decoded, ok := decodeEscape(input[index])
				if !ok {
					return "", "", ErrInvalidSyntax
				}
				value.WriteByte(decoded)
			default:
				if input[index] == '\r' || input[index] == '\n' || input[index] == 0 {
					return "", "", ErrInvalidSyntax
				}
				value.WriteByte(input[index])
			}
		}
		return "", "", ErrInvalidSyntax
	default:
		commentStart := -1
		for index := start; index < len(input); index++ {
			if input[index] == '#' && index > start && isHorizontalSpace(input[index-1]) {
				commentStart = index
				break
			}
		}
		valueEnd := len(input)
		suffix := ""
		if commentStart >= 0 {
			suffixStart := commentStart
			for suffixStart > start && isHorizontalSpace(input[suffixStart-1]) {
				suffixStart--
			}
			valueEnd = suffixStart
			suffix = input[suffixStart:]
		}
		value := strings.TrimRight(input[start:valueEnd], " \t")
		if err := validateValue(value); err != nil {
			return "", "", ErrInvalidSyntax
		}
		return value, suffix, nil
	}
}

// parseQuoteSuffix accepts only whitespace or an inline comment after a quoted value.
// parseQuoteSuffix 只接受引号值后的空白或内联注释。
func parseQuoteSuffix(input string) (string, error) {
	if strings.TrimSpace(input) == "" {
		return "", nil
	}
	start := 0
	for start < len(input) && isHorizontalSpace(input[start]) {
		start++
	}
	if start < len(input) && input[start] == '#' {
		return input[:start] + input[start:], nil
	}
	return "", ErrInvalidSyntax
}

// decodeEscape decodes the escape forms accepted by the safe double-quoted subset.
// decodeEscape 解码安全双引号子集中支持的转义形式。
func decodeEscape(value byte) (byte, bool) {
	switch value {
	case 'n':
		return '\n', true
	case 'r':
		return '\r', true
	case 't':
		return '\t', true
	case '\\', '"', '\'', '$', '#':
		return value, true
	default:
		return 0, false
	}
}

// encodeValue quotes a value so dotenv comments and variable expansion cannot alter it.
// encodeValue 将值加引号，使 dotenv 注释和变量展开不能改变它。
func encodeValue(value string) string {
	if !strings.ContainsRune(value, '\'') {
		return "'" + value + "'"
	}
	var doubleQuoted strings.Builder
	doubleQuoted.WriteByte('"')
	for _, char := range value {
		switch char {
		case '\\', '"', '$':
			doubleQuoted.WriteByte('\\')
		}
		doubleQuoted.WriteRune(char)
	}
	doubleQuoted.WriteByte('"')
	return doubleQuoted.String()
}

// splitLines retains each line ending so existing files remain layout-stable.
// splitLines 保留每行换行符，使现有文件布局保持稳定。
func splitLines(data []byte) []documentLine {
	if len(data) == 0 {
		return nil
	}
	lines := make([]documentLine, 0, bytes.Count(data, []byte{'\n'})+1)
	start := 0
	for index, value := range data {
		if value != '\n' {
			continue
		}
		end := index
		ending := "\n"
		if end > start && data[end-1] == '\r' {
			end--
			ending = "\r\n"
		}
		lines = append(lines, documentLine{text: string(data[start:end]), ending: ending})
		start = index + 1
	}
	if start < len(data) {
		lines = append(lines, documentLine{text: string(data[start:])})
	}
	return lines
}

// detectNewline selects the first existing newline style and otherwise uses LF.
// detectNewline 选择现有的第一种换行风格，否则使用 LF。
func detectNewline(data []byte) string {
	if bytes.Contains(data, []byte("\r\n")) {
		return "\r\n"
	}
	return defaultNewline
}

// validatePath rejects ambiguous paths and names other than the adjacent .env file.
// validatePath 拒绝有歧义的路径以及非目标 .env 文件名。
func validatePath(path string) error {
	if path == "" || filepath.Base(path) != ".env" || !filepath.IsAbs(path) {
		return ErrInvalidPath
	}
	for _, char := range path {
		if unicode.IsControl(char) {
			return ErrInvalidPath
		}
	}
	return nil
}

// validateName enforces the portable identifier grammar used by VMM references.
// validateName 强制使用 VMM 引用采用的跨平台标识符语法。
func validateName(name string) error {
	if name == "" || strings.TrimSpace(name) != name {
		return ErrInvalidName
	}
	for index, char := range name {
		if index == 0 {
			if !isASCIIAlpha(char) && char != '_' {
				return ErrInvalidName
			}
			continue
		}
		if !isASCIIAlpha(char) && (char < '0' || char > '9') && char != '_' {
			return ErrInvalidName
		}
	}
	return nil
}

// validateValue rejects NUL and all Unicode control characters, including newlines.
// validateValue 拒绝 NUL 以及包含换行在内的全部 Unicode 控制字符。
func validateValue(value string) error {
	if !utf8.ValidString(value) {
		return ErrInvalidValue
	}
	for _, char := range value {
		if char == 0 || unicode.IsControl(char) || char == '\u2028' || char == '\u2029' {
			return ErrInvalidValue
		}
	}
	return nil
}

// canonicalName normalizes the portable name for cross-platform duplicate detection.
// canonicalName 为跨平台重复检测规范化环境变量名称。
func canonicalName(name string) string {
	return strings.ToUpper(name)
}

// isASCIIAlpha reports whether a rune belongs to the portable ASCII alphabet.
// isASCIIAlpha 报告字符是否属于跨平台 ASCII 字母范围。
func isASCIIAlpha(value rune) bool {
	return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
}

// isHorizontalSpace reports whether a byte is a dotenv horizontal separator.
// isHorizontalSpace 报告字节是否为 dotenv 水平分隔空白。
func isHorizontalSpace(value byte) bool {
	return value == ' ' || value == '\t'
}

// readBounded reads at most maxDocumentBytes plus one byte to detect oversized files.
// readBounded 最多读取 maxDocumentBytes 加一个字节，以检测超大文件。
func readBounded(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxDocumentBytes+1))
	if err != nil {
		return nil, errors.New("could not read dotenv file")
	}
	if int64(len(data)) > maxDocumentBytes {
		return nil, errors.New("dotenv file is too large")
	}
	return data, nil
}
