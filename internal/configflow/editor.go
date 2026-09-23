// Package configflow applies schema-checked user choices to a preserved VMM YAML override.
// configflow 包将经过模式清单检查的用户选择写入保留原貌的 VMM YAML 覆盖层。
// It belongs to the manager application layer and requires VMM to validate the rendered draft.
// 它属于管理器应用层，渲染后的草稿仍必须交给 VMM 做最终校验。
package configflow

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configedit"
)

// StorageChoice is one user-facing database choice mapped to the VMM storage contract.
// StorageChoice 是映射到 VMM 存储契约的一种面向用户的数据库选择。
type StorageChoice string

const (
	// StorageNative selects local native SQLite and LanceDB adapters.
	// StorageNative 选择本地原生 SQLite 与 LanceDB 适配器。
	StorageNative StorageChoice = "native"
	// StorageSplit selects the local VLDB FFI SQLite and LanceDB adapters.
	// StorageSplit 选择本地 VLDB FFI SQLite 与 LanceDB 适配器。
	StorageSplit StorageChoice = "split"
	// StorageController selects the VLDB controller over local SQLite and LanceDB.
	// StorageController 选择使用本地 SQLite 与 LanceDB 的 VLDB 控制器。
	StorageController StorageChoice = "controller"
	// StoragePostgres selects standard PostgreSQL combined storage.
	// StoragePostgres 选择标准 PostgreSQL 组合存储。
	StoragePostgres StorageChoice = "postgres"
	// StorageParadeDB selects ParadeDB combined storage and BM25 search.
	// StorageParadeDB 选择 ParadeDB 组合存储和 BM25 检索。
	StorageParadeDB StorageChoice = "paradedb"
)

// StorageOptions contains only fields that differ among the five storage choices.
// StorageOptions 只包含五种存储选择之间有差异的配置字段。
type StorageOptions struct {
	// Choice selects one of the five user-facing storage forms.
	// Choice 选择五种面向用户的存储形式之一。
	Choice StorageChoice
	// LocalDataRoot stores split/controller databases outside the program files.
	// LocalDataRoot 将 split/controller 数据库存放在程序文件之外。
	LocalDataRoot string
	// NativeSQLitePath is the SQLite database file used only in native mode.
	// NativeSQLitePath 是仅在 native 模式使用的 SQLite 数据库文件。
	NativeSQLitePath string
	// NativeLanceDBPath is the LanceDB directory used only in native mode.
	// NativeLanceDBPath 是仅在 native 模式使用的 LanceDB 目录。
	NativeLanceDBPath string
	// PostgresDSNVariable names the credential variable used by combined storage.
	// PostgresDSNVariable 命名组合存储所用的凭据环境变量。
	PostgresDSNVariable string
}

// Editor keeps the schema inventory separate from the round-trip YAML document.
// Editor 将模式字段清单与可往返编辑的 YAML 文档分离保存。
type Editor struct {
	// draft retains the user's YAML nodes, comments, order, and aliases.
	// draft 保留用户 YAML 节点、注释、顺序和别名。
	draft *configedit.Draft
	// fields is the runtime-owned path inventory for the selected VMM version.
	// fields 是所选 VMM 版本拥有的运行时字段路径清单。
	fields map[string]configbridge.Field
}

// concreteIndex replaces array indexes only when the caller provided a concrete path.
// concreteIndex 仅在调用方提供具体路径时将数组索引归一成模式路径。
var concreteIndex = regexp.MustCompile(`\[[0-9]+\]`)

// envName permits the variable spelling accepted by the manager's credential writer.
// envName 限定管理器凭据写入器接受的环境变量名称格式。
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// New parses a user override and indexes the authoritative fields exported by the selected VMM binary.
// New 解析用户覆盖文件，并索引所选 VMM 可执行文件导出的权威配置字段。
func New(schema configbridge.Schema, yamlBytes []byte) (*Editor, error) {
	if schema.Version != "v1" || schema.ConfigType != "Config" || len(schema.Fields) == 0 {
		return nil, errors.New("unsupported or empty VMM configuration schema")
	}
	if len(strings.TrimSpace(string(yamlBytes))) == 0 {
		yamlBytes = []byte("{}\n")
	}
	draft, err := configedit.Parse(yamlBytes)
	if err != nil {
		// Parser diagnostics can contain secret-bearing source fragments; expose only the failure stage.
		// 解析器诊断可能包含带密钥的源码片段，因此只暴露失败阶段。
		return nil, errors.New("user configuration YAML could not be parsed")
	}
	fields := make(map[string]configbridge.Field, len(schema.Fields))
	for _, field := range schema.Fields {
		if field.Path == "" || field.Type == "" {
			return nil, errors.New("VMM configuration schema contains an incomplete field")
		}
		if _, exists := fields[field.Path]; exists {
			return nil, errors.New("VMM configuration schema contains a duplicate field")
		}
		fields[field.Path] = field
	}
	return &Editor{draft: draft, fields: fields}, nil
}

// Fields returns a detached, sorted field inventory for advanced configuration navigation.
// Fields 返回独立副本并排序的字段清单，供高级配置界面导航。
func (e *Editor) Fields() []configbridge.Field {
	if e == nil {
		return nil
	}
	fields := make([]configbridge.Field, 0, len(e.fields))
	for _, field := range e.fields {
		field.Enum = slices.Clone(field.Enum)
		field.Default = slices.Clone(field.Default)
		fields = append(fields, field)
	}
	slices.SortFunc(fields, func(a, b configbridge.Field) int { return strings.Compare(a.Path, b.Path) })
	return fields
}

// SetScalar writes a single known VMM field using the exact schema scalar type and enum.
// SetScalar 按模式声明的精确标量类型与枚举写入一个已知 VMM 字段。
func (e *Editor) SetScalar(path, value string) error {
	field, err := e.field(path)
	if err != nil {
		return err
	}
	if len(field.Enum) != 0 && !slices.Contains(field.Enum, value) {
		return fmt.Errorf("configuration field %q rejects the selected enum value", path)
	}
	var scalarType configedit.ScalarType
	switch field.Type {
	case "string":
		scalarType = configedit.ScalarString
	case "boolean":
		scalarType = configedit.ScalarBool
	case "integer":
		scalarType = configedit.ScalarInt
	case "number":
		scalarType = configedit.ScalarNumber
	case "duration":
		scalarType = configedit.ScalarDuration
	default:
		return fmt.Errorf("configuration field %q requires structured editing", path)
	}
	if err := e.draft.Set(path, scalarType, value); err != nil {
		// Keep user input out of errors that may reach logs or the TUI.
		// 避免用户输入进入日志或终端界面可能显示的错误。
		return fmt.Errorf("configuration field %q could not be changed", path)
	}
	return nil
}

// SetStructured replaces one known mapping or array without discarding unrelated YAML nodes.
// SetStructured 替换一个已知映射或数组，同时保留无关 YAML 节点。
func (e *Editor) SetStructured(path string, yamlBytes []byte) error {
	field, err := e.field(path)
	if err != nil {
		return err
	}
	var expected configedit.StructuredType
	switch field.Type {
	case "object", "map":
		expected = configedit.StructuredObject
	case "array":
		expected = configedit.StructuredArray
	default:
		return fmt.Errorf("configuration field %q is not a structured value", path)
	}
	if err := e.draft.SetStructured(path, expected, yamlBytes); err != nil {
		// Structured YAML may include provider credentials, even when the wizard normally uses references.
		// 结构化 YAML 可能包含供应商凭据，即使向导通常使用变量引用。
		return fmt.Errorf("structured configuration field %q could not be changed", path)
	}
	return nil
}

// Delete removes a known override so the lower VMM configuration layer can take effect.
// Delete 删除已知覆盖项，使 VMM 下层配置重新生效。
func (e *Editor) Delete(path string) error {
	if _, err := e.field(path); err != nil {
		return err
	}
	return e.draft.Delete(path)
}

// Render returns the complete YAML draft; the caller must validate it with VMM before saving.
// Render 返回完整 YAML 草稿；调用方必须先用 VMM 校验再保存。
func (e *Editor) Render() ([]byte, error) {
	if e == nil || e.draft == nil {
		return nil, errors.New("configuration editor is unavailable")
	}
	return e.draft.Render()
}

// ApplyStorage maps a user choice to VMM's authoritative mode, flavor, and address fields.
// ApplyStorage 将用户选择映射到 VMM 权威的模式、风味和地址字段。
func (e *Editor) ApplyStorage(options StorageOptions) error {
	if e == nil {
		return errors.New("configuration editor is unavailable")
	}
	// Validate and apply all related fields on a detached draft so one bad field cannot leave a partial mode switch.
	// 在独立草稿上校验并应用所有相关字段，避免单个错误字段留下部分生效的模式切换。
	current, err := e.Render()
	if err != nil {
		return err
	}
	draft, err := configedit.Parse(current)
	if err != nil {
		return err
	}
	candidate := &Editor{draft: draft, fields: e.fields}
	if err := candidate.applyStorage(options); err != nil {
		return err
	}
	e.draft = candidate.draft
	return nil
}

// applyStorage writes the selected VMM fields on an isolated candidate document.
// applyStorage 在隔离的候选文档中写入所选 VMM 配置字段。
func (e *Editor) applyStorage(options StorageOptions) error {
	// Keep the common mode selection explicit, then write only paths meaningful to that mode.
	// 先明确设置通用模式，再只写入该模式真正生效的地址字段。
	switch options.Choice {
	case StorageNative:
		if options.NativeSQLitePath == "" || options.NativeLanceDBPath == "" {
			return errors.New("native SQLite file and LanceDB directory must be selected")
		}
		if err := e.SetScalar("storage.mode", "native"); err != nil {
			return err
		}
		if err := e.SetScalar("sqlite.native.path", options.NativeSQLitePath); err != nil {
			return err
		}
		return e.SetScalar("lancedb.native.path", options.NativeLanceDBPath)
	case StorageSplit, StorageController:
		if options.LocalDataRoot == "" {
			return errors.New("local data root must be selected")
		}
		if err := e.SetScalar("storage.mode", string(options.Choice)); err != nil {
			return err
		}
		return e.SetScalar("storage.local_data_root", options.LocalDataRoot)
	case StoragePostgres, StorageParadeDB:
		if !envName.MatchString(options.PostgresDSNVariable) {
			return errors.New("PostgreSQL DSN environment variable name is invalid")
		}
		if err := e.SetScalar("storage.mode", "combined"); err != nil {
			return err
		}
		if err := e.SetScalar("storage.combined_provider", "postgres"); err != nil {
			return err
		}
		flavor := "standard"
		if options.Choice == StorageParadeDB {
			flavor = "paradedb"
		}
		if err := e.SetScalar("postgres.flavor", flavor); err != nil {
			return err
		}
		return e.SetScalar("postgres.dsn", "${"+options.PostgresDSNVariable+"}")
	default:
		return errors.New("unsupported storage choice")
	}
}

// field resolves only paths declared by the VMM schema, including concrete array indexes.
// field 仅解析 VMM 模式已声明的路径，包括具有具体索引的数组字段。
func (e *Editor) field(path string) (configbridge.Field, error) {
	if e == nil || e.draft == nil {
		return configbridge.Field{}, errors.New("configuration editor is unavailable")
	}
	if strings.TrimSpace(path) != path || path == "" {
		return configbridge.Field{}, errors.New("configuration path is invalid")
	}
	field, ok := e.fields[concreteIndex.ReplaceAllString(path, "[]")]
	if !ok {
		return configbridge.Field{}, fmt.Errorf("configuration field %q is absent from this VMM schema", path)
	}
	return field, nil
}
