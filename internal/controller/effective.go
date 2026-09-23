// This file bridges installed and candidate effective-configuration inspection to the authoritative VMM CLI.
// 本文件属于控制器层，将已安装及候选生效配置查看连接到权威 VMM CLI。
package controller

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/install"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// installedEffective refuses incomplete program files before invoking the registered runtime for a saved-config inspection.
// installedEffective 在查看已保存配置前拒绝不完整程序文件，随后调用登记运行时，返回安全错误或发出结果。
func (c *Controller) installedEffective(ctx context.Context, events chan tui.OperationEvent) error {
	installed, err := c.requireState()
	if err != nil {
		return err
	}
	if !installed.InstallationComplete || install.FilesIntact(installed) != "" {
		return errors.New("VMM installation is incomplete")
	}
	binary := filepath.Join(installed.Paths.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
	return c.emitEffective(ctx, binary, installed.Paths.ConfigRoot, false, events)
}

// emitEffective reads the actual selected root and publishes flattened safe values without modifying configuration or starting clients.
// emitEffective 读取实际选定配置根，发出展平后的安全值，不修改配置或启动运行时客户端。
func (c *Controller) emitEffective(ctx context.Context, binary, root string, candidate bool, events chan tui.OperationEvent) error {
	document, err := c.options.Effective(ctx, binary, root)
	if err != nil {
		return errors.New("VMM effective configuration could not be loaded")
	}
	projection := &tui.EffectiveConfiguration{Candidate: candidate}
	for name, raw := range document.Config {
		var value any
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return errors.New("VMM effective configuration is invalid")
		}
		appendEffectiveFields(value, effectivePointer("", name), &projection.Fields)
	}
	for index := range projection.Fields {
		field := &projection.Fields[index]
		source := document.Sources[field.Pointer]
		field.Kind, field.File, field.Normalized = source.Kind, source.File, source.Normalized
		field.Environment = append([]string(nil), source.Environment...)
	}
	sort.Slice(projection.Fields, func(i, j int) bool { return projection.Fields[i].Pointer < projection.Fields[j].Pointer })
	c.emit(events, tui.OperationEvent{Kind: tui.OperationEventProgress, Effective: projection})
	return nil
}

// effectivePointer appends an escaped object key or array index using the runtime's JSON Pointer contract.
// effectivePointer 按运行时 JSON Pointer 契约追加经转义的对象键或数组下标。
func effectivePointer(parent, key string) string {
	return parent + "/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
}

// appendEffectiveFields preserves exact JSON numbers, nulls, and empty containers while flattening redacted values.
// appendEffectiveFields 展平脱敏值时保留精确 JSON 数字、空值及空容器，将叶子写入结果切片。
func appendEffectiveFields(value any, pointer string, fields *[]tui.EffectiveField) {
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) > 0 {
			for key, child := range typed {
				appendEffectiveFields(child, effectivePointer(pointer, key), fields)
			}
			return
		}
	case []any:
		if len(typed) > 0 {
			for index, child := range typed {
				appendEffectiveFields(child, effectivePointer(pointer, strconv.Itoa(index)), fields)
			}
			return
		}
	}
	encoded, _ := json.Marshal(value)
	*fields = append(*fields, tui.EffectiveField{Pointer: pointer, Value: string(encoded)})
}
