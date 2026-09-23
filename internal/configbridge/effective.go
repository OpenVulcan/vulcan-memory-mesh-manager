// effective.go reads authoritative effective configuration through the bounded runtime CLI bridge.
// effective.go 通过有界运行时命令桥读取权威有效配置。
package configbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// EffectiveConfig is the versioned read-only snapshot; Config preserves runtime JSON values without local merging.
// EffectiveConfig 是带版本的只读快照；Config 保留运行时 JSON 值而不在本地合并。
type EffectiveConfig struct {
	Version  string                       `json:"version"`
	Redacted bool                         `json:"redacted"`
	Config   map[string]json.RawMessage   `json:"config"`
	Sources  map[string]ConfigValueSource `json:"sources,omitempty"`
}

// ConfigValueSource describes an authoritative leaf origin without storing environment values.
// ConfigValueSource 描述权威叶子来源，仅保留环境变量名；Normalized 表示输入随后经过归一化调整。
type ConfigValueSource struct {
	Kind        string   `json:"kind"`
	File        string   `json:"file,omitempty"`
	Environment []string `json:"environment,omitempty"`
	Normalized  bool     `json:"normalized,omitempty"`
}

// Effective requests the selected configuration root and returns a validated redacted response or a sanitized error.
// Effective 请求所选配置根，返回经过验证的脱敏结果或不含敏感值的错误。
func (c *Client) Effective(ctx context.Context) (EffectiveConfig, error) {
	output, code, err := c.run(ctx, "show-effective", "config", "show-effective", "--config", c.configRoot, "--json")
	if err != nil {
		return EffectiveConfig{}, err
	}
	if code != 0 {
		return EffectiveConfig{}, fmt.Errorf("VMM effective configuration command exited with code %d", code)
	}
	var result EffectiveConfig
	// Select the exact shape by the declared wire version; full strict decoding still rejects duplicate and unknown fields.
	// 按声明版本选择精确结构；随后严格解码仍拒绝重复键和未知字段。
	var header struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(output, &header); err != nil {
		return EffectiveConfig{}, protocolError("show-effective", err)
	}
	required := map[string]bool{"version": true, "redacted": true, "config": true}
	if header.Version == "v2" {
		required["sources"] = true
	}
	if err := decodeStrictDocument(output, &result, required); err != nil {
		return EffectiveConfig{}, protocolError("show-effective", err)
	}
	if (result.Version != "v1" && result.Version != "v2") || !result.Redacted || len(result.Config) == 0 {
		return EffectiveConfig{}, protocolError("show-effective", errors.New("invalid effective configuration document"))
	}
	if err := validateEffectiveSources(result); err != nil {
		return EffectiveConfig{}, protocolError("show-effective", err)
	}
	return result, nil
}

// validateEffectiveSources requires one valid origin per visible leaf in v2; v1 explicitly has no origins.
// validateEffectiveSources 要求第二版每个可见叶子都有合法来源；第一版明确不提供来源，错误不包含原始字段内容。
func validateEffectiveSources(result EffectiveConfig) error {
	if result.Version == "v1" {
		if result.Sources != nil {
			return errors.New("version one cannot declare sources")
		}
		return nil
	}
	body, err := json.Marshal(result.Config)
	if err != nil {
		return errors.New("effective configuration is invalid")
	}
	var config any
	if err := json.Unmarshal(body, &config); err != nil {
		return errors.New("effective configuration is invalid")
	}
	leaves := map[string]bool{}
	collectEffectiveLeaves(config, "", leaves)
	if len(result.Sources) != len(leaves) {
		return errors.New("effective source coverage is incomplete")
	}
	for pointer, source := range result.Sources {
		if !leaves[pointer] {
			return errors.New("effective source does not identify a leaf")
		}
		switch source.Kind {
		case "file":
			if strings.TrimSpace(source.File) == "" {
				return errors.New("file source is missing its path")
			}
		case "environment":
			if source.File != "" {
				return errors.New("environment source has a file path")
			}
		case "initial", "normalization":
			if source.File != "" || len(source.Environment) > 0 || source.Normalized {
				return errors.New("derived source metadata is invalid")
			}
		default:
			return errors.New("effective source kind is unsupported")
		}
		for _, name := range source.Environment {
			if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\x00\r\n") {
				return errors.New("effective source environment name is invalid")
			}
		}
	}
	return nil
}

// collectEffectiveLeaves enumerates canonical JSON Pointers including nulls and empty containers.
// collectEffectiveLeaves 枚举规范 JSON Pointer，同时包含空值和空容器，将结果写入调用方的集合。
func collectEffectiveLeaves(value any, pointer string, result map[string]bool) {
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) > 0 {
			for key, child := range typed {
				collectEffectiveLeaves(child, pointer+"/"+strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1"), result)
			}
			return
		}
	case []any:
		if len(typed) > 0 {
			for index, child := range typed {
				collectEffectiveLeaves(child, pointer+"/"+strconv.Itoa(index), result)
			}
			return
		}
	}
	result[pointer] = true
}
