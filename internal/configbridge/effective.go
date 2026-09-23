// effective.go reads authoritative effective configuration through the bounded runtime CLI bridge.
// effective.go 通过有界运行时命令桥读取权威有效配置。
package configbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// EffectiveConfig is the versioned read-only snapshot; Config preserves runtime JSON values without local merging.
// EffectiveConfig 是带版本的只读快照；Config 保留运行时 JSON 值而不在本地合并。
type EffectiveConfig struct {
	Version  string                     `json:"version"`
	Redacted bool                       `json:"redacted"`
	Config   map[string]json.RawMessage `json:"config"`
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
	if err := decodeStrictDocument(output, &result, map[string]bool{"version": true, "redacted": true, "config": true}); err != nil {
		return EffectiveConfig{}, protocolError("show-effective", err)
	}
	if result.Version != "v1" || !result.Redacted || len(result.Config) == 0 {
		return EffectiveConfig{}, protocolError("show-effective", errors.New("invalid effective configuration document"))
	}
	return result, nil
}
