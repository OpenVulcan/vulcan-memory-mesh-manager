// This bridge uses VMM's read-only local health contract after runtime startup.
// 此桥接层在运行时启动后使用 VMM 的本地只读健康契约。
package configbridge

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// HealthResult contains only the fixed diagnostic codes emitted by VMM health --json.
// HealthResult 仅包含 VMM health --json 输出的固定诊断码。
type HealthResult struct {
	// Status and Class distinguish readiness from configuration, transport, and storage failure.
	// Status 与 Class 区分就绪状态和配置、连接及存储故障。
	Status string `json:"status"`
	Class  string `json:"class"`
	// Error is the runtime's bounded diagnostic code, never its raw error text.
	// Error 是运行时有限集合的诊断码，绝不包含原始错误文本。
	Error string `json:"error,omitempty"`
	// ElapsedMsec is the time spent on the runtime probe.
	// ElapsedMsec 是运行时探测耗时。
	ElapsedMsec int64 `json:"elapsed_ms"`
}

// Health runs one bounded local probe and validates its status, exit code, and diagnostic vocabulary.
// Health 执行一次有界本地探测，并校验状态、退出码及诊断词汇。
func (c *Client) Health(ctx context.Context) (HealthResult, error) {
	output, code, err := c.run(ctx, "health", "health", "--config", c.configRoot, "--json")
	if err != nil {
		return HealthResult{}, err
	}
	return decodeHealth(output, code)
}

// decodeHealth rejects unknown or contradictory responses without returning their untrusted contents.
// decodeHealth 拒绝未知或矛盾的响应，且不返回不可信响应内容。
func decodeHealth(output []byte, code int) (HealthResult, error) {
	invalid := func() (HealthResult, error) { return HealthResult{}, protocolError("health", ErrProtocol) }
	if err := rejectDuplicateKeys(output); err != nil {
		return invalid()
	}
	if err := validateObjectKeys(output, map[string]bool{"status": true, "class": true, "error": false, "elapsed_ms": true}, "health"); err != nil {
		return invalid()
	}
	var result HealthResult
	if err := json.Unmarshal(output, &result); err != nil || result.ElapsedMsec < 0 {
		return invalid()
	}
	if code == 0 && result.Status == "ok" && result.Class == "ok" && result.Error == "" {
		return result, nil
	}
	if code != 1 || result.Status != "error" {
		return invalid()
	}
	valid := false
	switch result.Class {
	case "configuration_invalid":
		switch result.Error {
		case "configuration_layout", "configuration_invalid", "configuration_validation", "configuration_read", "configuration_parse", "configuration_environment", "grpc_address_invalid":
			valid = true
		}
	case "unreachable":
		valid = result.Error == "grpc_unreachable"
	case "storage_unavailable":
		valid = result.Error == "storage_health_failed"
	case "runtime_error":
		valid = result.Error == "health_rpc_failed" || result.Error == "health_status_invalid"
	}
	if !valid {
		return invalid()
	}
	return result, nil
}

// WaitHealthy allows startup to finish within thirty seconds, retrying only transport and storage readiness failures.
// WaitHealthy 为启动预留三十秒，只重试连接与存储尚未就绪的故障；其他协议或配置错误立即返回。
func (c *Client) WaitHealthy(ctx context.Context) error {
	if ctx == nil {
		return errors.New("health context is nil")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		result, err := c.Health(bounded)
		if err != nil {
			return err
		}
		if result.Class == "ok" {
			return nil
		}
		if result.Class != "unreachable" && result.Class != "storage_unavailable" {
			return errors.New("VMM health check failed: " + result.Class)
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-bounded.Done():
			timer.Stop()
			return errors.New("VMM did not become healthy before the startup deadline")
		case <-timer.C:
		}
	}
}
