// provider.go invokes explicitly requested paid diagnostics and validates their bounded, credential-free protocol.
// provider.go 调用明确请求的可能收费诊断，并验证有界、不含凭据的协议。
package configbridge

import (
	"context"
	"errors"
	"strconv"
)

// ProviderTestResult reports one selected runtime provider test without echoing provider responses.
// ProviderTestResult 报告一次所选运行时供应商测试，不回显供应商回复。
type ProviderTestResult struct {
	Version string `json:"version"`
	Purpose string `json:"purpose"`
	Route   int    `json:"route"`
	Success bool   `json:"success"`
	Class   string `json:"class"`
}

// TestProvider sends network consent only for an explicitly confirmed caller request and returns a strict protocol result.
// TestProvider 仅在调用方明确确认时传递联网许可，并返回严格协议结果。
func (c *Client) TestProvider(ctx context.Context, purpose string, route int, confirmed bool) (ProviderTestResult, error) {
	if !confirmed || (purpose != "llm" && purpose != "embedding" && purpose != "rerank") || route < 0 || (purpose == "embedding" && route != 0) {
		return ProviderTestResult{}, errors.New("provider test requires explicit network consent and a valid selection")
	}
	output, code, err := c.run(ctx, "test-provider", "config", "test-provider", "--config", c.configRoot, "--purpose", purpose, "--route", strconv.Itoa(route), "--allow-network", "--json")
	if err != nil {
		return ProviderTestResult{}, err
	}
	var result ProviderTestResult
	if err := decodeStrictDocument(output, &result, map[string]bool{"version": true, "purpose": true, "route": true, "success": true, "class": true}); err != nil {
		return ProviderTestResult{}, protocolError("test-provider", err)
	}
	validClass := false
	switch result.Class {
	case "ok", "configuration", "request-failed", "invalid-response", "timeout", "cancelled":
		validClass = true
	}
	if result.Version != "v1" || result.Purpose != purpose || result.Route != route || !validClass || (code != 0 && code != 1) || result.Success != (code == 0) || result.Success != (result.Class == "ok") {
		return ProviderTestResult{}, protocolError("test-provider", errors.New("contradictory provider diagnostic result"))
	}
	return result, nil
}
