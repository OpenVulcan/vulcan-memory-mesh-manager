// provider_test.go verifies diagnostic consent, argument binding and fixed result classes with subprocess fixtures.
// provider_test.go 使用子进程夹具验证诊断确认、参数绑定和固定结果类别。
package configbridge

import (
	"context"
	"reflect"
	"testing"
)

// TestProviderBridgeRequiresConsent checks that an unconfirmed call cannot create a subprocess and confirmed calls bind the selected root.
// TestProviderBridgeRequiresConsent 检查未确认时不会创建子进程，已确认调用绑定所选配置根。
func TestProviderBridgeRequiresConsent(t *testing.T) {
	client, calls := newFixtureClient(t, "provider-ok")
	if _, err := client.TestProvider(context.Background(), "llm", 0, false); err == nil || len(*calls) != 0 {
		t.Fatal("unconfirmed test started a process")
	}
	result, err := client.TestProvider(context.Background(), "llm", 0, true)
	expected := []string{"config", "test-provider", "--config", client.configRoot, "--purpose", "llm", "--route", "0", "--allow-network", "--json"}
	if err != nil || !result.Success || len(*calls) != 1 || !reflect.DeepEqual((*calls)[0], expected) {
		t.Fatalf("confirmed test did not use the fixed argument contract: %v", err)
	}
}

// TestProviderBridgeSeparatesFailuresFromMalformedResults accepts diagnostic failure but rejects contradictory or mismatched protocol data.
// TestProviderBridgeSeparatesFailuresFromMalformedResults 接受诊断失败，但拒绝矛盾或选择不匹配的协议数据。
func TestProviderBridgeSeparatesFailuresFromMalformedResults(t *testing.T) {
	client, _ := newFixtureClient(t, "provider-failed")
	result, err := client.TestProvider(context.Background(), "llm", 0, true)
	if err != nil || result.Success || result.Class != "request-failed" {
		t.Fatalf("network failure was misclassified as a protocol failure: %v", err)
	}
	for _, mode := range []string{"provider-contradiction", "provider-selection", "schema", "exit-seven"} {
		client, _ := newFixtureClient(t, mode)
		if _, err := client.TestProvider(context.Background(), "llm", 0, true); err == nil {
			t.Fatalf("bad provider protocol accepted: %s", mode)
		}
	}
}
