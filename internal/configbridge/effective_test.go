// effective_test.go checks the manager's strict effective-config subprocess contract.
// effective_test.go 检查管理器严格的有效配置子进程契约。
package configbridge

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// TestEffectiveUsesAuthoritativeCommand verifies the explicit root and preserves the runtime's nested values.
// TestEffectiveUsesAuthoritativeCommand 验证显式配置根参数并保留运行时嵌套配置值。
func TestEffectiveUsesAuthoritativeCommand(t *testing.T) {
	client, calls := newFixtureClient(t, "effective")
	result, err := client.Effective(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"config", "show-effective", "--config", client.configRoot, "--json"}
	if len(*calls) != 1 || !reflect.DeepEqual((*calls)[0], expected) || !result.Redacted || !strings.Contains(string(result.Config["embedding"]), "effective-model") {
		t.Fatal("effective export did not use the runtime contract")
	}
}

// TestEffectiveRejectsInvalidProtocol checks missing metadata, duplicate nested keys, unredacted output and child failures.
// TestEffectiveRejectsInvalidProtocol 检查元数据缺失、嵌套重键、未脱敏输出和子进程失败。
func TestEffectiveRejectsInvalidProtocol(t *testing.T) {
	for _, mode := range []string{"effective-unredacted", "effective-version", "effective-empty", "effective-duplicate", "schema", "garbage", "exit-seven"} {
		t.Run(mode, func(t *testing.T) {
			client, _ := newFixtureClient(t, mode)
			_, err := client.Effective(context.Background())
			if err == nil || strings.Contains(err.Error(), "do-not-leak-super-secret") {
				t.Fatal("invalid effective response was accepted or leaked child output")
			}
		})
	}
}
