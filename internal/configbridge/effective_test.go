// effective_test.go checks the manager's strict effective-config subprocess contract.
// effective_test.go 检查管理器严格的有效配置子进程契约。
package configbridge

import (
	"context"
	"encoding/json"
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

// TestEffectiveSourcesChecksCoverage retains runtime nulls and rejects incomplete or invented origin metadata.
// TestEffectiveSourcesChecksCoverage 保留运行时空值，并拒绝来源覆盖缺失或伪造的字段元数据。
func TestEffectiveSourcesChecksCoverage(t *testing.T) {
	client, _ := newFixtureClient(t, "effective-sources")
	result, err := client.Effective(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Sources["/logging/level"].File != "config.yaml" || !strings.Contains(string(result.Config["memory_pipeline"]), "null") {
		t.Fatal("source or null lost")
	}
	for _, mutate := range []func(*EffectiveConfig){
		func(r *EffectiveConfig) { delete(r.Sources, "/logging/level") },
		func(r *EffectiveConfig) { r.Sources["/logging/level"] = ConfigValueSource{Kind: "file"} },
		func(r *EffectiveConfig) { r.Sources["/logging/level"] = ConfigValueSource{Kind: "guessed"} },
		func(r *EffectiveConfig) { r.Version = "v1" },
	} {
		body, _ := json.Marshal(result)
		var candidate EffectiveConfig
		if err := json.Unmarshal(body, &candidate); err != nil {
			t.Fatal(err)
		}
		mutate(&candidate)
		if validateEffectiveSources(candidate) == nil {
			t.Fatal("invalid origins accepted")
		}
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
