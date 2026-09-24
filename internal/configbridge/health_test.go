// These tests cover the runtime readiness protocol and bounded startup wait.
// 这些测试覆盖运行时就绪协议与有界启动等待。
package configbridge

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// TestHealthContract checks fixed invocation, strict response shape, and contradictory exit codes.
// TestHealthContract 检查固定调用参数、严格响应结构与矛盾退出码。
func TestHealthContract(t *testing.T) {
	client, calls := newFixtureClient(t, "health-ok")
	result, err := client.Health(context.Background())
	if err != nil || result.Class != "ok" {
		t.Fatalf("health result: %+v, %v", result, err)
	}
	if !reflect.DeepEqual((*calls)[0], []string{"health", "--config", client.configRoot, "--json"}) {
		t.Fatal("incorrect health arguments")
	}
	for _, sample := range []string{
		`{"status":"ok","class":"ok"}`,
		`{"status":"ok","class":"ok","elapsed_ms":-1}`,
		`{"status":"ok","class":"ok","elapsed_ms":1,"unknown":"secret"}`,
		`{"status":"error","class":"unreachable","error":"secret","elapsed_ms":1}`,
		`{"status":"ok","status":"ok","class":"ok","elapsed_ms":1}`,
	} {
		if _, err := decodeHealth([]byte(sample), 0); !errors.Is(err, ErrProtocol) {
			t.Fatal("invalid health document accepted")
		}
	}
	if _, err := decodeHealth([]byte(`{"status":"ok","class":"ok","elapsed_ms":1}`), 1); !errors.Is(err, ErrProtocol) {
		t.Fatal("conflicting exit code accepted")
	}
}

// TestHealthWaitHonorsDeadline ensures a live but unreachable runtime cannot make startup succeed.
// TestHealthWaitHonorsDeadline 确保进程存在但端点不可达时启动不能被判为成功。
func TestHealthWaitHonorsDeadline(t *testing.T) {
	client, _ := newFixtureClient(t, "health-unreachable")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := client.WaitHealthy(ctx); err == nil {
		t.Fatal("unreachable runtime accepted")
	}
	client, _ = newFixtureClient(t, "health-ok")
	if err := client.WaitHealthy(context.Background()); err != nil {
		t.Fatal(err)
	}
}
