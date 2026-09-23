// provider_test.go checks provider metadata, key-reference safety, and generated patch compatibility.
// provider_test.go 用于验证供应商元数据、key 引用安全性和生成补丁的兼容性。
package providerwizard

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestProviderCatalogMatchesSupportedContracts checks the menu IDs and requirements against the VMM allowlists.
// TestProviderCatalogMatchesSupportedContracts 用于校验菜单标识和字段要求与 VMM 白名单一致。
func TestProviderCatalogMatchesSupportedContracts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		purpose Purpose
		want    []string
	}{
		{purpose: PurposeLLM, want: []string{"openai", "openai_native", "openai_go", "google_ai_studio", "openrouter"}},
		{purpose: PurposeEmbedding, want: []string{"openai", "openai_native", "openai_go", "google_ai_studio", "openrouter"}},
		{purpose: PurposeRerank, want: []string{"dashscope", "siliconflow", "openrouter"}},
	}
	for _, tc := range cases {
		catalog, err := ProviderCatalog(tc.purpose)
		if err != nil {
			t.Fatalf("ProviderCatalog(%q): %v", tc.purpose, err)
		}
		got := make([]string, 0, len(catalog))
		for _, provider := range catalog {
			got = append(got, provider.ID)
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("ProviderCatalog(%q) IDs = %v, want %v", tc.purpose, got, tc.want)
		}
	}
	if _, err := ProviderCatalog(Purpose("unknown")); err != ErrUnsupportedPurpose {
		t.Fatalf("unsupported purpose error = %v, want ErrUnsupportedPurpose", err)
	}

	for _, id := range []string{"openai", "openai_native", "openai_go"} {
		metadata, ok := LookupProvider(PurposeLLM, id)
		if !ok {
			t.Fatalf("LookupProvider(llm, %q) not found", id)
		}
		if metadata.EndpointRequirement != RequirementRequired {
			t.Errorf("%s endpoint requirement = %q, want required", id, metadata.EndpointRequirement)
		}
		if metadata.ReasoningProjectionKey != "reasoning_effort" || metadata.ReasoningProjectionValue != "none" {
			t.Errorf("%s disabled reasoning projection = %q:%q", id, metadata.ReasoningProjectionKey, metadata.ReasoningProjectionValue)
		}
	}
	for _, id := range []string{"openai", "openai_native", "openai_go", "google_ai_studio", "openrouter"} {
		metadata, ok := LookupProvider(PurposeEmbedding, id)
		if !ok || metadata.DimensionRequirement != RequirementRequired {
			t.Errorf("embedding provider %q metadata = %+v, found=%t; dimension must be required", id, metadata, ok)
		}
	}
	for _, id := range []string{"dashscope", "siliconflow", "openrouter"} {
		metadata, ok := LookupProvider(PurposeRerank, id)
		if !ok || metadata.EndpointDefault == "" || metadata.ModelDefault == "" {
			t.Errorf("rerank provider %q lacks its verified endpoint/model defaults: %+v", id, metadata)
		}
	}

	catalog, err := ProviderCatalog(PurposeLLM)
	if err != nil {
		t.Fatal(err)
	}
	catalog[0].ID = "mutated"
	metadata, ok := LookupProvider(PurposeLLM, "openai")
	if !ok || metadata.ID != "openai" {
		t.Fatalf("catalog mutation escaped into package state: %+v, found=%t", metadata, ok)
	}
}

// TestBuildYAMLPatchEmitsSafeProviderConfiguration validates all three config shapes and their secret-reference behavior.
// TestBuildYAMLPatchEmitsSafeProviderConfiguration 用于验证三类配置形态以及密钥引用行为。
func TestBuildYAMLPatchEmitsSafeProviderConfiguration(t *testing.T) {
	t.Parallel()

	configuration := Configuration{
		LLMRoutes: []LLMRouteInput{
			{
				Name:                   "primary",
				Provider:               "openai",
				Endpoint:               "https://llm.example.test/v1",
				Model:                  "test-chat-model",
				APIKeyEnvironmentNames: []string{"VMMM_LLM_PRIMARY_KEY", "VMMM_LLM_BACKUP_KEY"},
			},
			{
				Provider:               "google_ai_studio",
				Model:                  "gemini-test-model",
				APIKeyEnvironmentNames: []string{"VMMM_GOOGLE_KEY"},
			},
		},
		Embedding: &EmbeddingInput{
			Provider:               "openai",
			Endpoint:               "https://embed.example.test/v1",
			Model:                  "test-embedding-model",
			Dimension:              1536,
			APIKeyEnvironmentNames: []string{"VMMM_EMBEDDING_KEY"},
		},
		Rerank: &RerankInput{
			Enabled: true,
			Routes: []RerankRouteInput{
				{Provider: "siliconflow", APIKeyEnvironmentNames: []string{"VMMM_RERANK_KEY"}},
				{Provider: "openrouter", Priority: 2, APIKeyEnvironmentNames: []string{"VMMM_RERANK_BACKUP_KEY"}},
			},
		},
	}

	data, err := BuildYAMLPatch(configuration)
	if err != nil {
		t.Fatalf("BuildYAMLPatch: %v", err)
	}
	if strings.Contains(string(data), "sk-test") {
		t.Fatalf("patch unexpectedly contains a literal key: %s", data)
	}

	var decoded struct {
		LLM struct {
			Routes []struct {
				Provider string            `yaml:"provider"`
				Endpoint string            `yaml:"endpoint"`
				APIKeys  []string          `yaml:"api_keys"`
				Model    string            `yaml:"model"`
				Params   map[string]string `yaml:"params"`
			} `yaml:"routes"`
		} `yaml:"llm"`
		Embedding struct {
			Provider  string   `yaml:"provider"`
			Endpoint  string   `yaml:"endpoint"`
			APIKeys   []string `yaml:"api_keys"`
			Model     string   `yaml:"model"`
			Dimension int      `yaml:"dimension"`
		} `yaml:"embedding"`
		Rerank struct {
			Enabled bool `yaml:"enabled"`
			Routes  []struct {
				Provider string   `yaml:"provider"`
				Endpoint string   `yaml:"endpoint"`
				APIKeys  []string `yaml:"api_keys"`
				Model    string   `yaml:"model"`
				Priority int      `yaml:"priority"`
			} `yaml:"routes"`
		} `yaml:"rerank"`
	}
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("generated patch is not valid YAML: %v", err)
	}
	if len(decoded.LLM.Routes) != 2 {
		t.Fatalf("LLM route count = %d, want 2", len(decoded.LLM.Routes))
	}
	if decoded.LLM.Routes[0].Params["reasoning_effort"] != "none" {
		t.Errorf("OpenAI reasoning projection = %v, want reasoning_effort: none", decoded.LLM.Routes[0].Params)
	}
	if len(decoded.LLM.Routes[0].APIKeys) != 2 || decoded.LLM.Routes[0].APIKeys[0] != "${VMMM_LLM_PRIMARY_KEY}" || decoded.LLM.Routes[0].APIKeys[1] != "${VMMM_LLM_BACKUP_KEY}" {
		t.Errorf("LLM api key references = %v", decoded.LLM.Routes[0].APIKeys)
	}
	if decoded.LLM.Routes[1].Endpoint != "" {
		// Google AI Studio uses its native SDK default, so the generated route omits endpoint entirely.
		// Google AI Studio 使用原生 SDK 默认地址，因此生成路由会完全省略 endpoint。
		t.Errorf("Google AI Studio endpoint = %q, want omitted native SDK default", decoded.LLM.Routes[1].Endpoint)
	}
	if decoded.Embedding.Dimension != 1536 {
		t.Errorf("embedding dimension = %d, want user-supplied 1536", decoded.Embedding.Dimension)
	}
	if len(decoded.Embedding.APIKeys) != 1 || decoded.Embedding.APIKeys[0] != "${VMMM_EMBEDDING_KEY}" {
		t.Errorf("embedding api key references = %v", decoded.Embedding.APIKeys)
	}
	if !decoded.Rerank.Enabled || len(decoded.Rerank.Routes) != 2 {
		t.Fatalf("rerank enabled=%t routes=%d, want enabled with two routes", decoded.Rerank.Enabled, len(decoded.Rerank.Routes))
	}
	if got := decoded.Rerank.Routes[0]; got.Endpoint != "https://api.siliconflow.cn/v1/rerank" || got.Model != "BAAI/bge-reranker-v2-m3" || got.Priority != 0 {
		t.Errorf("SiliconFlow default route = %+v", got)
	}
	if got := decoded.Rerank.Routes[1]; got.Endpoint != "https://openrouter.ai/api/v1" || got.Model != "cohere/rerank-v3.5" || got.Priority != 2 {
		t.Errorf("OpenRouter default route = %+v", got)
	}
}

// TestBuildYAMLPatchRejectsInvalidAndSecretLikeInputs checks required fields and makes sure errors never echo secret-like values.
// TestBuildYAMLPatchRejectsInvalidAndSecretLikeInputs 用于检查必填字段，并确认错误不会回显疑似密钥的输入。
func TestBuildYAMLPatchRejectsInvalidAndSecretLikeInputs(t *testing.T) {
	t.Parallel()

	const rawKey = "sk-test-secret-value"
	cases := []struct {
		name          string
		configuration Configuration
		wantError     string
	}{
		{
			name:      "no selected section",
			wantError: "provider patch has no selected section",
		},
		{
			name:          "unknown provider",
			configuration: Configuration{LLMRoutes: []LLMRouteInput{{Provider: "provider-guess", Model: "m", APIKeyEnvironmentNames: []string{"VMMM_KEY"}}}},
			wantError:     "provider is not supported",
		},
		{
			name:          "openai endpoint required",
			configuration: Configuration{LLMRoutes: []LLMRouteInput{{Provider: "openai", Model: "m", APIKeyEnvironmentNames: []string{"VMMM_KEY"}}}},
			wantError:     "endpoint is required",
		},
		{
			name:          "embedding dimension required",
			configuration: Configuration{Embedding: &EmbeddingInput{Provider: "openai", Endpoint: "https://example.test", Model: "m", APIKeyEnvironmentNames: []string{"VMMM_KEY"}}},
			wantError:     "dimension must be supplied by the user",
		},
		{
			name:          "embedding keys must be environment names",
			configuration: Configuration{Embedding: &EmbeddingInput{Provider: "openai", Endpoint: "https://example.test", Model: "m", Dimension: 768, APIKeyEnvironmentNames: []string{rawKey}}},
			wantError:     "valid environment variable names",
		},
		{
			name:          "removed legacy variable is rejected",
			configuration: Configuration{Embedding: &EmbeddingInput{Provider: "openai", Endpoint: "https://example.test", Model: "m", Dimension: 768, APIKeyEnvironmentNames: []string{"VMM_LLM_API_KEYS"}}},
			wantError:     "removed VMM AI override",
		},
		{
			name:          "duplicate variables are rejected",
			configuration: Configuration{Embedding: &EmbeddingInput{Provider: "openai", Endpoint: "https://example.test", Model: "m", Dimension: 768, APIKeyEnvironmentNames: []string{"VMMM_KEY", "vmmm_key"}}},
			wantError:     "must be unique",
		},
		{
			name:          "enabled rerank requires a route",
			configuration: Configuration{Rerank: &RerankInput{Enabled: true}},
			wantError:     "at least one route is required",
		},
		{
			name:          "negative rerank priority is rejected",
			configuration: Configuration{Rerank: &RerankInput{Enabled: true, Routes: []RerankRouteInput{{Provider: "dashscope", Priority: -1, APIKeyEnvironmentNames: []string{"VMMM_KEY"}}}}},
			wantError:     "priority must not be negative",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildYAMLPatch(tc.configuration)
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("BuildYAMLPatch error = %v, want text %q", err, tc.wantError)
			}
			if strings.Contains(err.Error(), rawKey) {
				t.Fatalf("error exposed secret-like input: %v", err)
			}
		})
	}
}
