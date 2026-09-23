// Package providerwizard builds safe, provider-specific configuration patches for the VMM installer.
// providerwizard 包用于为 VMM 安装器生成安全且遵循供应商契约的配置补丁。
package providerwizard

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Purpose identifies one VMM AI configuration surface supported by the quick setup flow.
// Purpose 用于标识快捷配置流程支持的 VMM AI 配置类型。
type Purpose string

const (
	// PurposeLLM selects the multi-route text-generation configuration.
	// PurposeLLM 用于选择多路由文本生成配置。
	PurposeLLM Purpose = "llm"
	// PurposeEmbedding selects the single-provider embedding configuration.
	// PurposeEmbedding 用于选择单供应商 embedding 配置。
	PurposeEmbedding Purpose = "embedding"
	// PurposeRerank selects the ordered rerank route configuration.
	// PurposeRerank 用于选择有序 rerank 路由配置。
	PurposeRerank Purpose = "rerank"
)

// FieldRequirement describes whether a field is required, optional, or supplied by a verified runtime default.
// FieldRequirement 用于说明字段必填、可选或由已核实的运行时默认值提供。
type FieldRequirement string

const (
	// RequirementRequired marks fields that the VMM validator requires after normalization.
	// RequirementRequired 表示 VMM 规范化后仍要求提供的字段。
	RequirementRequired FieldRequirement = "required"
	// RequirementOptional marks fields that may be omitted for a provider with a native SDK default.
	// RequirementOptional 表示可由供应商原生 SDK 默认值补足的字段。
	RequirementOptional FieldRequirement = "optional"
	// RequirementDefaulted marks fields whose exact provider default is included in metadata.
	// RequirementDefaulted 表示元数据中提供了准确供应商默认值的字段。
	RequirementDefaulted FieldRequirement = "defaulted"
	// RequirementNotApplicable marks fields that do not belong to a provider purpose.
	// RequirementNotApplicable 表示该供应商类型不包含此字段。
	RequirementNotApplicable FieldRequirement = "not_applicable"
)

// ErrUnsupportedPurpose reports that a caller requested a purpose absent from the VMM provider contract.
// ErrUnsupportedPurpose 表示调用方请求了 VMM 供应商契约未定义的配置类型。
var ErrUnsupportedPurpose = errors.New("unsupported provider purpose")

// ProviderMetadata gives the TUI localized labels and verified requirements for one provider and purpose.
// ProviderMetadata 为 TUI 提供供应商的双语名称，以及经源码核实的字段要求。
type ProviderMetadata struct {
	// ID is the exact provider identifier accepted by VMM configuration validation.
	// ID 是 VMM 配置校验器接受的精确供应商标识。
	ID string
	// DisplayNameEN is the concise English label shown by the TUI.
	// DisplayNameEN 是 TUI 显示的简洁英文名称。
	DisplayNameEN string
	// DisplayNameZH is the concise Simplified Chinese label shown by the TUI.
	// DisplayNameZH 是 TUI 显示的简体中文名称。
	DisplayNameZH string
	// EndpointRequirement states whether the user must provide an endpoint or may use a verified default.
	// EndpointRequirement 说明用户是否必须填写 endpoint，或可以使用已核实的默认值。
	EndpointRequirement FieldRequirement
	// EndpointDefault is the verified provider endpoint inserted when the input omits one.
	// EndpointDefault 是输入未填写时采用的已核实供应商 endpoint。
	EndpointDefault string
	// ModelRequirement states whether the model is required or has a verified provider default.
	// ModelRequirement 说明模型是否必填，或是否存在已核实的供应商默认值。
	ModelRequirement FieldRequirement
	// ModelDefault is the verified rerank model inserted when the input omits one.
	// ModelDefault 是输入未填写时采用的已核实 rerank 模型。
	ModelDefault string
	// APIKeyEnvironmentRequirement describes the environment-variable references needed for the key pool.
	// APIKeyEnvironmentRequirement 说明 key 池需要的环境变量引用要求。
	APIKeyEnvironmentRequirement FieldRequirement
	// DimensionRequirement describes whether embedding output dimension must be supplied explicitly.
	// DimensionRequirement 说明 embedding 输出维度是否必须由用户明确填写。
	DimensionRequirement FieldRequirement
	// ReasoningProjectionKey is the exact request parameter required for generic OpenAI-compatible LLM routes.
	// ReasoningProjectionKey 是通用 OpenAI 兼容 LLM 路由必须声明的请求参数。
	ReasoningProjectionKey string
	// ReasoningProjectionValue is the value VMM forcibly projects to disable reasoning for that request field.
	// ReasoningProjectionValue 是 VMM 为关闭 reasoning 而强制投影到该请求字段的值。
	ReasoningProjectionValue string
	// DimensionHint gives the TUI a provider-specific constraint without inventing a model dimension.
	// DimensionHint 向 TUI 提供供应商维度约束提示，但不猜测模型维度。
	DimensionHint string
}

// LLMRouteInput contains one LLM route and environment-variable names only; it has no field for secret values.
// LLMRouteInput 保存一条 LLM 路由及环境变量名称，不包含用于输入密钥明文的字段。
type LLMRouteInput struct {
	// Name is an optional human-readable route name.
	// Name 是可选的人类可读路由名称。
	Name string
	// Provider is one exact provider ID returned by ProviderCatalog for PurposeLLM.
	// Provider 必须是 ProviderCatalog 为 PurposeLLM 返回的精确供应商标识。
	Provider string
	// Endpoint is required for generic OpenAI-compatible providers and optional for native SDK providers.
	// Endpoint 对通用 OpenAI 兼容供应商必填，对原生 SDK 供应商可选。
	Endpoint string
	// Model is the explicit model identifier selected by the user.
	// Model 是用户明确选择的模型标识。
	Model string
	// APIKeyEnvironmentNames lists environment-variable names whose values are the actual provider keys.
	// APIKeyEnvironmentNames 列出保存真实供应商密钥的环境变量名称。
	APIKeyEnvironmentNames []string
}

// EmbeddingInput contains the single embedding provider, model, dimension, and key environment references.
// EmbeddingInput 保存唯一的 embedding 供应商、模型、维度和 key 环境变量引用。
type EmbeddingInput struct {
	// Provider is one exact provider ID returned by ProviderCatalog for PurposeEmbedding.
	// Provider 必须是 ProviderCatalog 为 PurposeEmbedding 返回的精确供应商标识。
	Provider string
	// Endpoint is required for generic OpenAI-compatible providers and optional for native SDK providers.
	// Endpoint 对通用 OpenAI 兼容供应商必填，对原生 SDK 供应商可选。
	Endpoint string
	// Model is the explicit embedding model identifier selected by the user.
	// Model 是用户明确选择的 embedding 模型标识。
	Model string
	// Dimension is the user-supplied positive output vector dimension; zero is never inferred.
	// Dimension 是用户填写的正数输出向量维度；程序不会推断或猜测该值。
	Dimension int
	// APIKeyEnvironmentNames lists environment-variable names whose values are the actual provider keys.
	// APIKeyEnvironmentNames 列出保存真实供应商密钥的环境变量名称。
	APIKeyEnvironmentNames []string
}

// RerankRouteInput contains one rerank route and environment-variable names only; it has no field for secret values.
// RerankRouteInput 保存一条 rerank 路由及环境变量名称，不包含用于输入密钥明文的字段。
type RerankRouteInput struct {
	// Name is an optional human-readable route name.
	// Name 是可选的人类可读路由名称。
	Name string
	// Priority is a non-negative route priority; equal priorities retain the configured route order.
	// Priority 是非负路由优先级；相同优先级保留配置中的路由顺序。
	Priority int
	// Provider is one exact provider ID returned by ProviderCatalog for PurposeRerank.
	// Provider 必须是 ProviderCatalog 为 PurposeRerank 返回的精确供应商标识。
	Provider string
	// Endpoint overrides the verified provider endpoint default when non-empty.
	// Endpoint 非空时覆盖已核实的供应商 endpoint 默认值。
	Endpoint string
	// Model overrides the verified provider model default when non-empty.
	// Model 非空时覆盖已核实的供应商模型默认值。
	Model string
	// APIKeyEnvironmentNames lists environment-variable names whose values are the actual provider keys.
	// APIKeyEnvironmentNames 列出保存真实供应商密钥的环境变量名称。
	APIKeyEnvironmentNames []string
}

// RerankInput enables or disables reranking and optionally configures its ordered routes.
// RerankInput 用于启用或关闭 rerank，并可配置有序路由。
type RerankInput struct {
	// Enabled determines whether VMM runs reranking after vector recall.
	// Enabled 决定 VMM 是否在向量召回后执行 rerank。
	Enabled bool
	// Routes contains the ordered provider routes; an enabled reranker requires at least one route.
	// Routes 保存有序供应商路由；启用 rerank 时至少需要一条路由。
	Routes []RerankRouteInput
}

// Configuration contains the provider surfaces the TUI intends to add or replace in one YAML patch.
// Configuration 保存 TUI 本次计划新增或替换到 YAML 补丁中的供应商配置段。
type Configuration struct {
	// LLMRoutes replaces the explicit llm.routes list when non-nil and non-empty.
	// LLMRoutes 非空时替换显式 llm.routes 列表。
	LLMRoutes []LLMRouteInput
	// Embedding replaces the single embedding provider configuration when non-nil.
	// Embedding 非 nil 时替换单一 embedding 供应商配置。
	Embedding *EmbeddingInput
	// Rerank replaces rerank.enabled and, when supplied, its ordered routes when non-nil.
	// Rerank 非 nil 时替换 rerank.enabled，并在提供路由时替换其有序路由。
	Rerank *RerankInput
}

// providerCatalogs mirrors the provider allowlists, required fields, and built-in defaults in the VMM config source.
// providerCatalogs 对应 VMM 配置源码中的供应商白名单、必填字段和内建默认值。
var providerCatalogs = map[Purpose][]ProviderMetadata{
	PurposeLLM: {
		{ID: "openai", DisplayNameEN: "OpenAI-compatible", DisplayNameZH: "OpenAI 兼容接口", EndpointRequirement: RequirementRequired, ModelRequirement: RequirementRequired, APIKeyEnvironmentRequirement: RequirementRequired, DimensionRequirement: RequirementNotApplicable, ReasoningProjectionKey: "reasoning_effort", ReasoningProjectionValue: "none"},
		{ID: "openai_native", DisplayNameEN: "OpenAI-compatible alias (openai_native)", DisplayNameZH: "OpenAI 兼容接口别名 (openai_native)", EndpointRequirement: RequirementRequired, ModelRequirement: RequirementRequired, APIKeyEnvironmentRequirement: RequirementRequired, DimensionRequirement: RequirementNotApplicable, ReasoningProjectionKey: "reasoning_effort", ReasoningProjectionValue: "none"},
		{ID: "openai_go", DisplayNameEN: "OpenAI-compatible alias (openai_go)", DisplayNameZH: "OpenAI 兼容接口别名 (openai_go)", EndpointRequirement: RequirementRequired, ModelRequirement: RequirementRequired, APIKeyEnvironmentRequirement: RequirementRequired, DimensionRequirement: RequirementNotApplicable, ReasoningProjectionKey: "reasoning_effort", ReasoningProjectionValue: "none"},
		{ID: "google_ai_studio", DisplayNameEN: "Google AI Studio", DisplayNameZH: "Google AI Studio", EndpointRequirement: RequirementOptional, ModelRequirement: RequirementRequired, APIKeyEnvironmentRequirement: RequirementRequired, DimensionRequirement: RequirementNotApplicable},
		{ID: "openrouter", DisplayNameEN: "OpenRouter", DisplayNameZH: "OpenRouter", EndpointRequirement: RequirementOptional, EndpointDefault: "https://openrouter.ai/api/v1", ModelRequirement: RequirementRequired, APIKeyEnvironmentRequirement: RequirementRequired, DimensionRequirement: RequirementNotApplicable},
	},
	PurposeEmbedding: {
		{ID: "openai", DisplayNameEN: "OpenAI-compatible", DisplayNameZH: "OpenAI 兼容接口", EndpointRequirement: RequirementRequired, ModelRequirement: RequirementRequired, APIKeyEnvironmentRequirement: RequirementRequired, DimensionRequirement: RequirementRequired, DimensionHint: "Enter the dimension supported by the selected model."},
		{ID: "openai_native", DisplayNameEN: "OpenAI-compatible alias (openai_native)", DisplayNameZH: "OpenAI 兼容接口别名 (openai_native)", EndpointRequirement: RequirementRequired, ModelRequirement: RequirementRequired, APIKeyEnvironmentRequirement: RequirementRequired, DimensionRequirement: RequirementRequired, DimensionHint: "Enter the dimension supported by the selected model."},
		{ID: "openai_go", DisplayNameEN: "OpenAI-compatible alias (openai_go)", DisplayNameZH: "OpenAI 兼容接口别名 (openai_go)", EndpointRequirement: RequirementRequired, ModelRequirement: RequirementRequired, APIKeyEnvironmentRequirement: RequirementRequired, DimensionRequirement: RequirementRequired, DimensionHint: "Enter the dimension supported by the selected model."},
		{ID: "google_ai_studio", DisplayNameEN: "Google AI Studio", DisplayNameZH: "Google AI Studio", EndpointRequirement: RequirementOptional, ModelRequirement: RequirementRequired, APIKeyEnvironmentRequirement: RequirementRequired, DimensionRequirement: RequirementRequired, DimensionHint: "Enter a dimension supported by the selected Gemini model."},
		{ID: "openrouter", DisplayNameEN: "OpenRouter", DisplayNameZH: "OpenRouter", EndpointRequirement: RequirementOptional, EndpointDefault: "https://openrouter.ai/api/v1", ModelRequirement: RequirementRequired, APIKeyEnvironmentRequirement: RequirementRequired, DimensionRequirement: RequirementRequired, DimensionHint: "Enter the dimension supported by the selected model."},
	},
	PurposeRerank: {
		{ID: "dashscope", DisplayNameEN: "DashScope", DisplayNameZH: "阿里云百炼", EndpointRequirement: RequirementDefaulted, EndpointDefault: "https://dashscope.aliyuncs.com/api/v1/services/rerank/text-rerank/text-rerank", ModelRequirement: RequirementDefaulted, ModelDefault: "qwen3-vl-rerank", APIKeyEnvironmentRequirement: RequirementRequired, DimensionRequirement: RequirementNotApplicable},
		{ID: "siliconflow", DisplayNameEN: "SiliconFlow", DisplayNameZH: "硅基流动", EndpointRequirement: RequirementDefaulted, EndpointDefault: "https://api.siliconflow.cn/v1/rerank", ModelRequirement: RequirementDefaulted, ModelDefault: "BAAI/bge-reranker-v2-m3", APIKeyEnvironmentRequirement: RequirementRequired, DimensionRequirement: RequirementNotApplicable},
		{ID: "openrouter", DisplayNameEN: "OpenRouter", DisplayNameZH: "OpenRouter", EndpointRequirement: RequirementDefaulted, EndpointDefault: "https://openrouter.ai/api/v1", ModelRequirement: RequirementDefaulted, ModelDefault: "cohere/rerank-v3.5", APIKeyEnvironmentRequirement: RequirementRequired, DimensionRequirement: RequirementNotApplicable},
	},
}

// ProviderCatalog returns a defensive copy of the verified provider options for one purpose.
// ProviderCatalog 返回某种配置用途下经核实的供应商选项副本，调用方修改结果不会影响包内目录。
//
// Parameters:
// 参数：
//   - purpose: the VMM configuration surface requested by the TUI.
//   - purpose：TUI 请求的 VMM 配置类型。
//
// Returns:
// 返回值：
//   - []ProviderMetadata: localized display labels and field requirements in stable menu order.
//   - []ProviderMetadata：按稳定菜单顺序排列的双语名称与字段要求。
//   - error: ErrUnsupportedPurpose when the source contract has no such purpose.
//   - error：配置类型不在源码契约中时返回 ErrUnsupportedPurpose。
func ProviderCatalog(purpose Purpose) ([]ProviderMetadata, error) {
	entries, ok := providerCatalogs[purpose]
	if !ok {
		return nil, ErrUnsupportedPurpose
	}
	return append([]ProviderMetadata(nil), entries...), nil
}

// LookupProvider returns one provider's verified metadata without exposing mutable catalog storage.
// LookupProvider 返回一个供应商的已核实元数据，不暴露可修改的目录内部存储。
//
// Parameters:
// 参数：
//   - purpose: the VMM configuration surface that owns the provider ID.
//   - purpose：该供应商标识所属的 VMM 配置类型。
//   - id: the exact provider ID selected by the TUI.
//   - id：TUI 选择的精确供应商标识。
//
// Returns:
// 返回值：
//   - ProviderMetadata: a value copy of the matching metadata.
//   - ProviderMetadata：匹配元数据的值副本。
//   - bool: true only when both the purpose and provider ID are supported.
//   - bool：仅当配置类型和供应商标识均受支持时为 true。
func LookupProvider(purpose Purpose, id string) (ProviderMetadata, bool) {
	for _, entry := range providerCatalogs[purpose] {
		if entry.ID == id {
			return entry, true
		}
	}
	return ProviderMetadata{}, false
}

// BuildYAMLPatch validates provider input and emits a YAML patch containing only explicitly selected AI sections.
// BuildYAMLPatch 校验供应商输入，并仅为明确选择的 AI 配置段生成 YAML 补丁。
//
// Parameters:
// 参数：
//   - configuration: provider IDs, endpoints, models, user-supplied embedding dimension, and API-key environment names.
//   - configuration：供应商标识、endpoint、模型、用户填写的 embedding 维度和 API key 环境变量名称。
//
// Returns:
// 返回值：
//   - []byte: a YAML document with API keys represented only as ${ENV_NAME} references.
//   - []byte：API key 仅以 ${ENV_NAME} 引用形式表示的 YAML 文档。
//   - error: a value-free validation or encoding error; caller input values are never copied into error text.
//   - error：不包含输入字段值的校验或编码错误；调用方输入不会被复制到错误文本中。
func BuildYAMLPatch(configuration Configuration) ([]byte, error) {
	patch := yamlPatch{}
	if len(configuration.LLMRoutes) > 0 {
		routes := make([]llmRoutePatch, 0, len(configuration.LLMRoutes))
		for idx, input := range configuration.LLMRoutes {
			route, err := buildLLMRoute(input)
			if err != nil {
				return nil, fmt.Errorf("llm.routes[%d]: %w", idx, err)
			}
			routes = append(routes, route)
		}
		patch.LLM = &llmSectionPatch{Routes: routes}
	}
	if configuration.Embedding != nil {
		embedding, err := buildEmbedding(*configuration.Embedding)
		if err != nil {
			return nil, fmt.Errorf("embedding: %w", err)
		}
		patch.Embedding = embedding
	}
	if configuration.Rerank != nil {
		rerank, err := buildRerank(*configuration.Rerank)
		if err != nil {
			return nil, fmt.Errorf("rerank: %w", err)
		}
		patch.Rerank = rerank
	}
	if patch.LLM == nil && patch.Embedding == nil && patch.Rerank == nil {
		return nil, errors.New("provider patch has no selected section")
	}
	data, err := yaml.Marshal(patch)
	if err != nil {
		return nil, errors.New("could not encode provider patch")
	}
	return data, nil
}

// buildLLMRoute validates one LLM route and adds the required disabled-reasoning projection for OpenAI-compatible providers.
// buildLLMRoute 校验单条 LLM 路由，并为 OpenAI 兼容供应商加入必需的 reasoning 禁用投影。
func buildLLMRoute(input LLMRouteInput) (llmRoutePatch, error) {
	provider, ok := LookupProvider(PurposeLLM, strings.TrimSpace(input.Provider))
	if !ok {
		return llmRoutePatch{}, errors.New("provider is not supported")
	}
	endpoint := strings.TrimSpace(input.Endpoint)
	if provider.EndpointRequirement == RequirementRequired && endpoint == "" {
		return llmRoutePatch{}, errors.New("endpoint is required")
	}
	if endpoint == "" {
		endpoint = provider.EndpointDefault
	}
	model := strings.TrimSpace(input.Model)
	if model == "" {
		return llmRoutePatch{}, errors.New("model is required")
	}
	keys, err := keyReferences(input.APIKeyEnvironmentNames)
	if err != nil {
		return llmRoutePatch{}, err
	}
	route := llmRoutePatch{
		Name:     strings.TrimSpace(input.Name),
		Provider: provider.ID,
		Endpoint: endpoint,
		Model:    model,
		APIKeys:  keys,
	}
	if provider.ReasoningProjectionKey != "" {
		route.Params = map[string]string{provider.ReasoningProjectionKey: provider.ReasoningProjectionValue}
	}
	return route, nil
}

// buildEmbedding validates the fixed-provider embedding surface and requires an explicit positive dimension from the user.
// buildEmbedding 校验固定供应商的 embedding 配置，并要求用户明确填写正数维度。
func buildEmbedding(input EmbeddingInput) (*embeddingSectionPatch, error) {
	provider, ok := LookupProvider(PurposeEmbedding, strings.TrimSpace(input.Provider))
	if !ok {
		return nil, errors.New("provider is not supported")
	}
	endpoint := strings.TrimSpace(input.Endpoint)
	if provider.EndpointRequirement == RequirementRequired && endpoint == "" {
		return nil, errors.New("endpoint is required")
	}
	if endpoint == "" {
		endpoint = provider.EndpointDefault
	}
	model := strings.TrimSpace(input.Model)
	if model == "" {
		return nil, errors.New("model is required")
	}
	if input.Dimension <= 0 {
		return nil, errors.New("dimension must be supplied by the user and be greater than zero")
	}
	keys, err := keyReferences(input.APIKeyEnvironmentNames)
	if err != nil {
		return nil, err
	}
	return &embeddingSectionPatch{
		Provider:  provider.ID,
		Endpoint:  endpoint,
		APIKeys:   keys,
		Model:     model,
		Dimension: input.Dimension,
	}, nil
}

// buildRerank validates rerank routes and fills only the provider defaults verified in VMM normalization.
// buildRerank 校验 rerank 路由，并仅补入 VMM 规范化逻辑中已核实的供应商默认值。
func buildRerank(input RerankInput) (*rerankSectionPatch, error) {
	if input.Enabled && len(input.Routes) == 0 {
		return nil, errors.New("at least one route is required when reranking is enabled")
	}
	routes := make([]rerankRoutePatch, 0, len(input.Routes))
	for idx, routeInput := range input.Routes {
		provider, ok := LookupProvider(PurposeRerank, strings.TrimSpace(routeInput.Provider))
		if !ok {
			return nil, fmt.Errorf("routes[%d]: provider is not supported", idx)
		}
		if routeInput.Priority < 0 {
			return nil, fmt.Errorf("routes[%d]: priority must not be negative", idx)
		}
		endpoint := strings.TrimSpace(routeInput.Endpoint)
		if endpoint == "" {
			endpoint = provider.EndpointDefault
		}
		model := strings.TrimSpace(routeInput.Model)
		if model == "" {
			model = provider.ModelDefault
		}
		if endpoint == "" || model == "" {
			return nil, fmt.Errorf("routes[%d]: endpoint and model are required", idx)
		}
		keys, err := keyReferences(routeInput.APIKeyEnvironmentNames)
		if err != nil {
			return nil, fmt.Errorf("routes[%d]: %w", idx, err)
		}
		routes = append(routes, rerankRoutePatch{
			Name:     strings.TrimSpace(routeInput.Name),
			Priority: routeInput.Priority,
			Provider: provider.ID,
			Endpoint: endpoint,
			APIKeys:  keys,
			Model:    model,
		})
	}
	return &rerankSectionPatch{Enabled: input.Enabled, Routes: routes}, nil
}

// keyReferences validates environment-variable identifiers and converts them into VMM's explicit ${NAME} value syntax.
// keyReferences 校验环境变量标识，并将其转换成 VMM 使用的显式 ${NAME} 值语法。
func keyReferences(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, errors.New("api_keys must contain at least one environment variable name")
	}
	refs := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, rawName := range names {
		name := strings.TrimSpace(rawName)
		if !isEnvironmentIdentifier(name) {
			return nil, errors.New("api_keys entries must be valid environment variable names")
		}
		canonical := strings.ToUpper(name)
		if isRemovedAIEnvironmentOverride(canonical) {
			return nil, errors.New("api_keys entries must not use a removed VMM AI override name")
		}
		if _, exists := seen[canonical]; exists {
			return nil, errors.New("api_keys environment variable names must be unique")
		}
		seen[canonical] = struct{}{}
		refs = append(refs, "${"+name+"}")
	}
	return refs, nil
}

// isEnvironmentIdentifier checks the portable ASCII variable-name syntax used by both Windows and Unix environments.
// isEnvironmentIdentifier 校验 Windows 与 Unix 均可用的 ASCII 环境变量名称语法。
func isEnvironmentIdentifier(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for index, r := range value {
		if index == 0 {
			if !isASCIIAlpha(r) && r != '_' {
				return false
			}
			continue
		}
		if !isASCIIAlpha(r) && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

// isASCIIAlpha reports whether one rune belongs to the ASCII environment-name alphabet.
// isASCIIAlpha 用于判断字符是否属于 ASCII 环境变量名称字母范围。
func isASCIIAlpha(value rune) bool {
	return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
}

// isRemovedAIEnvironmentOverride identifies legacy single-provider variables explicitly rejected by the VMM loader.
// isRemovedAIEnvironmentOverride 用于识别 VMM 加载器明确拒绝的旧版单供应商环境变量。
func isRemovedAIEnvironmentOverride(name string) bool {
	switch name {
	case "VMM_LLM_PROVIDER", "VMM_LLM_ENDPOINT", "VMM_LLM_API_KEY", "VMM_LLM_API_KEYS",
		"VMM_LLM_RPM", "VMM_LLM_TPM", "VMM_LLM_RPD", "VMM_LLM_MODEL", "VMM_LLM_ORGANIZATION", "VMM_LLM_PROJECT",
		"VMM_LLM_KEY_FAILOVER_ENABLED", "VMM_LLM_KEY_FAILOVER_POLICY", "VMM_LLM_KEY_FAILOVER_RESPECT_RETRY_AFTER",
		"VMM_LLM_KEY_FAILOVER_RATE_LIMIT_COOLDOWN", "VMM_LLM_KEY_FAILOVER_QUOTA_COOLDOWN",
		"VMM_LLM_KEY_FAILOVER_AUTH_COOLDOWN", "VMM_LLM_KEY_FAILOVER_PROBE_AFTER_COOLDOWN",
		"VMM_RERANK_PROVIDER", "VMM_RERANK_ENDPOINT", "VMM_RERANK_API_KEY", "VMM_RERANK_API_KEYS",
		"VMM_RERANK_RPM", "VMM_RERANK_TPM", "VMM_RERANK_RPD", "VMM_RERANK_MODEL", "VMM_RERANK_TIMEOUT",
		"VMM_RERANK_KEY_FAILOVER_ENABLED", "VMM_RERANK_KEY_FAILOVER_POLICY", "VMM_RERANK_KEY_FAILOVER_RESPECT_RETRY_AFTER",
		"VMM_RERANK_KEY_FAILOVER_RATE_LIMIT_COOLDOWN", "VMM_RERANK_KEY_FAILOVER_QUOTA_COOLDOWN",
		"VMM_RERANK_KEY_FAILOVER_AUTH_COOLDOWN", "VMM_RERANK_KEY_FAILOVER_PROBE_AFTER_COOLDOWN", "VMM_EMBED_API_KEY":
		return true
	default:
		return false
	}
}

// yamlPatch contains only selected provider sections so unrelated runtime settings remain available to configedit merging.
// yamlPatch 仅包含选中的供应商配置段，便于 configedit 合并时保留其他运行时配置。
type yamlPatch struct {
	LLM       *llmSectionPatch       `yaml:"llm,omitempty"`
	Embedding *embeddingSectionPatch `yaml:"embedding,omitempty"`
	Rerank    *rerankSectionPatch    `yaml:"rerank,omitempty"`
}

// llmSectionPatch carries the complete ordered LLM routes requested by the TUI.
// llmSectionPatch 保存 TUI 请求的完整有序 LLM 路由列表。
type llmSectionPatch struct {
	Routes []llmRoutePatch `yaml:"routes"`
}

// llmRoutePatch is the snake-case YAML representation of one validated LLM route.
// llmRoutePatch 是一条已校验 LLM 路由的 snake_case YAML 表示。
type llmRoutePatch struct {
	Name     string            `yaml:"name,omitempty"`
	Provider string            `yaml:"provider"`
	Endpoint string            `yaml:"endpoint,omitempty"`
	APIKeys  []string          `yaml:"api_keys"`
	Model    string            `yaml:"model"`
	Params   map[string]string `yaml:"params,omitempty"`
}

// embeddingSectionPatch is the snake-case YAML representation of the single embedding configuration.
// embeddingSectionPatch 是单一 embedding 配置的 snake_case YAML 表示。
type embeddingSectionPatch struct {
	Provider  string   `yaml:"provider"`
	Endpoint  string   `yaml:"endpoint,omitempty"`
	APIKeys   []string `yaml:"api_keys"`
	Model     string   `yaml:"model"`
	Dimension int      `yaml:"dimension"`
}

// rerankSectionPatch carries the enable switch and ordered rerank routes requested by the TUI.
// rerankSectionPatch 保存 TUI 请求的启用开关和有序 rerank 路由。
type rerankSectionPatch struct {
	Enabled bool               `yaml:"enabled"`
	Routes  []rerankRoutePatch `yaml:"routes,omitempty"`
}

// rerankRoutePatch is the snake-case YAML representation of one validated rerank route.
// rerankRoutePatch 是一条已校验 rerank 路由的 snake_case YAML 表示。
type rerankRoutePatch struct {
	Name     string   `yaml:"name,omitempty"`
	Priority int      `yaml:"priority"`
	Provider string   `yaml:"provider"`
	Endpoint string   `yaml:"endpoint"`
	APIKeys  []string `yaml:"api_keys"`
	Model    string   `yaml:"model"`
}
