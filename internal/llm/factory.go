package llm

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	arkmodel "github.com/cloudwego/eino-ext/components/model/ark"
	claudemodel "github.com/cloudwego/eino-ext/components/model/claude"
	geminimodel "github.com/cloudwego/eino-ext/components/model/gemini"
	ollamamodel "github.com/cloudwego/eino-ext/components/model/ollama"
	openaiadapter "github.com/cloudwego/eino-ext/components/model/openai"
	openroutermodel "github.com/cloudwego/eino-ext/components/model/openrouter"
	"github.com/cloudwego/eino/components/model"
	"google.golang.org/genai"
)

type Config struct {
	Provider        string
	Model           string
	APIKey          string
	BaseURL         string
	APIVersion      string
	MaxOutputTokens int
	Timeout         time.Duration
	AuthMode        string
}

type ProviderInfo struct {
	Name           string
	Aliases        []string
	APIKeyEnv      string
	ModelEnv       string
	BaseURLEnv     string
	APIVersionEnv  string
	DefaultModel   string
	DefaultBaseURL string
	RequiresAPIKey bool
}

type Builder func(context.Context, Config) (model.BaseChatModel, error)

type Registry struct {
	providers map[string]registeredProvider
	aliases   map[string]string
}

type registeredProvider struct {
	info    ProviderInfo
	builder Builder
}

func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]registeredProvider), aliases: make(map[string]string)}
}

func DefaultRegistry() *Registry {
	registry := NewRegistry()
	mustRegister(registry, ProviderInfo{
		Name: "openai", APIKeyEnv: "OPENAI_API_KEY", ModelEnv: "OPENAI_MODEL", BaseURLEnv: "OPENAI_BASE_URL",
		DefaultModel: "gpt-5.6", RequiresAPIKey: true,
	}, buildOpenAI)
	mustRegister(registry, ProviderInfo{
		Name: "openai-compatible", Aliases: []string{"compatible", "custom"}, APIKeyEnv: "LLM_API_KEY", ModelEnv: "LLM_MODEL", BaseURLEnv: "LLM_BASE_URL",
	}, buildOpenAI)
	mustRegister(registry, ProviderInfo{
		Name: "azure-openai", Aliases: []string{"azure"}, APIKeyEnv: "AZURE_OPENAI_API_KEY", ModelEnv: "AZURE_OPENAI_MODEL",
		BaseURLEnv: "AZURE_OPENAI_ENDPOINT", APIVersionEnv: "OPENAI_API_VERSION", RequiresAPIKey: true,
	}, buildAzureOpenAI)
	mustRegister(registry, ProviderInfo{
		Name: "openrouter", APIKeyEnv: "OPENROUTER_API_KEY", ModelEnv: "OPENROUTER_MODEL", BaseURLEnv: "OPENROUTER_BASE_URL",
		DefaultBaseURL: "https://openrouter.ai/api/v1", RequiresAPIKey: true,
	}, buildOpenRouter)
	mustRegister(registry, ProviderInfo{
		Name: "anthropic", Aliases: []string{"claude"}, APIKeyEnv: "ANTHROPIC_API_KEY", ModelEnv: "ANTHROPIC_MODEL", BaseURLEnv: "ANTHROPIC_BASE_URL",
		RequiresAPIKey: true,
	}, buildClaude)
	mustRegister(registry, ProviderInfo{
		Name: "gemini", Aliases: []string{"google"}, APIKeyEnv: "GEMINI_API_KEY", ModelEnv: "GEMINI_MODEL", BaseURLEnv: "GEMINI_BASE_URL",
		APIVersionEnv: "GEMINI_API_VERSION", RequiresAPIKey: true,
	}, buildGemini)
	mustRegister(registry, ProviderInfo{
		Name: "ollama", ModelEnv: "OLLAMA_MODEL", BaseURLEnv: "OLLAMA_HOST", DefaultBaseURL: "http://localhost:11434",
	}, buildOllama)
	mustRegister(registry, ProviderInfo{
		Name: "ark", Aliases: []string{"volcengine"}, APIKeyEnv: "ARK_API_KEY", ModelEnv: "ARK_MODEL", BaseURLEnv: "ARK_BASE_URL",
		RequiresAPIKey: true,
	}, buildArk)
	return registry
}

func (r *Registry) Register(info ProviderInfo, builder Builder) error {
	info.Name = normalize(info.Name)
	if info.Name == "" {
		return fmt.Errorf("provider name is required")
	}
	if builder == nil {
		return fmt.Errorf("provider %s builder is required", info.Name)
	}
	if _, exists := r.providers[info.Name]; exists {
		return fmt.Errorf("provider %s is already registered", info.Name)
	}
	if existing, exists := r.aliases[info.Name]; exists {
		return fmt.Errorf("provider name %s is already an alias for %s", info.Name, existing)
	}
	for _, alias := range info.Aliases {
		alias = normalize(alias)
		if alias == "" {
			return fmt.Errorf("provider %s has an empty alias", info.Name)
		}
		if _, exists := r.providers[alias]; exists {
			return fmt.Errorf("provider alias %s conflicts with a provider", alias)
		}
		if existing, exists := r.aliases[alias]; exists {
			return fmt.Errorf("provider alias %s is already registered for %s", alias, existing)
		}
	}
	r.providers[info.Name] = registeredProvider{info: info, builder: builder}
	r.aliases[info.Name] = info.Name
	for _, alias := range info.Aliases {
		r.aliases[normalize(alias)] = info.Name
	}
	return nil
}

func (r *Registry) Providers() []ProviderInfo {
	providers := make([]ProviderInfo, 0, len(r.providers))
	for _, provider := range r.providers {
		providers = append(providers, provider.info)
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Name < providers[j].Name })
	return providers
}

func (r *Registry) Resolve(config Config) (Config, error) {
	providerName := firstNonEmpty(config.Provider, os.Getenv("SECURITY_SCANNER_PROVIDER"), "openai")
	canonical, ok := r.aliases[normalize(providerName)]
	if !ok {
		return Config{}, fmt.Errorf("unknown model provider %q; supported providers: %s", providerName, strings.Join(r.providerNames(), ", "))
	}
	provider := r.providers[canonical]
	authMode := normalize(config.AuthMode)
	if authMode == "" {
		authMode = "auto"
	}
	explicitAPIKey := strings.TrimSpace(config.APIKey)
	switch authMode {
	case "auto":
	case "env":
		if explicitAPIKey != "" {
			return Config{}, fmt.Errorf("--auth env cannot be combined with --api-key")
		}
	case "api-key":
		if explicitAPIKey == "" {
			return Config{}, fmt.Errorf("--auth api-key requires --api-key")
		}
	case "none":
		if explicitAPIKey != "" {
			return Config{}, fmt.Errorf("--auth none cannot be combined with --api-key")
		}
	default:
		return Config{}, fmt.Errorf("invalid auth mode %q; expected auto, env, api-key, or none", config.AuthMode)
	}
	config.AuthMode = authMode
	config.Provider = canonical
	switch authMode {
	case "none":
		config.APIKey = ""
	case "api-key":
		config.APIKey = explicitAPIKey
	default:
		config.APIKey = firstNonEmpty(config.APIKey, os.Getenv("SECURITY_SCANNER_API_KEY"), env(provider.info.APIKeyEnv))
	}
	config.Model = firstNonEmpty(config.Model, os.Getenv("SECURITY_SCANNER_MODEL"), env(provider.info.ModelEnv), provider.info.DefaultModel)
	config.BaseURL = firstNonEmpty(config.BaseURL, os.Getenv("SECURITY_SCANNER_BASE_URL"), env(provider.info.BaseURLEnv), provider.info.DefaultBaseURL)
	config.APIVersion = firstNonEmpty(config.APIVersion, os.Getenv("SECURITY_SCANNER_API_VERSION"), env(provider.info.APIVersionEnv))
	if config.MaxOutputTokens == 0 {
		if value := strings.TrimSpace(os.Getenv("SECURITY_SCANNER_MAX_OUTPUT_TOKENS")); value != "" {
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 {
				return Config{}, fmt.Errorf("SECURITY_SCANNER_MAX_OUTPUT_TOKENS must be a non-negative integer")
			}
			config.MaxOutputTokens = parsed
		}
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Minute
	}
	if strings.TrimSpace(config.Model) == "" {
		return Config{}, fmt.Errorf("model is required for provider %s; use --model or %s", canonical, provider.info.ModelEnv)
	}
	if provider.info.RequiresAPIKey && strings.TrimSpace(config.APIKey) == "" {
		return Config{}, fmt.Errorf("API key is required for provider %s; use --api-key or %s", canonical, provider.info.APIKeyEnv)
	}
	if canonical == "openai-compatible" && strings.TrimSpace(config.BaseURL) == "" {
		return Config{}, fmt.Errorf("base URL is required for provider openai-compatible")
	}
	if canonical == "azure-openai" {
		if strings.TrimSpace(config.BaseURL) == "" {
			return Config{}, fmt.Errorf("base URL is required for provider azure-openai")
		}
		if strings.TrimSpace(config.APIVersion) == "" {
			return Config{}, fmt.Errorf("API version is required for provider azure-openai; use --api-version or %s", provider.info.APIVersionEnv)
		}
	}
	if config.MaxOutputTokens < 0 {
		return Config{}, fmt.Errorf("max output tokens cannot be negative")
	}
	return config, nil
}

func (r *Registry) Build(ctx context.Context, config Config) (model.BaseChatModel, Config, error) {
	resolved, err := r.Resolve(config)
	if err != nil {
		return nil, Config{}, err
	}
	provider := r.providers[resolved.Provider]
	chatModel, err := provider.builder(ctx, resolved)
	if err != nil {
		return nil, Config{}, fmt.Errorf("create %s model %s: %w", resolved.Provider, resolved.Model, err)
	}
	return chatModel, resolved, nil
}

func (r *Registry) providerNames() []string {
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func buildOpenAI(ctx context.Context, config Config) (model.BaseChatModel, error) {
	return openaiadapter.NewChatModel(ctx, &openaiadapter.ChatModelConfig{
		APIKey: config.APIKey, BaseURL: config.BaseURL, Model: config.Model, Timeout: config.Timeout,
		MaxCompletionTokens: optionalInt(config.MaxOutputTokens),
	})
}

func buildAzureOpenAI(ctx context.Context, config Config) (model.BaseChatModel, error) {
	return openaiadapter.NewChatModel(ctx, &openaiadapter.ChatModelConfig{
		APIKey: config.APIKey, BaseURL: config.BaseURL, Model: config.Model, Timeout: config.Timeout,
		APIVersion: config.APIVersion, ByAzure: true, MaxCompletionTokens: optionalInt(config.MaxOutputTokens),
	})
}

func buildOpenRouter(ctx context.Context, config Config) (model.BaseChatModel, error) {
	return openroutermodel.NewChatModel(ctx, &openroutermodel.Config{
		APIKey: config.APIKey, BaseURL: config.BaseURL, Model: config.Model, Timeout: config.Timeout,
		MaxCompletionTokens: optionalInt(config.MaxOutputTokens),
	})
}

func buildClaude(ctx context.Context, config Config) (model.BaseChatModel, error) {
	maxTokens := config.MaxOutputTokens
	if maxTokens == 0 {
		maxTokens = 8192
	}
	var baseURL *string
	if config.BaseURL != "" {
		baseURL = &config.BaseURL
	}
	return claudemodel.NewChatModel(ctx, &claudemodel.Config{
		APIKey: config.APIKey, BaseURL: baseURL, Model: config.Model, MaxTokens: maxTokens, RequestTimeout: config.Timeout,
	})
}

func buildGemini(ctx context.Context, config Config) (model.BaseChatModel, error) {
	clientConfig := &genai.ClientConfig{APIKey: config.APIKey}
	timeout := config.Timeout
	clientConfig.HTTPOptions = genai.HTTPOptions{BaseURL: config.BaseURL, APIVersion: config.APIVersion, Timeout: &timeout}
	client, err := genai.NewClient(ctx, clientConfig)
	if err != nil {
		return nil, err
	}
	return geminimodel.NewChatModel(ctx, &geminimodel.Config{
		Client: client, Model: config.Model, MaxTokens: optionalInt(config.MaxOutputTokens),
	})
}

func buildOllama(ctx context.Context, config Config) (model.BaseChatModel, error) {
	return ollamamodel.NewChatModel(ctx, &ollamamodel.ChatModelConfig{
		BaseURL: config.BaseURL, Model: config.Model, Timeout: config.Timeout,
	})
}

func buildArk(ctx context.Context, config Config) (model.BaseChatModel, error) {
	timeout := config.Timeout
	return arkmodel.NewChatModel(ctx, &arkmodel.ChatModelConfig{
		APIKey: config.APIKey, BaseURL: config.BaseURL, Model: config.Model, Timeout: &timeout,
		MaxTokens: optionalInt(config.MaxOutputTokens),
	})
}

func optionalInt(value int) *int {
	if value <= 0 {
		return nil
	}
	return &value
}

func mustRegister(registry *Registry, info ProviderInfo, builder Builder) {
	if err := registry.Register(info, builder); err != nil {
		panic(err)
	}
}

func normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func env(name string) string {
	if name == "" {
		return ""
	}
	return os.Getenv(name)
}

var (
	_ model.ToolCallingChatModel = (*openaiadapter.ChatModel)(nil)
	_ model.ToolCallingChatModel = (*openroutermodel.ChatModel)(nil)
	_ model.ToolCallingChatModel = (*claudemodel.ChatModel)(nil)
	_ model.ToolCallingChatModel = (*geminimodel.ChatModel)(nil)
	_ model.ToolCallingChatModel = (*ollamamodel.ChatModel)(nil)
	_ model.ToolCallingChatModel = (*arkmodel.ChatModel)(nil)
)
