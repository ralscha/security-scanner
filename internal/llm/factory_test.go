package llm

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

func TestResolveProviderAliasesAndEnvironment(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "native-key")
	t.Setenv("ANTHROPIC_MODEL", "claude-test")
	t.Setenv("SECURITY_SCANNER_API_KEY", "")
	t.Setenv("SECURITY_SCANNER_MODEL", "")
	resolved, err := DefaultRegistry().Resolve(Config{Provider: "Claude"})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Provider != "anthropic" || resolved.APIKey != "native-key" || resolved.Model != "claude-test" {
		t.Fatalf("unexpected resolved config: %#v", resolved)
	}

	t.Setenv("SECURITY_SCANNER_MODEL", "scanner-override")
	resolved, err = DefaultRegistry().Resolve(Config{Provider: "anthropic", APIKey: "flag-key"})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.APIKey != "flag-key" || resolved.Model != "scanner-override" {
		t.Fatalf("override precedence is wrong: %#v", resolved)
	}
}

func TestResolveProviderRequirements(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("SECURITY_SCANNER_API_KEY", "")
	t.Setenv("SECURITY_SCANNER_MODEL", "")
	registry := DefaultRegistry()
	if _, err := registry.Resolve(Config{Provider: "openai"}); err == nil || !strings.Contains(err.Error(), "API key") {
		t.Fatalf("expected OpenAI API key error, got %v", err)
	}
	compatible, err := registry.Resolve(Config{Provider: "custom", BaseURL: "http://localhost:8080/v1", Model: "local-model"})
	if err != nil {
		t.Fatal(err)
	}
	if compatible.Provider != "openai-compatible" || compatible.APIKey != "" {
		t.Fatalf("unexpected compatible config: %#v", compatible)
	}
	if _, err := registry.Resolve(Config{Provider: "azure", APIKey: "key", BaseURL: "https://example.test", Model: "deployment"}); err == nil || !strings.Contains(err.Error(), "API version") {
		t.Fatalf("expected Azure API version error, got %v", err)
	}
}

func TestResolveFireworksEnvironment(t *testing.T) {
	t.Setenv("FIREWORKS_API_KEY", "fireworks-key")
	t.Setenv("FIREWORKS_MODEL", "accounts/fireworks/models/test")
	t.Setenv("SECURITY_SCANNER_API_KEY", "")
	t.Setenv("SECURITY_SCANNER_MODEL", "")
	t.Setenv("SECURITY_SCANNER_BASE_URL", "")
	resolved, err := DefaultRegistry().Resolve(Config{Provider: "fireworks"})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.APIKey != "fireworks-key" || resolved.Model != "accounts/fireworks/models/test" || resolved.BaseURL != "https://api.fireworks.ai/inference/v1" {
		t.Fatalf("unexpected Fireworks configuration: %#v", resolved)
	}
}

func TestDefaultProviderBuilders(t *testing.T) {
	t.Setenv("SECURITY_SCANNER_API_KEY", "")
	t.Setenv("SECURITY_SCANNER_MODEL", "")
	t.Setenv("SECURITY_SCANNER_BASE_URL", "")
	configs := []Config{
		{Provider: "openai", APIKey: "test", Model: "test"},
		{Provider: "openai-compatible", BaseURL: "http://localhost:8080/v1", Model: "test"},
		{Provider: "azure-openai", APIKey: "test", BaseURL: "https://example.test", APIVersion: "2025-01-01", Model: "test"},
		{Provider: "openrouter", APIKey: "test", Model: "test"},
		{Provider: "fireworks", APIKey: "test", Model: "test"},
		{Provider: "anthropic", APIKey: "test", Model: "test"},
		{Provider: "gemini", APIKey: "test", Model: "test"},
		{Provider: "ollama", Model: "test"},
		{Provider: "ark", APIKey: "test", Model: "test"},
	}
	registry := DefaultRegistry()
	for _, config := range configs {
		t.Run(config.Provider, func(t *testing.T) {
			chatModel, resolved, err := registry.Build(context.Background(), config)
			if err != nil {
				t.Fatal(err)
			}
			if chatModel == nil || resolved.Provider != config.Provider {
				t.Fatalf("unexpected build result: model=%T config=%#v", chatModel, resolved)
			}
			if _, ok := chatModel.(model.ToolCallingChatModel); !ok {
				t.Fatalf("provider model %T does not support immutable tool binding", chatModel)
			}
		})
	}
}

func TestRegistrySupportsCustomEinoModel(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register(ProviderInfo{Name: "in-memory", Aliases: []string{"test"}, DefaultModel: "fake"}, func(context.Context, Config) (model.BaseChatModel, error) {
		return fakeChatModel{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	chatModel, resolved, err := registry.Build(context.Background(), Config{Provider: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Provider != "in-memory" || reflect.TypeOf(chatModel) != reflect.TypeFor[fakeChatModel]() {
		t.Fatalf("custom provider was not used: %T %#v", chatModel, resolved)
	}
}

type fakeChatModel struct{}

func (fakeChatModel) Generate(context.Context, []*schema.Message, ...model.Option) (*schema.Message, error) {
	return schema.AssistantMessage("ok", nil), nil
}

func (fakeChatModel) Stream(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return schema.StreamReaderFromArray([]*schema.Message{schema.AssistantMessage("ok", nil)}), nil
}

var _ model.BaseChatModel = fakeChatModel{}

func TestResolveExplicitAuthModes(t *testing.T) {
	registry := DefaultRegistry()
	if _, err := registry.Resolve(Config{Provider: "openai", Model: "model", AuthMode: "api-key"}); err == nil {
		t.Fatal("api-key auth should require an explicit key")
	}
	resolved, err := registry.Resolve(Config{Provider: "ollama", Model: "model", AuthMode: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.AuthMode != "none" || resolved.APIKey != "" {
		t.Fatalf("unexpected auth resolution: %#v", resolved)
	}
	if _, err := registry.Resolve(Config{Provider: "ollama", Model: "model", AuthMode: "invalid"}); err == nil {
		t.Fatal("unknown auth mode should fail")
	}
}
