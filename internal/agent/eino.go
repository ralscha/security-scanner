package agent

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/prebuilt/deep"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"

	"security-scanner/internal/scan"
)

type Config struct {
	MaxIterations  int
	Progress       func(string)
	ScanPrompt     string
	FollowUpPrompt string
}

type EinoAnalyzer struct {
	chatModel model.BaseChatModel
	config    Config
	inventory *scan.Inventory
	tracker   *ReadTracker
}

func NewEinoAnalyzer(chatModel model.BaseChatModel, config Config, inventory *scan.Inventory, tracker *ReadTracker) *EinoAnalyzer {
	return &EinoAnalyzer{chatModel: chatModel, config: config, inventory: inventory, tracker: tracker}
}

func (a *EinoAnalyzer) Analyze(ctx context.Context, userContext string) (scan.Submission, error) {
	if a.chatModel == nil {
		return scan.Submission{}, fmt.Errorf("eino chat model is required")
	}
	if a.config.MaxIterations <= 0 {
		a.config.MaxIterations = 80
	}
	repository := NewRepository(a.inventory, a.tracker)
	repositoryTools, err := repository.Tools()
	if err != nil {
		return scan.Submission{}, fmt.Errorf("create repository tools: %w", err)
	}
	store := NewSubmissionStore(a.inventory)
	submitTool, err := store.Tool()
	if err != nil {
		return scan.Submission{}, fmt.Errorf("create submit tool: %w", err)
	}

	specialists, err := createSpecialists(ctx, a.chatModel, repositoryTools, a.config.MaxIterations, a.config.FollowUpPrompt)
	if err != nil {
		return scan.Submission{}, err
	}
	allTools := append(append([]tool.BaseTool(nil), repositoryTools...), submitTool)
	coordinator, err := deep.New(ctx, &deep.Config{
		Name:                   "security-scan-coordinator",
		Description:            "Coordinates exhaustive security discovery, validation, and attack-path analysis",
		ChatModel:              a.chatModel,
		Instruction:            coordinatorInstruction(a.config.ScanPrompt),
		SubAgents:              specialists,
		WithoutGeneralSubAgent: true,
		MaxIteration:           a.config.MaxIterations,
		ToolsConfig: adk.ToolsConfig{
			ToolsNodeConfig:    compose.ToolsNodeConfig{Tools: allTools},
			EmitInternalEvents: true,
		},
	})
	if err != nil {
		return scan.Submission{}, fmt.Errorf("create Eino DeepAgent: %w", err)
	}

	reviewable := 0
	for _, file := range a.inventory.Files {
		if file.Reviewable {
			reviewable++
		}
	}
	runner := adk.NewRunner(ctx, adk.RunnerConfig{Agent: coordinator})
	iterator := runner.Query(ctx, scanRequest(filepath.Base(a.inventory.Root), userContext, len(a.inventory.Files), reviewable))
	seenAgents := make(map[string]struct{})
	for {
		event, ok := iterator.Next()
		if !ok {
			break
		}
		if event.Err != nil {
			return scan.Submission{}, fmt.Errorf("eino agent run: %w", event.Err)
		}
		if event.AgentName != "" {
			if _, seen := seenAgents[event.AgentName]; !seen && a.config.Progress != nil {
				a.config.Progress("agent active: " + event.AgentName)
				seenAgents[event.AgentName] = struct{}{}
			}
		}
		if event.Output != nil && event.Output.MessageOutput != nil {
			_, _, err := adk.GetMessage(event)
			if err != nil {
				return scan.Submission{}, fmt.Errorf("read Eino event: %w", err)
			}
		}
	}
	submission, ok := store.Get()
	if !ok {
		return scan.Submission{}, fmt.Errorf("agent finished without a valid submit_scan call")
	}
	return submission, nil
}

func createSpecialists(ctx context.Context, chatModel model.BaseChatModel, tools []tool.BaseTool, maxIterations int, followUpPrompt string) ([]adk.Agent, error) {
	configs := []struct {
		name        string
		description string
		instruction string
	}{
		{name: "baseline", description: "Runs an independent general security audit without coordinator hypotheses", instruction: baselinePrompt},
		{name: "discovery", description: "Investigates focused source-backed security questions and evidence paths", instruction: discoveryPrompt},
		{name: "validation", description: "Adversarially validates or rejects vulnerability candidates", instruction: validationPrompt},
		{name: "attack-path", description: "Establishes reachability, impact, severity, and remediation", instruction: attackPathPrompt},
	}
	agents := make([]adk.Agent, 0, len(configs))
	for _, cfg := range configs {
		agent, err := adk.NewChatModelAgent(ctx, &adk.ChatModelAgentConfig{
			Name:          cfg.name,
			Description:   cfg.description,
			Instruction:   specialistInstruction(cfg.instruction, followUpPrompt),
			Model:         chatModel,
			MaxIterations: maxIterations,
			ToolsConfig: adk.ToolsConfig{
				ToolsNodeConfig: compose.ToolsNodeConfig{Tools: tools},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("create %s specialist: %w", cfg.name, err)
		}
		agents = append(agents, agent)
	}
	return agents, nil
}
