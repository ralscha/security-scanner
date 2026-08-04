package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"security-scanner/internal/agent"
	"security-scanner/internal/history"
	"security-scanner/internal/llm"
	"security-scanner/internal/output"
	"security-scanner/internal/scan"
)

type Options struct {
	Target              string
	OutputDir           string
	Provider            string
	Model               string
	APIKey              string
	BaseURL             string
	APIVersion          string
	MaxOutputTokens     int
	UserContext         string
	Excludes            []string
	Includes            []string
	TargetMode          string
	TargetRef           string
	ArchiveExisting     bool
	AuthMode            string
	MaxFileBytes        int64
	MaxIterations       int
	MaxAgentConcurrency int
	RequestTimeout      time.Duration
	MaxDuration         time.Duration
	FailOnSeverity      string
	Progress            func(string)
}

type Preparation struct {
	Target    string          `json:"target"`
	OutputDir string          `json:"output_dir"`
	Model     llm.Config      `json:"-"`
	Provider  string          `json:"provider"`
	ModelName string          `json:"model"`
	Inventory *scan.Inventory `json:"inventory"`
}

func Run(ctx context.Context, opts Options) (*scan.Result, error) {
	started := time.Now().UTC()
	if opts.MaxAgentConcurrency < 0 {
		return nil, fmt.Errorf("max agent concurrency cannot be negative")
	}
	if opts.MaxAgentConcurrency == 0 {
		opts.MaxAgentConcurrency = 4
	}
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = 1024 * 1024
	}
	if opts.MaxIterations <= 0 {
		opts.MaxIterations = 80
	}
	prepared, err := Prepare(opts, started)
	if err != nil {
		return nil, err
	}
	if archived, err := output.Prepare(prepared.OutputDir, opts.ArchiveExisting, started); err != nil {
		return nil, err
	} else if archived != "" && opts.Progress != nil {
		opts.Progress("archived existing output to " + archived)
	}
	outputGuard, err := output.PreparePrivateDir(prepared.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("prepare private output directory: %w", err)
	}
	chatModel, resolvedModel, err := llm.DefaultRegistry().Build(ctx, prepared.Model)
	if err != nil {
		return nil, err
	}
	chatModel, err = llm.LimitConcurrency(chatModel, opts.MaxAgentConcurrency)
	if err != nil {
		return nil, err
	}
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("using %s model %s", resolvedModel.Provider, resolvedModel.Model))
		opts.Progress(fmt.Sprintf("inventory contains %d files", len(prepared.Inventory.Files)))
	}
	preparationDuration := time.Since(started)
	tracker := agent.NewReadTracker()
	analyzer := agent.NewEinoAnalyzer(chatModel, agent.Config{
		MaxIterations: opts.MaxIterations,
		Progress:      opts.Progress,
	}, prepared.Inventory, tracker)
	analysisStarted := time.Now()
	submission, err := analyzer.Analyze(ctx, opts.UserContext)
	if err != nil {
		return nil, err
	}
	if opts.Progress != nil {
		opts.Progress("validating and writing scan artifacts")
	}
	result, err := scan.Finalize(prepared.Inventory, tracker, submission, scan.FinalizeOptions{
		OutputDir:           prepared.OutputDir,
		Provider:            resolvedModel.Provider,
		Model:               resolvedModel.Model,
		StartedAt:           started,
		TargetMode:          opts.TargetMode,
		TargetRef:           opts.TargetRef,
		TargetPaths:         opts.Includes,
		PreparationDuration: preparationDuration,
		AnalysisDuration:    time.Since(analysisStarted),
		OutputGuard:         outputGuard,
		LaunchConfig: &scan.LaunchConfiguration{
			AuthMode:               resolvedModel.AuthMode,
			RequiresExplicitAPIKey: strings.TrimSpace(opts.APIKey) != "",
			BaseURL:                resolvedModel.BaseURL,
			APIVersion:             resolvedModel.APIVersion,
			MaxOutputTokens:        resolvedModel.MaxOutputTokens,
			UserContext:            opts.UserContext,
			Excludes:               append([]string(nil), opts.Excludes...),
			MaxFileBytes:           opts.MaxFileBytes,
			MaxIterations:          opts.MaxIterations,
			MaxAgentConcurrency:    opts.MaxAgentConcurrency,
			RequestTimeout:         resolvedModel.Timeout.String(),
			MaxDuration:            durationString(opts.MaxDuration),
			FailOnSeverity:         strings.TrimSpace(opts.FailOnSeverity),
		},
	})
	if err != nil {
		return nil, err
	}
	store, err := history.DefaultStore()
	if err != nil {
		return nil, err
	}
	if err := store.Add(result); err != nil {
		return nil, fmt.Errorf("record scan history: %w", err)
	}
	return result, nil
}

func durationString(duration time.Duration) string {
	if duration <= 0 {
		return ""
	}
	return duration.String()
}

// Prepare validates a scan and freezes its inventory without constructing or calling a model.
func Prepare(opts Options, started time.Time) (*Preparation, error) {
	if opts.Target == "" {
		opts.Target = "."
	}
	absTarget, err := filepath.Abs(opts.Target)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	absTarget, err = filepath.EvalSymlinks(absTarget)
	if err != nil {
		return nil, fmt.Errorf("resolve target symlinks: %w", err)
	}
	if opts.OutputDir == "" {
		opts.OutputDir, err = output.DefaultScanDir(absTarget, started)
		if err != nil {
			return nil, err
		}
	} else if opts.OutputDir, err = filepath.Abs(opts.OutputDir); err != nil {
		return nil, fmt.Errorf("resolve output directory: %w", err)
	}
	if samePath(absTarget, opts.OutputDir) {
		return nil, fmt.Errorf("output directory cannot be the scan target")
	}
	if err := rejectOutputSymlinks(absTarget, opts.OutputDir); err != nil {
		return nil, err
	}
	if opts.OutputDir, err = output.Validate(context.Background(), absTarget, opts.OutputDir, opts.ArchiveExisting); err != nil {
		return nil, err
	}
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = 1024 * 1024
	}
	resolvedModel, err := llm.DefaultRegistry().Resolve(llm.Config{
		Provider:        opts.Provider,
		Model:           opts.Model,
		APIKey:          opts.APIKey,
		BaseURL:         opts.BaseURL,
		APIVersion:      opts.APIVersion,
		MaxOutputTokens: opts.MaxOutputTokens,
		Timeout:         opts.RequestTimeout,
		AuthMode:        opts.AuthMode,
	})
	if err != nil {
		return nil, err
	}
	if opts.Progress != nil {
		opts.Progress("building fixed file inventory")
	}
	inventory, err := scan.BuildInventory(absTarget, scan.InventoryOptions{
		MaxFileBytes: opts.MaxFileBytes,
		OutputDir:    opts.OutputDir,
		Excludes:     opts.Excludes,
		Includes:     opts.Includes,
	})
	if err != nil {
		return nil, err
	}
	if len(inventory.Files) == 0 {
		return nil, fmt.Errorf("target contains no files after exclusions")
	}
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("inventory contains %d files", len(inventory.Files)))
	}
	return &Preparation{
		Target: absTarget, OutputDir: opts.OutputDir, Model: resolvedModel,
		Provider: resolvedModel.Provider, ModelName: resolvedModel.Model, Inventory: inventory,
	}, nil
}

func samePath(left, right string) bool {
	rel, err := filepath.Rel(filepath.Clean(left), filepath.Clean(right))
	return err == nil && rel == "."
}

func rejectOutputSymlinks(root, output string) error {
	rel, err := filepath.Rel(root, output)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil
	}
	current := root
	for part := range strings.SplitSeq(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect output path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("output path inside target traverses symlink: %s", current)
		}
	}
	return nil
}
