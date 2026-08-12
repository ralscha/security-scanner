package preflight

import (
	"context"
	"time"

	"security-scanner/internal/app"
	"security-scanner/internal/redact"
)

type Check struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type Result struct {
	OK                     bool    `json:"ok"`
	Target                 string  `json:"target,omitempty"`
	OutputDir              string  `json:"output_dir,omitempty"`
	Provider               string  `json:"provider,omitempty"`
	Model                  string  `json:"model,omitempty"`
	FilesTotal             int     `json:"files_total,omitempty"`
	KnowledgeBaseDocuments int     `json:"knowledge_base_documents,omitempty"`
	Checks                 []Check `json:"checks"`
}

func Run(_ context.Context, opts app.Options) Result {
	prepared, err := app.Prepare(opts, time.Now().UTC())
	if err != nil {
		return Result{Checks: []Check{{Name: "configuration", Status: "error", Message: redact.Text(err.Error())}}}
	}
	return Result{
		OK: true, Target: prepared.Target, OutputDir: prepared.OutputDir,
		Provider: prepared.Provider, Model: prepared.ModelName, FilesTotal: len(prepared.Inventory.Files), KnowledgeBaseDocuments: knowledgeDocumentCount(prepared),
		Checks: []Check{
			{Name: "repository", Status: "ok", Message: "target is readable and contains reviewable scope"},
			{Name: "output", Status: "ok", Message: "output path resolved and destination policy passed"},
			{Name: "provider", Status: "ok", Message: "provider, model, and authentication configuration resolved"},
			{Name: "knowledge_base", Status: "ok", Message: "knowledge-base paths and document limits passed"},
		},
	}
}

func knowledgeDocumentCount(prepared *app.Preparation) int {
	if prepared == nil || prepared.KnowledgeBase == nil {
		return 0
	}
	return len(prepared.KnowledgeBase.Documents)
}
