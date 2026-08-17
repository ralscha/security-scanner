package scan

import (
	"encoding/json"
	"time"
)

const SchemaVersion = "1"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Location struct {
	Path      string `json:"path" jsonschema:"description=Repository-relative path"`
	StartLine int    `json:"start_line" jsonschema:"description=First affected line,minimum=1"`
	EndLine   int    `json:"end_line,omitempty" jsonschema:"description=Last affected line,minimum=1"`
	Role      string `json:"role" jsonschema:"description=Security role such as source root_control sink entrypoint or evidence"`
	Snippet   string `json:"snippet,omitempty"`
}

type FindingDraft struct {
	Title       string     `json:"title" jsonschema:"description=Specific vulnerability title"`
	Severity    Severity   `json:"severity" jsonschema:"enum=critical,enum=high,enum=medium,enum=low,enum=info"`
	Confidence  Confidence `json:"confidence" jsonschema:"enum=high,enum=medium,enum=low"`
	CWEIDs      []string   `json:"cwe_ids" jsonschema:"description=Applicable CWE identifiers such as CWE-79"`
	Summary     string     `json:"summary" jsonschema:"description=Concise description of the broken security control"`
	Impact      string     `json:"impact" jsonschema:"description=Concrete attacker impact"`
	Evidence    string     `json:"evidence" jsonschema:"description=Source to sink evidence grounded in the code"`
	Remediation string     `json:"remediation" jsonschema:"description=Actionable fix for the root cause"`
	AttackPath  string     `json:"attack_path" jsonschema:"description=Realistic reachability and preconditions"`
	Locations   []Location `json:"locations" jsonschema:"description=All source control and sink locations"`
}

type Finding struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	FindingDraft
}

type Submission struct {
	ThreatModel string         `json:"threat_model" jsonschema:"description=Trust boundaries assets attacker capabilities and exposed entrypoints"`
	Findings    []FindingDraft `json:"findings" jsonschema:"description=Only validated and realistically reachable findings; empty is valid"`
	Gaps        []string       `json:"gaps,omitempty" jsonschema:"description=Analysis limitations unrelated to automatically measured file coverage"`
}

type File struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	Lines      int    `json:"lines"`
	Language   string `json:"language,omitempty"`
	Reviewable bool   `json:"reviewable"`
	SkipReason string `json:"skip_reason,omitempty"`
	digest     string
}

type Inventory struct {
	Root          string `json:"root"`
	Files         []File `json:"files"`
	options       InventoryOptions
	snapshotReady bool
}

type CoverageFile struct {
	Path    string `json:"path"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
}

type CoverageSummary struct {
	Total      int `json:"total"`
	Reviewed   int `json:"reviewed"`
	Unreviewed int `json:"unreviewed"`
	Skipped    int `json:"skipped"`
}

type CoverageDocument struct {
	SchemaVersion string          `json:"schema_version"`
	ScanID        string          `json:"scan_id,omitempty"`
	Summary       CoverageSummary `json:"summary"`
	Files         []CoverageFile  `json:"files"`
}

type FindingsDocument struct {
	SchemaVersion string    `json:"schema_version"`
	ScanID        string    `json:"scan_id"`
	ThreatModel   string    `json:"threat_model"`
	Findings      []Finding `json:"findings"`
	Gaps          []string  `json:"gaps,omitempty"`
}

type TimingBreakdown struct {
	PreparationMS int64 `json:"preparation_ms"`
	AnalysisMS    int64 `json:"analysis_ms"`
}

type ActivityEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	Event        string    `json:"event"`
	Message      string    `json:"message,omitempty"`
	ScanID       string    `json:"scan_id,omitempty"`
	Attempt      int       `json:"attempt,omitempty"`
	Phase        string    `json:"phase,omitempty"`
	ErrorClass   string    `json:"error_class,omitempty"`
	Retryable    *bool     `json:"retryable,omitempty"`
	CheckpointID string    `json:"checkpoint_id,omitempty"`
	WorkerID     string    `json:"worker_id,omitempty"`
	WorkerRole   string    `json:"worker_role,omitempty"`
}

// LaunchConfiguration contains the inputs needed to faithfully rerun a scan.
// API keys are intentionally never persisted.
type LaunchConfiguration struct {
	AuthMode                      string   `json:"auth_mode,omitempty"`
	RequiresExplicitAPIKey        bool     `json:"requires_explicit_api_key,omitempty"`
	BaseURL                       string   `json:"base_url,omitempty"`
	APIVersion                    string   `json:"api_version,omitempty"`
	MaxOutputTokens               int      `json:"max_output_tokens,omitempty"`
	UserContext                   string   `json:"user_context,omitempty"`
	ScanPrompt                    string   `json:"scan_prompt,omitempty"`
	FollowUpPrompt                string   `json:"follow_up_prompt,omitempty"`
	PostScanPrompt                string   `json:"post_scan_prompt,omitempty"`
	PostScanOn                    string   `json:"post_scan_on,omitempty"`
	PostScanFailureMode           string   `json:"post_scan_failure_mode,omitempty"`
	PostScanMaxDuration           string   `json:"post_scan_max_duration,omitempty"`
	PostScanMaxIterations         int      `json:"post_scan_max_iterations,omitempty"`
	KnowledgeBasePaths            []string `json:"knowledge_base_paths,omitempty"`
	KnowledgeBaseMaxDocuments     int      `json:"knowledge_base_max_documents,omitempty"`
	KnowledgeBaseMaxDocumentBytes int64    `json:"knowledge_base_max_document_bytes,omitempty"`
	KnowledgeBaseMaxTotalBytes    int64    `json:"knowledge_base_max_total_bytes,omitempty"`
	Excludes                      []string `json:"excludes,omitempty"`
	MaxFileBytes                  int64    `json:"max_file_bytes,omitempty"`
	MaxIterations                 int      `json:"max_iterations,omitempty"`
	MaxAgentConcurrency           int      `json:"max_agent_concurrency,omitempty"`
	RequestTimeout                string   `json:"request_timeout,omitempty"`
	MaxDuration                   string   `json:"max_duration,omitempty"`
	FailOnSeverity                string   `json:"fail_on_severity,omitempty"`
	MaxAnalysisAttempts           int      `json:"max_analysis_attempts,omitempty"`
	AnalysisRetryBaseDelay        string   `json:"analysis_retry_base_delay,omitempty"`
}

type ScanManifest struct {
	SchemaVersion   string               `json:"schema_version"`
	ScanID          string               `json:"scan_id"`
	Status          string               `json:"status"`
	Target          string               `json:"target"`
	Provider        string               `json:"provider"`
	Model           string               `json:"model"`
	TargetMode      string               `json:"target_mode,omitempty"`
	TargetRef       string               `json:"target_ref,omitempty"`
	TargetPaths     []string             `json:"target_paths,omitempty"`
	StartedAt       time.Time            `json:"started_at"`
	CompletedAt     time.Time            `json:"completed_at"`
	Artifacts       map[string]string    `json:"artifacts"`
	ArtifactDigests map[string]string    `json:"artifact_digests"`
	FilesTotal      int                  `json:"files_total"`
	FilesReviewed   int                  `json:"files_reviewed"`
	FindingCount    int                  `json:"finding_count"`
	DurationMS      int64                `json:"duration_ms"`
	Timings         TimingBreakdown      `json:"timings"`
	LaunchConfig    *LaunchConfiguration `json:"launch_configuration,omitempty"`
}

type Result struct {
	Manifest         ScanManifest
	Findings         FindingsDocument
	Coverage         CoverageDocument
	Activity         []ActivityEvent
	OutDir           string
	Warnings         []string
	AnalysisAttempts int
	PostScan         json.RawMessage `json:"post_scan,omitempty"`
}
