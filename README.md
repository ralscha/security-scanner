# Security Scanner

`security-scanner` is a Go CLI that inventories a codebase, uses an Eino DeepAgent to perform a security review, and writes a validated report bundle. Its scan engine depends on Eino's `model.BaseChatModel` abstraction rather than a provider SDK.

The scan workflow adapts the strongest ideas from Codex Security's repository scan process:

- Freeze one content-attested file inventory before analysis and account for every in-scope file.
- Separate candidate discovery, adversarial validation, and attack-path/severity reasoning.
- Require repository-relative, line-level evidence for every finding.
- Treat incomplete coverage as an explicit report state instead of claiming success.
- Produce canonical JSON first, then derive Markdown and SARIF deterministically.

## Architecture

The Eino DeepAgent is the coordinator. It has four named sub-agents: an independent `baseline` auditor plus focused `discovery`, adversarial `validation`, and `attack-path` specialists. The coordinator builds source-backed investigation packets, reconciles candidate results once, and retains full-inventory coverage responsibility. Agents receive only read-only repository capabilities: `list_files`, `read_file`, and `search_code` (`search_file` is a provider-compatibility alias). They have no shell and cannot write to the target.

Provider construction is isolated in a registry. The scanner includes Eino adapters for OpenAI, Azure OpenAI, OpenRouter, Fireworks AI, Anthropic Claude, Google Gemini, Ollama, and Volcengine Ark. The `openai-compatible` provider also covers servers and vendors that expose a compatible chat-completions and tool-calling API, including self-hosted gateways.

Go code owns the security boundary and final output:

- The inventory honors root and nested `.gitignore` rules, and excludes VCS metadata, dependency/build directories, `.scanner`, and explicit `--exclude` paths. An exact `--path` selection overrides ignore and default dependency/build exclusions, but never VCS metadata, `.scanner`, or `--exclude`.
- Symlinks and non-regular filesystem entries are inventoried as skipped. Content digests are checked on every read and again before artifacts are published, so changed targets fail closed.
- Full-file coverage is measured from actual `read_file` line ranges. Search results do not count as review.
- `submit_scan` rejects unknown files, invalid lines, malformed CWE values, and incomplete finding fields.
- Finding IDs, source snippets, coverage, Markdown, and SARIF are generated outside the model.

Repository contents and `--context` are always treated as untrusted analysis data, not agent instructions.

## Build

Requires Go 1.26.5 or newer.

```bash
go build -o security-scanner ./cmd/security-scanner
```

Prebuilt binaries are available from the [GitHub Releases page](https://github.com/ralscha/security-scanner/releases). After extracting an archive:

```bash
./security-scanner version
```

## Scan

OpenAI is the default provider. Set an API key and scan a repository:

```bash
export OPENAI_API_KEY="..."
./security-scanner scan --target /path/to/repo
```

The default OpenAI model is `gpt-5.6`. Provider, model, and endpoint can be selected independently:

```bash
./security-scanner scan \
  --target /path/to/repo \
  --output-dir "$HOME/security-reports/my-scan" \
  --provider openai \
  --model gpt-5.6 \
  --context "Internet-facing service; authenticated users are untrusted."
```

List the compiled providers and their native environment variables:

```bash
./security-scanner providers
```

### Provider Examples

Anthropic:

```bash
export ANTHROPIC_API_KEY="..."
./security-scanner scan --provider anthropic --model "YOUR_TOOL_CAPABLE_CLAUDE_MODEL" --target /path/to/repo
```

Gemini:

```bash
export GEMINI_API_KEY="..."
./security-scanner scan --provider gemini --model "YOUR_TOOL_CAPABLE_GEMINI_MODEL" --target /path/to/repo
```

Ollama requires no API key:

```bash
./security-scanner scan --provider ollama --model "YOUR_INSTALLED_TOOL_CAPABLE_MODEL" --target /path/to/repo
```

OpenRouter:

```bash
export OPENROUTER_API_KEY="..."
./security-scanner scan --provider openrouter --model "PROVIDER/MODEL" --target /path/to/repo
```

Fireworks AI:

```bash
export FIREWORKS_API_KEY="..."
./security-scanner scan \
  --provider fireworks \
  --model "accounts/fireworks/models/YOUR_MODEL" \
  --target /path/to/repo
```

Any OpenAI-compatible endpoint:

```bash
./security-scanner scan \
  --provider openai-compatible \
  --base-url http://localhost:8080/v1 \
  --model "YOUR_MODEL" \
  --target /path/to/repo
```

DeepSeek uses the OpenAI-compatible provider:

```bash
export LLM_API_KEY="..."
./security-scanner scan \
  --provider openai-compatible \
  --base-url https://api.deepseek.com \
  --model deepseek-v4-pro \
  --target /path/to/repo
```

Azure OpenAI additionally requires the deployment/model name and API version:

```bash
export AZURE_OPENAI_API_KEY="..."
export AZURE_OPENAI_ENDPOINT="https://example.openai.azure.com"
export OPENAI_API_VERSION="YOUR_API_VERSION"
./security-scanner scan --provider azure-openai --model "YOUR_DEPLOYMENT" --target /path/to/repo
```

Configuration precedence is: command-line flag, `SECURITY_SCANNER_*` environment variable, provider-native environment variable, then provider default. For example, `--model` overrides `SECURITY_SCANNER_MODEL`, which overrides `ANTHROPIC_MODEL` when the Anthropic provider is selected.

Useful controls:

```text
--exclude PATH          Repeatable repository-relative exclusion
--max-file-bytes N      Files above N are accounted for as skipped; 0 is unlimited (default)
--max-iterations N      Reasoning iterations available to each agent
--max-agent-concurrency N Maximum concurrent model requests across all agents
--max-output-tokens N   Provider response limit; 0 uses its default
--max-duration DURATION Overall deadline, such as 30m
--request-timeout D     Timeout for one model request
--scan-prompt TEXT      Custom coordinator prompt extension
--scan-prompt-file P    Read custom coordinator prompt extension from file
--follow-up-prompt TEXT Custom specialist follow-up prompt extension
--follow-up-prompt-file P Read custom specialist follow-up prompt extension from file
--knowledge-base PATH   Read-only .txt/.md/.markdown source; repeatable
--post-scan-prompt TEXT Run a separate advisory pass after the primary scan
--post-scan-on VALUE    success, gaps, failure, or all
--post-scan-failure-mode VALUE warn or fail
--max-analysis-attempts N Bounded primary-analysis attempts; default 1
--analysis-retry-base-delay D Base delay for typed transient retries
--quiet                 Suppress progress events
--json-progress         Emit JSON progress events on stderr
--json-progress-strict  With --json-progress, emit only JSON events on stderr
--verbose               Print redacted lifecycle diagnostics to stderr
```

`SECURITY_SCANNER_LOG_LEVEL=debug` also enables verbose diagnostics;
`LOG_LEVEL=debug` is used as a fallback. Scan results remain on stdout.

Target a subset of a repository with exactly one selector mode:

```bash
# One or more files/directories
./security-scanner scan --target /path/to/repo --path cmd --path internal/auth

# Committed changes from a Git revision to the clean, full HEAD checkout
./security-scanner scan --target /path/to/repo --diff origin/main

# Tracked modifications plus untracked files
./security-scanner scan --target /path/to/repo --working-tree
```

Committed-diff scans reject dirty or sparse checkouts so the inventoried source is the requested committed HEAD. Use `--working-tree` when local tracked or untracked changes are intentionally in scope.

Validate provider configuration and the resolved target without constructing or calling a model:

```bash
./security-scanner scan --target /path/to/repo --diff origin/main --dry-run
```

For CI, fail when a finding meets a threshold:

```bash
./security-scanner scan --target . --fail-on-severity high --quiet
```

Exit `1` means a completed scan violated the configured threshold. Exit `2` means invalid input, runtime failure, or incomplete coverage. See [the complete exit contract](docs/EXIT_CODES.md) and [capability matrix](docs/CAPABILITY_MATRIX.md).

API keys passed through `--api-key` may be exposed in process listings. Provider-native environment variables are preferred.

`--follow-up-prompt` keeps its original meaning: it extends specialist instructions inside the primary scan and can affect canonical findings and coverage. `--post-scan-prompt` starts a distinct, bounded pass after the primary attempt. That pass has read-only repository and knowledge-base tools and writes advisory output only; it cannot call `submit_scan` or replace canonical findings, coverage, Markdown, or SARIF.

Text knowledge bases are opt-in and may be supplied more than once:

```bash
./security-scanner scan --target . \
  --knowledge-base ./security-guidance \
  --knowledge-base ~/organization-policy.md
```

Directories are searched recursively for `.txt`, `.md`, and `.markdown` files. Documents are UTF-8, bounded, content-attested, and exposed to the model by logical ID. Their content is always untrusted analysis data. Defaults are 100 documents, 2 MiB per document, and 10 MiB of normalized text in total. The same flags work with `--dry-run`, `scan preflight`, rerun, and bulk scan.

Use a separate advisory pass when follow-through should not change scan truth:

```bash
./security-scanner scan --target . \
  --post-scan-prompt "Prioritize the next three remediation actions." \
  --post-scan-on all --post-scan-failure-mode warn
```

Post-scan defaults are `success`, `warn`, five minutes, and ten iterations. Eligible primary failures can trigger an advisory pass, but cancellation, deadline expiry, configuration/authentication failure, inventory drift, and recovery-state corruption never do. The primary error remains authoritative.

To inspect scope without making model calls:

```bash
./security-scanner inventory --target /path/to/repo
```

## Artifacts

Each scan writes:

- `scan-manifest.json`: scan identity, status, timestamps, provider/model, counts, artifact paths, and SHA-256 digests sealing every canonical artifact.
- `findings.json`: threat model and normalized findings.
- `coverage.json`: one outcome for every inventoried file.
- `report.md`: human-readable report derived from the canonical documents.
- `results.sarif`: SARIF 2.1.0 results for code scanning integrations.
- `scan-log.jsonl`: redacted lifecycle, preparation, and agent-activity events.
- `run-state.json`: private durable lifecycle and primary-attempt state, created before model analysis.

When configured and completed, the advisory pass additionally writes `post-scan.json` and `post-scan.md`. These fixed filenames are intentionally absent from the canonical manifest. If primary analysis fails, only private operational state and the activity log are retained; no findings, coverage, report, SARIF, or manifest is fabricated.

By default, artifacts are written below the per-user scanner state directory. An explicit `--output-dir` is resolved to an absolute, canonical path and must be disjoint from the scan target and its enclosing Git worktree: it may neither be inside that tree nor contain it. Scan directories and artifacts are private to the current operating-system user: POSIX output directories must use mode `0700` and have trusted, non-writable ancestry; Windows output receives a protected current-user-only ACL. A non-empty destination is rejected unless `--archive-existing` is supplied; in that case it is atomically renamed to a timestamped sibling before the new scan starts. Bulk scan output follows the same boundary so concurrent inventories remain isolated.

A scan is `completed` only when every reviewable text file was read from start to finish. Otherwise it is `completed_with_gaps`, and all unread files are listed.

## History And Triage

Scan sessions are indexed in the per-user scanner state directory before analysis, so failed sessions can also be resolved by exact or unique-prefix ID for `scans logs`. Canonical result commands still require completed artifacts:

```bash
./security-scanner scans list --target /path/to/repo
./security-scanner scans show SCAN_ID
./security-scanner scans logs SCAN_ID
./security-scanner scans logs SCAN_ID --json
./security-scanner scans rerun SCAN_ID
./security-scanner scans match BEFORE_SCAN_ID AFTER_SCAN_ID
./security-scanner scans compare BEFORE_SCAN_ID AFTER_SCAN_ID
./security-scanner scans compare --json BEFORE_SCAN_ID AFTER_SCAN_ID
```

Commands that accept a saved scan ID also accept any unique prefix. Ambiguous
prefixes are rejected and list the matching scan IDs.

From a repository root, `scans`, `findings`, `scans show`, `scans logs`, and
`scans rerun` use their natural list/latest default when the subcommand or scan
ID is omitted. `scans compare` uses the two latest completed scans when both
IDs are omitted, or compares an explicit earlier scan with the latest completed
scan when only one ID is supplied. Missing or damaged saved outputs are not
selected as completed-scan defaults.

New scans save their launch configuration, excluding API keys, so reruns retain
authentication mode, provider endpoint, target scope, exclusions, threat-model
context, policy, knowledge-base paths and bounds, post-scan policy, and runtime limits. Add `--verbose` to a rerun for diagnostics.
If the original command supplied `--api-key`, rerun it manually with the key;
the scanner never writes that credential to its manifest or history index.

Finding occurrences use `SCAN_ID:FINDING_ID`. Analyst decisions are stored separately from canonical scan artifacts:

```bash
./security-scanner findings list --target /path/to/repo
./security-scanner findings list --target /path/to/repo --json
./security-scanner findings false-positive "SCAN_ID:FINDING_ID" --reason "Protected by the authorization check at the only call site."
```

The repository findings view groups occurrences by stable fingerprint, keeps
open historical findings visible when the latest scan does not reconfirm them,
and suppresses identities marked false positive. Each entry states whether it
was seen in the repository's latest saved scan.

## Validation And Patch Assist

Validate a stored finding occurrence, an entire `findings.json` artifact, or an ad hoc prompt:

```bash
./security-scanner validate "SCAN_ID:FINDING_ID"
./security-scanner validate "$HOME/security-reports/scan/findings.json"
./security-scanner validate --target /path/to/repo "Check whether user input reaches the command runner."
```

`patch` uses the same input forms. It emits bounded proposed replacements, rationale, risks, and verification steps. It never modifies the repository. `--export` writes a new JSON file and refuses to overwrite an existing file:

```bash
./security-scanner patch --export "$HOME/security-reports/proposal.json" "SCAN_ID:FINDING_ID"
```

`patch` can also import read-only remediation requests from Linear. Select
individual issues by identifier or `linear.app` URL, or all matching issues in
one exactly named project. Project intake excludes completed and canceled
issues unless `--linear-filter` supplies its own `state` filter:

```bash
export CODEX_SECURITY_LINEAR_API_KEY="..."
./security-scanner patch --target /path/to/repo \
  --linear-issue SEC-123 --linear-issue SEC-456

./security-scanner patch --target /path/to/repo \
  --linear-project "Security backlog" \
  --linear-filter '{"priority":{"lte":2}}'
```

Credential precedence is `--linear-api-key`,
`CODEX_SECURITY_LINEAR_API_KEY`, `LINEAR_API_KEY`, then
`LINEAR_ACCESS_TOKEN`. Imported issue titles and descriptions are untrusted
requests; the reviewer must verify them against the explicitly selected local
repository before proposing changes.

## Publish Completed Scans To Linear

Publish every canonical finding from a completed saved scan as a separate
Linear issue:

```bash
export CODEX_SECURITY_LINEAR_API_KEY="..."
./security-scanner publish scan SCAN_ID \
  --to linear --linear-team TEAM_ID
```

`SCAN_ID` may be an exact ID, unique prefix, or the private scan directory.
Omitting it selects the latest valid completed scan for the current repository
and reports that selection before publication. Use `--linear-project PROJECT_ID`
(or its `--project` alias) to attach issues to a project, and
`--linear-assignee EMAIL_OR_USER_ID` to assign them. Team and project defaults
may be supplied by `CODEX_SECURITY_LINEAR_TEAM` and
`CODEX_SECURITY_LINEAR_PROJECT`.

Unlike the TypeScript upstream's optional Codex connected-app route, this Go
port publishes directly through Linear's API and therefore requires
`CODEX_SECURITY_LINEAR_API_KEY` or `--linear-api-key`. `--dry-run` is the
exception: it validates and renders every issue without contacting Linear or
writing publication state.

Issue titles use `[Codex Security][HIGH] Finding title`. Descriptions preserve
the scan/finding/occurrence IDs, repository and scope, coverage, timestamps,
severity, confidence, CWE classifications, affected locations and snippets,
impact, attack path, evidence, and remediation. Severity maps to Linear
priority 1 through 4; informational findings have no explicit priority.

Creation runs concurrently in sequential batches of at most 20. Individual
Linear rejections are retained in the structured result without discarding
successful issues. Private, atomically updated handoffs protect completed
mutations during interruption or persistence failure; successful runs write a
separate receipt below the scanner state directory and remove the temporary
handoff. Running publication again intentionally creates a new set of issues.
Publication data contains source snippets and vulnerability details, so the
Linear destination and local receipts must be handled like source code.

## Preflight And Bulk Scans

Authentication can be selected explicitly with `--auth auto`, `env`, `api-key`, or `none`. Preflight validates repository scope, output policy, credentials, and model selection without constructing a model:

```bash
./security-scanner scan preflight --target /path/to/repo --provider ollama --model qwen3-coder --auth none
./security-scanner scan preflight --target /path/to/repo --json
```

Bulk input may be a JSON string array, a JSON job array with per-repository `context`, a newline-delimited list, or a header-based CSV. CSV accepts `target`, `repository`, or `path` as the repository column and an optional `context` column in any order. Use a `.csv` extension for single-column CSV input so it cannot be confused with a newline-delimited list. A job array has this shape:

```json
[
  {
    "target": "/path/to/repo",
    "context": "Internet-facing service; authenticated users are untrusted."
  }
]
```

Equivalent CSV:

```csv
context,repository
Internet-facing service; authenticated users are untrusted.,/path/to/repo
```

Run the bulk scan:

```bash
./security-scanner bulk-scan repos.json \
  --output-dir "$HOME/security-reports/bulk" \
  --workers 4 --retries 2 --fail-on-severity high \
  --max-budget 20 --estimated-scan-cost 2
```

The input may appear before or after options, or be supplied with `--input repos.json`.

The atomic `bulk-receipt.json` supports resume. An OS-backed supervisor lock prevents concurrent bulk processes from using the same receipt and output directory. Completed scans with coverage gaps are recorded as `completed_with_gaps`: they still make the bulk command exit `2`, but their sealed artifacts are preserved and are not rescanned on resume. Receipts disclose outer job and inner analysis-attempt maxima; the combined ceiling is `(retries + 1) * max-analysis-attempts`. Warning-only post-scan failure does not cause an outer retry. Budget units are operator estimates, not provider billing claims; include expected post-scan work in the supplied estimate.

Provider adapters do not currently expose consistent usage accounting through Eino's shared model interface, so manifests do not claim token or billing totals. Bulk budget reservations are explicit operator-supplied estimates.

## Limitations

- Results depend on model capability and the available iteration/time budget.
- DeepAgent requires reliable structured tool calling. A text-only model or a model that merely accepts an OpenAI-compatible request without correctly implementing tool calls cannot run the scanner.
- The scanner does not execute builds, tests, dependency audits, or application code.
- Common dependency and build directories are excluded by default. Additional generated paths require `.gitignore` entries or `--exclude`.
- Provider-specific hosted tools are disabled. All providers receive the same scanner-owned read-only tools and report contract.
- PDF and DOCX knowledge-base parsing is not enabled; no ambient converter is executed.
- Eino v0.9.13 checkpoints are written at handled framework interruptions and are not guaranteed after abrupt process termination. Checkpoint resume and selective worker recovery are therefore not exposed; see [ADR 0002](docs/adr/0002-eino-recovery-feasibility.md). Whole-analysis retry always starts a fresh analyzer and does not preserve partial worker progress.

## Development And Release

Run the local verification gates:

```bash
task verify
```

Release tags trigger GitHub Actions and GoReleaser. The release task requires a clean worktree, runs verification, creates an annotated semantic-version tag, and pushes it:

```bash
task release-tag TAG=v1.0.0
```

To separate tag creation from pushing, use `task tag TAG=v1.0.0` followed by `task push-tag TAG=v1.0.0`.
