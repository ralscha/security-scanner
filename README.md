# Security Scanner

`security-scanner` is a Go CLI that inventories a codebase, uses an Eino DeepAgent to perform a security review, and writes a validated report bundle. Its scan engine depends on Eino's `model.BaseChatModel` abstraction rather than a provider SDK.

The scan workflow adapts the strongest ideas from Codex Security's repository scan process:

- Freeze one file inventory before analysis and account for every in-scope file.
- Separate candidate discovery, adversarial validation, and attack-path/severity reasoning.
- Require repository-relative, line-level evidence for every finding.
- Treat incomplete coverage as an explicit report state instead of claiming success.
- Produce canonical JSON first, then derive Markdown and SARIF deterministically.

## Architecture

The Eino DeepAgent is the coordinator. It has three named sub-agents (`discovery`, `validation`, and `attack-path`) plus task tracking. Agents receive only read-only repository capabilities: `list_files`, `read_file`, and `search_code` (`search_file` is a provider-compatibility alias). They have no shell and cannot write to the target.

Provider construction is isolated in a registry. The scanner includes official Eino adapters for OpenAI, Azure OpenAI, OpenRouter, Anthropic Claude, Google Gemini, Ollama, and Volcengine Ark. The `openai-compatible` provider also covers servers and vendors that expose a compatible chat-completions and tool-calling API, including self-hosted gateways.

Go code owns the security boundary and final output:

- The inventory honors root and nested `.gitignore` rules, and excludes VCS metadata, dependency/build directories, `.scanner`, and explicit `--exclude` paths.
- Symlinks are inventoried as skipped and checked again before each read.
- Full-file coverage is measured from actual `read_file` line ranges. Search results do not count as review.
- `submit_scan` rejects unknown files, invalid lines, malformed CWE values, and incomplete finding fields.
- Finding IDs, source snippets, coverage, Markdown, and SARIF are generated outside the model.

Repository contents and `--context` are always treated as untrusted analysis data, not agent instructions.

## Build

Requires Go 1.25.5 or newer.

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
--max-file-bytes N      Files above N are accounted for as skipped
--max-iterations N      Reasoning iterations available to each agent
--max-agent-concurrency N Maximum concurrent model requests across all agents
--max-output-tokens N   Provider response limit; 0 uses its default
--max-duration DURATION Overall deadline, such as 30m
--request-timeout D     Timeout for one model request
--quiet                 Suppress progress events
```

Target a subset of a repository with exactly one selector mode:

```bash
# One or more files/directories
./security-scanner scan --target /path/to/repo --path cmd --path internal/auth

# Changes relative to a Git revision
./security-scanner scan --target /path/to/repo --diff origin/main

# Tracked modifications plus untracked files
./security-scanner scan --target /path/to/repo --working-tree
```

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

To inspect scope without making model calls:

```bash
./security-scanner inventory --target /path/to/repo
```

## Artifacts

Each scan writes:

- `scan-manifest.json`: scan identity, status, timestamps, provider/model, counts, and artifact paths.
- `findings.json`: threat model and normalized findings.
- `coverage.json`: one outcome for every inventoried file.
- `report.md`: human-readable report derived from the canonical documents.
- `results.sarif`: SARIF 2.1.0 results for code scanning integrations.

By default, artifacts are written below the per-user scanner state directory. An explicit `--output-dir` is resolved to an absolute, canonical path and may be anywhere except the scan target itself. A destination inside the target is excluded from the fixed file inventory. Scan directories and artifacts are private to the current operating-system user: POSIX output directories must use mode `0700` and have trusted, non-writable ancestry; Windows output receives a protected current-user-only ACL. A non-empty destination is rejected unless `--archive-existing` is supplied; in that case it is atomically renamed to a timestamped sibling before the new scan starts. Bulk scan output must remain outside every scanned worktree to keep concurrent inventories isolated.

A scan is `completed` only when every reviewable text file was read from start to finish. Otherwise it is `completed_with_gaps`, and all unread files are listed.

## History And Triage

Completed scans are indexed in the per-user scanner state directory:

```bash
./security-scanner scans list --target /path/to/repo
./security-scanner scans show SCAN_ID
./security-scanner scans rerun SCAN_ID
./security-scanner scans match BEFORE_SCAN_ID AFTER_SCAN_ID
./security-scanner scans compare BEFORE_SCAN_ID AFTER_SCAN_ID
./security-scanner scans compare --json BEFORE_SCAN_ID AFTER_SCAN_ID
```

Finding occurrences use `SCAN_ID:FINDING_ID`. Analyst decisions are stored separately from canonical scan artifacts:

```bash
./security-scanner findings false-positive "SCAN_ID:FINDING_ID" --reason "Protected by the authorization check at the only call site."
```

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

## Preflight And Bulk Scans

Authentication can be selected explicitly with `--auth auto`, `env`, `api-key`, or `none`. Preflight validates repository scope, output policy, credentials, and model selection without constructing a model:

```bash
./security-scanner scan preflight --target /path/to/repo --provider ollama --model qwen3-coder --auth none
./security-scanner scan preflight --target /path/to/repo --json
```

Bulk input may be a JSON string array, a JSON job array with per-repository `context`, or a newline-delimited list. A job array has this shape:

```json
[
  {
    "target": "/path/to/repo",
    "context": "Internet-facing service; authenticated users are untrusted."
  }
]
```

Run the bulk scan:

```bash
./security-scanner bulk-scan repos.json \
  --output-dir "$HOME/security-reports/bulk" \
  --workers 4 --retries 2 --fail-on-severity high \
  --max-budget 20 --estimated-scan-cost 2
```

The atomic `bulk-receipt.json` supports resume. Budget units are operator estimates, not provider billing claims.

Provider adapters do not currently expose consistent usage accounting through Eino's shared model interface, so manifests do not claim token or billing totals. Bulk budget reservations are explicit operator-supplied estimates.

## Limitations

- Results depend on model capability and the available iteration/time budget.
- DeepAgent requires reliable structured tool calling. A text-only model or a model that merely accepts an OpenAI-compatible request without correctly implementing tool calls cannot run the scanner.
- The scanner does not execute builds, tests, dependency audits, or application code.
- Common dependency and build directories are excluded by default. Additional generated paths require `.gitignore` entries or `--exclude`.
- Provider-specific hosted tools are disabled. All providers receive the same scanner-owned read-only tools and report contract.

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
