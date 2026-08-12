# Operations

## State And Sensitive Data

Scanner state defaults to the operating system user configuration directory and can be moved with `SECURITY_SCANNER_STATE_DIR`. It contains history and analyst triage. Each scan output also receives private `run-state.json` and an atomically rewritten activity journal before primary model execution. Scanner-owned directories and files are secured for the current operating-system user (`0700`/`0600` on POSIX and a protected current-user-only ACL on Windows), and their identity is rechecked before sensitive reads and writes. On POSIX, custom output also requires trusted ownership and no group- or world-writable non-sticky ancestor. Artifacts may contain sensitive snippets, knowledge-base material, checkpoint-coupled state, and threat-model context; restrict and expire them like source code.

Credential-shaped values in runtime failures are redacted before CLI diagnostics, JSON progress events, model tool errors, scan activity logs, and bulk receipt persistence. Credentials passed for provider authentication are not written to scanner state; scan artifacts can still quote credential-like source text found in the repository and must be handled as sensitive.

## Progress And Timing

Interactive scans emit phase messages on stderr unless `--quiet` is used. Every started analysis stores redacted lifecycle and agent-activity events in `scan-log.jsonl`; inspect completed or failed sessions with `scans logs SCAN_ID`. Bulk scans support `--json-progress` and persist outer job attempts, inner analysis-attempt maxima, timestamps, outcomes, and errors. Manifests record total duration plus preparation and model-analysis timing in milliseconds.

## Reliability And Cost

Bulk concurrency is bounded by `--workers`; retries use exponential backoff from `--retry-delay`; sealed receipt entries resume without another model call. An OS-backed lock allows only one bulk supervisor to own an output receipt at a time and is released automatically if the process exits. This includes `completed_with_gaps` scans: their artifacts remain terminal and available, while the bulk command still returns exit `2` for incomplete coverage. `--max-budget` reserves the operator-supplied `--estimated-scan-cost` for each scheduled repository. `--max-scans` is an independent hard-count guardrail.

Repository inventories include content digests for regular files. Repository tools reject files that change after inventory, and finalization rebuilds the original scoped inventory before and after snippet generation. A changed, added, or removed in-scope file makes the scan fail with exit `2` before artifacts are published.

Knowledge-base inventories apply the same fail-closed principle. Text and Markdown sources reject symlinks, replacements, invalid UTF-8, NUL bytes, and configured count/size overruns. Source-byte digests attest content while CRLF is normalized for model reads. Knowledge-base text and repository text are untrusted data and cannot modify system instructions. PDF and DOCX inputs are currently rejected; the scanner never shells out to a converter.

Protected VCS and scanner metadata is excluded whether represented as a directory or a control file. This keeps submodule and linked-worktree `.git` pointers out of model input, coverage, and persisted findings while retaining their nested source files.

Within one repository scan, `--max-agent-concurrency` bounds concurrent Eino model requests across the coordinator and all specialists. The limiter is provider-neutral and remains shared after immutable tool binding.

`--max-analysis-attempts` bounds fresh primary attempts and defaults to one. Only typed temporary network/provider failures are retried; unknown errors, authentication, invalid input/submission, drift, cancellation, deadlines, and recovery corruption fail immediately. Backoff is context-aware. Bulk retry multiplication is explicit: `(outer retries + 1) * inner analysis attempts`.

The optional post-scan pass runs after canonical publication for success/gaps, or after eligible exhausted primary failures. It is separately time/iteration bounded, receives read-only tools, and owns only `post-scan.json` and `post-scan.md`. Hashes and ownership of findings, coverage, report, and SARIF remain unchanged. Cancellation never starts an advisory pass.

Checkpoint resume and worker recovery are not operational features. Eino v0.9.13 does not guarantee a safe checkpoint after process kill and does not expose scanner-controlled stable worker invocation IDs or an idempotent merge boundary. Whole-analysis retry is the supported recovery mechanism; see ADR 0002.

Eino provider adapters do not expose one consistent usage/cost record through `model.BaseChatModel`. The scanner therefore does not invent token or currency values; budget receipts clearly label operator estimates.

User interruption returns `130`. Atomic artifacts and receipts use a destination-local temporary file followed by rename.

Track scan duration, reviewed-file counts, coverage gaps, findings by severity, policy violations, retry/failure counts, and reserved bulk budget.

## Release Verification

Release tags must be semantic versions that identify a commit on `main`. The release workflow pins third-party actions to commit SHAs, publishes GoReleaser checksums, and creates GitHub artifact attestations for both the released archives and the checksum manifest. Verify a downloaded artifact with:

```bash
gh attestation verify security-scanner_VERSION_OS_ARCH.tar.gz --repo ralscha/security-scanner
```

Windows archives use `.zip` instead of `.tar.gz`.
