# Operations

## State And Sensitive Data

Scanner state defaults to the operating system user configuration directory and can be moved with `SECURITY_SCANNER_STATE_DIR`. It contains history and analyst triage. Artifacts may contain sensitive snippets and threat-model context; restrict and expire them like source code. Credentials are never persisted.

## Progress And Timing

Interactive scans emit phase messages on stderr unless `--quiet` is used. Bulk scans support `--json-progress` and persist attempts, timestamps, outcomes, and errors. Manifests record total duration plus preparation and model-analysis timing in milliseconds.

## Reliability And Cost

Bulk concurrency is bounded by `--workers`; retries use exponential backoff from `--retry-delay`; completed receipt entries resume without another model call. `--max-budget` reserves the operator-supplied `--estimated-scan-cost` for each scheduled repository. `--max-scans` is an independent hard-count guardrail.

Within one repository scan, `--max-agent-concurrency` bounds concurrent Eino model requests across the coordinator and all specialists. The limiter is provider-neutral and remains shared after immutable tool binding.

Eino provider adapters do not expose one consistent usage/cost record through `model.BaseChatModel`. The scanner therefore does not invent token or currency values; budget receipts clearly label operator estimates.

User interruption returns `130`. Atomic artifacts and receipts use a destination-local temporary file followed by rename.

Track scan duration, reviewed-file counts, coverage gaps, findings by severity, policy violations, retry/failure counts, and reserved bulk budget.
