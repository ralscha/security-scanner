# Operations

## State And Sensitive Data

Scanner state defaults to the operating system user configuration directory and can be moved with `SECURITY_SCANNER_STATE_DIR`. It contains history and analyst triage. Scanner-owned directories and files are secured for the current operating-system user (`0700`/`0600` on POSIX and a protected current-user-only ACL on Windows), and their identity is rechecked before sensitive reads and writes. On POSIX, custom output also requires trusted ownership and no group- or world-writable non-sticky ancestor. Artifacts may contain sensitive snippets and threat-model context; restrict and expire them like source code.

Credential-shaped values in runtime failures are redacted before CLI diagnostics, JSON progress events, model tool errors, and bulk receipt persistence. Credentials passed for provider authentication are not written to scanner state; scan artifacts can still quote credential-like source text found in the repository and must be handled as sensitive.

## Progress And Timing

Interactive scans emit phase messages on stderr unless `--quiet` is used. Bulk scans support `--json-progress` and persist attempts, timestamps, outcomes, and errors. Manifests record total duration plus preparation and model-analysis timing in milliseconds.

## Reliability And Cost

Bulk concurrency is bounded by `--workers`; retries use exponential backoff from `--retry-delay`; sealed receipt entries resume without another model call. An OS-backed lock allows only one bulk supervisor to own an output receipt at a time and is released automatically if the process exits. This includes `completed_with_gaps` scans: their artifacts remain terminal and available, while the bulk command still returns exit `2` for incomplete coverage. `--max-budget` reserves the operator-supplied `--estimated-scan-cost` for each scheduled repository. `--max-scans` is an independent hard-count guardrail.

Repository inventories include content digests for regular files. Repository tools reject files that change after inventory, and finalization rebuilds the original scoped inventory before and after snippet generation. A changed, added, or removed in-scope file makes the scan fail with exit `2` before artifacts are published.

Within one repository scan, `--max-agent-concurrency` bounds concurrent Eino model requests across the coordinator and all specialists. The limiter is provider-neutral and remains shared after immutable tool binding.

Eino provider adapters do not expose one consistent usage/cost record through `model.BaseChatModel`. The scanner therefore does not invent token or currency values; budget receipts clearly label operator estimates.

User interruption returns `130`. Atomic artifacts and receipts use a destination-local temporary file followed by rename.

Track scan duration, reviewed-file counts, coverage gaps, findings by severity, policy violations, retry/failure counts, and reserved bulk budget.

## Release Verification

Release tags must be semantic versions that identify a commit on `main`. The release workflow pins third-party actions to commit SHAs, publishes GoReleaser checksums, and creates GitHub artifact attestations for both the released archives and the checksum manifest. Verify a downloaded artifact with:

```bash
gh attestation verify security-scanner_VERSION_OS_ARCH.tar.gz --repo ralscha/security-scanner
```

Windows archives use `.zip` instead of `.tar.gz`.
