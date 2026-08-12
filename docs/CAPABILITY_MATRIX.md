# Capability Matrix

This matrix is the implementation contract for the parity roadmap. A capability is complete only when its command behavior, negative paths, documentation, and tests exist. The pre-release artifact contract starts at schema version `1`; no migration history is maintained before deployment.

| Capability | CLI/API | Status | Evidence |
| --- | --- | --- | --- |
| Full repository scan | `scan --target` | Implemented | `internal/app`, app and CLI tests |
| Path targeting | `scan --path` (repeatable) | Implemented | `internal/targeting`, inventory and CLI tests |
| Committed diff targeting | `scan --diff REF` | Implemented | targeting git integration test |
| Working-tree targeting | `scan --working-tree` | Implemented | targeting git integration test |
| Content-attested target | fixed inventory and finalization | Implemented | inventory, repository-read and report finalization tests |
| Configuration-only execution | `scan --dry-run` | Implemented | CLI dry-run test |
| Severity policy | `scan --fail-on-severity` | Implemented | `internal/policy`, policy tests |
| Stable exit semantics | process exit status | Implemented | `docs/EXIT_CODES.md`, CLI tests |
| Safe output and archive | `--output-dir`, `--archive-existing` | Implemented | `internal/output`, output tests |
| Scan history | `scans list/show/logs/rerun` | Implemented | unique scan-ID prefixes, private activity logs, history and CLI tests |
| Repository findings | `findings list` | Implemented | fingerprint aggregation, latest-scan state, triage suppression tests |
| Finding matching and comparison | `scans match/compare` | Implemented | `internal/match`, matcher tests |
| False-positive triage | `findings false-positive` | Implemented | `internal/triage`, persistence and CLI tests |
| Validation | `validate` | Implemented | Eino reviewer, grounded-result validators and tests |
| Patch assist | `patch` | Implemented | bounded proposal schema, non-overwriting export and tests |
| Preflight and explicit auth | `scan preflight`, `scan --auth` | Implemented | `internal/preflight`, auth resolution tests |
| Bulk orchestration | `bulk-scan` | Implemented | `internal/bulk`, JSON/CSV/list parsing, supervisor lock, resume/retry/budget tests |
| Text knowledge bases | `--knowledge-base` in scan/preflight/dry-run/rerun/bulk | Implemented | `internal/knowledgebase`, read-only agent tools, drift and bounds tests |
| Advisory post-scan pass | `--post-scan-prompt`, trigger and failure policy | Implemented | `internal/postscan`, immutable canonical-artifact tests |
| Whole-analysis retry | `--max-analysis-attempts` | Implemented | typed classification, fresh analyzer/tracker, durable attempt journal |
| Durable failed sessions | `run-state.json`, `scans logs` | Implemented | `internal/runstate`, history prefix lookup |
| Checkpoint resume | `scans resume` | Unsupported by current Eino safe-point guarantees | `docs/adr/0002-eino-recovery-feasibility.md` |
| Selective worker recovery | none | Unsupported by current DeepAgent invocation/merge controls | `docs/adr/0002-eino-recovery-feasibility.md` |
| PDF/DOCX knowledge bases | none | Deferred pending parser security review | text formats remain the supported contract |

The matrix is updated in the same change that completes a capability.
