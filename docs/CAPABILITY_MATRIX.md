# Capability Matrix

This matrix is the implementation contract for the parity roadmap. A capability is complete only when its command behavior, negative paths, documentation, and tests exist. The pre-release artifact contract starts at schema version `1`; no migration history is maintained before deployment.

| Capability | CLI/API | Status | Evidence |
| --- | --- | --- | --- |
| Full repository scan | `scan --target` | Implemented | `internal/app`, app and CLI tests |
| Path targeting | `scan --path` (repeatable) | Implemented | `internal/targeting`, inventory and CLI tests |
| Committed diff targeting | `scan --diff REF` | Implemented | targeting git integration test |
| Working-tree targeting | `scan --working-tree` | Implemented | targeting git integration test |
| Configuration-only execution | `scan --dry-run` | Implemented | CLI dry-run test |
| Severity policy | `scan --fail-on-severity` | Implemented | `internal/policy`, policy tests |
| Stable exit semantics | process exit status | Implemented | `docs/EXIT_CODES.md`, CLI tests |
| Safe output and archive | `--output-dir`, `--archive-existing` | Implemented | `internal/output`, output tests |
| Scan history | `scans list/show/rerun` | Implemented | `internal/history`, history and CLI tests |
| Finding matching and comparison | `scans match/compare` | Implemented | `internal/match`, matcher tests |
| False-positive triage | `findings false-positive` | Implemented | `internal/triage`, persistence and CLI tests |
| Validation | `validate` | Implemented | Eino reviewer, grounded-result validators and tests |
| Patch assist | `patch` | Implemented | bounded proposal schema, non-overwriting export and tests |
| Preflight and explicit auth | `scan preflight`, `scan --auth` | Implemented | `internal/preflight`, auth resolution tests |
| Bulk orchestration | `bulk-scan` | Implemented | `internal/bulk`, resume/retry/budget tests |

The matrix is updated in the same change that completes a capability.
