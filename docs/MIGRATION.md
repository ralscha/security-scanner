# Pre-Release Migration Notes

Current JSON documents start at schema version `1`. Because the application has not deployed, there is no historical schema or migration chain to maintain. Migration logic should be introduced only after a deployed contract actually needs to evolve.

Changes from the initial prototype:

- Prefer `--output-dir`; `--out` remains an alias.
- Default artifacts moved from `<target>/.scanner` to per-user scanner state.
- Explicit single-scan output resolves to an absolute path and may be inside the target; the destination is excluded from inventory. Bulk output remains outside scanned worktrees.
- Existing non-empty output requires `--archive-existing`.
- Invalid input, runtime errors, preflight failures, and incomplete coverage return `2`; configured severity violations return `1`.
- Findings include a stable full fingerprint while retaining the compact `F-...` ID.

Automation should consume canonical JSON artifacts rather than console text.
