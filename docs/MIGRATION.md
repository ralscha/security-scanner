# Pre-Release Migration Notes

Current JSON documents start at schema version `1`. Because the application has not deployed, there is no historical schema or migration chain to maintain. Migration logic should be introduced only after a deployed contract actually needs to evolve.

Changes from the initial prototype:

- Prefer `--output-dir`; `--out` remains an alias.
- Default artifacts moved from `<target>/.scanner` to per-user scanner state.
- Repository source files are no longer skipped above an implicit 1 MiB threshold. Use a positive `--max-file-bytes` value to retain an explicit cap; `0` is now unlimited.
- Explicit single-scan output resolves to an absolute path and may be inside the target; the destination is excluded from inventory. Bulk output remains outside scanned worktrees.
- Existing non-empty output requires `--archive-existing`.
- Invalid input, runtime errors, preflight failures, and incomplete coverage return `2`; configured severity violations return `1`.
- Findings include a stable full fingerprint while retaining the compact `F-...` ID.
- Scan IDs are allocated before primary analysis. Failed sessions now appear in history and retain private `run-state.json` and `scan-log.jsonl` files without canonical result artifacts.
- `--follow-up-prompt` remains primary specialist guidance. Use `--post-scan-prompt` only for a separate advisory pass whose output cannot alter canonical scan truth.
- Launch configurations add optional knowledge-base, post-scan, and inner retry fields. Existing schema-version-1 manifests without them continue to load with prior behavior.

Automation should consume canonical JSON artifacts rather than console text.
