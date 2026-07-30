# ADR 0001: Output Directory And Archival Policy

Status: accepted

Canonical scan artifacts must not be mixed with scanned input. Default artifacts are stored below the per-user scanner state directory. Explicit output paths are resolved before inventory, must be outside both the target and its enclosing Git worktree, and may not traverse a symlink inside the target.

An existing non-empty output directory is an error by default. `--archive-existing` atomically renames it to a collision-safe UTC timestamped sibling before a scan writes new artifacts. Archives are immutable inputs to history and comparison commands. Cross-volume copy-and-delete is not considered atomic and is rejected.
