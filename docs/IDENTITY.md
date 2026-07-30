# Scan And Finding Identity

## Scan identity

A scan ID is `scan-<UTC timestamp>-<root/time digest>`. It identifies one execution, not a repository revision. The manifest records the canonical target root, target mode, optional reference, and frozen target paths.

## Finding identity

The canonical fingerprint is a SHA-256 digest of normalized title, sorted CWE IDs, and sorted repository-relative location path/role pairs. Line numbers and snippets are intentionally excluded so ordinary edits do not change identity. The human-facing finding ID is the uppercase first ten hexadecimal characters prefixed by `F-`. These fields belong to the initial schema version `1`; there is no pre-release migration history to maintain.

Comparison first uses the full fingerprint. A future fallback matcher may use CWE, normalized title, path, role, and nearby lines, but must label non-exact matches with a confidence value. Ambiguous matches remain `unknown`; they are never silently treated as persisting.
