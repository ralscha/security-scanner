# Exit Codes

The CLI exit contract is stable for CI consumers:

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded and no configured scan policy was violated. |
| `1` | A completed scan violated `--fail-on-severity`. Artifacts are available. |
| `2` | Invalid input, configuration/preflight/runtime failure, changed scan target, or incomplete coverage. |
| `130` | Interrupted by the user. |
| `143` | Terminated by an external signal where the platform preserves that distinction. |

Incomplete coverage takes precedence over severity policy because the result cannot prove the policy over unread input. A repository or knowledge-base target that changes after inventory is rejected before artifacts are published. Output write failures also return `2`.

Post-scan advisory failure in the default `warn` mode preserves the primary exit result. With `--post-scan-failure-mode=fail`, canonical artifacts remain available but the command returns `2`. Incomplete coverage still returns `2`, and a completed severity-policy violation still returns `1` when post-scan failure is warning-only. After a primary failure, that primary failure and its exit code always win over the advisory pass.
