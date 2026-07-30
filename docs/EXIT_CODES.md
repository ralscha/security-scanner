# Exit Codes

The CLI exit contract is stable for CI consumers:

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded and no configured scan policy was violated. |
| `1` | A completed scan violated `--fail-on-severity`. Artifacts are available. |
| `2` | Invalid input, configuration/preflight/runtime failure, or incomplete coverage. |
| `130` | Interrupted by the user. |
| `143` | Terminated by an external signal where the platform preserves that distinction. |

Incomplete coverage takes precedence over severity policy because the result cannot prove the policy over unread input. Output write failures also return `2`.
