# ADR 0002: Eino recovery feasibility

- Status: Accepted — checkpoint resume and worker recovery are not exposed
- Date: 2026-08-12
- Eino version evaluated: `v0.9.13`

## Decision

The scanner supports bounded whole-analysis retry. It does not expose `scans resume` or claim worker recovery with the current DeepAgent integration.

Eino's runner has a byte-oriented `CheckPointStore`, `WithCheckPointID`, and `ResumeWithParams`. A test-only private file store verified safe hashed keys, atomic bounded writes, and loading opaque bytes from a fresh store instance. Source inspection and the upstream integration tests show that the runner APIs resume framework interruption/cancellation safe points. In `adk/runner.go`, checkpoint persistence is initiated while handling an emitted interrupt or a handled cancellation signal. There is no periodic or write-ahead safe point that is guaranteed to run before an abrupt process kill.

Consequently, the required process-kill test cannot be made reliable: a killed scanner can lose all progress since the last explicit framework interrupt and may have no checkpoint at all. The current scanner workflow also has no intentional human-in-the-loop interrupt at the specialist boundaries.

## Checkpoint findings

- Opaque checkpoint bytes can be stored outside the process and loaded by a fresh runner.
- Explicit framework interruptions can be resumed and can preserve graph state.
- Compatibility metadata can be checked by the scanner before handing bytes to Eino.
- Truncated or missing bytes can be rejected instead of falling back to a fresh run.
- Abrupt process termination does not guarantee a usable checkpoint because writes are tied to handled interrupt/cancel events.
- A completion after `submit_scan` has no scanner-controlled checkpoint boundary before the event stream closes.

The production checkpoint-resume gate therefore fails the requirement that a helper process can be killed and reliably resumed. Implementing a file store, lock, and CLI around this behavior would imply durability the framework does not provide.

## Worker-identity findings

`AgentEvent.AgentName` identifies a role such as `discovery`; it is not an immutable invocation ID. A role may be invoked repeatedly. The DeepAgent API does not provide the scanner with a durable ledger of worker inputs and outputs, control over replaying exactly one invocation, or an idempotent merge/reducer boundary. Cancellation addresses internal graph components but does not establish a scanner-owned worker identity contract.

Worker recovery therefore fails every control requirement that depends on stable invocation identity and selective replay. Restarting DeepAgent is whole-analysis retry and must not be described as worker recovery.

## Consequences

- `--max-analysis-attempts` provides fresh, bounded whole-analysis retries for typed transient failures.
- Durable run state records a compatibility fingerprint for a future implementation but stores no API key.
- No checkpoint bytes, resume command, or worker ledger are written in this release.
- Checkpoint resume may be reconsidered when Eino provides durable periodic/safe-point persistence that survives abrupt termination, or when the scanner adopts an explicit workflow scheduler.
- Worker recovery may be reconsidered only when immutable invocation IDs, durable worker inputs and outputs, selective replay, and an idempotent reducer are under scanner control.
