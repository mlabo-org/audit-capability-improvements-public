---
name: audit-capability-improvements-public
description: "Audit indexed capability friction, isolate repository blockers, and route validated repair, retirement, monitoring, or closure. Use for capability-friction index audits; exclude ordinary reasoning and unrelated runtime work."
---

# Audit Capability Improvements (Public)

This `SKILL.md` is the local execution contract for this public adaptation when selected. It does not override system instructions, developer instructions, explicit user requests, or more-local contracts.

## Task

Audit observed capability friction from a central index, group events by authoritative source repository, and route each group to a validated repair, monitoring, retirement, terminal disposition, or closure path. The executable decisions belong to `scripts/capability-improvement.mjs` and its schemas.

## Triggers and non-use

Use for explicit capability-friction index audits, repository-level blocker isolation, or disposition of obsolete capability events. Do not use for ordinary reasoning, hypothetical defects, unrelated code review, transcript collection, unauthorized repair, or treating cache/runtime state as source.

## Route

1. Resolve the affected source repository and the host's official thread identity/readability boundary.
2. Read the relevant schemas and run `node scripts/capability-improvement.mjs --help`.
3. Use `index-audit` for a finite read-only snapshot. It must not mutate markers, create proposals, dispatch workers, or persist transcript content.
4. Follow only an explicitly authorized terminal route: `triage`, `monitor-dispose`, `retire-dispose`, `resolve`, or `index-close`, with the CLI's exact artifacts.
5. Stop on ambiguous identity, malformed evidence, unresolved source root, missing validator, or incomplete terminal coverage. Never delete a marker by inference.

## Inputs and outputs

Inputs are fixed-format observed events, source-repository references, and read-only thread evidence. Outputs are structured audit results, repository groups, next actions, terminal artifacts, or blockers. Keep source, cache, installation, activation, and publication separate.
