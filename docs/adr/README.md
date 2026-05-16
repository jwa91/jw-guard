# Architecture Decision Records

This directory holds accepted structural decisions for `jw-guard`. Each ADR is
short, code-grounded, and includes a concrete trigger that should cause it to
be revisited.

## Authority

- ADRs document **accepted decisions** with cited evidence in code and git history.
- `docs/concepts/` remains the **conceptual baseline** (terminology, fundamental
  form, layer definitions). Concepts say *what is true now*; ADRs say *what was
  decided and why*.
- When ADRs and concepts disagree, the ADR wins until the concept is explicitly
  revised in the same change.

## Index

| #    | Title                                                         | Status   |
| ---- | ------------------------------------------------------------- | -------- |
| 0001 | [Type-only, policy-neutral core](0001-type-only-neutral-core.md) | Accepted |
| 0002 | [Type-axis lock at L1–L2; L3+ provisional](0002-type-axis-lock-l1-l2-l3-provisional.md) | Accepted |
| 0003 | [Three orthogonal axes: type, graph, observation](0003-three-orthogonal-axes.md) | Accepted |
| 0004 | [Format adapters are syntax-only; declarers own policy vocabulary](0004-syntax-only-format-adapters.md) | Accepted |
| 0005 | [Uncertainty-preserving evaluation outcomes](0005-uncertainty-preserving-outcomes.md) | Accepted |

## Adding an ADR

Use the next free number. Keep the format consistent with existing ADRs:

```
# ADR-NNNN: <title>

- Status: Proposed | Accepted | Superseded by ADR-MMMM
- Date: YYYY-MM-DD
- Codifies: <commit SHAs with one-line subjects>

## Context
## Decision
## Consequences
## Evidence in code
## What would re-open this decision
```
