# ADR-0002: Type-axis lock at L1–L2; L3+ provisional

- Status: Accepted
- Date: 2026-05-16
- Codifies:
  - `03d7042` — Define deterministic L1 type layer over L0 atoms.
  - `aadd682` — Define deterministic L2 typegate over cleared L1 types.
  - `445062f` — Mark L3+ as provisional and lock type-axis to L1–L2.

## Context

After the collapse described in ADR-0001, the type axis was rebuilt one layer
at a time. L1 (named single-atom wrappers with pure local invariants) and L2
(pure type-theoretic products, sums, and refinements over cleared L1) compose
deterministically. Higher layers raise unresolved strategy questions: L3 must
choose how to model cross-referent relations (identity/incidence vs
applicability/observation), and L4 must choose how to express normative
semantics (must/forbidden/allowed) over the L3 graph. Premature commitment at
L3+ would force the same kind of policy leak that triggered the collapse.

## Decision

- Deterministic deconstructability is guaranteed only for L1 and L2.
- L3 and L4 are documented as design-strategy-dependent and remain provisional.
- `core` and `canon` must not silently elevate semantics into L3+ shapes.
- L3+ work proceeds in `declare`, `eval`, and adapter layers — never as a
  silent core extension.

## Consequences

- Positive: the locked baseline is small enough to audit exhaustively. Layer
  boundaries are enforceable in code review.
- Positive: L3+ exploration can happen in higher layers without committing
  `core` to a strategy it cannot reverse.
- Negative: contributors must resist the temptation to "just add" graph or
  policy semantics to `core` types.
- Accepted trade-off: the workspace grows by adding crates rather than by
  extending `core`.

## Evidence in code

- [docs/concepts/05-l1-type-definition.md](../concepts/05-l1-type-definition.md)
- [docs/concepts/06-l2-typegate.md](../concepts/06-l2-typegate.md)
- [docs/concepts/09-type-axis-detectability.md](../concepts/09-type-axis-detectability.md)
- [docs/concepts/README.md](../concepts/README.md) — explicit `provisional`
  status for `07-l3-type-definition.md` and `08-l4-type-definition.md`.
- [core/src/l0.rs](../../core/src/l0.rs) and the surrounding module structure
  (`enums`, `id`, `scalars`, `structs`, `composites`) embody L0 through L2
  without crossing into graph or policy semantics.

## What would re-open this decision

- An explicit decision to lock an L3 abstraction strategy (committing to
  identity/incidence-based composition, applicability/observation-based
  composition, or a justified hybrid).
- A change to `core` or `canon` that introduces graph traversal or normative
  semantics beyond what L1/L2 deconstructability covers.
