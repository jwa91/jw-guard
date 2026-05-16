# ADR-0003: Three orthogonal axes — type, graph, observation

- Status: Accepted
- Date: 2026-05-16
- Codifies:
  - `a06b54d` — Add first-principles graph primitives as a separate axis.
  - `5175aa6` — Add an atomic observation/applicability decision axis.

## Context

During the layered rebuild after the collapse (ADR-0001), it became clear that
fusing type semantics, graph semantics, and observation/applicability semantics
into a single composite would recreate the conditions that allowed policy
opinions to leak into `core`. Each axis has a different decidability profile,
a different validator surface, and a different reason to fail. Keeping them
separate is the only way the L1/L2 deconstructability guarantee in ADR-0002
remains tractable.

## Decision

`jw-guard` treats three axes as separable, orthogonal concerns:

- **Type axis** — what an atom *is* (sorts, enums, refined scalars). Governed
  by L0/L1/L2 in ADR-0002.
- **Graph axis** — what relations and incidences exist (referents, boundaries,
  edges, sides). Identity and incidence only; no policy reading.
- **Observation/applicability axis** — what evidence has been observed and
  whether a fact applies (membership, applicability, evidence basis). No
  forced collapse to pass/fail.

Composites may carry fields from multiple axes, but no single type may
*overload* axes (e.g., no enum that simultaneously encodes a type tag, a graph
role, and an applicability state).

## Consequences

- Positive: each axis can be validated, tested, and extended independently.
  Concept docs map 1:1 to axes (concepts 05/06/07/08 → type; 10 → graph; 11 →
  observation).
- Positive: failure modes stay legible — a graph violation is structurally
  distinct from an applicability violation.
- Negative: callers wiring high-level semantics together must traverse three
  surfaces rather than one merged surface.
- Accepted trade-off: a slightly higher integration cost in exchange for
  reasoning that scales without policy bleed.

## Evidence in code

- [docs/concepts/10-graph-primitives-axis.md](../concepts/10-graph-primitives-axis.md)
- [docs/concepts/11-observation-primitives-axis.md](../concepts/11-observation-primitives-axis.md)
- [core/src/composites.rs](../../core/src/composites.rs) — boundaries/edges
  (graph) and evidence basis (observation) are distinct fields, not collapsed
  into a single enum.
- [eval/src/decision.rs](../../eval/src/decision.rs) and
  [eval/src/predicate.rs](../../eval/src/predicate.rs) — observation/membership
  semantics live in `eval`, kept off the `core` graph types.

## What would re-open this decision

- A proposal for a single "evaluated security fact" type that fuses two or
  more axes into one enum/struct.
- A proposal to attach applicability state directly to `core` graph types
  (e.g., `Edge.observed: bool`).
