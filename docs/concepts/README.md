# Concepts

## As-Is Situation

`docs/concepts/` is the active conceptual authority baseline for `jw-guard`.

Current status model:

- locked baseline:
  - `00-terminology.md`
  - `01-fundamental-form.md`
  - `02-minimum-atoms-and-declarations.md`
  - `03-deterministic-concretisation.md`
  - `04-loop-control.md`
  - `05-l1-type-definition.md`
  - `06-l2-typegate.md`
  - `09-type-axis-detectability.md`
  - `10-graph-primitives-axis.md`
  - `11-observation-primitives-axis.md`
- provisional:
  - `07-l3-type-definition.md`
  - `08-l4-type-definition.md`

Interpretation rules:

- concept docs outrank drafts and historical design notes
- when code diverges from locked concepts, reconcile code or explicitly revise concepts
- no hidden policy opinion should be introduced into core semantics

## Goal and Roadmap

Goal:

- Keep concepts as a strict, minimal, deterministic authority aligned to the
  active implementation and the non-opinionated north star.

Roadmap:

1. keep locked files concise and implementation-relevant
2. move stale concept material into explicit archival status or remove it
3. promote provisional `L3/L4` only after explicit strategy lock criteria are met
4. ensure every concept file maps to a real acceptance gate or core/canon surface
5. maintain deterministic authority ordering: concepts > code-consistent behavior > drafts
