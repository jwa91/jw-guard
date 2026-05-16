# ADR-0005: Uncertainty-preserving evaluation outcomes

- Status: Accepted
- Date: 2026-05-16
- Codifies:
  - `c8dd759` — Add deterministic evaluation layer.

## Context

A boolean pass/fail evaluation surface collapses three distinct situations
(satisfied, violated, evidence-incomplete) into two states. That collapse
hides the most operationally important case — "we do not yet know" — and
encourages tests that claim enforcement when only structural validity has
been proven. The deterministic evaluation layer was built to preserve these
distinctions in the type system itself.

## Decision

- Evaluation outcomes are an explicit closed enum that preserves uncertainty.
  The current set in `eval` is:
  - `Satisfied`
  - `Violated`
  - `Unknown`
  - `NotApplicable`
  - `OperatorValueMismatch`
- A typed reason tag (`DecisionReasonTag`) accompanies each outcome so the
  cause is machine-readable, not narrative.
- `core` and `eval` must not collapse outcomes to `bool` in any public API.
- Validation surfaces accumulate violations (`Vec<CoreViolation>`,
  `Vec<DeclareError>`) rather than short-circuiting on the first failure, so
  callers see the full picture.
- Tests must describe exactly what they validate. A structural-integrity test
  may not claim it proves enforcement, applicability, or membership.

## Consequences

- Positive: callers can route `Unknown` and `NotApplicable` differently from
  `Violated` (e.g., gather more evidence vs. fail closed).
- Positive: regressions where a layer silently coerces uncertainty to a
  decision become type errors at compile time.
- Negative: every consumer must handle more than two outcomes, even when the
  domain is binary in practice.
- Accepted trade-off: more match arms downstream in exchange for honest
  semantics.

## Evidence in code

- [eval/src/decision.rs](../../eval/src/decision.rs) — `DecisionOutcome` enum
  (5 variants) and `DecisionReasonTag` enum at lines 10–28.
- [core/src/validation.rs](../../core/src/validation.rs) —
  `validate_declared_model` and `validate_evaluated_model` both return
  `Vec<CoreViolation>`.
- [wire/src/convert.rs](../../wire/src/convert.rs) — `TryFrom` implementation
  accumulates `Vec<DeclareError>` rather than returning the first error.

## What would re-open this decision

- An API request that returns `bool` for a policy decision in `core` or
  `eval`.
- A proposal to remove `Unknown` or `NotApplicable` from `DecisionOutcome`.
- A proposal to short-circuit any validation surface so it stops at the first
  violation.
