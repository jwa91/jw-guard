# ADR-0001: Type-only, policy-neutral core

- Status: Accepted
- Date: 2026-05-16
- Codifies:
  - `c67b004` — Restore core neutrality and add deterministic loop control.
  - `fb7d5f6` — Collapse workspace to a strict L0-only baseline.
  - `85f5329` — Add neutrality regression for signing-route cadence.

## Context

The first cut of `jw-guard` placed model composites, validation, theory, and a
concept-feedback loop inside `core`. Over a few iterations, policy semantics
leaked in: implicit "signing must use airlock" cadence checks, hardening profile
defaults, and risk heuristics ended up as core invariants. This made `core`
opinionated, which contradicts the project's north star (universal,
unopinionated, deterministic). The fix was a deliberate ~7,000-line collapse to
an L0-only baseline, followed by a neutrality regression test that pins down
what `core` is *not* allowed to assert.

## Decision

`jw-guard-core` is restricted to:

1. Types, deterministic constructors, and deterministic validators.
2. No runtime side effects in core logic (no time, env, network, filesystem,
   process, randomness).
3. No policy posture defaults. Forbidden: implicit mandates ("signing must use
   airlock"), hardening profile defaults, risk heuristics, cadence assumptions.
4. Policy posture is owned by `declare`, profiles, and evaluators — never by
   `core`.

## Consequences

- Positive: `core` is reusable across projects with different policy postures
  without a fork. Auditability is concrete: any `core` change can be checked
  against this ADR.
- Positive: deterministic construction means identical inputs produce identical
  outputs/errors across machines, environments, and time.
- Negative: convenience defaults that would make `core` "ready to use out of
  the box" are explicitly disallowed. Callers must declare intent in higher
  layers.
- Accepted trade-off: more boilerplate for downstream users in exchange for
  policy neutrality and replay determinism.

## Evidence in code

- [core/src/lib.rs](../../core/src/lib.rs) — `#![forbid(unsafe_code)]`,
  `no_std` + `alloc` only; no env/fs/network deps.
- [core/src/validation.rs](../../core/src/validation.rs) —
  `validate_declared_model(&DeclaredModel) -> Vec<CoreViolation>` returns
  accumulated typed violations; never a bool.
- [core/Cargo.toml](../../core/Cargo.toml) — dependency list contains only
  optional `serde`; nothing else.

## What would re-open this decision

- A proposal to ship runtime enforcement (gate verification cadence, profile
  application, remediation actions) inside `core`.
- A proposal to add policy defaults to any `core` constructor or validator.
- A proposal to take an environmental input (time, env var, fs read) in any
  `core` validator.
