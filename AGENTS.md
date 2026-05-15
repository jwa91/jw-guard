# Agent Guardrails: Core Boundary Constraints

This file is authoritative for agent behavior when editing `jw-guard`.
Use it to preserve strictness and avoid semantic drift.

## Mission Boundary

- North Star: universal, unopinionated, deterministic security-model type system.
- Core package (`jw-guard-core`) is type-only baseline and must remain neutral.
- Precision-first and strictness-first override convenience.

## Hard Constraints (Do Not Violate)

1. **Type-only core**
   - `core` may define types, deterministic constructors, and deterministic validators.
   - `core` must not include runtime enforcement/orchestration/remediation behavior.

2. **No hidden policy opinion in core**
   - Do not encode project posture defaults as core truth.
   - Forbidden in core: implicit mandates like "signing must use airlock", hardening profile defaults, risk heuristics.
   - Policy posture belongs in higher layers (`declare`, profiles, evaluators), not core axioms.

3. **Deterministic construction only**
   - Constructors and validators must be total, pure, and stable for identical inputs.
   - No time/env/network/fs/process/randomness in core validity logic.
   - No hidden semantic defaults unless explicitly schema-declared.

4. **Locked type-axis discipline**
   - `L0` fixed primitive baseline.
   - `L1-L2` only for current stable lock scope.
   - `L3+` is provisional; do not silently elevate semantics into core.

5. **Axis orthogonality**
   - Keep type, graph, and observation semantics explicit and separable.
   - Do not collapse axis semantics into one overloaded type.

6. **Evidence semantics boundary**
   - Evidence is modeled as structured claims/provenance/resolution state.
   - Core must not force binary compliance collapse.
   - Keep uncertainty-explicit outcomes (`Unknown`, `ContradictoryEvidence`, `StaleEvidence`) available.

## Learned Anti-Patterns To Avoid

- Tests claiming "enforcement complete" when they only prove structural validity.
- Using boolean pass/fail as the only evaluation semantics in core.
- Adding convenience defaults that alter normative meaning.
- Mixing declaration intent with runtime observation or enforcement logic.
- Hard-coding policy vocabulary/allowed values in shared language layers too early.

## YAML Policy Boundary Rule

- YAML adapters may adapt YAML syntax/shape only; they must not invent policy posture.
- Policy lossiness and boundary cuts are declarer-owned decisions and must be explicit.
- Preferred sequencing for policy authoring evolution:
  1) template tagging
  2) declarer-defined allowed value sets
  3) typed value bindings
  4) schema hardening from declared constraints
- If a schema encodes domain opinions before this sequence is explicit, treat it as
  reference-only work and do not merge into mainline.

## Required Style For Core Changes

- Prefer constructor gates for invalid-state prevention.
- Return explicit typed violations/errors.
- Keep enums closed and exhaustive where possible.
- Keep APIs lean: smallest composable type additions, no speculative architecture.

## Minimal Acceptance Checklist (for any core PR)

- [ ] No hidden policy/default posture introduced.
- [ ] No runtime side effects in core logic.
- [ ] Deterministic behavior preserved (same input -> same output/errors).
- [ ] L1/L2 lock scope respected; no silent L3+ elevation.
- [ ] Outcome semantics remain uncertainty-preserving (no forced bool-only collapse).
- [ ] Tests describe exactly what they validate (no over-claims).

