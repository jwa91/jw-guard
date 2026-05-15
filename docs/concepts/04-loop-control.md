# Loop Control

This document defines the deterministic control loop that governs what work is
allowed at each step.

The purpose is to prevent "locally correct but globally misaligned" actions.

## Four Required Inputs

Every cycle must begin by establishing these four objects in order:

1. `Goal`
2. `State`
3. `Loop`
4. `Mayrun`

If any input is missing, the cycle is invalid.

## Goal

`Goal` is the north-star target derived from the concept authority.

For `jw-guard` core:

- keep vocabulary typed and deterministic,
- keep core neutral (no hidden project policy opinion),
- allow project-specific hardening only as declarations/profiles/evaluations.

Goal must be explicit and stable for the cycle.

## State

`State` is an auditable snapshot of current reality.

Minimum state inventory:

- concept authority documents (`docs/concepts/*`),
- current code behavior (validation paths, constructors, concretisation),
- current tests and current git state.

State must be read from source, not assumed from memory.

## Loop

The loop is deterministic and must run in this fixed order:

1. **Compare Goal vs State**
   - enumerate mismatches, not opinions.
2. **Determine candidate action**
   - the smallest composable step that reduces one mismatch.
3. **Evaluate action upwards**
   - prove action is aligned with Goal and authority ordering.
4. **Validate action downwards**
   - prove action preserves atomic/core determinism and does not inject hidden policy.
5. **Execute**
   - only if `Mayrun` returns allowed.
6. **Re-evaluate State**
   - confirm mismatch reduction and no new drift.

Skipping any step invalidates the cycle.

## Mayrun

`Mayrun` is the execution gate. It returns one of:

- `HARDEN_ONLY`
- `INCREMENTAL_ALLOWED`
- `BLOCKED`

### Mayrun Decision Rules

Return `HARDEN_ONLY` when any of the following is true:

- state is compromised against concept authority,
- core neutrality is violated by embedded project policy,
- deterministic baseline is uncertain.

Return `INCREMENTAL_ALLOWED` only when:

- no unresolved authority conflict exists,
- no unresolved state compromise exists,
- deterministic baseline is passing and trusted.

Return `BLOCKED` when:

- required authority inputs are missing or contradictory,
- state cannot be proven.

## Mandatory Priority Rule

If state is compromised:

1. fix state first,
2. include a loop-improvement change that reduces recurrence risk,
3. only then allow incremental goal steps.

No feature or extension work is allowed while state compromise is unresolved.

## Authority Ordering

When sources conflict, resolve in this order:

1. `docs/concepts/*`
2. code that is consistent with concepts
3. drafts and preference documents

Lower-ranked sources must not override higher-ranked sources.

## Deterministic Output Contract

Each cycle must output:

- `Goal` (explicit),
- `State` (explicit),
- `Mayrun` verdict,
- chosen action (or block reason),
- upward evaluation result,
- downward validation result,
- next cycle entry condition.
