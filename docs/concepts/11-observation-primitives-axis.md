# Observation Primitives Axis

This document defines the atomic observation/applicability axis from first
principles.

It is orthogonal to:

- the type axis (deconstructability and layering), and
- the graph axis (identity/incidence abstraction potential).

Its role is to determine whether abstractions are decidable from evidence
without hidden assumptions.

## First Principle

A system claim is applicable only if it can be represented as an explicit
observation with explicit provenance and resolution state.

Before policy outcomes, we need atomic evidence semantics.

## Atomic Observation Primitives

1. `ClaimIdentity`
   - stable nominal identity of one claim.
2. `EvidenceIdentity`
   - stable nominal identity of one evidence item.
3. `SourceIdentity`
   - stable nominal identity of evidence source.
4. `ObservationKind`
   - closed kind of observation (`measured | inferred | declared`).
5. `ResolutionState`
   - closed resolution status (`resolved | unresolved | ambiguous | conflicting`).
6. `SnapshotMarker`
   - deterministic temporal/snapshot anchor for observation context.
7. `SubjectRef`
   - typed reference to the subject the claim/evidence concerns.

## Minimal Composition Rules

Compose only the minimum observation forms:

- `Claim = (ClaimIdentity, ObservationKind, SubjectRef, SnapshotMarker)`
- `Evidence = (EvidenceIdentity, SourceIdentity, ClaimIdentity, ResolutionState)`

No policy satisfaction semantics are implied at this axis.

## Deterministic Invariants

1. **Identity uniqueness**
   - claim/evidence/source identities are unique in their namespaces.
2. **Reference totality**
   - every claim subject and evidence claim reference resolves.
3. **State explicitness**
   - every evidence item has one explicit `ResolutionState`.
4. **Snapshot explicitness**
   - every claim has one explicit `SnapshotMarker`.
5. **Deterministic normalization**
   - canonical ordering for claims/evidence/source declarations.

## Not Included (By Design)

This axis excludes:

- normative policy requirement semantics,
- enforcement decisions (`permit/deny`),
- confidence weighting heuristics,
- runtime remediation workflows.

Those are higher abstractions.

## Axis Usage

Use as third decision axis:

```text
AbstractionDecisionSpace = TypeAxis × GraphAxis × ObservationAxis
```

Where:

- Type axis answers structural foundational deconstructability.
- Graph axis answers atomic identity/incidence reducibility.
- Observation axis answers applicability/decidability from explicit evidence.

A candidate abstraction is strategy-safe only if valid on all three axes.

## Strategy-Safety Predicate

```text
observation_atomic(def) -> bool
```

Returns true iff the definition can be reduced to these atomic observation
primitives without ambiguous claim identity, provenance, or resolution meaning.

