# Minimum Atoms And Declarations

This document lists the smallest type atoms and declaration objects needed to
instantiate the fundamental form.

## Type Atoms

These are semantic atoms. They are not all Rust structs yet.

### Identity Atoms

`ModelId`

: Stable identity of the model itself.

`ActorId`

: Stable identity of an accountable actor.

`ReferentId`

: Stable identity of a model referent.

### Sort Atoms

`ReferentSort`

: The semantic type of a referent. A typed scope selects exactly one sort.

`EdgeSort`

: The semantic type of an edge. Examples: depends-on, signs, logs-to,
  crosses-boundary.

`RequirementSort`

: The semantic type of a requirement. Examples: presence, count, strength,
  cadence, encryption, signature method.

### Graph Atoms

`Referent`

: A typed thing the model can point at.

`Boundary`

: A declared separation between two sides.

`Side`

: One end of a boundary.

`Surface`

: One exposed face of a boundary as seen from a side.

`Edge`

: A typed relation between referents.

### Policy Atoms

`Policy`

: Accountable normative claim over a typed scope.

`TypedScope`

: Context-relative selected set of referents of one referent sort.

`Requirement`

: Normative predicate applicable to the selected referent sort.

### Evidence Atoms

`EvidenceItem`

: A claim or observation with provenance.

`EvidenceBasis`

: The evidence set and assumptions used for one evaluation.

`Evaluation`

: The result of applying requirements to scoped referents under evidence.

## Minimum Declaration Objects

A declared model needs these declarations.

### ModelDeclaration

```text
ModelDeclaration {
  id: ModelId
  version: SemVer
  declared_at: Timestamp
  declared_by: ActorRef
}
```

This creates `Self`.

### ActorDeclaration

```text
ActorDeclaration {
  id: ActorId
  role: ActorRole
}
```

This creates accountability. Actor roles must be vocabulary, not authorization
by themselves.

### ReferentDeclaration

```text
ReferentDeclaration {
  id: ReferentId
  sort: ReferentSort
}
```

This creates the model's targetable things.

Specialized declarations such as zone, server, process, artifact, dependency,
or credential are refinements of `ReferentDeclaration`.

### BoundaryDeclaration

```text
BoundaryDeclaration {
  id: BoundaryId
  side_a: SideDeclaration
  side_b: SideDeclaration
  surface_a: SurfaceDeclaration
  surface_b: SurfaceDeclaration
}
```

This creates separation and exposure anchors.

### EdgeDeclaration

```text
EdgeDeclaration {
  id: EdgeId
  sort: EdgeSort
  from: ReferentRef
  to: ReferentRef
}
```

This creates typed relation. Movement, dependency, trust handover, signing,
backup, and logging are all edge sorts or refinements of edge sorts.

### TypedScopeDeclaration

```text
TypedScopeDeclaration {
  id: ScopeId
  referent_sort: ReferentSort
  context: EvaluationContextDeclaration
  predicate: MembershipPredicateDeclaration
}
```

This creates applicability.

The selected carrier is:

```text
Carrier(context, referent_sort)
```

The selected members are:

```text
{ r in Carrier(context, referent_sort) | predicate_context(r) }
```

### RequirementDeclaration

```text
RequirementDeclaration {
  id: RequirementId
  sort: RequirementSort
  operator: RequirementOperator
  value: TypedValue
}
```

This creates normative content.

Requirement operators include, at minimum:

- presence: required, forbidden, optional
- order: exactly, at least, at most
- set: includes, excludes, equals
- count: equal, min, max
- temporal: before, after, within, every
- relation: exists, not exists, path length, edge count

### PolicyDeclaration

```text
PolicyDeclaration {
  id: PolicyId
  declared_by: ActorRef
  scope: TypedScopeRef
  requirement: RequirementRef
}
```

This creates security meaning.

## Evaluation Declarations

These are not required for a pure declared model, but are required for mapping
real-world input.

### EvidenceSourceDeclaration

```text
EvidenceSourceDeclaration {
  id: EvidenceSourceId
  source_type: EvidenceSourceType
  mapper: MapperId
  trust_assumption: TrustAssumption
}
```

### ObservationDeclaration

```text
ObservationDeclaration {
  id: ObservationId
  source: EvidenceSourceRef
  observed_referent: ReferentRef?
  observed_sort: ReferentSort
  at: Timestamp
  claim: TypedClaim
}
```

### EvaluationDeclaration

```text
EvaluationDeclaration {
  id: EvaluationId
  policy: PolicyRef
  evidence_basis: EvidenceBasisRef
  result: EvaluationResult
}
```

## Minimum Validity Rules

A declaration is invalid if:

1. it has no model identity,
2. it has no actor,
3. it has no policy,
4. a policy has no typed scope,
5. a policy has no requirement,
6. a typed scope has no referent sort,
7. a typed scope has no evaluation context,
8. a typed scope predicate is untyped,
9. a requirement operator is not meaningful for its value type,
10. a boundary has anything other than two sides and two surfaces,
11. an edge references missing referents,
12. a policy references missing actors, scopes, or requirements.

## Current Rust Mapping

Current crates approximate this as follows:

- `jw-guard-core` contains many concrete referent and graph atoms.
- `jw-guard-declare` begins the declaration layer with symbolic names,
  requirement operators, scope declarations, boundary declarations, and route
  policy declarations.

The concept model in this document is stricter than the current code where the
code still uses narrower terms such as `Zone`, `Route`, or `ScopeKind`.
