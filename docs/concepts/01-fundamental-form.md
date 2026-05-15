# Fundamental Form

This document defines the smallest abstract form that can still be called a
security model.

## First Principle

Security is the typed restriction of permitted relations across declared
boundaries.

The model must therefore represent:

1. things that can be referred to,
2. separations between things,
3. relations across or inside those separations,
4. actors accountable for claims,
5. policies that declare requirements over typed applicability sets,
6. evidence used to evaluate those requirements.

## Fundamental Shape

```text
SecurityModel =
  Self
  + ActorSet
  + ReferentSet
  + BoundaryGraph
  + PolicySet
  + EvidenceBasis?
  + EvaluationSet?
```

The `EvidenceBasis` and `EvaluationSet` are optional for a pure declared model.
They are required for an evaluated model.

## Minimum Viable Security Model

A minimum viable declared security model contains:

```text
Self: exactly one model identity
Actors: at least one accountable actor
Referents: at least the referents needed by the boundary graph and policies
Boundaries: at least one boundary
Sides: exactly two sides per boundary
Surfaces: exactly two surfaces per boundary
Edges: at least one typed edge
Policies: at least one policy
TypedScopes: at least one typed scope referenced by a policy
Requirements: at least one requirement referenced by a policy
```

Why each is required:

- Without `Self`, there is no closed object to validate or version.
- Without `Actor`, declarations have no accountability.
- Without `Referent`, policies have nothing to point at.
- Without `Boundary`, the model has no separation.
- Without `Side`, a boundary has no ends.
- Without `Surface`, exposure cannot be described.
- Without `Edge`, relations and movement cannot be described.
- Without `Policy`, the graph is topology, not security.
- Without `TypedScope`, policy applicability is ambiguous.
- Without `Requirement`, policy has no normative content.

## Boundary Graph

The boundary graph is not merely a network graph.

```text
BoundaryGraph =
  Referents
  + Boundaries
  + Sides
  + Surfaces
  + Edges
```

Edges are typed relations. Some edges cross boundaries. Some are inside one
side. Some relate policy objects rather than runtime objects. A route is only
one edge kind.

## Policy Form

The most abstract policy form is:

```text
Policy<A, T, C, P, R> =
  declared_by: A
  scope: TypedScope<T, C, P>
  requirement: R<T>
```

Where:

- `A` is an accountable actor.
- `T` is the referent sort selected by the scope.
- `C` is the evaluation context.
- `P` is the membership predicate.
- `R<T>` is a requirement meaningful for referents of sort `T`.

This form deliberately does not say "allow" or "deny". Allow/deny is one
possible decision vocabulary. The more fundamental concept is requirement over
scope.

## TypedScope Form

```text
TypedScope<T, C, P> = { r in Carrier(C, T) | P_C(r) }
```

This form forces four questions to be explicit:

1. What sort of referent is selected?
2. What context determines the available carrier?
3. What predicate selects members?
4. What policy requirement will be applied to those members?

## Declared Model vs Evaluated Model

A declared model answers:

```text
What must be true?
```

An evaluated model answers:

```text
What appears to be true, according to this evidence basis, and does it satisfy
the declaration?
```

They are related but not the same object.

```text
Declaration + EvidenceBasis -> Evaluation
```

No mapper may silently convert unknown evidence into satisfaction.

## Neutrality Rule

The fundamental form must not embed project policy opinion.

It may express:

- "this edge must use cadence airlock"
- "this boundary path must have at least four layers"
- "this artifact must be signed with method X"

It must not universally assert:

- every signing route must be airlock
- every boundary must have four layers
- every project must use one signature method

Those are declarations or profiles, not model axioms.
