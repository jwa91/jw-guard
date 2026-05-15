# Terminology

This document locks the words used by the model.

The goal is precision, not completeness. A term should be added only when a
later model, declaration, mapper, or evaluator cannot be expressed without it.

## Model

A `SecurityModel` is a policy-bearing graph of typed referents, boundaries,
surfaces, edges, and actors.

A graph without policy is topology. A policy without a graph is an unanchored
claim. A model requires both.

## Referent

A `Referent` is anything the model can point at.

Examples at different layers include an actor, domain, boundary, surface, edge,
file, dependency, process, event, artifact, credential, backup, log stream,
state, relation, path, claim, or evidence item.

A referent is not necessarily the real-world object itself. It is the model's
typed handle for that object, relation, state, or claim.

## Referent Sort

A `ReferentSort` is the declared semantic type of a referent.

Examples:

- `Actor`
- `Boundary`
- `Surface`
- `Edge`
- `StoredObject`
- `DependencyEdge`
- `TrustHandover`
- `BoundaryPath`
- `ProcessEvent`
- `ReleaseArtifact`

`ReferentSort` must not be treated as an arbitrary union. If `T` is allowed to
mean "file or dependency or actor", the scope is no longer semantically
homogeneous even if the implementation calls it one type.

## Identity And Equality

Every model referent must have a stable model identity.

Referent equality is nominal unless a specific mapper or canonicalization rule
declares otherwise. Two observations that look structurally similar are not the
same referent until they resolve to the same canonical referent identity.

This prevents false equivalence such as:

- path vs inode
- declared dependency vs resolved dependency
- source artifact vs shipped artifact
- process name vs process instance
- log entry vs event it describes

## Actor

An `Actor` is an accountable subject in the model.

An actor may declare, approve, enforce, observe, or perform a relation. The
model must be able to attribute policy and evidence to actors. Actor does not
mean human only.

## Boundary

A `Boundary` is a declared separation between two sides.

A boundary is not itself a policy. It is the place where policy can constrain
relations.

## Side

A `Side` is one end of a boundary.

At the most abstract level a side is only an anchor. Richer terms like zone,
server, phase, package, tenant, account, or outside are concrete side kinds.

## Surface

A `Surface` is the exposed face of a boundary as seen from one side.

Surfaces are necessary because a boundary can expose different referents,
relations, or capabilities from each side.

## Edge

An `Edge` is a typed relation between model referents.

Examples:

- can reach
- depends on
- trusts
- signs
- logs to
- backs up to
- contains
- crosses boundary
- serves
- builds

A route is a more specific edge: a sanctioned movement edge.

## Policy

A `Policy` is a normative claim over a typed scope.

Minimum shape:

```text
Policy = Actor + TypedScope + Requirement
```

The actor provides accountability. The typed scope says what the policy applies
to. The requirement says what must, may, or must not be true.

## Requirement

A `Requirement` is a typed normative predicate.

It must be expressible without relying on hidden project opinion. For example:

- `count(defense_layer) >= 4`
- `encrypted == true`
- `signature_method == ed25519`
- `max_trust_handovers <= 30`
- `backup_interval <= 24h`

Whether a project chooses those values is policy. The model language only needs
to express them.

## TypedScope

A `TypedScope` is the applicability set of a policy or observation.

Formal shape:

```text
TypedScope<T, C, P> = { r in Carrier(C, T) | P_C(r) }
```

Where:

- `T` is a referent sort.
- `C` is the evaluation context.
- `Carrier(C, T)` is the set of referents of sort `T` available under context
  `C`.
- `P_C` is the membership predicate interpreted under the same context.

Short definition:

> A `TypedScope` is a refinement of the context-defined carrier of one referent
> sort.

This replaces the weaker phrase "things within a boundary". Boundary may be
part of context, but context may also include snapshot, authority, evidence
source, traversal rule, namespace, and time window.

## Evaluation Context

An `EvaluationContext` defines the carrier from which a typed scope selects.

It may include:

- model version
- snapshot time or time range
- boundary or graph region
- authority domain
- namespace
- evidence source
- traversal depth or path rule
- mapper version

Context must be explicit when changing it could change scope membership.

## Evidence

`Evidence` is a claim or observation with provenance.

Evidence can be a referent in its own right, but evidence that supports scope
membership must not be confused with the selected referent.

Example:

- Referent: a stored object.
- Evidence: a filesystem scan that observed the object.

## Observation

An `Observation` is evidence mapped into model language.

Observations may be incomplete, stale, contradictory, or probabilistic. The
declaration can be crisp while evaluation may be evidence-qualified.

## Evaluation

An `Evaluation` compares a requirement against a typed scope under an evidence
basis.

Minimum outcomes:

- satisfied
- violated
- unknown
- not applicable
- contradictory evidence
- stale evidence

Boolean pass/fail is a later reduction, not the fundamental form.
