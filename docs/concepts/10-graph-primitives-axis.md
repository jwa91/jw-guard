# Graph Primitives Axis

This document defines an atomic graph axis from first principles.

It is orthogonal to the type-layer axis (`L0`, `L1`, `L2`, ...).  
Its purpose is to provide stable graph atoms that can be combined with type
atoms when deciding abstraction strategy.

## First Principle

A graph model is a finite set of identifiable points and typed relations between
those points.

Before policy/evaluation meaning, we need atomic graph identity and incidence.

## Atomic Graph Primitives

These are graph atoms, not composite graph objects.

1. `NodeIdentity`
   - stable nominal identity for one node.
2. `EdgeIdentity`
   - stable nominal identity for one edge instance.
3. `NodeKind`
   - closed vocabulary describing node semantic category.
4. `EdgeKind`
   - closed vocabulary describing relation semantic category.
5. `EndpointRef`
   - typed reference to a node identity used by an edge endpoint.
6. `Direction`
   - `directed` or `undirected`.
7. `Incidence`
   - atomic endpoint binding: `(edge, endpoint-role, node-ref)`.

## Minimal Composition Rules

From these atoms, compose only the minimum graph forms:

- `Node = (NodeIdentity, NodeKind)`
- `Edge = (EdgeIdentity, EdgeKind, Direction, EndpointRef...)`

No additional semantics are implied.

## Deterministic Invariants

Any graph definition built from these atoms must satisfy:

1. **Identity uniqueness**
   - node identities are unique in node namespace.
   - edge identities are unique in edge namespace.
2. **Endpoint totality**
   - every endpoint reference resolves to an existing node identity.
3. **Endpoint arity validity**
   - directed edge has exactly one `from` and one `to`.
   - undirected edge has exactly two unordered endpoints.
4. **Kind explicitness**
   - every node and edge has explicit kind from closed vocabularies.
5. **Deterministic normalization**
   - canonical ordering exists for nodes, edges, and endpoint listings.

## Not Included (By Design)

The following are not graph atoms and belong to higher abstractions:

- policy claims (`required`, `forbidden`, thresholds),
- evidence confidence/uncertainty,
- authority/delegation semantics,
- runtime state transitions,
- optimization preferences.

## Axis Usage

Use this axis with the type axis as a product:

```text
AbstractionDecisionSpace = TypeAxis × GraphAxis
```

Where:

- Type axis answers: "is decomposition to foundational type atoms unambiguous?"
- Graph axis answers: "is graph structure reducible to atomic identity and incidence?"

A candidate abstraction is strategy-safe only if it is valid on both axes.

## Strategy-Safety Predicate

```text
graph_atomic(def) -> bool
```

Returns true iff the definition can be reduced to the atomic graph primitives
above with no ambiguous identity, incidence, or direction interpretation.

