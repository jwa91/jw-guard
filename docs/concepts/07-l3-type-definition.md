# L3 Type Definition

> **Status:** provisional candidate, not stable baseline.
>  
> L3 introduces semantics via graph/reference interpretation. Final L3 shape is
> gated on an explicit abstraction strategy decision and is therefore not locked.

This document defines Layer 3 (`L3`) in pure type-theory terms.

`L3` is the first layer that may represent graph/reference semantics between
typed objects. It still excludes policy/evaluation logic.

## Purpose

`L3` introduces:

- typed object identity at graph level,
- typed references between objects,
- total referential coherence constraints.

It does not introduce:

- normative requirements,
- actor authority decisions,
- evidence interpretation.

## Input Contract

`L3` may use only:

- cleared `L2` product/sum/refinement types,
- deterministic finite collections over those types.

## Formal Shape

Let `A2` be the set of cleared `L2` types.

Define:

```text
Node<T>      where T in A2
Ref<T>       nominal reference to Node<T>
Edge<A, B>   typed relation from Ref<A> to Ref<B>
Graph        finite set of Nodes and Edges
```

With constraints:

1. every `Ref<T>` resolves to exactly one node of type `T`,
2. every edge endpoint reference resolves,
3. edge type is explicit (no untyped relation edges),
4. graph validity is deterministic and total.

## Allowed Constructors

Allowed `L3` constructors:

- finite node collections,
- finite typed edge collections,
- deterministic graph constructor with explicit coherence checks.

Not allowed:

- implicit reference resolution,
- runtime-global lookup side effects,
- open-world reference fallback ("best effort" linking),
- context-dependent typing of edges.

## Rust Shape Constraints

Allowed:

- nominal IDs for `Ref<T>` (typed id wrappers),
- explicit node records with nominal ids,
- explicit edge records with typed `from` and `to` id wrappers,
- deterministic constructor/validator returning typed errors.

Disallowed in `L3`:

- policy-specific edge meaning baked into type validity,
- environment/time-dependent graph acceptance,
- dynamic trait object dispatch as semantic identity.

## L3 Invariant Class

`L3` may introduce:

1. **Referential totality**: every reference target exists,
2. **Referential uniqueness**: one id maps to one node in namespace,
3. **Typed endpoint constraints**: edge endpoint sorts are fixed by edge type,
4. **Finite graph constraints**: no infinite/implicit expansion.

`L3` must not introduce:

- policy profile constraints (hardness minimums, cadence mandates, etc.),
- evaluation outcomes (`satisfied`, `violated`, etc.),
- evidence uncertainty classes.

## Determinism Rules

For any `L3` constructor:

1. output graph and errors are deterministic for identical input sets,
2. ordering sensitivity must be normalized or explicitly rejected,
3. reference resolution algorithm is deterministic and documented,
4. no hidden defaults create nodes/edges.

## L3 Gate Criteria

`L3` is cleared only if every introduced graph type satisfies:

1. references are typed and total,
2. node/edge identity is nominal and deterministic,
3. graph validity depends only on provided values,
4. no policy/evaluation semantics are part of type validity.

Additionally:

5. the project has selected and documented an abstraction strategy proving this
   `L3` semantic model is the intended one (not just a sensible default).

## Boundary to L4

`L4` may open only after `L3` is cleared, and is the first layer allowed to
attach normative policy semantics over typed graph scopes.

