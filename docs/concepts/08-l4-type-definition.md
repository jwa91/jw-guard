# L4 Type Definition

This document defines Layer 4 (`L4`) in pure type-theory terms.

`L4` is the first layer that may introduce normative semantics
("must/forbidden/allowed") over the typed graph from `L3`.

## Purpose

`L4` introduces:

- typed policy declarations,
- typed applicability sets (scopes),
- typed normative predicates (requirements),
- deterministic policy application form.

It does not introduce:

- observational uncertainty handling,
- probabilistic evidence semantics,
- runtime enforcement behavior.

## Input Contract

`L4` may use only:

- cleared `L3` graph/reference types,
- deterministic finite collections and closed unions.

## Formal Shape

Let `G` be a cleared `L3` graph.

Define:

```text
Scope<T>        = refinement over carrier of graph referents of type T
Requirement<T>  = typed normative predicate over T
Policy<A, T>    = (declared_by: A, scope: Scope<T>, requirement: Requirement<T>)
PolicySet       = finite set of Policy values
```

Where:

1. `T` is explicit and fixed per scope/requirement/policy,
2. `Requirement<T>` is well-typed for `T`,
3. `Policy` references resolve to existing typed objects in `G`,
4. policy validity is deterministic and total.

## Allowed Constructors

Allowed:

- closed requirement operator families (presence, count, set, order, relation),
- explicit typed scope constructors,
- deterministic policy constructors and validators.

Not allowed:

- untyped requirement values,
- implicit scope sort inference,
- operator/value combinations without typed meaning,
- context-dependent reinterpretation of requirement operators.

## Rust Shape Constraints

Allowed:

- nominal policy/scope/requirement identifiers,
- explicit enums for requirement operators,
- explicit typed value unions for requirement payloads,
- deterministic constructor APIs returning typed errors.

Disallowed:

- stringly-typed policy operators as open text,
- dynamic runtime casting for requirement meaning,
- hidden default operators or hidden default scope sort.

## L4 Invariant Class

`L4` may introduce:

1. **Typed applicability invariants**: scope selects one declared referent type.
2. **Operator/value compatibility invariants**: each operator admits only valid value kinds.
3. **Policy linkage invariants**: policy references existing actor/scope/requirement.
4. **Deterministic ordering invariants** for ordered policy substructures.

`L4` must not introduce:

- evidence confidence semantics (`unknown`, `stale`, etc.),
- runtime event interpretation,
- external-source trust weighting.

Those belong to later layers.

## Determinism Rules

For any `L4` constructor/validator:

1. same inputs -> same pass/fail result,
2. no hidden defaults that alter normative meaning,
3. all unions are closed and exhaustively handled,
4. all failure modes are explicit and typed.

## L4 Gate Criteria

`L4` is cleared only if:

1. every policy is typed as `(actor, typed scope, typed requirement)`,
2. every requirement operator is type-compatible with its value domain,
3. every scope is explicit in referent type and membership predicate family,
4. no evidence/evaluation/enforcement semantics are embedded in type validity.

## Boundary to L5

`L5` may open only after `L4` is cleared, and is the first layer allowed to
attach evidence semantics and evaluation outcomes to policies.

