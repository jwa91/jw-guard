# L2 Typegate

This document defines Layer 2 (`L2`) as the first compositional layer after
`L1`, using pure type theory only.

`L2` is only one angle (structural typing angle). It does not cover policy,
evaluation, mapping, or runtime enforcement.

## Purpose

`L2` introduces compositional structure while preserving determinism and
neutrality:

- combine `L1` types into products and sums,
- encode structural relations,
- keep all semantics local to type structure and invariants.

## Input Contract

`L2` may use only:

- `L1` nominal single-atom types that passed the `L1` gate.

`L2` must not directly introduce raw `L0` atoms except through approved `L1`
wrappers.

## Formal Type-Theory Shape

Let `A1` be the set of cleared `L1` types.

Allowed `L2` constructors:

```text
Product: T = A × B × ...      where A,B in A1 or prior-cleared L2 products
Sum:     T = A + B + ...      where A,B in A1 or prior-cleared L2 sums
Refine:  T = { x : U | P(x) } where U is allowed L2 type and P is deterministic
```

Where `P` must be total, pure, deterministic, and finite-time.

## Allowed Rust Shape

Allowed:

- structs with named fields of `L1` types (and cleared `L2` subtypes),
- enums with variants carrying `L1`/cleared-`L2` payloads,
- constructor functions enforcing deterministic structural invariants.

Not allowed:

- references/pointers for identity semantics,
- trait-object based semantic polymorphism,
- generic unconstrained containers as domain identity,
- context-dependent constructors (time/env/io/network).

## L2 Invariant Class

`L2` may introduce:

1. **Shape invariants** (field presence, cardinality, ordering markers),
2. **Cross-field deterministic invariants** (e.g. `left != right`),
3. **Closed-union discriminants** (tagged sums with exhaustive variants).

`L2` must not introduce:

- global graph constraints,
- policy-profile constraints,
- authority/actor semantics,
- evidence/evaluation semantics.

Those are higher layers.

## Determinism Rules

For every `L2` constructor:

1. output depends only on input arguments,
2. invariant outcome is stable for identical inputs,
3. no hidden default that changes semantic identity,
4. failure paths are explicit and typed.

## L2 Gate Criteria

`L2` is cleared only if all candidate types satisfy:

1. built exclusively from cleared `L1` types (and cleared `L2` dependencies),
2. constructor invariants are deterministic and local to provided values,
3. no policy or runtime context enters type validity,
4. sum variants are closed and exhaustively matchable,
5. products have explicit nominal identity (no anonymous tuple-as-domain).

## Boundary to L3

`L3` may open only after `L2` is cleared, and is the first layer allowed to
introduce graph-level composition and inter-object reference semantics.

