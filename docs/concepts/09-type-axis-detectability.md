# Type-Axis Detectability (L1-L2 Lock)

This document locks deterministic detection for `L1` and `L2`, and defines
the helper function:

```text
foundational_type_deconstructable(definition)
```

If and only if a definition can be decomposed into foundational types (`L0`)
without ambiguity, type-axis layering holds.

## Scope

This document is purely about structural/type-theory detectability.

It does **not** decide:

- package architecture placement,
- policy correctness,
- runtime/evaluation behavior.

## Canonical Definition Representation

All detection operates on a normalized abstract syntax:

```text
TypeDef =
  | Atom(name)                       -- L0 primitive atom
  | Nominal(name, inner: TypeDef)    -- nominal wrapper
  | Product(name, fields: Field[])
  | Sum(name, variants: Variant[])
  | Refine(name, base: TypeDef, predicate: PredicateId)
  | Ref(name, target: TypeDef)
  | Edge(name, from: TypeDef, to: TypeDef)
```

Normalization rules (required before detection):

1. deterministic field ordering by canonical key,
2. deterministic variant ordering by canonical key,
3. explicit nominal names (no anonymous domain types),
4. explicit predicates as stable identifiers.

If normalization fails, detection must fail.

## Locked Layer Predicates

### `is_l1(def)`

True iff:

1. `def = Nominal(N, Atom(A))` or `def = Refine(N, Atom(A), P)`,
2. exactly one `Atom(A)` leaf,
3. no products, sums, refs, or edges.

### `is_l2(def)`

True iff:

1. `def` is Product/Sum/Refine over `L1` or cleared `L2` children,
2. every leaf under `def` is a cleared `L1`,
3. no `Ref` or `Edge` constructors occur.

### Layer Uniqueness

For any normalized `def`, exactly one layer predicate should be the highest
true layer among `{L1, L2}`. If multiple highest-layer interpretations are
possible, detection fails as ambiguous.

## Decomposition Tree

Define canonical decomposition:

```text
DecompositionTree =
  Node(kind, name, children[])
```

Where leaves are only:

```text
Node(kind="atom", name=<L0 atom>, children=[])
```

Canonicalization:

1. preorder traversal,
2. children sorted by canonical key,
3. stable textual fingerprint of tree.

## Helper Function

```text
foundational_type_deconstructable(definition)
  -> Result<DeconstructabilityReport, DeconstructabilityError>
```

### Report

```text
DeconstructabilityReport = {
  normalized: bool
  detected_layer: "L1" | "L2"
  decomposition_tree: DecompositionTree
  l0_leaf_set: Set<AtomName>
  ambiguous: bool
}
```

### Error Kinds

```text
DeconstructabilityError =
  | NormalizationFailed
  | UnknownConstructor
  | InvalidLayerShape
  | AmbiguousDecomposition
  | NonFoundationalLeaf
```

## Deterministic Pass Criterion

A definition passes type-axis deconstructability iff:

1. normalization succeeds,
2. detected layer is one of `L1|L2`,
3. decomposition tree has only `L0` atom leaves,
4. exactly one canonical decomposition exists (`ambiguous == false`).

## Minimal Pseudocode

```text
fn foundational_type_deconstructable(def):
  norm = normalize(def) ? NormalizationFailed
  layer = detect_layer(norm) ? InvalidLayerShape
  tree = decompose_to_l0(norm) ? NonFoundationalLeaf
  if has_ambiguous_form(norm):
      return Err(AmbiguousDecomposition)
  return Ok({
      normalized: true,
      detected_layer: layer,
      decomposition_tree: canonicalize(tree),
      l0_leaf_set: collect_l0_leaves(tree),
      ambiguous: false,
  })
```

## Lock Statement

L1-L2 are considered locked on the type axis when this helper definition and
its predicates are the single acceptance oracle for structural classification.

## Provisional Extension Note

`L3+` detection is intentionally excluded from lock status. From `L3` onward,
classification depends on chosen semantic abstraction strategy, so those layers
remain provisional until that strategy is explicitly fixed and proven.

