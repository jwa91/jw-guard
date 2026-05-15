# L1 Type Definition

This document defines Layer 1 (`L1`) on top of the current `L0` baseline.

`L0` is fixed to irreducible primitive atoms.  
`L1` is the first compositional layer, but remains strictly local and
deterministic.

## Purpose

`L1` exists to introduce **named meaning** without introducing graph/policy
structure.

It answers:

```text
How do we attach domain semantics to one atomic value?
```

It does not answer:

```text
How values relate to each other, or what policy they imply.
```

## Formal Definition

Let `A0` be the set of `L0` atoms.

An `L1` type is a pair:

```text
L1Type = (Name, Base, Invariant)
where:
  Name      : unique nominal identifier
  Base      : element of A0
  Invariant : Base -> bool (total, deterministic, side-effect free)
```

Runtime construction:

```text
new(base_value) -> Result<L1Type, InvariantError>
```

If `Invariant(base_value) == true`, construction succeeds; otherwise it fails.

## Allowed Rust Shape

Only this structural form is allowed in `L1`:

```text
pub struct X(Base);
```

Where:

- `Base` is exactly one `L0` atom,
- `X` is nominal (non-alias) and domain-named,
- no nested fields,
- no references, pointers, containers, or generics.

Allowed associated functions:

- `new(base: Base) -> Result<Self, ErrorCode>`
- `get(self) -> Base` or `as_base(&self) -> Base`

## Determinism Constraints

For `L1`, invariants must be:

1. **Total**: defined for every possible `Base` value.
2. **Pure**: no IO, randomness, time, filesystem, env, or network.
3. **Stable**: same input always produces same pass/fail result.
4. **Local**: depends only on the `Base` value, not global model state.

## Not Allowed in L1

These are explicitly outside `L1`:

- multi-field records,
- tuples combining multiple atoms,
- cross-type invariants (`x` valid only if `y` exists),
- graph references (`id` points to another object),
- policy/profile obligations ("must have at least N layers"),
- context-dependent checks (time, authority, host, environment).

Those belong to higher layers.

## Gate to Clear L1

`L1` is considered cleared when all introduced types satisfy:

1. one-field nominal wrapper over one `L0` atom,
2. deterministic local constructor invariant,
3. no cross-type coupling,
4. no policy/profile semantics in constructor logic.

Only after this gate is cleared may `L2` be opened for multi-atom composition.

## Examples

Valid `L1` examples:

- `Port(u16)` with invariant `value != 0`
- `NonEmptyName(char...)` over a chosen `L0` base representation with
  deterministic non-empty/allowed-character predicate
- `Sha256Hex(...)` over an `L0` base representation with deterministic length and
  alphabet checks

Invalid `L1` examples:

- `Boundary { left: ZoneId, right: ZoneId }` (multi-field composition)
- `RouteAllowed(bool)` where validity depends on zone kind/policy context
- any constructor that reads system time or external state

