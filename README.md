# jw-guard

Deterministic, unopinionated security-model type system.

## As-Is Situation

The current authority baseline is in `docs/concepts/` and is the source of truth
for terminology, layer boundaries, and determinism constraints.

Current workspace:

```
jw-guard (workspace)
├── core/        -- type-only model kernel (IDs, scalars, enums, structs, composites, validation)
├── canon/       -- deterministic canonicalization primitives (paths, ordering, IDs, normalization)
├── declare/     -- symbolic declaration layer and deterministic concretisation
├── eval/        -- uncertainty-preserving policy evaluation primitives
├── mapper/      -- neutral deterministic source-fact mapping contract
├── wire/        -- strict DTO boundary and schema export
├── adapter-*/   -- syntax-only JSON/YAML/TOML adapters
├── cli/         -- contract-first validation CLI
└── integration-tests/
```

Current stable properties:

- `core` is type-only and deterministic.
- `core` does not encode project policy posture defaults.
- evaluation semantics keep uncertainty states (no forced bool-only collapse).
- `canon` provides deterministic path/order/ID/normalization foundations for concretization.
- mappers translate source facts into neutral observations; policy meaning
  remains in declarations and evaluation.

## Goal and Roadmap

Goal:

- Build a universal, strict, deterministic security-model type system that stays
  unopinionated at core and composes upward into declaration, mapping,
  evaluation, and enforcement ecosystems.

Roadmap:

1. Lock `core` + `canon` as deterministic baseline (no hidden policy semantics).
2. Build declaration layer for normative intent over typed scopes/requirements.
3. Build evaluation layer with explicit uncertainty-preserving outcomes.
4. Build mapping layer from system/security inputs into canonical model evidence.
5. Add optional profile and runtime layers outside core for opinionated posture
   and operational enforcement.
6. Add lint/audit tooling for drift detection, replay determinism, and axis
   boundary integrity.
