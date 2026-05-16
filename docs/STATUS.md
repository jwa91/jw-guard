# Project Status

## As-Is Situation

Active workspace members:

- `core` - deterministic, type-only model kernel
- `canon` - deterministic canonicalization primitives
- `declare` - symbolic declaration layer and deterministic concretisation
- `eval` - uncertainty-preserving policy evaluation primitives
- `mapper` - neutral deterministic source-fact mapping contract
- `wire` - strict DTO boundary and schema export
- `adapter-json` - syntax-only JSON adapter
- `adapter-yaml` - syntax-only YAML adapter
- `adapter-toml` - syntax-only TOML adapter
- `cli` - contract-first validation CLI
- `integration-tests` - cross-crate regression tests

Documentation status:

- `docs/concepts/` is the active concept authority baseline
- `docs/adr/` records accepted boundary decisions for core, adapters,
  evaluation, and mapping

## Goal and Roadmap

Goal:

- Keep project status explicit so agents and contributors treat only active
  workspace crates and active concept authority as baseline.

Roadmap:

1. add future crates only through explicit scope, deterministic gate criteria,
   and workspace membership
2. continuously trim stale docs and keep only active authority and roadmap state
3. enforce concept-to-implementation traceability for locked layers (`L0-L2`)
4. gate provisional layers (`L3+`) behind explicit strategy lock criteria
5. keep mapper implementations neutral: source facts only, no policy verdicts
