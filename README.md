# jw-guard

Security policy type system for supply-chain hardening.

## Architecture

```
jw-guard (workspace)
├── core/       — Atomic and canonical model types (pure, sync, zero deps)
├── declare/    — First-principles declaration IR and declaration validation
└── cli/        — Thin binary entrypoint; adapter/enforcement commands reserved
```

This project contains my vision on a strict layered atomic typing system for security policies. I want to create the atomic most modular and atomic types of my system in pure rust. this will be the foundation for a second package that allows you to use these types within a scoped declaration, of a policy, or of a current situation.
This could also be used to map a wide variety of inputs against these types, based on the scope type of the input. (filetype, a log, a structure, a combination)
all of this together allows you to declare, analyze and enforce security policies for systems.

Start by reading the evolution ofmy thinking by going through the docs, then build the atomic type definitions in rust. When done, use these definitions to build the next layer of types. until the entire typesystem has been translated to rust.

Then help me structure this project in a smart way that enables me to build the perfectly consistant security library. for now focus on pure types, then translate it to a policy config document, after that build core adapters that resolve all types for a wide variety of config files and potentially other inputs.

## Current Rust Layering

The strict concept baseline lives in `docs/concepts/`. The Rust implementation
uses `atomic-security-type-system.md` and the drafts as design input, but those
drafts are not binding when they conflict with the concepts or current Rust
layer boundaries:

1. `core/src/id.rs` — branded entity IDs over `[u8; 16]`.
2. `core/src/scalars.rs` — validated scalar foundations and non-empty sequences.
3. `core/src/enums.rs` — closed vocabularies with ordered trust, hardness, and credential strength.
4. `core/src/structs.rs` — the ten atomic security types.
5. `core/src/composites.rs` — canonical aggregates and fundamental objects.
6. `core/src/validation.rs` — pure validation functions returning typed violations.
7. `declare/src/*` — symbolic declaration names, requirement operators, scope kinds, declaration objects, and declaration-local validation.

The core crate supports `no_std` with `alloc`; `serde` is available only behind
the optional `serde` feature.

`jw-guard-declare` is intentionally not a serializer for `SecurityModel`. It is
the normative layer for policy intent: names instead of core IDs, minimum
requirements instead of observations, and scope kinds that later mappers can use
to compare real-world inputs against the declared architecture.

## Development Toolchain

This workspace currently uses the Homebrew Rust toolchain:

- `cargo`
- `rustc`
- `rustfmt`
- `cargo-clippy`

`rustup` is not required for this project unless you want per-project toolchain
pinning, nightly Rust, cross-compilation targets, or component management.
If rustup is present, it should point at the Homebrew `system` toolchain so
Cargo subcommands such as `cargo fmt` and `cargo clippy` do not hit stale
rustup proxies.

## Roadmap Shape

Keep the foundation strict and small:

1. `jw-guard-core` — pure atoms, composites, and validation.
2. `jw-guard-declare` — policy config document schema and declarators.
3. `jw-guard-lint` — consistency, drift, and invariant linters.
4. `jw-guard-map` — mappers from YAML, JSON, TOML, logs, lockfiles, firewall rules, CI files, and runtime snapshots into core types.
5. `jw-guard-viz` — route graphs, boundary maps, trust chains, and policy coverage views.
6. `jw-guard-adapters` — platform and ecosystem adapters kept outside core.
7. Language packages and build/runtime plugins — wrappers for package managers, CI, build systems, and service runtimes.
