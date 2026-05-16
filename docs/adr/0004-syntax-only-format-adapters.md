# ADR-0004: Format adapters are syntax-only; declarers own policy vocabulary

- Status: Accepted
- Date: 2026-05-16
- Codifies:
  - `e45f9ca` — Add strict wire and adapter pipeline for `DeclaredSpec` (#2).
  - `8e54605` — Add DS_Store ignore and YAML boundary rule.
  - `50b21ab` — Harden adapter error staging and strictness checks (#3).
  - `6586769` — Fix TOML source mapping and adapter error assumptions.
  - `aa6693c` — Record rejected opinionated YAML policy attempt (kept as
    cautionary reference branch).

## Context

A prior YAML-policy experiment baked policy vocabulary (allowed values, schema
hardening, posture defaults) into the format layer. That made format upgrades
indistinguishable from policy changes and gave non-declarers de facto policy
authority. The experiment was reverted; the lesson became a hard boundary rule.

The current pipeline is `adapter-{json,yaml,toml}` → shared wire DTO → `declare`
→ `core`. Each stage has a single, narrow job. Conflating any two stages
recreates the lossiness-without-authority problem.

## Decision

- `adapter-{json,yaml,toml}` parse bytes into the shared wire DTO only. They
  perform no semantic validation, no defaults, no reference resolution, no
  reordering.
- Two error stages are exposed distinctly and never collapsed:
  1. **Syntax errors** — format parser failed.
  2. **Wire/shape errors** — DTO mismatch (unknown fields, null where invalid,
     bad union kind, type/range violations, name lexical failures).
- Format-specific strictness, enforced at parse time:
  - **JSON** — reject duplicate keys; reject trailing non-whitespace data.
  - **YAML** — reject anchors, aliases, explicit tags, merge keys (`<<`),
    multi-document streams. Detect via parser events, not substring heuristics.
  - **TOML** — reject native datetime values, mixed-type arrays, range
    overflows for unsigned DTO fields. Use the `@none` sentinel inline table
    for `ExplicitOption` tri-state, alone in the table and only with value
    `true`.
- All wire DTOs use `#[serde(deny_unknown_fields)]`.
- Lossiness and policy vocabulary (allowed values, posture defaults, schema
  hardening) are declarer-owned decisions that live in `declare` and above.
- Parser locations must never be invented. Byte offsets (e.g.,
  `toml::de::Error::span()`) may not be reinterpreted as line/column without
  the source text — emit no location rather than an inaccurate one.

## Consequences

- Positive: format upgrades and policy changes are reviewable independently.
- Positive: adapters stay small and auditable; new formats can be added
  without revisiting policy semantics.
- Positive: declarers retain authority over what their vocabulary means.
- Negative: convenient sugar (auto-defaults, alias expansion, type coercion)
  cannot be added at the adapter layer.
- Accepted trade-off: more verbose declarer-side specs in exchange for a
  clean authority boundary.

## Evidence in code

- [docs/format_convention.md](../format_convention.md) — normative contract.
- [adapter-json/src/lib.rs](../../adapter-json/src/lib.rs) — duplicate-key and
  trailing-data rejection.
- [adapter-yaml/src/lib.rs](../../adapter-yaml/src/lib.rs) — event-driven
  rejection of anchors/aliases/tags/merge keys/multi-doc.
- [adapter-toml/src/lib.rs](../../adapter-toml/src/lib.rs) — datetime
  rejection; `@none` sentinel handling.
- [wire/src/dto.rs](../../wire/src/dto.rs) — every DTO struct carries
  `#[serde(deny_unknown_fields)]`.
- [wire/src/convert.rs](../../wire/src/convert.rs) —
  `impl TryFrom<WireDeclaredSpec> for DeclaredSpec` accumulates errors instead
  of short-circuiting.

## What would re-open this decision

- A proposal to add semantic defaults, reordering, reference resolution, or
  policy vocabulary inside any adapter or the wire layer.
- A proposal to collapse the two-stage error model into a single string error.
- A proposal to accept a new format whose constraints cannot be expressed
  without inventing policy posture in the adapter.
