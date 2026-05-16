# Agent Guardrails

This file is authoritative for agent behavior when editing `jw-guard`. Read it
before any change. It points to the ADRs and concept docs that own specific
constraints; this file is the index and the operating rules.

## Mission

`jw-guard` is a universal, strict, deterministic security-model type system.
It stays unopinionated at the core and composes upward into declaration,
mapping, evaluation, and (later) enforcement layers. Precision and strictness
override convenience. When in doubt about a structural choice, default to the
narrower, more deterministic option.

## Authoritative documents (in resolution order)

1. **`AGENTS.md`** (this file) — operating rules and the ADR index.
2. **`docs/adr/`** — accepted structural decisions, each with citable
   evidence and a re-open trigger. ADRs win over concepts when they disagree.
3. **`docs/concepts/`** — conceptual baseline (terminology, fundamental form,
   layer definitions). The `README.md` there tracks locked vs provisional
   concepts.
4. **`docs/format_convention.md`** — normative contract for format adapters.

Drafts and historical exploration notes never outrank the four documents above.

## ADR index

- [ADR-0001 — Type-only, policy-neutral core](docs/adr/0001-type-only-neutral-core.md):
  `core` may define types, deterministic constructors, and deterministic
  validators only. No side effects, no policy posture defaults.
- [ADR-0002 — Type-axis lock at L1–L2; L3+ provisional](docs/adr/0002-type-axis-lock-l1-l2-l3-provisional.md):
  deconstructability is guaranteed only at L1 and L2; L3+ remains
  design-strategy-dependent.
- [ADR-0003 — Three orthogonal axes: type, graph, observation](docs/adr/0003-three-orthogonal-axes.md):
  type, graph, and observation/applicability semantics stay separate; no
  overloaded type fuses them.
- [ADR-0004 — Syntax-only format adapters](docs/adr/0004-syntax-only-format-adapters.md):
  `adapter-{json,yaml,toml}` parse syntax only; declarers own policy
  vocabulary; two-stage error model is mandatory.
- [ADR-0005 — Uncertainty-preserving evaluation outcomes](docs/adr/0005-uncertainty-preserving-outcomes.md):
  evaluation outcomes preserve `Unknown` and `NotApplicable`; never collapse
  to `bool`; validation accumulates.
- [ADR-0006 — Neutral deterministic mapper contract](docs/adr/0006-neutral-mapper-contract.md):
 mappers translate source facts into neutral observations; they must not emit
 policy verdicts or threshold-derived posture tags.

## Hard constraints (do not violate)

Each constraint cites the ADR that owns it. The ADR is the place to extend or
contest the rule.

1. **Type-only core.** `core` defines types, deterministic constructors, and
   deterministic validators only — no runtime enforcement, orchestration, or
   remediation. *(ADR-0001)*
2. **No hidden policy opinion in core.** No implicit mandates ("signing must
   use airlock"), hardening profile defaults, or risk heuristics in `core`.
   Policy posture belongs in `declare`, profiles, and evaluators. *(ADR-0001)*
3. **Deterministic construction only.** Constructors and validators are
   total, pure, and stable for identical inputs. No time, env, network, fs,
   process, or randomness in `core` validity logic. *(ADR-0001)*
4. **Locked type-axis discipline.** L0 is the fixed primitive baseline; L1
   and L2 are the current stable lock scope. L3+ is provisional and must not
   silently elevate semantics into `core`. *(ADR-0002)*
5. **Axis orthogonality.** Keep type, graph, and observation semantics
   explicit and separable. Do not collapse axis semantics into one overloaded
   type. *(ADR-0003)*
6. **Adapter boundary.** Format adapters perform syntax-to-DTO translation
   only — no semantic validation, no defaults, no reordering, no reference
   resolution. Two error stages (syntax / wire-shape) are exposed distinctly.
   *(ADR-0004)*
7. **Uncertainty-preserving outcomes.** Evaluation outcomes keep `Unknown`
   and `NotApplicable` available; no public API in `core` or `eval` collapses
   a policy decision to `bool`. Validation surfaces accumulate violations.
   *(ADR-0005)*
8. **Neutral mapping.** Mappers translate external source facts into neutral
 observations. They must not own policy posture, threshold choices, or
 enforcement outcomes. *(ADR-0006)*

## Style for core changes

- Prefer constructor gates to runtime checks for invalid-state prevention.
- Return explicit typed violations and errors; never strings, never bools.
- Keep enums closed and exhaustive where possible; no wildcard match arms
  except where the type explicitly requires it.
- Keep APIs lean: smallest composable type additions; no speculative
  architecture.
- Newtype-wrap IDs and scalars at the type boundary; rely on the type system
  rather than runtime checks to prevent cross-field confusion.

## Learned anti-patterns to avoid

- Tests claiming "enforcement complete" when they only prove structural
  validity. *(see ADR-0005)*
- Using boolean pass/fail as the only evaluation semantics in `core` or
  `eval`. *(ADR-0005)*
- Adding convenience defaults that alter normative meaning. *(ADR-0001)*
- Mixing declaration intent with runtime observation or enforcement logic.
  *(ADR-0001, ADR-0003)*
- Hard-coding policy vocabulary or allowed value sets in shared language or
  format layers before a declarer-defined sequence exists. *(ADR-0004)*
- Inventing parser source locations from byte offsets when the source text is
  unavailable for conversion. *(ADR-0004)*

## Adapter implementation notes

Concrete reminders that follow from ADR-0004 and have already cost time:

- `parse()` returns syntax/shape errors only. Declare-conversion errors are
  produced in `DeclaredSpec::try_from(wire)`. Do not write unreachable match
  arms that imply a stage the code path cannot produce.
- For TOML, never reinterpret `toml::de::Error::span()` (a byte range) as
  line/column coordinates without the source text. Emit no location rather
  than an inaccurate one.
- For YAML, detect forbidden features (anchors, aliases, tags, merge keys,
  multi-doc) via parser events, never via substring heuristics on the input.
- Every wire DTO struct must carry `#[serde(deny_unknown_fields)]`.

## YAML policy boundary (specific to ADR-0004)

- YAML adapters may adapt YAML syntax and shape only; they must not invent
  policy posture.
- Preferred sequencing for policy authoring evolution (declarer-owned):
  1. template tagging
  2. declarer-defined allowed value sets
  3. typed value bindings
  4. schema hardening from declared constraints
- If a schema encodes domain opinions before this sequence is explicit, treat
  it as reference-only work and do not merge into mainline.

## Acceptance checklist for any core or adapter PR

- [ ] No hidden policy or default posture introduced. *(ADR-0001, ADR-0004)*
- [ ] No runtime side effects in core logic. *(ADR-0001)*
- [ ] Deterministic behavior preserved (same input → same output / errors).
      *(ADR-0001)*
- [ ] L1/L2 lock scope respected; no silent L3+ elevation. *(ADR-0002)*
- [ ] Axis orthogonality preserved; no overloaded fusion across type, graph,
      or observation. *(ADR-0003)*
- [ ] Outcome semantics remain uncertainty-preserving (no forced bool-only
      collapse). *(ADR-0005)*
- [ ] Format adapters stay syntax-only; two-stage error model intact.
      *(ADR-0004)*
- [ ] Tests describe exactly what they validate (no over-claims).
- [ ] If a change touches structure that an ADR governs, the ADR is either
      still accurate, or this PR also updates the ADR.
