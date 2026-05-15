# Deterministic Concretisation

This document defines how abstract declarations become concrete model referents
and how real-world observations are compared to them.

The goal is dispute resistance. Given the same declaration, same mapper
versions, same evidence, and same evaluation context, the system must produce
the same canonical model and the same evaluation results.

## Definitions

`Declaration`

: Normative source of intent.

`Canonical Model`

: The normalized graph of model referents, boundaries, surfaces, edges, typed
  scopes, and policies derived from declarations.

`Observation`

: Real-world evidence mapped into model language.

`Evaluation`

: Comparison of policy requirements against scoped model or observed referents.

## Pipeline

```text
Declaration
  -> validate declaration
  -> normalize declaration
  -> derive canonical referent identities
  -> build canonical model graph
  -> validate canonical model

Evidence
  -> map evidence to observations
  -> normalize observations
  -> resolve observations to model referents
  -> evaluate policies over typed scopes
```

No step may rely on iteration order, filesystem order, map/hash table order, or
implicit defaults.

## Declaration Validation

Declaration validation checks intent before concretisation.

It must reject:

- duplicate names in the same namespace,
- missing references,
- untyped predicates,
- ambiguous referent sorts,
- requirements whose operator cannot apply to their value type,
- contradictory requirements within the same typed scope,
- policy declarations without actor, typed scope, or requirement.

It must not reject a declaration merely because the declaration is stricter or
weaker than a project preference.

## Normalization

Normalization converts equivalent declaration spellings into one canonical
form.

Rules:

1. All declaration names are already strict machine names.
2. All references resolve to canonical declaration paths.
3. All unordered collections are sorted by canonical key.
4. All ordered collections preserve declared order and validate that order is
   meaningful.
5. All optional values are represented explicitly as absent or present.
6. No default is injected unless the declaration schema explicitly defines that
   default.

## Canonical Paths

Each declaration object has a canonical path.

Examples:

```text
model/<model-name>
actor/<actor-name>
referent/<sort>/<name>
boundary/<boundary-name>
boundary/<boundary-name>/side/a
boundary/<boundary-name>/surface/a
edge/<edge-sort>/<edge-name>
scope/<scope-name>
requirement/<requirement-name>
policy/<policy-name>
```

The path is part of referent identity. Renaming a declaration object changes
identity unless an explicit alias/migration declaration says otherwise.

## Deterministic IDs

When a compact ID is needed, derive it from the canonical path and model
version using a domain-separated hash.

Normative strategy:

```text
id_bytes = first_16_bytes(
  sha256("jw-guard:<id-kind>:<schema-version>:<canonical-path>")
)
```

Rules:

1. `id-kind` is the target ID brand, such as `zone`, `boundary`, `edge`, or
   `policy`.
2. `schema-version` is the declaration schema version, not a tool version.
3. `canonical-path` is the normalized path.
4. The first 16 bytes map to current core `[u8; 16]` branded IDs.
5. A collision is a hard validation error.

This is deterministic, but not authority by itself. The canonical path remains
the human-auditable identity.

## Carrier Construction

For a typed scope:

```text
TypedScope<T, C, P> = { r in Carrier(C, T) | P_C(r) }
```

Concretisation must define `Carrier(C, T)` before evaluating `P_C`.

Carrier construction must be deterministic:

1. Select all model referents with referent sort `T`.
2. Restrict by context `C`.
3. Sort by canonical referent identity.
4. Do not include observed referents unless the evaluation context explicitly
   includes an evidence basis.

The context `C` must say what kind of restriction it applies:

- model boundary,
- graph region,
- traversal rule,
- namespace,
- actor authority,
- snapshot time,
- evidence source,
- mapper version.

## Predicate Evaluation

`P_C` is evaluated against each referent in the carrier.

For pure declarations, membership may be crisp:

```text
member | non-member
```

For observations, membership may be evidence-qualified:

```text
member
non-member
unknown
contradictory
stale
```

An evaluator must not collapse `unknown`, `contradictory`, or `stale` into
`member`.

## Requirement Evaluation

A requirement is evaluated only over members of its typed scope.

Examples:

```text
count(defense_layer) >= 4
encrypted == true
signature_method == ed25519
backup_interval <= 24h
max_trust_handover_edges <= 30
```

The evaluator must verify that the requirement operator is meaningful for the
referent sort and value type.

## Observation Mapping

A mapper converts real-world input into observations. It does not decide policy.

Mapper output must include:

- evidence source,
- mapper identity and version,
- observation time,
- observed referent sort,
- claimed properties or relations,
- confidence or certainty class when known,
- raw source pointer or digest where possible.

Mapping is deterministic when the same input and mapper version produce the same
observations.

## Resolution

Observation resolution maps observations to canonical model referents.

Outcomes:

- resolved to one referent,
- unresolved,
- ambiguous,
- creates candidate referent outside declared model,
- conflicts with existing referent identity.

Only resolved observations can directly satisfy requirements. Unresolved or
ambiguous observations may support discovery findings, but they do not silently
prove compliance.

## No Hidden Opinion Rule

Concretisation must not create project-specific security requirements.

Allowed:

```text
Declaration says route X requires cadence airlock.
Canonical model contains that requirement.
```

Forbidden:

```text
Route touches signing zone.
Concretisation silently requires cadence airlock.
```

Allowed:

```text
Declaration says dependency paths must have <= 30 trust handovers.
Evaluator checks that count.
```

Forbidden:

```text
All dependency paths are capped at 30 by the core model.
```

## Dispute Procedure

If two outputs differ, compare in this order:

1. declaration bytes,
2. declaration schema version,
3. normalization rules,
4. canonical paths,
5. derived IDs,
6. mapper identity and version,
7. evidence bytes or source digest,
8. evaluation context,
9. predicate version,
10. requirement operator version.

The first difference explains the output difference. If no difference exists,
the implementation is non-deterministic and invalid.
