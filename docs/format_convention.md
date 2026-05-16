# Format Convention for `DeclaredSpec` Adapters

This document is normative for file-format adapters that target
`jw_guard_declare::DeclaredSpec`.

Scope: JSON, YAML, and TOML inputs that parse into a shared wire DTO and then
translate into `DeclaredSpec`.

## Layering and Responsibilities

1. **Format adapter**: bytes to wire DTO only.
2. **Wire conversion**: wire DTO to `DeclaredSpec` with typed errors.
3. **Declare/concretise layers**: semantic validation and deterministic ordering.

Adapters MUST NOT perform semantic validation, defaults, reference resolution,
or reordering.

## Two-Stage Error Model

Adapters expose two distinct stages:

1. **Syntax errors**: input cannot be parsed by the format parser.
2. **Wire/shape errors**: parsed input cannot be translated into `DeclaredSpec`.

These stages are never collapsed into a single string error.

## Root Shape

Every file maps to one `DeclaredSpec` wire document with these root fields:

- `schema_version`
- `model`
- `actors`
- `referents`
- `boundaries`
- `edges`
- `scopes`
- `requirements`
- `policies`

Key casing is snake_case in all three formats. Adapters do not accept alternate
spellings (for example, `schemaVersion`).

Unknown fields are rejected as wire/shape errors at every nesting level.
Implementations use `#[serde(deny_unknown_fields)]` for wire DTO structs.

`null` is meaningful only for `ExplicitOption` fields. For all other fields,
`null` is a wire/shape error.

## Tagged-Union Encoding

All union values use an internally tagged object with a `kind` discriminator.
This rule is identical in JSON, YAML, and TOML.

Current unions:

- `scope.predicate` (`all`, `has_tag`, `name_equals`)
- `requirement.value` (`bool`, `u64`, `name`, `names`, `duration_seconds`)

Payload fields are variant-specific:

- `all`: no payload fields
- `has_tag`: `tag`
- `name_equals`: `name`
- `bool`: `value` (boolean)
- `u64`: `value` (u64)
- `name`: `name` (symbolic name string)
- `names`: `names` (array of symbolic name strings)
- `duration_seconds`: `seconds` (u64)

## `ExplicitOption<T>` Convention

`ExplicitOption<T>` is represented consistently across all formats:

- **Unspecified**: field omitted.
- **ExplicitNone**: explicit null/none marker.
- **ExplicitSome**: concrete value present.

For JSON and YAML:

- omitted field -> `Unspecified`
- `null` -> `ExplicitNone`
- value -> `ExplicitSome(value)`

For TOML:

- omitted field -> `Unspecified`
- sentinel inline table `{"@none" = true}` -> `ExplicitNone`
- value -> `ExplicitSome(value)`

TOML sentinel constraints:

- `{"@none" = true}` is valid only when it is the sole key in the inline table.
- An inline table containing `@none` together with any other key is rejected as
  a wire/shape error.
- `{"@none" = false}` is rejected.

The sentinel key is reserved by convention and uses `@` to avoid collision with
`SymbolicName` values (`[a-z0-9_-]` only).

For the current `WireDeclaredSpec`, no field currently uses `ExplicitOption<T>`.
The `@none` rule is therefore dormant until such a field is added.

Reference tri-state examples are available at:

- `docs/examples/explicit_option_tri_state.json`
- `docs/examples/explicit_option_tri_state.yaml`
- `docs/examples/explicit_option_tri_state.toml`

## `schema_version` Handshake

- `schema_version` is a required root field.
- The adapter and wire layer parse and preserve it as declarer-authored data.
- If the value cannot be represented as `SymbolicName`, translation fails as a
  wire/shape error.
- If downstream layers apply schema-version compatibility policy, that policy is
  not implemented in adapters.

## Ordering Rule

- Adapters preserve declarer order exactly as authored.
- Adapters and wire conversion do not sort any section.
- Deterministic reordering (if needed) is owned by `concretise`.

## Forbidden or Refused Format Features

### JSON

- Duplicate object keys are rejected.
- Trailing non-whitespace data after the root value is rejected.

### YAML

- Anchors and aliases are rejected.
- Explicit tags (`!!...`) are rejected.
- Merge keys (`<<`) are rejected.
- Multi-document streams are rejected.

If parser configuration cannot reject a forbidden YAML feature up front, the
adapter MUST fail closed at syntax stage.

### TOML

Supported TOML subset:

- Standard key/value data.
- Arrays and arrays of tables for list sections.
- Inline tables where required by this convention (including `@none` sentinel).

Unsupported/ambiguous constructs are rejected when they cannot be represented
without coercion in the wire DTO.

Explicit TOML exclusions:

- Native TOML datetime values are rejected.
- Mixed-type arrays are rejected.
- Negative integers for unsigned DTO fields are wire/shape errors.
- Integer range violations (for example, `70000` into a `u16`) are wire/shape
  errors.

## Reference Resolution Timing

- Symbolic reference strings are lexical at adapter/wire layers.
- Name lexical validation occurs during wire translation to `SymbolicName`.
- `SymbolicName` lexical failures are wire/shape errors with field/index path
  information.
- Cross-reference existence/linking is semantic validation in `declare`, not in
  adapters.

Section-level semantic constraints (for example, `actors` and `referents` must
be non-empty) are validated in `declare`, not in adapters/wire conversion.

## JSON Schema

- Generated from wire DTO using `schemars`.
- Used for documentation/editor tooling.
- Never used as a runtime validation gate inside adapters.

## Round-Trip Invariant

The convention and adapters are required to satisfy round-trip determinism:

1. parse bytes into wire DTO,
2. serialize wire DTO back to bytes,
3. parse and re-serialize again.

The first and second serializations MUST be byte-identical for the same
adapter, and the round-tripped `DeclaredSpec` MUST be structurally equal to the
canonical source `DeclaredSpec`.
