# CLI Diagnostic Contract (v1)

This document defines the versioned JSON diagnostic contract emitted by:

- `jw-guard validate <path> --output json`

The JSON report is the machine-readable source of truth. Human output is a rendering over the same model.

## Top-level report shape

```json
{
  "report_version": "1",
  "outcome": "ok | syntax_error | wire_error | validation_error",
  "input": { "path": "string", "format": "json | yaml | toml" },
  "stage_reached": "syntax | wire | validation | concretise",
  "errors": [
    {
      "stage": "syntax | wire | validation | concretise",
      "code": "SCREAMING_SNAKE_CASE_CODE",
      "path": ["segment", 0, "segment"],
      "message": "human-readable detail",
      "source": { "line": 1, "column": 1 } | null
    }
  ]
}
```

## Source availability by stage

- `syntax`: `source` is populated when parser-native location exists.
- `wire`: `source` is populated when the underlying parser provides shape-error locations.
  - JSON: expected to provide line/column for direct wire decode failures.
  - YAML: expected to provide line/column for direct wire decode failures.
  - TOML: best-effort; `source` may be present or null depending on parser error form and conversion path.
- `validation`: `source` is null (typed `DeclaredSpec` phase, no spans).
- `concretise`: `source` is null (typed concretisation phase, no spans).

## Compatibility policy

- `report_version` is required and currently `"1"`.
- New error codes can be added in v1.
- Renaming/removing fields or error codes is a breaking change.
- Deterministic ordering is required: errors are sorted by `(stage, path, code)`.
