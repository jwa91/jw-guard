use jw_guard_declare::{DeclareError, ValidationError};

use crate::report::{ErrorCode, PathSegment, ReportError, SourceLocation, Stage, parse_path};

pub fn map_json_syntax_error(error: &serde_json::Error) -> ReportError {
    let message = error.to_string();
    let code = if message.contains("duplicate key") {
        ErrorCode::DuplicateKey
    } else if message.contains("trailing") {
        ErrorCode::TrailingData
    } else {
        ErrorCode::InvalidShape
    };

    ReportError {
        stage: Stage::Syntax,
        code,
        path: Vec::new(),
        message,
        source: Some(SourceLocation {
            line: error.line(),
            column: error.column(),
        }),
    }
}

pub fn map_yaml_syntax_error(error: &jw_guard_adapter_yaml::YamlSyntaxError) -> ReportError {
    let (code, source) = match error {
        jw_guard_adapter_yaml::YamlSyntaxError::Utf8 => (ErrorCode::InvalidUtf8, None),
        jw_guard_adapter_yaml::YamlSyntaxError::EmptyInput => (ErrorCode::EmptyInput, None),
        jw_guard_adapter_yaml::YamlSyntaxError::Scan(scan) => (
            ErrorCode::InvalidShape,
            Some(SourceLocation {
                line: scan.marker().line() + 1,
                column: scan.marker().col() + 1,
            }),
        ),
        jw_guard_adapter_yaml::YamlSyntaxError::Serde(serde_error) => (
            ErrorCode::InvalidShape,
            serde_error.location().map(|loc| SourceLocation {
                line: loc.line(),
                column: loc.column(),
            }),
        ),
        jw_guard_adapter_yaml::YamlSyntaxError::ForbiddenFeature(_) => (ErrorCode::ForbiddenYamlFeature, None),
    };

    ReportError {
        stage: Stage::Syntax,
        code,
        path: Vec::new(),
        message: error.to_string(),
        source,
    }
}

pub fn map_toml_syntax_error(error: &jw_guard_adapter_toml::TomlSyntaxError) -> ReportError {
    let (code, path, source) = match error {
        jw_guard_adapter_toml::TomlSyntaxError::Utf8 => (ErrorCode::InvalidUtf8, Vec::new(), None),
        // toml::de::Error::span() returns byte offsets, not line/column coordinates.
        // Until we derive line/column from source text, keep source unset to avoid
        // emitting misleading locations in the contract.
        jw_guard_adapter_toml::TomlSyntaxError::Parse(_parse) => (ErrorCode::InvalidShape, Vec::new(), None),
        jw_guard_adapter_toml::TomlSyntaxError::Serialize(_) => (ErrorCode::InvalidShape, Vec::new(), None),
        jw_guard_adapter_toml::TomlSyntaxError::UnsupportedType { path, .. } => {
            (ErrorCode::InvalidShape, parse_path(path), None)
        }
        jw_guard_adapter_toml::TomlSyntaxError::InvalidSentinel { path, .. } => {
            (ErrorCode::InvalidShape, parse_path(path), None)
        }
    };

    ReportError {
        stage: Stage::Syntax,
        code,
        path,
        message: error.to_string(),
        source,
    }
}

pub fn map_json_wire_shape_error(error: &serde_json::Error) -> ReportError {
    let source = match (error.line(), error.column()) {
        (0, 0) => None,
        (line, column) => Some(SourceLocation { line, column }),
    };
    map_wire_shape_error(Stage::Wire, error.to_string(), source)
}

pub fn map_yaml_wire_shape_error(error: &serde_yaml::Error) -> ReportError {
    let source = error.location().map(|loc| SourceLocation {
        line: loc.line(),
        column: loc.column(),
    });
    map_wire_shape_error(Stage::Wire, error.to_string(), source)
}

pub fn map_declare_error(error: &DeclareError, stage: Stage) -> ReportError {
    match error {
        DeclareError::InvalidSymbolicName { path, .. } => ReportError {
            stage,
            code: ErrorCode::InvalidSymbolicName,
            path: parse_path(path),
            message: error.to_string(),
            source: None,
        },
        DeclareError::ValidationFailed(errors) => ReportError {
            stage,
            code: ErrorCode::DeclareConversionFailed,
            path: Vec::new(),
            message: format!("validation failed with {} error(s)", errors.len()),
            source: None,
        },
        DeclareError::CanonicalPath(_) => ReportError {
            stage,
            code: ErrorCode::CanonicalPathError,
            path: Vec::new(),
            message: error.to_string(),
            source: None,
        },
        DeclareError::DeterministicId(_) => ReportError {
            stage,
            code: ErrorCode::DeterministicIdError,
            path: Vec::new(),
            message: error.to_string(),
            source: None,
        },
        DeclareError::InvalidCanonicalName(_) => ReportError {
            stage,
            code: ErrorCode::InvalidCanonicalName,
            path: Vec::new(),
            message: error.to_string(),
            source: None,
        },
        DeclareError::InvalidConstruction(_) => ReportError {
            stage,
            code: ErrorCode::InvalidConstruction,
            path: Vec::new(),
            message: error.to_string(),
            source: None,
        },
        DeclareError::MissingReference {
            section,
            field,
            name,
        } => ReportError {
            stage,
            code: ErrorCode::MissingReference,
            path: vec![
                PathSegment::Key((*section).to_owned()),
                PathSegment::Key((*field).to_owned()),
                PathSegment::Key(name.clone()),
            ],
            message: error.to_string(),
            source: None,
        },
    }
}

pub fn map_validation_error(error: &ValidationError) -> ReportError {
    match error {
        ValidationError::EmptySection { section } => ReportError {
            stage: Stage::Validation,
            code: ErrorCode::ValidationEmptySection,
            path: vec![PathSegment::Key((*section).to_owned())],
            message: format!("section '{section}' must not be empty"),
            source: None,
        },
        ValidationError::DuplicateName { section, name } => ReportError {
            stage: Stage::Validation,
            code: ErrorCode::ValidationDuplicateName,
            path: vec![
                PathSegment::Key((*section).to_owned()),
                PathSegment::Key(name.as_str().to_owned()),
            ],
            message: format!("duplicate name '{}' in section '{section}'", name.as_str()),
            source: None,
        },
        ValidationError::MissingReference {
            section,
            field,
            name,
        } => ReportError {
            stage: Stage::Validation,
            code: ErrorCode::ValidationMissingReference,
            path: vec![
                PathSegment::Key((*section).to_owned()),
                PathSegment::Key((*field).to_owned()),
                PathSegment::Key(name.as_str().to_owned()),
            ],
            message: format!(
                "missing reference '{}' for {}.{}",
                name.as_str(),
                section,
                field
            ),
            source: None,
        },
        ValidationError::InvalidRequirementValue { name, operator } => ReportError {
            stage: Stage::Validation,
            code: ErrorCode::InvalidRequirementValue,
            path: vec![
                PathSegment::Key("requirements".to_owned()),
                PathSegment::Key(name.as_str().to_owned()),
            ],
            message: format!(
                "invalid requirement value for '{}' and operator '{operator:?}'",
                name.as_str()
            ),
            source: None,
        },
    }
}

fn map_wire_shape_error(stage: Stage, message: String, source: Option<SourceLocation>) -> ReportError {
    let code = if message.contains("unknown field") {
        ErrorCode::UnknownField
    } else if message.contains("unknown variant")
        || message.contains("invalid type")
        || message.contains("missing field `kind`")
    {
        ErrorCode::InvalidDiscriminator
    } else {
        ErrorCode::WireShapeDecodeFailed
    };

    ReportError {
        stage,
        code,
        path: Vec::new(),
        message,
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::{map_declare_error, map_wire_shape_error};
    use crate::report::{ErrorCode, Stage};
    use jw_guard_canon::CanonicalPathError;
    use jw_guard_core::ConstructionViolation;
    use jw_guard_declare::DeclareError;

    #[test]
    fn unknown_field_maps_to_unknown_field_code() {
        let report = map_wire_shape_error(Stage::Wire, "unknown field `x`".to_owned(), None);
        assert_eq!(report.code, ErrorCode::UnknownField);
        assert!(report.source.is_none());
    }

    #[test]
    fn unknown_variant_maps_to_discriminator_code() {
        let report = map_wire_shape_error(Stage::Wire, "unknown variant `x`".to_owned(), None);
        assert_eq!(report.code, ErrorCode::InvalidDiscriminator);
        assert!(report.source.is_none());
    }

    #[test]
    fn concretise_construction_violation_uses_distinct_code() {
        let error = DeclareError::InvalidConstruction(ConstructionViolation::InvalidRequirementValueType);
        let report = map_declare_error(&error, Stage::Concretise);
        assert_eq!(report.code, ErrorCode::InvalidConstruction);
    }

    #[test]
    fn concretise_canonical_path_violation_uses_distinct_code() {
        let error = DeclareError::CanonicalPath(CanonicalPathError::EmptyPath);
        let report = map_declare_error(&error, Stage::Concretise);
        assert_eq!(report.code, ErrorCode::CanonicalPathError);
        assert!(report.source.is_none());
    }

    #[test]
    fn concretise_error_snapshot_has_null_source() {
        let error = DeclareError::InvalidConstruction(ConstructionViolation::InvalidRequirementValueType);
        let report = map_declare_error(&error, Stage::Concretise);
        let serialized = serde_json::to_string_pretty(&report).expect("report should serialize");
        let expected = r#"{
  "stage": "concretise",
  "code": "INVALID_CONSTRUCTION",
  "path": [],
  "message": "core declaration construction failed: requirement value type is incompatible with operator",
  "source": null
}"#;
        assert_eq!(serialized, expected);
    }
}
