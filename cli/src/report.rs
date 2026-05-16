use std::cmp::Ordering;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageStop {
    Parse,
    Wire,
    Validate,
    Concretise,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Syntax,
    Wire,
    Validation,
    Concretise,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InputFormat {
    Json,
    Yaml,
    Toml,
}

impl InputFormat {
    pub fn detect(path: &Path) -> Option<Self> {
        let extension = path.extension()?.to_str()?;
        match extension {
            "json" => Some(Self::Json),
            "yaml" | "yml" => Some(Self::Yaml),
            "toml" => Some(Self::Toml),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    SyntaxError,
    WireError,
    ValidationError,
}

impl Outcome {
    pub fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputDescriptor {
    pub path: String,
    pub format: InputFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceLocation {
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum PathSegment {
    Key(String),
    Index(usize),
}

impl Ord for PathSegment {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Key(left), Self::Key(right)) => left.cmp(right),
            (Self::Index(left), Self::Index(right)) => left.cmp(right),
            (Self::Key(_), Self::Index(_)) => Ordering::Less,
            (Self::Index(_), Self::Key(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for PathSegment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ErrorCode {
    CanonicalPathError,
    DeclareConversionFailed,
    DeterministicIdError,
    DuplicateKey,
    EmptyInput,
    ForbiddenYamlFeature,
    InvalidCanonicalName,
    InvalidConstruction,
    InvalidDiscriminator,
    InvalidRequirementValue,
    InvalidShape,
    InvalidSymbolicName,
    InvalidUtf8,
    MissingReference,
    TrailingData,
    UnknownField,
    ValidationDuplicateName,
    ValidationEmptySection,
    ValidationMissingReference,
    WireShapeDecodeFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportError {
    pub stage: Stage,
    pub code: ErrorCode,
    pub path: Vec<PathSegment>,
    pub message: String,
    pub source: Option<SourceLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationReport {
    pub report_version: String,
    pub outcome: Outcome,
    pub input: InputDescriptor,
    pub stage_reached: Stage,
    pub errors: Vec<ReportError>,
}

impl ValidationReport {
    pub fn new(path: String, format: InputFormat) -> Self {
        Self {
            report_version: "1".to_owned(),
            outcome: Outcome::Ok,
            input: InputDescriptor { path, format },
            stage_reached: Stage::Syntax,
            errors: Vec::new(),
        }
    }

    pub fn push_error(&mut self, error: ReportError) {
        self.stage_reached = error.stage;
        self.outcome = match error.stage {
            Stage::Syntax => Outcome::SyntaxError,
            Stage::Wire => Outcome::WireError,
            Stage::Validation | Stage::Concretise => Outcome::ValidationError,
        };
        self.errors.push(error);
        self.sort_errors();
    }

    pub fn set_stage_reached(&mut self, stage: Stage) {
        self.stage_reached = stage;
    }

    pub fn sort_errors(&mut self) {
        self.errors.sort_by(compare_errors);
    }
}

pub fn compare_errors(left: &ReportError, right: &ReportError) -> Ordering {
    left.stage
        .cmp(&right.stage)
        .then_with(|| left.path.cmp(&right.path))
        .then_with(|| left.code.cmp(&right.code))
        .then_with(|| left.message.cmp(&right.message))
}

pub fn parse_path(path: &str) -> Vec<PathSegment> {
    let mut result = Vec::new();
    let mut key = String::new();
    let mut chars = path.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '.' => {
                if !key.is_empty() {
                    result.push(PathSegment::Key(std::mem::take(&mut key)));
                }
            }
            '[' => {
                if !key.is_empty() {
                    result.push(PathSegment::Key(std::mem::take(&mut key)));
                }
                let mut index_text = String::new();
                while let Some(next) = chars.peek() {
                    if *next == ']' {
                        break;
                    }
                    index_text.push(*next);
                    let _ = chars.next();
                }
                if chars.peek() == Some(&']') {
                    let _ = chars.next();
                }
                if let Ok(index) = index_text.parse::<usize>() {
                    result.push(PathSegment::Index(index));
                } else if !index_text.is_empty() {
                    result.push(PathSegment::Key(index_text));
                }
            }
            '$' => {}
            _ => key.push(ch),
        }
    }
    if !key.is_empty() {
        result.push(PathSegment::Key(key));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{
        ErrorCode, InputDescriptor, InputFormat, Outcome, PathSegment, ReportError, SourceLocation, Stage,
        ValidationReport, compare_errors, parse_path,
    };

    fn all_error_codes() -> Vec<ErrorCode> {
        vec![
            ErrorCode::CanonicalPathError,
            ErrorCode::DeclareConversionFailed,
            ErrorCode::DeterministicIdError,
            ErrorCode::DuplicateKey,
            ErrorCode::EmptyInput,
            ErrorCode::ForbiddenYamlFeature,
            ErrorCode::InvalidCanonicalName,
            ErrorCode::InvalidConstruction,
            ErrorCode::InvalidDiscriminator,
            ErrorCode::InvalidRequirementValue,
            ErrorCode::InvalidShape,
            ErrorCode::InvalidSymbolicName,
            ErrorCode::InvalidUtf8,
            ErrorCode::MissingReference,
            ErrorCode::TrailingData,
            ErrorCode::UnknownField,
            ErrorCode::ValidationDuplicateName,
            ErrorCode::ValidationEmptySection,
            ErrorCode::ValidationMissingReference,
            ErrorCode::WireShapeDecodeFailed,
        ]
    }

    #[test]
    fn parse_path_splits_indexes_and_keys() {
        let parsed = parse_path("scopes[0].predicate.kind");
        assert_eq!(
            parsed,
            vec![
                PathSegment::Key("scopes".to_owned()),
                PathSegment::Index(0),
                PathSegment::Key("predicate".to_owned()),
                PathSegment::Key("kind".to_owned()),
            ]
        );
    }

    #[test]
    fn parse_path_ignores_root_marker() {
        let parsed = parse_path("$.root[1].value");
        assert_eq!(
            parsed,
            vec![
                PathSegment::Key("root".to_owned()),
                PathSegment::Index(1),
                PathSegment::Key("value".to_owned()),
            ]
        );
    }

    #[test]
    fn compare_errors_sorts_by_stage_path_and_code() {
        let left = ReportError {
            stage: Stage::Wire,
            code: ErrorCode::UnknownField,
            path: vec![PathSegment::Key("model".to_owned())],
            message: "message".to_owned(),
            source: Some(SourceLocation { line: 1, column: 1 }),
        };
        let right = ReportError {
            stage: Stage::Validation,
            code: ErrorCode::ValidationMissingReference,
            path: vec![PathSegment::Key("model".to_owned())],
            message: "message".to_owned(),
            source: None,
        };

        assert!(compare_errors(&left, &right).is_lt());
    }

    #[test]
    fn error_code_vocabulary_snapshot_is_stable() {
        let serialized = serde_json::to_string_pretty(&all_error_codes()).expect("codes should serialize");
        let expected = r#"[
  "CANONICAL_PATH_ERROR",
  "DECLARE_CONVERSION_FAILED",
  "DETERMINISTIC_ID_ERROR",
  "DUPLICATE_KEY",
  "EMPTY_INPUT",
  "FORBIDDEN_YAML_FEATURE",
  "INVALID_CANONICAL_NAME",
  "INVALID_CONSTRUCTION",
  "INVALID_DISCRIMINATOR",
  "INVALID_REQUIREMENT_VALUE",
  "INVALID_SHAPE",
  "INVALID_SYMBOLIC_NAME",
  "INVALID_UTF8",
  "MISSING_REFERENCE",
  "TRAILING_DATA",
  "UNKNOWN_FIELD",
  "VALIDATION_DUPLICATE_NAME",
  "VALIDATION_EMPTY_SECTION",
  "VALIDATION_MISSING_REFERENCE",
  "WIRE_SHAPE_DECODE_FAILED"
]"#;
        assert_eq!(serialized, expected);
    }

    #[test]
    fn report_round_trip_json_is_byte_stable() {
        let report = ValidationReport {
            report_version: "1".to_owned(),
            outcome: Outcome::WireError,
            input: InputDescriptor {
                path: "/tmp/spec.json".to_owned(),
                format: InputFormat::Json,
            },
            stage_reached: Stage::Wire,
            errors: vec![ReportError {
                stage: Stage::Wire,
                code: ErrorCode::InvalidSymbolicName,
                path: vec![
                    PathSegment::Key("scopes".to_owned()),
                    PathSegment::Index(0),
                    PathSegment::Key("predicate".to_owned()),
                ],
                message: "invalid symbolic name".to_owned(),
                source: None,
            }],
        };

        let first = serde_json::to_string_pretty(&report).expect("report should serialize");
        let decoded: ValidationReport = serde_json::from_str(&first).expect("report should deserialize");
        let second = serde_json::to_string_pretty(&decoded).expect("report should reserialize");
        assert_eq!(first, second);
    }
}
