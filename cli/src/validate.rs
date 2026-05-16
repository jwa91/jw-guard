use std::fmt;
use std::path::Path;

use jw_guard_declare::{DeclaredSpec, concretise, validate_spec};
use jw_guard_wire::WireDeclaredSpec;

use crate::error_map::{
    map_declare_error, map_json_syntax_error, map_json_wire_shape_error, map_toml_syntax_error,
    map_validation_error, map_yaml_syntax_error, map_yaml_wire_shape_error,
};
use crate::report::{ErrorCode, InputFormat, ReportError, Stage, StageStop, ValidationReport};

#[derive(Debug)]
pub enum ValidateFailure {
    Io(std::io::Error),
    UnsupportedFormat(String),
}

impl ValidateFailure {
    pub fn is_io(&self) -> bool {
        matches!(self, Self::Io(_))
    }
}

impl fmt::Display for ValidateFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "i/o error: {error}"),
            Self::UnsupportedFormat(path) => write!(
                f,
                "unsupported file extension for '{path}', use --format-override json|yaml|toml"
            ),
        }
    }
}

impl std::error::Error for ValidateFailure {}

pub fn validate_file(
    path: &Path,
    format_override: Option<InputFormat>,
    stage_stop: StageStop,
) -> Result<ValidationReport, ValidateFailure> {
    let bytes = std::fs::read(path).map_err(ValidateFailure::Io)?;
    let format =
        format_override.unwrap_or_else(|| InputFormat::detect(path).unwrap_or(InputFormat::Json));
    if format_override.is_none() && InputFormat::detect(path).is_none() {
        return Err(ValidateFailure::UnsupportedFormat(path.display().to_string()));
    }

    let mut report = ValidationReport::new(path.display().to_string(), format);
    let wire = match format {
        InputFormat::Json => parse_json(&bytes, &mut report),
        InputFormat::Yaml => parse_yaml(&bytes, &mut report),
        InputFormat::Toml => parse_toml(&bytes, &mut report),
    };

    if report.outcome == crate::report::Outcome::Ok {
        report.set_stage_reached(Stage::Syntax);
    }
    if report.outcome != crate::report::Outcome::Ok || matches!(stage_stop, StageStop::Parse) {
        return Ok(report);
    }

    let spec = match DeclaredSpec::try_from(wire.expect("wire must be present when no parse errors")) {
        Ok(spec) => spec,
        Err(errors) => {
            for error in &errors {
                report.push_error(map_declare_error(error, Stage::Wire));
            }
            return Ok(report);
        }
    };
    report.set_stage_reached(Stage::Wire);
    if matches!(stage_stop, StageStop::Wire) {
        return Ok(report);
    }

    let validation_errors = validate_spec(&spec);
    if !validation_errors.is_empty() {
        for error in &validation_errors {
            report.push_error(map_validation_error(error));
        }
        return Ok(report);
    }
    report.set_stage_reached(Stage::Validation);
    if matches!(stage_stop, StageStop::Validate) {
        return Ok(report);
    }

    if let Err(error) = concretise(&spec) {
        report.push_error(map_declare_error(&error, Stage::Concretise));
        return Ok(report);
    }
    report.set_stage_reached(Stage::Concretise);
    Ok(report)
}

fn parse_json(bytes: &[u8], report: &mut ValidationReport) -> Option<jw_guard_wire::WireDeclaredSpec> {
    match jw_guard_adapter_json::parse(bytes) {
        Ok(wire) => Some(wire),
        Err(jw_guard_adapter_json::AdapterError::Syntax(error)) => {
            report.push_error(map_json_syntax_error(&error));
            None
        }
        Err(jw_guard_adapter_json::AdapterError::Wire(jw_guard_adapter_json::WireError::Shape(error))) => {
            let direct_error = serde_json::from_slice::<WireDeclaredSpec>(bytes).err();
            let mapped = direct_error
                .as_ref()
                .map(map_json_wire_shape_error)
                .unwrap_or_else(|| map_json_wire_shape_error(&error));
            report.push_error(mapped);
            None
        }
        Err(jw_guard_adapter_json::AdapterError::Wire(jw_guard_adapter_json::WireError::Declare(_))) => {
            push_unexpected_adapter_declare_error(report, "json");
            None
        }
    }
}

fn parse_yaml(bytes: &[u8], report: &mut ValidationReport) -> Option<jw_guard_wire::WireDeclaredSpec> {
    match jw_guard_adapter_yaml::parse(bytes) {
        Ok(wire) => Some(wire),
        Err(jw_guard_adapter_yaml::AdapterError::Syntax(error)) => {
            report.push_error(map_yaml_syntax_error(&error));
            None
        }
        Err(jw_guard_adapter_yaml::AdapterError::Wire(jw_guard_adapter_yaml::WireError::Shape(error))) => {
            let direct_error = serde_yaml::from_slice::<WireDeclaredSpec>(bytes).err();
            let mapped = direct_error
                .as_ref()
                .map(map_yaml_wire_shape_error)
                .unwrap_or_else(|| map_yaml_wire_shape_error(&error));
            report.push_error(mapped);
            None
        }
        Err(jw_guard_adapter_yaml::AdapterError::Wire(jw_guard_adapter_yaml::WireError::Declare(_))) => {
            push_unexpected_adapter_declare_error(report, "yaml");
            None
        }
    }
}

fn parse_toml(bytes: &[u8], report: &mut ValidationReport) -> Option<jw_guard_wire::WireDeclaredSpec> {
    match jw_guard_adapter_toml::parse(bytes) {
        Ok(wire) => Some(wire),
        Err(jw_guard_adapter_toml::AdapterError::Syntax(error)) => {
            report.push_error(map_toml_syntax_error(&error));
            None
        }
        Err(jw_guard_adapter_toml::AdapterError::Wire(jw_guard_adapter_toml::WireError::Shape(error))) => {
            report.push_error(map_json_wire_shape_error(&error));
            None
        }
        Err(jw_guard_adapter_toml::AdapterError::Wire(jw_guard_adapter_toml::WireError::Declare(_))) => {
            push_unexpected_adapter_declare_error(report, "toml");
            None
        }
    }
}

fn push_unexpected_adapter_declare_error(report: &mut ValidationReport, format: &str) {
    debug_assert!(
        false,
        "{format} adapter parse() returned Declare errors unexpectedly"
    );
    report.push_error(ReportError {
        stage: Stage::Wire,
        code: ErrorCode::DeclareConversionFailed,
        path: Vec::new(),
        message: format!(
            "unexpected {format} adapter state: parse() returned declare conversion errors"
        ),
        source: None,
    });
}
