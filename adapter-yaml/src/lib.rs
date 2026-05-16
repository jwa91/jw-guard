#![forbid(unsafe_code)]

use std::fmt;

use jw_guard_declare::{DeclaredSpec, DeclareError};
use jw_guard_wire::WireDeclaredSpec;

#[derive(Debug)]
pub enum YamlSyntaxError {
    Serde(serde_yaml::Error),
    ForbiddenFeature(&'static str),
}

impl fmt::Display for YamlSyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serde(error) => write!(f, "{error}"),
            Self::ForbiddenFeature(feature) => write!(f, "forbidden YAML feature used: {feature}"),
        }
    }
}

impl std::error::Error for YamlSyntaxError {}

#[derive(Debug)]
pub enum AdapterError {
    Syntax(YamlSyntaxError),
    Wire(Vec<DeclareError>),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(f, "yaml syntax error: {error}"),
            Self::Wire(errors) => write!(f, "wire conversion failed with {} error(s)", errors.len()),
        }
    }
}

impl std::error::Error for AdapterError {}

pub fn parse(bytes: &[u8]) -> Result<WireDeclaredSpec, AdapterError> {
    reject_forbidden_yaml_features(bytes).map_err(AdapterError::Syntax)?;
    serde_yaml::from_slice(bytes)
        .map_err(YamlSyntaxError::Serde)
        .map_err(AdapterError::Syntax)
}

pub fn parse_to_spec(bytes: &[u8]) -> Result<DeclaredSpec, AdapterError> {
    let wire = parse(bytes)?;
    DeclaredSpec::try_from(wire).map_err(AdapterError::Wire)
}

pub fn serialize(wire: &WireDeclaredSpec) -> Result<Vec<u8>, AdapterError> {
    serde_yaml::to_string(wire)
        .map(|text| text.into_bytes())
        .map_err(YamlSyntaxError::Serde)
        .map_err(AdapterError::Syntax)
}

fn reject_forbidden_yaml_features(bytes: &[u8]) -> Result<(), YamlSyntaxError> {
    let text = std::str::from_utf8(bytes).unwrap_or_default();
    let trimmed = text.trim_start();

    if trimmed.contains('&') {
        return Err(YamlSyntaxError::ForbiddenFeature("anchors"));
    }

    if trimmed.contains('*') {
        return Err(YamlSyntaxError::ForbiddenFeature("aliases"));
    }

    if trimmed.contains("!!") || trimmed.contains("!<") {
        return Err(YamlSyntaxError::ForbiddenFeature("tags"));
    }

    if trimmed.contains("<<:") {
        return Err(YamlSyntaxError::ForbiddenFeature("merge keys"));
    }

    let multi_document_markers = trimmed.lines().filter(|line| line.trim_start().starts_with("---")).count();
    if multi_document_markers > 1 {
        return Err(YamlSyntaxError::ForbiddenFeature("multi-document streams"));
    }

    Ok(())
}
