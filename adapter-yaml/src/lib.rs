#![forbid(unsafe_code)]

use std::fmt;

use jw_guard_declare::{DeclaredSpec, DeclareError};
use jw_guard_wire::WireDeclaredSpec;
use yaml_rust2::parser::{Event, EventReceiver, Parser};

#[derive(Debug)]
pub enum YamlSyntaxError {
    Utf8,
    EmptyInput,
    Scan(yaml_rust2::scanner::ScanError),
    Serde(serde_yaml::Error),
    ForbiddenFeature(&'static str),
}

impl fmt::Display for YamlSyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utf8 => f.write_str("input must be valid UTF-8"),
            Self::EmptyInput => f.write_str("yaml input is empty"),
            Self::Scan(error) => write!(f, "{error}"),
            Self::Serde(error) => write!(f, "{error}"),
            Self::ForbiddenFeature(feature) => write!(f, "forbidden YAML feature used: {feature}"),
        }
    }
}

impl std::error::Error for YamlSyntaxError {}

#[derive(Debug)]
pub enum AdapterError {
    Syntax(YamlSyntaxError),
    Wire(WireError),
}

#[derive(Debug)]
pub enum WireError {
    Shape(serde_yaml::Error),
    Declare(Vec<DeclareError>),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(f, "yaml syntax error: {error}"),
            Self::Wire(error) => write!(f, "wire error: {error}"),
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shape(error) => write!(f, "shape decode failed: {error}"),
            Self::Declare(errors) => write!(f, "declare conversion failed with {} error(s)", errors.len()),
        }
    }
}

impl std::error::Error for AdapterError {}

pub fn parse(bytes: &[u8]) -> Result<WireDeclaredSpec, AdapterError> {
    reject_forbidden_yaml_features(bytes).map_err(AdapterError::Syntax)?;
    let value = serde_yaml::from_slice::<serde_yaml::Value>(bytes)
        .map_err(YamlSyntaxError::Serde)
        .map_err(AdapterError::Syntax)?;
    serde_yaml::from_value(value)
        .map_err(WireError::Shape)
        .map_err(AdapterError::Wire)
}

pub fn parse_to_spec(bytes: &[u8]) -> Result<DeclaredSpec, AdapterError> {
    let wire = parse(bytes)?;
    DeclaredSpec::try_from(wire)
        .map_err(WireError::Declare)
        .map_err(AdapterError::Wire)
}

pub fn serialize(wire: &WireDeclaredSpec) -> Result<Vec<u8>, AdapterError> {
    serde_yaml::to_string(wire)
        .map(|text| text.into_bytes())
        .map_err(YamlSyntaxError::Serde)
        .map_err(AdapterError::Syntax)
}

fn reject_forbidden_yaml_features(bytes: &[u8]) -> Result<(), YamlSyntaxError> {
    let text = std::str::from_utf8(bytes).map_err(|_| YamlSyntaxError::Utf8)?;
    let mut receiver = ForbiddenFeatureReceiver::default();
    let mut parser = Parser::new(text.chars());
    parser.load(&mut receiver, true).map_err(YamlSyntaxError::Scan)?;
    receiver.finish()?;

    let mut docs = serde_yaml::Deserializer::from_slice(bytes);
    if docs.next().is_none() {
        return Err(YamlSyntaxError::EmptyInput);
    };
    if docs.next().is_some() {
        return Err(YamlSyntaxError::ForbiddenFeature("multi-document streams"));
    }
    Ok(())
}

#[derive(Default)]
struct ForbiddenFeatureReceiver {
    pending_error: Option<&'static str>,
    current_mapping_key: Option<String>,
}

impl ForbiddenFeatureReceiver {
    fn finish(self) -> Result<(), YamlSyntaxError> {
        if let Some(feature) = self.pending_error {
            return Err(YamlSyntaxError::ForbiddenFeature(feature));
        }
        Ok(())
    }
}

impl EventReceiver for ForbiddenFeatureReceiver {
    fn on_event(&mut self, event: Event) {
        if self.pending_error.is_some() {
            return;
        }

        match event {
            Event::Alias(_) => {
                self.pending_error = Some("aliases");
            }
            Event::Scalar(value, _, anchor_id, tag) => {
                if anchor_id > 0 {
                    self.pending_error = Some("anchors");
                    return;
                }
                if tag.is_some() {
                    self.pending_error = Some("tags");
                    return;
                }
                if value == "<<" && self.current_mapping_key.is_none() {
                    self.pending_error = Some("merge keys");
                    return;
                }
                self.current_mapping_key = match self.current_mapping_key.take() {
                    None => Some(value),
                    Some(_) => None,
                };
            }
            Event::SequenceStart(anchor_id, tag) | Event::MappingStart(anchor_id, tag) => {
                if anchor_id > 0 {
                    self.pending_error = Some("anchors");
                }
                if tag.is_some() {
                    self.pending_error = Some("tags");
                }
                self.current_mapping_key = None;
            }
            Event::SequenceEnd | Event::MappingEnd => {
                self.current_mapping_key = None;
            }
            _ => {}
        }
    }
}
