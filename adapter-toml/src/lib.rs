#![forbid(unsafe_code)]

use std::fmt;

use jw_guard_declare::{DeclaredSpec, DeclareError};
use jw_guard_wire::WireDeclaredSpec;
use serde_json::{Map, Value};

#[derive(Debug)]
pub enum TomlSyntaxError {
    Utf8,
    Parse(toml::de::Error),
    Serialize(toml::ser::Error),
    UnsupportedType { path: String, kind: &'static str },
    InvalidSentinel { path: String, reason: &'static str },
    JsonBridge(serde_json::Error),
}

impl fmt::Display for TomlSyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utf8 => f.write_str("input must be valid UTF-8"),
            Self::Parse(error) => write!(f, "{error}"),
            Self::Serialize(error) => write!(f, "{error}"),
            Self::UnsupportedType { path, kind } => write!(f, "unsupported TOML type at {path}: {kind}"),
            Self::InvalidSentinel { path, reason } => write!(f, "invalid @none sentinel at {path}: {reason}"),
            Self::JsonBridge(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for TomlSyntaxError {}

#[derive(Debug)]
pub enum AdapterError {
    Syntax(TomlSyntaxError),
    Wire(Vec<DeclareError>),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(f, "toml syntax error: {error}"),
            Self::Wire(errors) => write!(f, "wire conversion failed with {} error(s)", errors.len()),
        }
    }
}

impl std::error::Error for AdapterError {}

pub fn parse(bytes: &[u8]) -> Result<WireDeclaredSpec, AdapterError> {
    let text = std::str::from_utf8(bytes).map_err(|_| AdapterError::Syntax(TomlSyntaxError::Utf8))?;
    let value: toml::Value = toml::from_str(text)
        .map_err(TomlSyntaxError::Parse)
        .map_err(AdapterError::Syntax)?;
    let bridged = bridge_toml_to_json("$".to_string(), value)
        .map_err(AdapterError::Syntax)?;
    serde_json::from_value(bridged)
        .map_err(TomlSyntaxError::JsonBridge)
        .map_err(AdapterError::Syntax)
}

pub fn parse_to_spec(bytes: &[u8]) -> Result<DeclaredSpec, AdapterError> {
    let wire = parse(bytes)?;
    DeclaredSpec::try_from(wire).map_err(AdapterError::Wire)
}

pub fn serialize(wire: &WireDeclaredSpec) -> Result<Vec<u8>, AdapterError> {
    toml::to_string_pretty(wire)
        .map(|text| text.into_bytes())
        .map_err(TomlSyntaxError::Serialize)
        .map_err(AdapterError::Syntax)
}

fn bridge_toml_to_json(path: String, value: toml::Value) -> Result<Value, TomlSyntaxError> {
    match value {
        toml::Value::String(value) => Ok(Value::String(value)),
        toml::Value::Integer(value) => Ok(Value::Number(value.into())),
        toml::Value::Float(value) => serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or(TomlSyntaxError::InvalidSentinel {
                path,
                reason: "non-finite float is unsupported",
            }),
        toml::Value::Boolean(value) => Ok(Value::Bool(value)),
        toml::Value::Datetime(_) => Err(TomlSyntaxError::UnsupportedType {
            path,
            kind: "datetime",
        }),
        toml::Value::Array(values) => values
            .into_iter()
            .enumerate()
            .map(|(index, value)| bridge_toml_to_json(format!("{path}[{index}]"), value))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        toml::Value::Table(values) => convert_table(path, values),
    }
}

fn convert_table(path: String, table: toml::map::Map<String, toml::Value>) -> Result<Value, TomlSyntaxError> {
    if let Some(marker) = table.get("@none") {
        if table.len() != 1 {
            return Err(TomlSyntaxError::InvalidSentinel {
                path,
                reason: "sentinel table must not contain payload keys",
            });
        }
        return match marker {
            toml::Value::Boolean(true) => Ok(Value::Null),
            toml::Value::Boolean(false) => Err(TomlSyntaxError::InvalidSentinel {
                path,
                reason: "@none must be true",
            }),
            _ => Err(TomlSyntaxError::InvalidSentinel {
                path,
                reason: "@none must be a boolean",
            }),
        };
    }

    let mut mapped = Map::new();
    for (key, value) in table {
        let key_path = format!("{path}.{key}");
        mapped.insert(key, bridge_toml_to_json(key_path, value)?);
    }
    Ok(Value::Object(mapped))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_toml(input: &str) -> toml::Value {
        toml::from_str(input).expect("test TOML should parse")
    }

    #[test]
    fn bridge_maps_valid_none_sentinel_to_null() {
        let value = parse_toml("root = { \"@none\" = true }");
        let bridged = bridge_toml_to_json("$".to_string(), value).expect("bridge should succeed");

        assert_eq!(bridged["root"], Value::Null);
    }

    #[test]
    fn bridge_rejects_none_sentinel_with_payload_keys() {
        let value = parse_toml("root = { \"@none\" = true, other = \"x\" }");
        let error = bridge_toml_to_json("$".to_string(), value).expect_err("bridge should fail");

        match error {
            TomlSyntaxError::InvalidSentinel { path, reason } => {
                assert_eq!(path, "$.root");
                assert_eq!(reason, "sentinel table must not contain payload keys");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn bridge_rejects_none_sentinel_when_false() {
        let value = parse_toml("root = { \"@none\" = false }");
        let error = bridge_toml_to_json("$".to_string(), value).expect_err("bridge should fail");

        match error {
            TomlSyntaxError::InvalidSentinel { path, reason } => {
                assert_eq!(path, "$.root");
                assert_eq!(reason, "@none must be true");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn bridge_rejects_toml_datetime_values() {
        let value = parse_toml("root = 1979-05-27T07:32:00Z");
        let error = bridge_toml_to_json("$".to_string(), value).expect_err("bridge should fail");

        match error {
            TomlSyntaxError::UnsupportedType { path, kind } => {
                assert_eq!(path, "$.root");
                assert_eq!(kind, "datetime");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
