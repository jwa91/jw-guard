#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use jw_guard_declare::{DeclaredSpec, DeclareError};
use jw_guard_wire::WireDeclaredSpec;
use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::Deserializer;

#[derive(Debug)]
pub enum AdapterError {
    Syntax(serde_json::Error),
    Wire(WireError),
}

#[derive(Debug)]
pub enum WireError {
    Shape(serde_json::Error),
    Declare(Vec<DeclareError>),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(f, "json syntax error: {error}"),
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
    reject_duplicate_keys_and_trailing_data(bytes)?;
    let value = serde_json::from_slice::<serde_json::Value>(bytes).map_err(AdapterError::Syntax)?;
    serde_json::from_value(value)
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
    serde_json::to_vec_pretty(wire).map_err(AdapterError::Syntax)
}

fn reject_duplicate_keys_and_trailing_data(bytes: &[u8]) -> Result<(), AdapterError> {
    let mut deserializer = Deserializer::from_slice(bytes);
    DuplicateKeyValidator::deserialize(&mut deserializer).map_err(AdapterError::Syntax)?;
    deserializer.end().map_err(AdapterError::Syntax)
}

struct DuplicateKeyValidator;

impl<'de> serde::Deserialize<'de> for DuplicateKeyValidator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateKeyVisitor)?;
        Ok(Self)
    }
}

struct DuplicateKeyVisitor;

impl<'de> Visitor<'de> for DuplicateKeyVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_bool<E>(self, _v: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_i64<E>(self, _v: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_i128<E>(self, _v: i128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_u64<E>(self, _v: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_u128<E>(self, _v: u128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_f64<E>(self, _v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_str<E>(self, _v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _v: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_string<E>(self, _v: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(Self)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(()) = seq.next_element_seed(DuplicateKeySeed)? {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate key '{key}'")));
            }
            map.next_value_seed(DuplicateKeySeed)?;
        }
        Ok(())
    }
}

struct DuplicateKeySeed;

impl<'de> de::DeserializeSeed<'de> for DuplicateKeySeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateKeyVisitor)
    }
}
