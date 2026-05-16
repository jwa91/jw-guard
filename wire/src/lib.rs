#![forbid(unsafe_code)]

pub mod convert;
pub mod dto;
pub mod error;

pub use dto::*;
pub use error::*;

pub fn declared_spec_schema() -> schemars::schema::RootSchema {
    schemars::schema_for!(WireDeclaredSpec)
}

pub fn declared_spec_schema_value() -> serde_json::Value {
    serde_json::to_value(declared_spec_schema()).expect("wire schema must serialize")
}
