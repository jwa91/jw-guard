#![forbid(unsafe_code)]

pub mod convert;
pub mod dto;
pub mod error;
pub mod evidence_convert;
pub mod evidence_dto;

pub use dto::*;
pub use error::*;
pub use evidence_dto::*;

pub fn declared_spec_schema() -> schemars::schema::RootSchema {
    schemars::schema_for!(WireDeclaredSpec)
}

pub fn declared_spec_schema_value() -> serde_json::Value {
    serde_json::to_value(declared_spec_schema()).expect("wire schema must serialize")
}

pub fn mapped_evidence_schema() -> schemars::schema::RootSchema {
    schemars::schema_for!(WireMappedEvidence)
}

pub fn mapped_evidence_schema_value() -> serde_json::Value {
    serde_json::to_value(mapped_evidence_schema()).expect("mapped evidence schema must serialize")
}
