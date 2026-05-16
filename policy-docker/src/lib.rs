#![forbid(unsafe_code)]

//! Domain-specific Docker policy authoring helpers.
//!
//! This is **not** a syntax-only YAML adapter (`adapter-yaml`): it translates a
//! narrow authoring shape into semantic [`jw_guard_eval::PropertyRequirement`]
//! values for generic evaluation against neutral mapped evidence.

use std::fmt;

use jw_guard_core::{CanonicalName, ScalarViolation};
use jw_guard_eval::PropertyRequirement;
use jw_guard_mapper::MappedValue;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoolPropertyRequirementWire {
    subject: String,
    property: String,
    #[serde(rename = "expected_bool")]
    expected_bool: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DockerComposePolicyWire {
    /// Proof-of-concept: exactly one requirement per file.
    property_requirements: Vec<BoolPropertyRequirementWire>,
}

#[derive(Debug)]
pub enum PolicyDockerError {
    SerdeYaml(serde_yaml::Error),
    RequirementCount(usize),
    InvalidCanonicalName {
        field: &'static str,
        source: ScalarViolation,
    },
}

impl fmt::Display for PolicyDockerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SerdeYaml(error) => write!(f, "docker policy YAML error: {error}"),
            Self::RequirementCount(actual) => write!(
                f,
                "docker policy must declare exactly one item in property_requirements (found {actual})",
            ),
            Self::InvalidCanonicalName { field, source } => {
                write!(f, "invalid canonical name for `{field}`: {source}")
            }
        }
    }
}

impl std::error::Error for PolicyDockerError {}

/// Parse YAML policy into a [`PropertyRequirement`].
///
/// The format is deliberately narrow so policy intent lowers into typed
/// requirements without coupling to Docker mapper output details.
#[must_use = "constructed requirement must drive evaluation explicitly"]
pub fn property_requirement_from_yaml(
    input: &str,
) -> Result<PropertyRequirement, PolicyDockerError> {
    let wire: DockerComposePolicyWire =
        serde_yaml::from_str(input).map_err(PolicyDockerError::SerdeYaml)?;
    if wire.property_requirements.len() != 1 {
        return Err(PolicyDockerError::RequirementCount(
            wire.property_requirements.len(),
        ));
    }

    let item = wire
        .property_requirements
        .into_iter()
        .next()
        .expect("checked length"); // exhaustive

    let subject = CanonicalName::new(item.subject).map_err(|source| {
        PolicyDockerError::InvalidCanonicalName {
            field: "subject",
            source,
        }
    })?;
    let property = CanonicalName::new(item.property).map_err(|source| {
        PolicyDockerError::InvalidCanonicalName {
            field: "property",
            source,
        }
    })?;

    Ok(PropertyRequirement::new(
        subject,
        property,
        MappedValue::Bool(item.expected_bool),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jw_guard_mapper::MappedValue;

    #[test]
    fn parses_single_bool_requirement_from_policy_yaml() {
        let yaml = r#"
property_requirements:
  - subject: web
    property: privileged
    expected_bool: false
"#;
        let req = property_requirement_from_yaml(yaml).expect("policy should parse");
        assert_eq!(req.subject().as_str(), "web");
        assert_eq!(req.property().as_str(), "privileged");
        assert_eq!(req.expected(), &MappedValue::Bool(false));
    }

    #[test]
    fn rejects_policy_with_zero_or_many_requirements() {
        let empty = "property_requirements: []\n";
        assert!(matches!(
            property_requirement_from_yaml(empty).expect_err("count"),
            PolicyDockerError::RequirementCount(0)
        ));

        let two = r#"
property_requirements:
  - subject: web
    property: privileged
    expected_bool: false
  - subject: db
    property: privileged
    expected_bool: false
"#;
        assert!(matches!(
            property_requirement_from_yaml(two).expect_err("count"),
            PolicyDockerError::RequirementCount(2)
        ));
    }
}
