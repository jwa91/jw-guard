use serde::de::DeserializeOwned;
#[cfg(feature = "yaml")]
use serde::Deserialize;

#[cfg(feature = "yaml")]
use crate::{
    EdgeBudgetPolicyDocument, PhaseSeparationPolicyDocument, PolicyKind, PortProfilePolicyDocument,
    ScopePolicyDocument, TransportRoutesPolicyDocument,
};
use crate::{PolicyDocument, PolicySchemaError};

#[cfg(feature = "yaml")]
pub fn parse_yaml<T>(input: &str) -> Result<T, PolicySchemaError>
where
    T: DeserializeOwned,
{
    serde_yaml::from_str(input).map_err(PolicySchemaError::from)
}

#[cfg(feature = "yaml")]
#[derive(Debug, Deserialize)]
struct KindProbe {
    kind: PolicyKind,
}

#[cfg(feature = "yaml")]
pub fn parse_policy_document(input: &str) -> Result<PolicyDocument, PolicySchemaError> {
    let value: serde_yaml::Value = serde_yaml::from_str(input).map_err(PolicySchemaError::from)?;
    let probe: KindProbe = serde_yaml::from_value(value.clone()).map_err(PolicySchemaError::from)?;

    match probe.kind {
        PolicyKind::ScopePolicy => {
            let document: ScopePolicyDocument =
                serde_yaml::from_value(value).map_err(PolicySchemaError::from)?;
            Ok(PolicyDocument::ScopePolicy(document))
        }
        PolicyKind::PhaseSeparationPolicy => {
            let document: PhaseSeparationPolicyDocument =
                serde_yaml::from_value(value).map_err(PolicySchemaError::from)?;
            Ok(PolicyDocument::PhaseSeparationPolicy(document))
        }
        PolicyKind::EdgeBudgetPolicy => {
            let document: EdgeBudgetPolicyDocument =
                serde_yaml::from_value(value).map_err(PolicySchemaError::from)?;
            Ok(PolicyDocument::EdgeBudgetPolicy(document))
        }
        PolicyKind::PortProfilePolicy => {
            let document: PortProfilePolicyDocument =
                serde_yaml::from_value(value).map_err(PolicySchemaError::from)?;
            Ok(PolicyDocument::PortProfilePolicy(document))
        }
        PolicyKind::TransportRoutesPolicy => {
            let document: TransportRoutesPolicyDocument =
                serde_yaml::from_value(value).map_err(PolicySchemaError::from)?;
            Ok(PolicyDocument::TransportRoutesPolicy(document))
        }
    }
}

#[cfg(not(feature = "yaml"))]
pub fn parse_yaml<T>(_input: &str) -> Result<T, PolicySchemaError>
where
    T: DeserializeOwned,
{
    Err(PolicySchemaError::YamlParse(
        "yaml feature is disabled".into(),
    ))
}

#[cfg(not(feature = "yaml"))]
pub fn parse_policy_document(_input: &str) -> Result<PolicyDocument, PolicySchemaError> {
    Err(PolicySchemaError::YamlParse(
        "yaml feature is disabled".into(),
    ))
}
