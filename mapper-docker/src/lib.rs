#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use jw_guard_core::{CanonicalName, Timestamp};
use jw_guard_mapper::{
    MapError, MapErrorCode, MappedEvidence, MappedPropertyClaim, MappedReferent, MappedSource,
    MappedValue, Mapper, MapperIdentity,
};
use serde::Deserialize;

#[derive(Debug, Clone, Copy)]
pub struct DockerComposeMapper {
    observed_at: Timestamp,
}

impl DockerComposeMapper {
    #[must_use]
    pub const fn new(observed_at: Timestamp) -> Self {
        Self { observed_at }
    }
}

impl Mapper for DockerComposeMapper {
    type Input = str;

    fn identity(&self) -> MapperIdentity {
        MapperIdentity::new(
            docker_name("docker-compose"),
            jw_guard_vocab_docker::vocabulary_version(),
        )
    }

    fn map(&self, input: &Self::Input) -> Result<MappedEvidence, MapError> {
        let compose: ComposeFile = serde_yaml::from_str(input)
            .map_err(|_| MapError::InvalidInput(MapErrorCode::InvalidInputShape))?;

        let mut referents = Vec::new();
        let mut property_claims = Vec::new();

        for (service_name, service) in compose.services {
            let subject = CanonicalName::new(service_name)
                .map_err(|_| MapError::InvalidInput(MapErrorCode::InvalidInputShape))?;

            referents.push(MappedReferent::new(
                subject.clone(),
                docker_name(jw_guard_vocab_docker::referent_sort::SERVICE),
            ));

            if let Some(privileged) = service.privileged {
                property_claims.push(MappedPropertyClaim::new(
                    subject,
                    docker_name(jw_guard_vocab_docker::property::PRIVILEGED),
                    MappedValue::Bool(privileged),
                    self.observed_at,
                ));
            }
        }

        MappedEvidence::new(
            MappedSource::new(
                self.identity(),
                docker_name("docker-compose-yaml"),
                self.observed_at,
            ),
            referents,
            property_claims,
        )
    }
}

#[derive(Debug, Deserialize)]
struct ComposeFile {
    #[serde(default)]
    services: BTreeMap<String, ComposeService>,
}

#[derive(Debug, Deserialize)]
struct ComposeService {
    privileged: Option<bool>,
}

fn docker_name(value: &str) -> CanonicalName {
    jw_guard_vocab_docker::canonical_name(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jw_guard_core::Timestamp;

    #[test]
    fn docker_compose_mapper_emits_neutral_privileged_property_claims() {
        let input = r#"
services:
  web:
    image: nginx
    privileged: true
  db:
    image: postgres
    privileged: false
"#;
        let mapper = DockerComposeMapper::new(Timestamp::from_unix_seconds(1));

        let evidence = mapper.map(input).expect("compose should map");

        assert_eq!(evidence.referents().len(), 2);
        assert_eq!(evidence.referents()[0].name.as_str(), "db");
        assert_eq!(evidence.property_claims().len(), 2);
        assert_eq!(evidence.property_claims()[0].subject.as_str(), "db");
        assert_eq!(
            evidence.property_claims()[0].property.as_str(),
            "privileged"
        );
        assert_eq!(
            evidence.property_claims()[0].value,
            MappedValue::Bool(false)
        );
        assert_eq!(evidence.property_claims()[1].subject.as_str(), "web");
        assert_eq!(evidence.property_claims()[1].value, MappedValue::Bool(true));
    }

    #[test]
    fn docker_compose_mapper_leaves_missing_privileged_as_missing_evidence() {
        let input = r#"
services:
  web:
    image: nginx
"#;
        let mapper = DockerComposeMapper::new(Timestamp::from_unix_seconds(1));

        let evidence = mapper.map(input).expect("compose should map");

        assert_eq!(evidence.referents().len(), 1);
        assert!(evidence.property_claims().is_empty());
    }

    #[test]
    fn docker_compose_mapper_rejects_non_boolean_privileged_values() {
        let input = r#"
services:
  web:
    privileged: maybe
"#;
        let mapper = DockerComposeMapper::new(Timestamp::from_unix_seconds(1));

        let error = mapper
            .map(input)
            .expect_err("invalid privileged should fail");

        assert_eq!(
            error,
            MapError::InvalidInput(MapErrorCode::InvalidInputShape)
        );
    }
}
