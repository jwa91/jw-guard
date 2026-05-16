#![forbid(unsafe_code)]

use jw_guard_core::{CanonicalName, Timestamp};
use jw_guard_mapper::{
    MapError, MapErrorCode, MappedEvidence, MappedPropertyClaim, MappedReferent, MappedSource,
    MappedValue, Mapper, MapperIdentity,
};
use serde::Deserialize;
use serde_yaml::Value;

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
        let root = parse_single_yaml_document(input)?;
        let root_mapping = root
            .as_mapping()
            .ok_or(MapError::InvalidInput(MapErrorCode::InvalidInputShape))?;

        let services_val = root_mapping
            .get(Value::String("services".to_owned()))
            .ok_or(MapError::InvalidInput(MapErrorCode::InvalidInputShape))?;

        let services_mapping = services_val
            .as_mapping()
            .ok_or(MapError::InvalidInput(MapErrorCode::InvalidInputShape))?;

        let mut referents = Vec::new();
        let mut property_claims = Vec::new();

        for (raw_name, definition) in services_mapping {
            let service_name = raw_name
                .as_str()
                .ok_or(MapError::InvalidInput(MapErrorCode::InvalidInputShape))?;

            let subject = CanonicalName::new(service_name.to_owned())
                .map_err(|_| MapError::InvalidInput(MapErrorCode::InvalidInputShape))?;

            let svc_map = definition
                .as_mapping()
                .ok_or(MapError::InvalidInput(MapErrorCode::InvalidInputShape))?;

            referents.push(MappedReferent::new(
                subject.clone(),
                docker_name(jw_guard_vocab_docker::referent_sort::SERVICE),
            ));

            match svc_map.get(Value::String("privileged".to_owned())) {
                None => {}
                Some(Value::Bool(privileged)) => {
                    property_claims.push(MappedPropertyClaim::new(
                        subject,
                        docker_name(jw_guard_vocab_docker::property::PRIVILEGED),
                        MappedValue::Bool(*privileged),
                        self.observed_at,
                    ));
                }
                Some(_) => {
                    return Err(MapError::InvalidInput(MapErrorCode::InvalidInputShape));
                }
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

fn parse_single_yaml_document(input: &str) -> Result<Value, MapError> {
    let mut documents = serde_yaml::Deserializer::from_str(input);
    let Some(first) = documents.next() else {
        return Err(MapError::InvalidInput(MapErrorCode::InvalidInputShape));
    };
    let root = Value::deserialize(first).map_err(yaml_to_map_err)?;
    if documents.next().is_some() {
        return Err(MapError::InvalidInput(MapErrorCode::AmbiguousInput));
    }
    Ok(root)
}

fn yaml_to_map_err(err: serde_yaml::Error) -> MapError {
    let message = err.to_string();
    if message.contains("duplicate entry") {
        MapError::InvalidInput(MapErrorCode::AmbiguousInput)
    } else {
        MapError::InvalidInput(MapErrorCode::InvalidInputShape)
    }
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

    #[test]
    fn docker_compose_mapper_requires_services_map() {
        let mapper = DockerComposeMapper::new(Timestamp::from_unix_seconds(1));

        for input in [
            "version: \"3\"\n",
            "{}\n",
            "services: []\n",
            "services: not-a-map\n",
        ] {
            let error = mapper.map(input).expect_err("compose should reject");
            assert_eq!(
                error,
                MapError::InvalidInput(MapErrorCode::InvalidInputShape),
                "input:\n{input}"
            );
        }
    }

    #[test]
    fn docker_compose_mapper_rejects_duplicate_services_keys() {
        let input = r#"
services:
  web:
    privileged: true
  web:
    privileged: false
"#;
        let mapper = DockerComposeMapper::new(Timestamp::from_unix_seconds(1));

        assert_eq!(
            mapper.map(input).expect_err("should reject duplicate keys"),
            MapError::InvalidInput(MapErrorCode::AmbiguousInput)
        );
    }

    #[test]
    fn docker_compose_mapper_maps_empty_explicit_services_mapping() {
        let input = "services: {}\n";
        let mapper = DockerComposeMapper::new(Timestamp::from_unix_seconds(1));

        let evidence = mapper.map(input).expect("empty services maps");
        assert!(evidence.referents().is_empty());
        assert!(evidence.property_claims().is_empty());
    }

    #[test]
    fn docker_compose_mapper_rejects_service_definition_without_mapping_body() {
        let mapper = DockerComposeMapper::new(Timestamp::from_unix_seconds(1));
        assert_eq!(
            mapper
                .map("services:\n  web: not-a-mapping\n")
                .expect_err("service must be mapping"),
            MapError::InvalidInput(MapErrorCode::InvalidInputShape)
        );
    }

    #[test]
    fn docker_compose_mapper_rejects_multi_document_yaml() {
        let input = "---\nservices:\n  web: {}\n---\nservices:\n  web: {}\n";
        let mapper = DockerComposeMapper::new(Timestamp::from_unix_seconds(1));

        assert_eq!(
            mapper.map(input).expect_err("multi-doc should fail"),
            MapError::InvalidInput(MapErrorCode::AmbiguousInput)
        );
    }

    #[test]
    fn docker_compose_mapper_rejects_null_privileged_values() {
        let mapper = DockerComposeMapper::new(Timestamp::from_unix_seconds(1));
        let input = r#"
services:
  web:
    privileged: null
"#;
        assert_eq!(
            mapper.map(input).expect_err("null privileged should fail"),
            MapError::InvalidInput(MapErrorCode::InvalidInputShape)
        );
    }
}
