use jw_guard_core::{CanonicalName, SemVer, Timestamp};
use jw_guard_mapper::{
    MapError, MappedEvidence, MappedPropertyClaim, MappedReferent, MappedSource, MappedValue,
    MapperIdentity,
};

use crate::dto::WireVersionSpec;
use crate::error::EvidenceConvertError;
use crate::evidence_dto::{
    WireMappedEvidence, WireMappedPropertyClaim, WireMappedReferent, WireMappedSource,
    WireMappedValue,
};

impl TryFrom<WireMappedEvidence> for MappedEvidence {
    type Error = Vec<EvidenceConvertError>;

    fn try_from(value: WireMappedEvidence) -> Result<Self, Self::Error> {
        let mut errors = Vec::new();

        let source = convert_source(value.source, &mut errors);
        let referents = value
            .referents
            .into_iter()
            .enumerate()
            .filter_map(|(index, referent)| convert_referent(index, referent, &mut errors))
            .collect();
        let property_claims = value
            .property_claims
            .into_iter()
            .enumerate()
            .filter_map(|(index, claim)| convert_property_claim(index, claim, &mut errors))
            .collect();

        if !errors.is_empty() {
            return Err(errors);
        }

        MappedEvidence::new(
            source.expect("source should be present without conversion errors"),
            referents,
            property_claims,
        )
        .map_err(|error| match error {
            MapError::InvalidOutput(violations) => {
                vec![EvidenceConvertError::InvalidMappedOutput(violations)]
            }
            MapError::InvalidInput(code) => {
                vec![EvidenceConvertError::UnexpectedMapperInputError(code)]
            }
        })
    }
}

fn convert_source(
    source: WireMappedSource,
    errors: &mut Vec<EvidenceConvertError>,
) -> Option<MappedSource> {
    let mapper_name = parse_name("source.mapper.name", source.mapper.name, errors);
    let input_kind = parse_name("source.input_kind", source.input_kind, errors);

    if mapper_name.is_none() || input_kind.is_none() {
        return None;
    }

    Some(MappedSource::new(
        MapperIdentity::new(
            mapper_name.expect("mapper name checked"),
            convert_version(&source.mapper.version),
        ),
        input_kind.expect("input kind checked"),
        Timestamp::from_unix_seconds(source.observed_at_unix_seconds),
    ))
}

fn convert_referent(
    index: usize,
    referent: WireMappedReferent,
    errors: &mut Vec<EvidenceConvertError>,
) -> Option<MappedReferent> {
    let name = parse_name_with_index("referents", index, "name", referent.name, errors);
    let sort = parse_name_with_index("referents", index, "sort", referent.sort, errors);

    if name.is_none() || sort.is_none() {
        return None;
    }

    Some(MappedReferent::new(
        name.expect("name checked"),
        sort.expect("sort checked"),
    ))
}

fn convert_property_claim(
    index: usize,
    claim: WireMappedPropertyClaim,
    errors: &mut Vec<EvidenceConvertError>,
) -> Option<MappedPropertyClaim> {
    let subject = parse_name_with_index("property_claims", index, "subject", claim.subject, errors);
    let property =
        parse_name_with_index("property_claims", index, "property", claim.property, errors);
    let value = convert_value(index, claim.value, errors);

    if subject.is_none() || property.is_none() || value.is_none() {
        return None;
    }

    Some(MappedPropertyClaim::new(
        subject.expect("subject checked"),
        property.expect("property checked"),
        value.expect("value checked"),
        Timestamp::from_unix_seconds(claim.observed_at_unix_seconds),
    ))
}

fn convert_value(
    claim_index: usize,
    value: WireMappedValue,
    errors: &mut Vec<EvidenceConvertError>,
) -> Option<MappedValue> {
    Some(match value {
        WireMappedValue::Bool { value } => MappedValue::Bool(value),
        WireMappedValue::U64 { value } => MappedValue::U64(value),
        WireMappedValue::Name { name } => MappedValue::Name(parse_name_with_path(
            format!("property_claims[{claim_index}].value.name"),
            name,
            errors,
        )?),
        WireMappedValue::Names { names } => MappedValue::Names(
            names
                .into_iter()
                .enumerate()
                .filter_map(|(name_index, name)| {
                    parse_name_with_path(
                        format!("property_claims[{claim_index}].value.names[{name_index}]"),
                        name,
                        errors,
                    )
                })
                .collect(),
        ),
        WireMappedValue::DurationSeconds { seconds } => MappedValue::DurationSeconds(seconds),
    })
}

fn convert_version(version: &WireVersionSpec) -> SemVer {
    SemVer::new(version.major, version.minor, version.patch)
}

fn parse_name_with_index(
    section: &str,
    index: usize,
    field: &str,
    value: String,
    errors: &mut Vec<EvidenceConvertError>,
) -> Option<CanonicalName> {
    parse_name_with_path(format!("{section}[{index}].{field}"), value, errors)
}

fn parse_name(
    path: &str,
    value: String,
    errors: &mut Vec<EvidenceConvertError>,
) -> Option<CanonicalName> {
    parse_name_with_path(path.to_owned(), value, errors)
}

fn parse_name_with_path(
    path: String,
    value: String,
    errors: &mut Vec<EvidenceConvertError>,
) -> Option<CanonicalName> {
    CanonicalName::new(value.clone()).map_or_else(
        |source| {
            errors.push(EvidenceConvertError::InvalidCanonicalName {
                path,
                value,
                source,
            });
            None
        },
        Some,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_dto::{WireMappedSource, WireMapperIdentity};

    fn version() -> WireVersionSpec {
        WireVersionSpec {
            major: 0,
            minor: 1,
            patch: 0,
        }
    }

    fn source() -> WireMappedSource {
        WireMappedSource {
            mapper: WireMapperIdentity {
                name: "docker-compose".to_owned(),
                version: version(),
            },
            input_kind: "docker-compose-yaml".to_owned(),
            observed_at_unix_seconds: 1,
        }
    }

    #[test]
    fn converts_wire_mapped_evidence_and_sorts_output() {
        let wire = WireMappedEvidence {
            source: source(),
            referents: vec![
                WireMappedReferent {
                    name: "web".to_owned(),
                    sort: "service".to_owned(),
                },
                WireMappedReferent {
                    name: "db".to_owned(),
                    sort: "service".to_owned(),
                },
            ],
            property_claims: vec![
                WireMappedPropertyClaim {
                    subject: "web".to_owned(),
                    property: "privileged".to_owned(),
                    value: WireMappedValue::Bool { value: false },
                    observed_at_unix_seconds: 1,
                },
                WireMappedPropertyClaim {
                    subject: "db".to_owned(),
                    property: "privileged".to_owned(),
                    value: WireMappedValue::Bool { value: false },
                    observed_at_unix_seconds: 1,
                },
            ],
        };

        let evidence = MappedEvidence::try_from(wire).expect("wire evidence should convert");

        assert_eq!(evidence.referents()[0].name.as_str(), "db");
        assert_eq!(evidence.property_claims()[0].subject.as_str(), "db");
    }

    #[test]
    fn conversion_accumulates_invalid_names() {
        let wire = WireMappedEvidence {
            source: WireMappedSource {
                mapper: WireMapperIdentity {
                    name: "DockerCompose".to_owned(),
                    version: version(),
                },
                input_kind: "docker-compose-yaml".to_owned(),
                observed_at_unix_seconds: 1,
            },
            referents: vec![WireMappedReferent {
                name: "Web".to_owned(),
                sort: "service".to_owned(),
            }],
            property_claims: vec![],
        };

        let errors = MappedEvidence::try_from(wire).expect_err("invalid names should fail");

        assert_eq!(errors.len(), 2);
        assert!(errors.iter().any(|error| matches!(
            error,
            EvidenceConvertError::InvalidCanonicalName { path, .. } if path == "source.mapper.name"
        )));
        assert!(errors.iter().any(|error| matches!(
            error,
            EvidenceConvertError::InvalidCanonicalName { path, .. } if path == "referents[0].name"
        )));
    }
}
