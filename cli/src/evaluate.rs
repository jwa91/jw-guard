use std::fmt;
use std::path::Path;

use jw_guard_core::{CanonicalName, Timestamp};
use jw_guard_eval::{
    evaluate_property_requirement, PropertyEvaluation, PropertyOutcome, PropertyReasonTag,
    PropertyRequirement,
};
use jw_guard_mapper::{MappedValue, Mapper};
use jw_guard_mapper_docker::DockerComposeMapper;
use serde::Serialize;

#[derive(Debug)]
pub enum EvaluateFailure {
    Io(std::io::Error),
    InvalidCanonicalName {
        field: &'static str,
        source: jw_guard_core::ScalarViolation,
    },
    Map(jw_guard_mapper::MapError),
}

impl fmt::Display for EvaluateFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "i/o error: {error}"),
            Self::InvalidCanonicalName { field, source } => {
                write!(f, "invalid canonical name for {field}: {source}")
            }
            Self::Map(error) => write!(f, "mapping failed: {error:?}"),
        }
    }
}

impl std::error::Error for EvaluateFailure {}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EvaluateReport {
    pub report_version: String,
    pub kind: String,
    pub subject: String,
    pub property: String,
    pub expected_bool: bool,
    pub outcome: &'static str,
    pub reason: &'static str,
}

pub fn evaluate_docker_compose_bool_property(
    compose_path: &Path,
    subject: &str,
    property: &str,
    expected: bool,
    observed_at_unix_seconds: u64,
) -> Result<EvaluateReport, EvaluateFailure> {
    let input = std::fs::read_to_string(compose_path).map_err(EvaluateFailure::Io)?;
    let subject = parse_name("subject", subject)?;
    let property = parse_name("property", property)?;
    let mapper = DockerComposeMapper::new(Timestamp::from_unix_seconds(observed_at_unix_seconds));
    let evidence = mapper.map(&input).map_err(EvaluateFailure::Map)?;
    let requirement = PropertyRequirement::new(
        subject.clone(),
        property.clone(),
        MappedValue::Bool(expected),
    );
    let evaluation = evaluate_property_requirement(&requirement, &evidence);

    Ok(report(subject, property, expected, evaluation))
}

fn parse_name(field: &'static str, value: &str) -> Result<CanonicalName, EvaluateFailure> {
    CanonicalName::new(value.to_owned())
        .map_err(|source| EvaluateFailure::InvalidCanonicalName { field, source })
}

fn report(
    subject: CanonicalName,
    property: CanonicalName,
    expected_bool: bool,
    evaluation: PropertyEvaluation,
) -> EvaluateReport {
    EvaluateReport {
        report_version: "1".to_owned(),
        kind: "docker_compose_property".to_owned(),
        subject: subject.as_str().to_owned(),
        property: property.as_str().to_owned(),
        expected_bool,
        outcome: outcome_label(evaluation.outcome()),
        reason: reason_label(evaluation.reason()),
    }
}

fn outcome_label(outcome: PropertyOutcome) -> &'static str {
    match outcome {
        PropertyOutcome::Satisfied => "satisfied",
        PropertyOutcome::Violated => "violated",
        PropertyOutcome::Unknown => "unknown",
        PropertyOutcome::NotApplicable => "not_applicable",
        PropertyOutcome::ValueTypeMismatch => "value_type_mismatch",
    }
}

fn reason_label(reason: PropertyReasonTag) -> &'static str {
    match reason {
        PropertyReasonTag::PropertySatisfied => "property_satisfied",
        PropertyReasonTag::PropertyViolated => "property_violated",
        PropertyReasonTag::PropertyMissing => "property_missing",
        PropertyReasonTag::SubjectMissing => "subject_missing",
        PropertyReasonTag::ValueTypeMismatch => "value_type_mismatch",
    }
}
