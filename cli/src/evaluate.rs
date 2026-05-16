use std::fmt;
use std::path::Path;

use jw_guard_core::{CanonicalName, Timestamp};
use jw_guard_eval::{
    evaluate_property_requirement, PropertyEvaluation, PropertyOutcome, PropertyReasonTag,
    PropertyRequirement,
};
use jw_guard_mapper::{MappedValue, Mapper};
use jw_guard_mapper_docker::DockerComposeMapper;
use jw_guard_policy_docker::PolicyDockerError;
use serde::Serialize;

#[derive(Debug)]
pub enum EvaluateFailure {
    Io(std::io::Error),
    InvalidEvaluateArgs(&'static str),
    InvalidCanonicalName {
        field: &'static str,
        source: jw_guard_core::ScalarViolation,
    },
    Map(jw_guard_mapper::MapError),
    DockerPolicy(PolicyDockerError),
}

impl fmt::Display for EvaluateFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "i/o error: {error}"),
            Self::InvalidEvaluateArgs(message) => f.write_str(message),
            Self::InvalidCanonicalName { field, source } => {
                write!(f, "invalid canonical name for {field}: {source}")
            }
            Self::Map(error) => write!(f, "mapping failed: {error:?}"),
            Self::DockerPolicy(error) => write!(f, "{error}"),
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

pub fn evaluate_docker_compose(
    compose_path: &Path,
    policy_path: Option<&Path>,
    subject: Option<&str>,
    property: Option<&str>,
    expect_bool: Option<bool>,
    observed_at_unix_seconds: u64,
) -> Result<EvaluateReport, EvaluateFailure> {
    let requirement = match (policy_path, subject, property, expect_bool) {
        (Some(policy_path), None, None, None) => {
            let text = std::fs::read_to_string(policy_path).map_err(EvaluateFailure::Io)?;
            jw_guard_policy_docker::property_requirement_from_yaml(&text).map_err(EvaluateFailure::DockerPolicy)?
        }
        (
            None,
            Some(subject),
            Some(property),
            Some(expect_bool),
        ) => PropertyRequirement::new(
            parse_name("subject", subject)?,
            parse_name("property", property)?,
            MappedValue::Bool(expect_bool),
        ),
        (Some(_), _, _, _) => {
            return Err(EvaluateFailure::InvalidEvaluateArgs(
                "`--policy` cannot be combined with `--subject`, `--property`, or `--expect-bool`",
            ))
        }
        _ => Err(EvaluateFailure::InvalidEvaluateArgs(
            "supply `--policy POLICY.yaml` or all of `--subject`, `--property`, and `--expect-bool`",
        ))?,
    };

    let input = std::fs::read_to_string(compose_path).map_err(EvaluateFailure::Io)?;

    let mapper = DockerComposeMapper::new(Timestamp::from_unix_seconds(observed_at_unix_seconds));
    let evidence = mapper.map(&input).map_err(EvaluateFailure::Map)?;
    let evaluation = evaluate_property_requirement(&requirement, &evidence);

    Ok(report(
        requirement.subject().clone(),
        requirement.property().clone(),
        bool_expectation(requirement.expected())?,
        evaluation,
    ))
}

fn bool_expectation(expected: &MappedValue) -> Result<bool, EvaluateFailure> {
    match expected {
        MappedValue::Bool(value) => Ok(*value),
        _ => Err(EvaluateFailure::InvalidEvaluateArgs(
            "internal error: CLI evaluation expects bool property requirements only",
        )),
    }
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
