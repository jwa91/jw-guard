use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::spec::{DeclaredSpec, RequirementValueSpec};
use jw_guard_core::{RequirementDeclaration, RequirementId, RequirementSortId, RequirementValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    EmptySection {
        section: &'static str,
    },
    DuplicateName {
        section: &'static str,
        name: crate::SymbolicName,
    },
    MissingReference {
        section: &'static str,
        field: &'static str,
        name: crate::SymbolicName,
    },
    InvalidRequirementValue {
        name: crate::SymbolicName,
        operator: jw_guard_core::RequirementOperator,
    },
}

pub fn validate_spec(spec: &DeclaredSpec) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    if spec.actors.is_empty() {
        errors.push(ValidationError::EmptySection { section: "actors" });
    }
    if spec.referents.is_empty() {
        errors.push(ValidationError::EmptySection { section: "referents" });
    }

    collect_duplicate_names(spec.actors.iter().map(|item| &item.name), "actors", &mut errors);
    collect_duplicate_names(
        spec.referents.iter().map(|item| &item.name),
        "referents",
        &mut errors,
    );
    collect_duplicate_names(
        spec.boundaries.iter().map(|item| &item.name),
        "boundaries",
        &mut errors,
    );
    collect_duplicate_names(spec.edges.iter().map(|item| &item.name), "edges", &mut errors);
    collect_duplicate_names(spec.scopes.iter().map(|item| &item.name), "scopes", &mut errors);
    collect_duplicate_names(
        spec.requirements.iter().map(|item| &item.name),
        "requirements",
        &mut errors,
    );
    collect_duplicate_names(
        spec.policies.iter().map(|item| &item.name),
        "policies",
        &mut errors,
    );

    let actor_names: BTreeSet<_> = spec.actors.iter().map(|item| item.name.clone()).collect();
    let referent_names: BTreeSet<_> = spec.referents.iter().map(|item| item.name.clone()).collect();
    let scope_names: BTreeSet<_> = spec.scopes.iter().map(|item| item.name.clone()).collect();
    let requirement_names: BTreeSet<_> = spec.requirements.iter().map(|item| item.name.clone()).collect();

    if !actor_names.contains(&spec.model.declared_by) {
        errors.push(ValidationError::MissingReference {
            section: "model",
            field: "declared_by",
            name: spec.model.declared_by.clone(),
        });
    }

    for boundary in &spec.boundaries {
        if !referent_names.contains(&boundary.side_a_anchor) {
            errors.push(ValidationError::MissingReference {
                section: "boundaries",
                field: "side_a_anchor",
                name: boundary.side_a_anchor.clone(),
            });
        }
        if !referent_names.contains(&boundary.side_b_anchor) {
            errors.push(ValidationError::MissingReference {
                section: "boundaries",
                field: "side_b_anchor",
                name: boundary.side_b_anchor.clone(),
            });
        }
    }

    for edge in &spec.edges {
        if !referent_names.contains(&edge.first) {
            errors.push(ValidationError::MissingReference {
                section: "edges",
                field: "first",
                name: edge.first.clone(),
            });
        }
        if !referent_names.contains(&edge.second) {
            errors.push(ValidationError::MissingReference {
                section: "edges",
                field: "second",
                name: edge.second.clone(),
            });
        }
    }

    for policy in &spec.policies {
        if !actor_names.contains(&policy.declared_by) {
            errors.push(ValidationError::MissingReference {
                section: "policies",
                field: "declared_by",
                name: policy.declared_by.clone(),
            });
        }
        if !scope_names.contains(&policy.scope) {
            errors.push(ValidationError::MissingReference {
                section: "policies",
                field: "scope",
                name: policy.scope.clone(),
            });
        }
        if !requirement_names.contains(&policy.requirement) {
            errors.push(ValidationError::MissingReference {
                section: "policies",
                field: "requirement",
                name: policy.requirement.clone(),
            });
        }
    }

    for requirement in &spec.requirements {
        let check = RequirementDeclaration::new(
            RequirementId::from_bytes([0; 16]),
            RequirementSortId(requirement.sort),
            requirement.operator,
            to_requirement_value(&requirement.value),
        );
        if check.is_err() {
            errors.push(ValidationError::InvalidRequirementValue {
                name: requirement.name.clone(),
                operator: requirement.operator,
            });
        }
    }

    errors
}

fn collect_duplicate_names<'a, I>(
    names: I,
    section: &'static str,
    errors: &mut Vec<ValidationError>,
)
where
    I: Iterator<Item = &'a crate::SymbolicName>,
{
    let mut seen = BTreeSet::new();
    for name in names {
        if !seen.insert(name.clone()) {
            errors.push(ValidationError::DuplicateName {
                section,
                name: name.clone(),
            });
        }
    }
}

fn to_requirement_value(value: &RequirementValueSpec) -> RequirementValue {
    match value {
        RequirementValueSpec::Bool(item) => RequirementValue::Bool(*item),
        RequirementValueSpec::U64(item) => RequirementValue::U64(*item),
        RequirementValueSpec::Name(item) => RequirementValue::Name(
            jw_guard_core::CanonicalName::new(item.as_str().into())
                .expect("symbolic name should always map to canonical names"),
        ),
        RequirementValueSpec::Names(items) => RequirementValue::Names(
            items
                .iter()
                .map(|item| {
                    jw_guard_core::CanonicalName::new(item.as_str().into())
                        .expect("symbolic name should always map to canonical names")
                })
                .collect(),
        ),
        RequirementValueSpec::DurationSeconds(item) => RequirementValue::DurationSeconds(*item),
    }
}
