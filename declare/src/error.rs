use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolicNameError {
    Empty,
    InvalidCharacter { index: usize, character: char },
}

impl fmt::Display for SymbolicNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("symbolic name cannot be empty"),
            Self::InvalidCharacter { index, character } => {
                write!(
                    f,
                    "symbolic name contains invalid character '{}' at index {}",
                    character, index
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SymbolicNameError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclareError {
    ValidationFailed(Vec<crate::validation::ValidationError>),
    CanonicalPath(jw_guard_canon::CanonicalPathError),
    DeterministicId(jw_guard_canon::DeterministicIdError),
    InvalidCanonicalName(jw_guard_core::ScalarViolation),
    InvalidConstruction(jw_guard_core::ConstructionViolation),
    MissingReference {
        section: &'static str,
        field: &'static str,
        name: String,
    },
}

impl fmt::Display for DeclareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValidationFailed(errors) => {
                write!(f, "spec validation failed with {} error(s)", errors.len())
            }
            Self::CanonicalPath(error) => write!(f, "canonical path derivation failed: {error}"),
            Self::DeterministicId(error) => write!(f, "deterministic id derivation failed: {error}"),
            Self::InvalidCanonicalName(error) => write!(f, "canonical name conversion failed: {error}"),
            Self::InvalidConstruction(error) => write!(f, "core declaration construction failed: {error}"),
            Self::MissingReference {
                section,
                field,
                name,
            } => write!(f, "missing reference '{name}' for {section}.{field}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DeclareError {}

impl From<jw_guard_canon::CanonicalPathError> for DeclareError {
    fn from(value: jw_guard_canon::CanonicalPathError) -> Self {
        Self::CanonicalPath(value)
    }
}

impl From<jw_guard_canon::DeterministicIdError> for DeclareError {
    fn from(value: jw_guard_canon::DeterministicIdError) -> Self {
        Self::DeterministicId(value)
    }
}

impl From<jw_guard_core::ScalarViolation> for DeclareError {
    fn from(value: jw_guard_core::ScalarViolation) -> Self {
        Self::InvalidCanonicalName(value)
    }
}

impl From<jw_guard_core::ConstructionViolation> for DeclareError {
    fn from(value: jw_guard_core::ConstructionViolation) -> Self {
        Self::InvalidConstruction(value)
    }
}
