use alloc::string::String;
use core::fmt;

use jw_guard_declare::SymbolicNameError;
use jw_guard_policy_schema::PolicyKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyCompileError {
    UnsupportedPolicyKind {
        kind: PolicyKind,
    },
    InconsistentPolicyKind {
        expected: PolicyKind,
        found: PolicyKind,
    },
    InvalidSymbolicName {
        field: &'static str,
        value: String,
        source: SymbolicNameError,
    },
    InvalidVersion {
        value: String,
    },
    EmptyRequirements {
        kind: PolicyKind,
        policy_name: String,
    },
    ConflictingDuplicate {
        section: &'static str,
        name: String,
    },
}

impl fmt::Display for PolicyCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPolicyKind { kind } => {
                write!(f, "unsupported policy kind for compiler: {kind:?}")
            }
            Self::InconsistentPolicyKind { expected, found } => write!(
                f,
                "policy document kind is inconsistent: expected {expected:?}, found {found:?}"
            ),
            Self::InvalidSymbolicName {
                field,
                value,
                source,
            } => {
                write!(
                    f,
                    "invalid symbolic name for {field} ('{value}'): {source}"
                )
            }
            Self::InvalidVersion { value } => {
                write!(f, "invalid semantic version '{value}', expected '<major>.<minor>.<patch>'")
            }
            Self::EmptyRequirements { kind, policy_name } => write!(
                f,
                "policy kind {kind:?} for '{policy_name}' does not contain any requirements"
            ),
            Self::ConflictingDuplicate { section, name } => {
                write!(f, "conflicting duplicate '{name}' found in {section}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PolicyCompileError {}
