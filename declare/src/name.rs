use crate::error::SymbolicNameError;
use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolicName(String);

impl SymbolicName {
    pub fn new(value: &str) -> Result<Self, SymbolicNameError> {
        if value.is_empty() {
            return Err(SymbolicNameError::Empty);
        }

        for (index, character) in value.chars().enumerate() {
            let is_valid = matches!(character, 'a'..='z' | '0'..='9' | '_' | '-');
            if !is_valid {
                return Err(SymbolicNameError::InvalidCharacter { index, character });
            }
        }

        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SymbolicName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for SymbolicName {
    type Error = SymbolicNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_symbolic_names() {
        let names = ["a", "alpha", "alpha_2", "model-edge_9", "z0"];

        for value in names {
            assert!(SymbolicName::new(value).is_ok(), "expected '{value}' to be valid");
        }
    }

    #[test]
    fn rejects_empty_symbolic_name() {
        let error = SymbolicName::new("").expect_err("empty name should fail validation");
        assert_eq!(error, SymbolicNameError::Empty);
    }

    #[test]
    fn rejects_invalid_symbolic_characters() {
        let error = SymbolicName::new("Alpha").expect_err("uppercase character should fail");
        assert_eq!(
            error,
            SymbolicNameError::InvalidCharacter {
                index: 0,
                character: 'A',
            }
        );
    }
}
