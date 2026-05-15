use alloc::string::String;
use core::ops::Deref;

use crate::error::{DeclareError, DeclareResult};

/// Stable symbolic name used inside a declaration document.
///
/// A declaration name is not a human label and not a core id. It is the
/// machine-facing reference key that lets the declaration layer validate intent
/// before any canonical core ids are assigned.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DeclarationName(String);

impl DeclarationName {
    /// Creates a declaration name.
    ///
    /// Names are intentionally stricter than labels: lowercase ASCII
    /// alphanumeric words separated by single hyphens, 1..=63 bytes.
    pub fn new(value: impl Into<String>) -> DeclareResult<Self> {
        let value = value.into();
        if value.is_empty() {
            return Err(DeclareError::Empty {
                field: "declaration_name",
            });
        }
        if !is_declaration_name(&value) {
            return Err(DeclareError::Invalid {
                field: "declaration_name",
            });
        }
        Ok(Self(value))
    }

    /// Creates a declaration name without validation for trusted catalogs.
    pub fn new_unchecked(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the inner name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes this name and returns the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for DeclarationName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for DeclarationName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DeclarationName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(|_| serde::de::Error::custom("invalid declaration name"))
    }
}

/// Human-facing label attached to declaration objects.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Label(String);

impl Label {
    /// Creates a non-empty label.
    pub fn new(value: impl Into<String>) -> DeclareResult<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(DeclareError::Empty { field: "label" });
        }
        Ok(Self(value))
    }

    /// Returns the inner label.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes this label and returns the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for Label {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Label {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Label {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(|_| serde::de::Error::custom("invalid label"))
    }
}

fn is_declaration_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() > 63 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() || bytes[bytes.len() - 1] == b'-' {
        return false;
    }
    let mut previous_hyphen = false;
    for byte in bytes {
        let current_hyphen = *byte == b'-';
        if current_hyphen && previous_hyphen {
            return false;
        }
        if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || current_hyphen) {
            return false;
        }
        previous_hyphen = current_hyphen;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::DeclarationName;

    #[test]
    fn declaration_names_are_strict_machine_references() {
        assert!(DeclarationName::new("dev").is_ok());
        assert!(DeclarationName::new("dev-zone").is_ok());
        assert!(DeclarationName::new("Dev").is_err());
        assert!(DeclarationName::new("dev zone").is_err());
        assert!(DeclarationName::new("dev--zone").is_err());
        assert!(DeclarationName::new("dev-").is_err());
    }
}
