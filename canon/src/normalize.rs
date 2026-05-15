use alloc::string::String;
use alloc::vec::Vec;

/// Canonical representation of normalized textual input.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NormalizedText(String);

impl NormalizedText {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Normalizes an unordered collection by sorting and removing duplicates.
#[must_use]
pub fn normalize_unordered<T>(values: impl IntoIterator<Item = T>) -> Vec<T>
where
    T: Ord,
{
    let mut normalized: Vec<T> = values.into_iter().collect();
    normalized.sort();
    normalized.dedup();
    normalized
}

/// Normalizes an ordered collection by preserving input order.
#[must_use]
pub fn normalize_ordered<T>(values: impl IntoIterator<Item = T>) -> Vec<T> {
    values.into_iter().collect()
}

/// Ordered collection validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrderedValidationError {
    LengthMismatch,
    ReorderedAt(usize),
}

/// Validates that normalized values preserve exactly the original order.
pub fn validate_preserved_order<T>(
    original: &[T],
    normalized: &[T],
) -> Result<(), OrderedValidationError>
where
    T: PartialEq,
{
    if original.len() != normalized.len() {
        return Err(OrderedValidationError::LengthMismatch);
    }

    match original
        .iter()
        .zip(normalized.iter())
        .position(|(left, right)| left != right)
    {
        Some(index) => Err(OrderedValidationError::ReorderedAt(index)),
        None => Ok(()),
    }
}

/// Explicit wrapper for optional values.
///
/// `Unspecified` means the field was omitted, while `ExplicitNone` and
/// `ExplicitSome` represent explicit declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExplicitOption<T> {
    Unspecified,
    ExplicitNone,
    ExplicitSome(T),
}

impl<T> ExplicitOption<T> {
    #[must_use]
    pub const fn unspecified() -> Self {
        Self::Unspecified
    }

    #[must_use]
    pub const fn explicit_none() -> Self {
        Self::ExplicitNone
    }

    #[must_use]
    pub fn explicit_some(value: T) -> Self {
        Self::ExplicitSome(value)
    }

    #[must_use]
    pub fn from_option(value: Option<T>) -> Self {
        match value {
            Some(inner) => Self::ExplicitSome(inner),
            None => Self::ExplicitNone,
        }
    }

    #[must_use]
    pub const fn is_explicit(&self) -> bool {
        !matches!(self, Self::Unspecified)
    }

    #[must_use]
    pub const fn is_some(&self) -> bool {
        matches!(self, Self::ExplicitSome(_))
    }

    #[must_use]
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::ExplicitNone)
    }

    #[must_use]
    pub fn into_option(self) -> Option<T> {
        match self {
            Self::ExplicitSome(value) => Some(value),
            Self::Unspecified | Self::ExplicitNone => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExplicitOption, OrderedValidationError, normalize_ordered, normalize_unordered,
        validate_preserved_order,
    };

    #[test]
    fn normalize_unordered_sorts_and_dedups() {
        let normalized = normalize_unordered(["z", "a", "z", "m", "a"]);
        assert_eq!(normalized, vec!["a", "m", "z"]);
    }

    #[test]
    fn normalize_ordered_preserves_input_order() {
        let original = vec!["edge/b", "edge/a", "edge/c"];
        let normalized = normalize_ordered(original.clone());

        assert_eq!(normalized, original);
        assert_eq!(validate_preserved_order(&original, &normalized), Ok(()));
    }

    #[test]
    fn validate_preserved_order_reports_first_difference() {
        let original = ["a", "b", "c"];
        let reordered = ["a", "c", "b"];

        assert_eq!(
            validate_preserved_order(&original, &reordered),
            Err(OrderedValidationError::ReorderedAt(1))
        );
    }

    #[test]
    fn validate_preserved_order_reports_length_mismatch() {
        assert_eq!(
            validate_preserved_order(&["a", "b"], &["a"]),
            Err(OrderedValidationError::LengthMismatch)
        );
    }

    #[test]
    fn explicit_option_tracks_explicitness() {
        let omitted: ExplicitOption<&str> = ExplicitOption::unspecified();
        let none: ExplicitOption<&str> = ExplicitOption::explicit_none();
        let some = ExplicitOption::explicit_some("value");

        assert!(!omitted.is_explicit());
        assert!(none.is_explicit());
        assert!(none.is_none());
        assert!(some.is_some());
        assert_eq!(some.into_option(), Some("value"));
        assert_eq!(none.into_option(), None);
        assert_eq!(omitted.into_option(), None);
    }
}
