use alloc::{string::String, vec::Vec};
use core::fmt;

/// Typed canonical-path construction failures.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CanonicalPathError {
    EmptyPath,
    EmptySegment { segment_index: usize },
    InvalidSegmentChar {
        segment_index: usize,
        char_index: usize,
        found: char,
    },
}

impl fmt::Display for CanonicalPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => f.write_str("canonical path must not be empty"),
            Self::EmptySegment { segment_index } => {
                write!(f, "canonical path segment {segment_index} must not be empty")
            }
            Self::InvalidSegmentChar {
                segment_index,
                char_index,
                found,
            } => write!(
                f,
                "canonical path segment {segment_index} contains invalid character '{found}' at index {char_index}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CanonicalPathError {}

/// Canonical path token retained as deterministic string data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CanonicalPath(String);

impl CanonicalPath {
    pub fn try_new(value: impl AsRef<str>) -> Result<Self, CanonicalPathError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(CanonicalPathError::EmptyPath);
        }

        for (segment_index, segment) in value.split('/').enumerate() {
            validate_segment(segment, segment_index)?;
        }

        Ok(Self(value.into()))
    }

    pub fn from_segments<I, S>(segments: I) -> Result<Self, CanonicalPathError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut joined = String::new();
        let mut saw_segment = false;

        for (segment_index, segment) in segments.into_iter().enumerate() {
            let segment = segment.as_ref();
            validate_segment(segment, segment_index)?;

            if saw_segment {
                joined.push('/');
            }
            joined.push_str(segment);
            saw_segment = true;
        }

        if !saw_segment {
            return Err(CanonicalPathError::EmptyPath);
        }

        Ok(Self(joined))
    }

    pub fn join(&self, segment: impl AsRef<str>) -> Result<Self, CanonicalPathError> {
        let segment = segment.as_ref();
        validate_segment(segment, self.segments().len())?;

        let mut value = String::with_capacity(self.0.len() + 1 + segment.len());
        value.push_str(&self.0);
        value.push('/');
        value.push_str(segment);
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn segments(&self) -> Vec<&str> {
        self.0.split('/').collect()
    }
}

impl fmt::Display for CanonicalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::str::FromStr for CanonicalPath {
    type Err = CanonicalPathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

fn validate_segment(segment: &str, segment_index: usize) -> Result<(), CanonicalPathError> {
    if segment.is_empty() {
        return Err(CanonicalPathError::EmptySegment { segment_index });
    }

    for (char_index, character) in segment.chars().enumerate() {
        let is_valid = character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == '_'
            || character == '-';
        if !is_valid {
            return Err(CanonicalPathError::InvalidSegmentChar {
                segment_index,
                char_index,
                found: character,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CanonicalPath, CanonicalPathError};

    #[test]
    fn try_new_accepts_valid_paths() {
        let path = CanonicalPath::try_new("alpha/beta_2/gamma-3").expect("valid path");
        assert_eq!(path.as_str(), "alpha/beta_2/gamma-3");
        assert_eq!(path.segments(), vec!["alpha", "beta_2", "gamma-3"]);
        assert_eq!(path.to_string(), "alpha/beta_2/gamma-3");
    }

    #[test]
    fn try_new_rejects_empty_path() {
        let error = CanonicalPath::try_new("").expect_err("empty path must fail");
        assert_eq!(error, CanonicalPathError::EmptyPath);
    }

    #[test]
    fn try_new_rejects_empty_segments() {
        let error = CanonicalPath::try_new("alpha//beta").expect_err("empty segment must fail");
        assert_eq!(error, CanonicalPathError::EmptySegment { segment_index: 1 });
    }

    #[test]
    fn try_new_rejects_invalid_segment_characters() {
        let error = CanonicalPath::try_new("alpha/Beta").expect_err("uppercase char must fail");
        assert_eq!(
            error,
            CanonicalPathError::InvalidSegmentChar {
                segment_index: 1,
                char_index: 0,
                found: 'B',
            }
        );
    }

    #[test]
    fn from_segments_builds_deterministic_joined_path() {
        let path =
            CanonicalPath::from_segments(["root", "nested_item", "leaf-1"]).expect("valid path");
        assert_eq!(path.as_str(), "root/nested_item/leaf-1");
    }

    #[test]
    fn from_segments_rejects_empty_input() {
        let empty: [&str; 0] = [];
        let error = CanonicalPath::from_segments(empty).expect_err("empty input must fail");
        assert_eq!(error, CanonicalPathError::EmptyPath);
    }

    #[test]
    fn join_appends_valid_segment() {
        let joined = CanonicalPath::try_new("alpha")
            .expect("valid base path")
            .join("beta-1")
            .expect("valid join segment");
        assert_eq!(joined.as_str(), "alpha/beta-1");
    }
}
