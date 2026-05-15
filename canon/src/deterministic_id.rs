use alloc::string::String;
use core::fmt;

/// Fixed-size deterministic identifier payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeterministicId([u8; 16]);

/// Derivation errors for deterministic ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeterministicIdError {
    EmptyIdKind,
    EmptySchemaVersion,
    EmptyCanonicalPath,
}

impl fmt::Display for DeterministicIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdKind => f.write_str("id kind must not be empty"),
            Self::EmptySchemaVersion => f.write_str("schema version must not be empty"),
            Self::EmptyCanonicalPath => f.write_str("canonical path must not be empty"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DeterministicIdError {}

const DERIVATION_DOMAIN: &[u8] = b"jw-guard:canon:deterministic-id:v1";

impl DeterministicId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Derives a deterministic, domain-separated 128-bit identifier.
    pub fn derive(
        id_kind: &str,
        schema_version: &str,
        canonical_path: &str,
    ) -> Result<Self, DeterministicIdError> {
        if id_kind.is_empty() {
            return Err(DeterministicIdError::EmptyIdKind);
        }
        if schema_version.is_empty() {
            return Err(DeterministicIdError::EmptySchemaVersion);
        }
        if canonical_path.is_empty() {
            return Err(DeterministicIdError::EmptyCanonicalPath);
        }

        let mut hasher = Fnv1a128::new();
        hasher.write(DERIVATION_DOMAIN);
        hasher.write(&[0]);
        write_field(&mut hasher, 1, id_kind);
        write_field(&mut hasher, 2, schema_version);
        write_field(&mut hasher, 3, canonical_path);
        Ok(Self(hasher.finish().to_be_bytes()))
    }

    /// Renders the identifier as a lowercase hexadecimal string.
    #[must_use]
    pub fn to_hex(self) -> String {
        render_hex(self.0)
    }
}

/// Renders raw id bytes as lowercase hexadecimal.
#[must_use]
pub fn render_hex(bytes: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn write_field(hasher: &mut Fnv1a128, tag: u8, value: &str) {
    hasher.write(&[tag]);
    hasher.write(&(value.len() as u64).to_be_bytes());
    hasher.write(value.as_bytes());
}

#[derive(Debug, Clone, Copy)]
struct Fnv1a128(u128);

impl Fnv1a128 {
    const OFFSET_BASIS: u128 = 144_066_263_297_769_815_596_495_629_667_062_367_629;
    const PRIME: u128 = 309_485_009_821_345_068_724_781_371;

    const fn new() -> Self {
        Self(Self::OFFSET_BASIS)
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 ^= u128::from(byte);
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }

    const fn finish(self) -> u128 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{DeterministicId, DeterministicIdError, render_hex};

    #[test]
    fn derive_is_repeatable() {
        let left = DeterministicId::derive("boundary", "1.0.0", "boundary/public")
            .expect("inputs are non-empty");
        let right = DeterministicId::derive("boundary", "1.0.0", "boundary/public")
            .expect("inputs are non-empty");

        assert_eq!(left, right);
    }

    #[test]
    fn derive_is_domain_separated() {
        let left = DeterministicId::derive("boundary", "1.0.0", "boundary/public")
            .expect("inputs are non-empty");
        let right = DeterministicId::derive("scope", "1.0.0", "boundary/public")
            .expect("inputs are non-empty");

        assert_ne!(left, right);
    }

    #[test]
    fn derive_rejects_empty_fields() {
        assert_eq!(
            DeterministicId::derive("", "1.0.0", "boundary/public"),
            Err(DeterministicIdError::EmptyIdKind)
        );
        assert_eq!(
            DeterministicId::derive("boundary", "", "boundary/public"),
            Err(DeterministicIdError::EmptySchemaVersion)
        );
        assert_eq!(
            DeterministicId::derive("boundary", "1.0.0", ""),
            Err(DeterministicIdError::EmptyCanonicalPath)
        );
    }

    #[test]
    fn render_hex_is_lowercase_and_stable() {
        let id = DeterministicId::derive("boundary", "1.0.0", "boundary/public")
            .expect("inputs are non-empty");

        assert_eq!(id.to_hex(), "2271c6ebc0079fe9b199bb418f957ea1");
        assert_eq!(id.to_hex(), render_hex(id.as_bytes()));
    }
}
