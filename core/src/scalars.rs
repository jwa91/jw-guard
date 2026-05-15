use alloc::{string::String, vec::Vec};
use core::ops::Deref;

use crate::error::{GuardError, GuardResult};

macro_rules! string_scalar {
    ($(#[$meta:meta])* $name:ident, $field:literal, $validator:path) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates the scalar after checking its static format rules.
            pub fn new(value: impl Into<String>) -> GuardResult<Self> {
                let value = value.into();
                if value.is_empty() {
                    return Err(GuardError::Empty { field: $field });
                }
                if !$validator(&value) {
                    return Err(GuardError::Invalid { field: $field });
                }
                Ok(Self(value))
            }

            /// Creates the scalar without validation for trusted compile-time catalogs.
            pub fn new_unchecked(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Returns the inner string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes this scalar and returns its inner string.
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                self.as_str()
            }
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(|_| serde::de::Error::custom(concat!("invalid ", $field)))
            }
        }
    };
}

/// Non-empty ordered sequence used where the type system requires at least one item.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonEmptyVec<T> {
    items: Vec<T>,
}

impl<T> NonEmptyVec<T> {
    /// Creates a non-empty sequence.
    pub fn new(items: Vec<T>, field: &'static str) -> GuardResult<Self> {
        if items.is_empty() {
            return Err(GuardError::EmptySequence { field });
        }
        Ok(Self { items })
    }

    /// Creates a sequence containing one item.
    pub fn from_item(item: T) -> Self {
        Self {
            items: alloc::vec![item],
        }
    }

    /// Returns all items as a slice.
    pub fn as_slice(&self) -> &[T] {
        &self.items
    }

    /// Returns the number of items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true when the sequence is empty.
    ///
    /// This is always false for constructed values, but is useful for generic code
    /// and defensive validation after deserialization.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Consumes this sequence and returns the inner vector.
    pub fn into_vec(self) -> Vec<T> {
        self.items
    }
}

impl<T> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T> From<NonEmptyVec<T>> for Vec<T> {
    fn from(value: NonEmptyVec<T>) -> Self {
        value.into_vec()
    }
}

#[cfg(feature = "serde")]
impl<T> serde::Serialize for NonEmptyVec<T>
where
    T: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.items.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, T> serde::Deserialize<'de> for NonEmptyVec<T>
where
    T: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let items = Vec::<T>::deserialize(deserializer)?;
        Self::new(items, "non_empty_vec")
            .map_err(|_| serde::de::Error::custom("expected non-empty sequence"))
    }
}

string_scalar! {
    /// RFC 3339 timestamp that must be represented in UTC.
    UtcTimestamp,
    "utc_timestamp",
    is_utc_timestamp
}

string_scalar! {
    /// Lowercase SHA-256 digest encoded as 64 hexadecimal characters.
    Sha256,
    "sha256",
    is_lower_hex_64
}

string_scalar! {
    /// Detached signature material encoded outside the core type system.
    Signature,
    "signature",
    is_non_empty
}

string_scalar! {
    /// Algorithm-prefixed key fingerprint.
    KeyFingerprint,
    "key_fingerprint",
    is_key_fingerprint
}

string_scalar! {
    /// RFC 1123 hostname or explicit wildcard hostname pattern.
    Hostname,
    "hostname",
    is_hostname
}

string_scalar! {
    /// IPv4 or IPv6 CIDR range.
    Cidr,
    "cidr",
    is_cidr
}

string_scalar! {
    /// Filesystem path rooted at `/`.
    AbsolutePath,
    "absolute_path",
    is_absolute_path
}

string_scalar! {
    /// Semantic version in `major.minor.patch` form.
    SemVer,
    "semver",
    is_semver
}

string_scalar! {
    /// One-sentence declaration of a zone's purpose.
    ZonePurpose,
    "zone_purpose",
    is_non_empty
}

string_scalar! {
    /// Human-readable identity display name.
    DisplayName,
    "display_name",
    is_non_empty
}

string_scalar! {
    /// IANA-style media type.
    MediaType,
    "media_type",
    is_media_type
}

string_scalar! {
    /// Glob pattern used to include or exclude artifact contents.
    GlobPattern,
    "glob_pattern",
    is_non_empty
}

string_scalar! {
    /// UTC hour-minute boundary in `HH:MM` form.
    HourMinute,
    "hour_minute",
    is_hour_minute
}

string_scalar! {
    /// Human-readable detail for an artifact contract violation.
    ContractViolation,
    "contract_violation",
    is_non_empty
}

string_scalar! {
    /// Non-empty policy or governance note.
    NonEmptyString,
    "non_empty_string",
    is_non_empty
}

/// Non-negative duration in seconds.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct DurationSeconds(u64);

impl DurationSeconds {
    /// Creates a duration in seconds.
    pub const fn new(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns the number of seconds.
    pub const fn as_secs(self) -> u64 {
        self.0
    }
}

/// TCP or UDP port number in the range 1..=65535.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Port(u16);

impl Port {
    /// Creates a port and rejects port zero.
    pub fn new(port: u16) -> GuardResult<Self> {
        if port == 0 {
            return Err(GuardError::OutOfRange { field: "port" });
        }
        Ok(Self(port))
    }

    /// Creates a port without validation for trusted catalogs.
    pub const fn new_unchecked(port: u16) -> Self {
        Self(port)
    }

    /// Returns the port number.
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Port {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u16(self.get())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Port {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::new(value).map_err(|_| serde::de::Error::custom("invalid port"))
    }
}

/// Byte size used by artifact contracts.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct ByteSize(u64);

impl ByteSize {
    /// Creates a byte size.
    pub const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Returns the number of bytes.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Positive hourly rate limit.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Rate(u32);

impl Rate {
    /// Creates a rate limit and rejects zero.
    pub fn new(max_per_hour: u32) -> GuardResult<Self> {
        if max_per_hour == 0 {
            return Err(GuardError::OutOfRange { field: "rate" });
        }
        Ok(Self(max_per_hour))
    }

    /// Returns the rate limit.
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Rate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.get())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Rate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::new(value).map_err(|_| serde::de::Error::custom("invalid rate"))
    }
}

/// One-based gate sequence number.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct GateSequence(u32);

impl GateSequence {
    /// Creates a gate sequence and rejects zero.
    pub fn new(sequence: u32) -> GuardResult<Self> {
        if sequence == 0 {
            return Err(GuardError::OutOfRange {
                field: "gate_sequence",
            });
        }
        Ok(Self(sequence))
    }

    /// Creates a gate sequence without validation for trusted catalogs.
    pub const fn new_unchecked(sequence: u32) -> Self {
        Self(sequence)
    }

    /// Returns the sequence number.
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for GateSequence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.get())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for GateSequence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::new(value).map_err(|_| serde::de::Error::custom("invalid gate sequence"))
    }
}

fn is_non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}

fn is_utc_timestamp(value: &str) -> bool {
    value.ends_with('Z') && value.contains('T') && value.len() >= 20
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_key_fingerprint(value: &str) -> bool {
    let Some((algorithm, fingerprint)) = value.split_once(':') else {
        return false;
    };
    is_non_empty(algorithm) && is_non_empty(fingerprint)
}

fn is_hostname(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'*'))
}

fn is_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    if address.is_empty() || prefix.is_empty() {
        return false;
    }
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    if address.contains(':') {
        prefix <= 128
    } else if address.contains('.') {
        prefix <= 32
    } else {
        false
    }
}

fn is_absolute_path(value: &str) -> bool {
    value.starts_with('/')
}

fn is_semver(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(major) = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    let Some(patch) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    [major, minor, patch]
        .iter()
        .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_media_type(value: &str) -> bool {
    let Some((top, sub)) = value.split_once('/') else {
        return false;
    };
    is_non_empty(top) && is_non_empty(sub)
}

fn is_hour_minute(value: &str) -> bool {
    if value.len() != 5 || value.as_bytes()[2] != b':' {
        return false;
    }
    let Ok(hour) = value[0..2].parse::<u8>() else {
        return false;
    };
    let Ok(minute) = value[3..5].parse::<u8>() else {
        return false;
    };
    hour <= 23 && minute <= 59
}
