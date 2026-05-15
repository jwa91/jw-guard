/// Construction error for statically invalid core values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuardError {
    /// A required field was empty.
    Empty { field: &'static str },
    /// A field did not match its required format.
    Invalid { field: &'static str },
    /// A numeric field was outside its permitted range.
    OutOfRange { field: &'static str },
    /// A required non-empty sequence had no elements.
    EmptySequence { field: &'static str },
    /// A static cross-field invariant was violated.
    Invariant { field: &'static str },
}

/// Result alias used by constructors in the pure core crate.
pub type GuardResult<T> = core::result::Result<T, GuardError>;
