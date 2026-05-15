/// Construction error for statically invalid declaration-layer values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeclareError {
    /// A required field was empty.
    Empty { field: &'static str },
    /// A field did not match its required declaration format.
    Invalid { field: &'static str },
    /// A static cross-field invariant was violated.
    Invariant { field: &'static str },
}

/// Result alias used by declaration constructors.
pub type DeclareResult<T> = core::result::Result<T, DeclareError>;
