//! Layer-0 atomic type surface.
//!
//! L0 is intentionally minimal: only irreducible primitive atoms.
//! No composed security/domain types are exposed at this layer.

/// Marker trait for Layer-0 primitive atoms.
pub trait L0Atom: Copy + 'static {}

impl L0Atom for () {}
impl L0Atom for bool {}
impl L0Atom for char {}

impl L0Atom for u8 {}
impl L0Atom for u16 {}
impl L0Atom for u32 {}
impl L0Atom for u64 {}
impl L0Atom for u128 {}

impl L0Atom for i8 {}
impl L0Atom for i16 {}
impl L0Atom for i32 {}
impl L0Atom for i64 {}
impl L0Atom for i128 {}

impl L0Atom for f32 {}
impl L0Atom for f64 {}

/// Deterministic list of all stable L0 atom names exposed by this crate.
pub const L0_ATOM_NAMES: &[&str] = &[
    "()",
    "bool",
    "char",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "f32",
    "f64",
];

