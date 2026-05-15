#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod composites;
pub mod enums;
pub mod error;
pub mod id;
pub mod scalars;
pub mod structs;
pub mod validation;

#[cfg(test)]
mod tests;

pub use composites::*;
pub use enums::*;
pub use error::*;
pub use id::*;
pub use scalars::*;
pub use structs::*;
pub use validation::*;
