#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod concretise;
pub mod declaration;
pub mod error;
pub mod name;
pub mod requirement;
pub mod scope;
pub mod validation;

pub use concretise::*;
pub use declaration::*;
pub use error::*;
pub use name::*;
pub use requirement::*;
pub use scope::*;
pub use validation::*;

#[cfg(test)]
mod tests;
