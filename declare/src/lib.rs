#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod concretise;
pub mod error;
pub mod name;
pub mod spec;
pub mod validation;

pub use concretise::*;
pub use error::*;
pub use name::*;
pub use spec::*;
pub use validation::*;
