#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::ToString;

use jw_guard_core::{CanonicalName, SemVer};

pub mod referent_sort {
    pub const SERVICE: &str = "service";
    pub const NETWORK: &str = "network";
    pub const VOLUME: &str = "volume";
    pub const IMAGE: &str = "image";
}

pub mod property {
    pub const PRIVILEGED: &str = "privileged";
    pub const IMAGE: &str = "image";
    pub const IMAGE_TAG: &str = "image_tag";
    pub const USER: &str = "user";
    pub const HEALTHCHECK: &str = "healthcheck";
    pub const CAP_ADD: &str = "cap_add";
}

#[must_use]
pub const fn vocabulary_version() -> SemVer {
    SemVer::new(0, 1, 0)
}

#[must_use]
pub fn canonical_name(value: &str) -> CanonicalName {
    CanonicalName::new(value.to_string()).expect("docker vocabulary constants must be canonical")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_vocabulary_names_are_canonical() {
        let names = [
            referent_sort::SERVICE,
            referent_sort::NETWORK,
            referent_sort::VOLUME,
            referent_sort::IMAGE,
            property::PRIVILEGED,
            property::IMAGE,
            property::IMAGE_TAG,
            property::USER,
            property::HEALTHCHECK,
            property::CAP_ADD,
        ];

        for name in names {
            assert_eq!(canonical_name(name).as_str(), name);
        }
    }
}
