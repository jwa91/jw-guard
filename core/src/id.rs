use core::fmt;

macro_rules! define_id {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name([u8; 16]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(self) -> [u8; 16] {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(", stringify!($name))?;
                for byte in self.0 {
                    write!(f, "{:02x}", byte)?;
                }
                write!(f, ")")
            }
        }
    };
}

define_id!(ModelId);
define_id!(ActorId);
define_id!(ReferentId);
define_id!(BoundaryId);
define_id!(SideId);
define_id!(SurfaceId);
define_id!(EdgeId);
define_id!(ScopeId);
define_id!(RequirementId);
define_id!(PolicyId);
define_id!(ClaimId);
define_id!(EvidenceId);
define_id!(SourceId);
define_id!(EvaluationId);
define_id!(RevisionId);
define_id!(PredicateId);

