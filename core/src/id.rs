macro_rules! branded_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[repr(transparent)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Creates an id from its branded 128-bit value.
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Returns the branded 128-bit value.
            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// Consumes this id and returns its branded 128-bit value.
            pub const fn into_bytes(self) -> [u8; 16] {
                self.0
            }
        }
    };
}

branded_id! {
    /// Identifier for a bounded execution domain.
    ZoneId
}

branded_id! {
    /// Identifier for an interface between two boundary ends.
    BoundaryId
}

branded_id! {
    /// Identifier for a boundary face visible from one side.
    SurfaceId
}

branded_id! {
    /// Identifier for a protection mechanism applied to a boundary.
    LayerId
}

branded_id! {
    /// Identifier for a sanctioned one-way crossing.
    RouteId
}

branded_id! {
    /// Identifier for a route checkpoint.
    GateId
}

branded_id! {
    /// Identifier for an acting principal.
    IdentityId
}

branded_id! {
    /// Identifier for a bounded permission context.
    ScopeId
}

branded_id! {
    /// Identifier for proof bound to an identity.
    CredentialId
}

branded_id! {
    /// Identifier for an identity-to-scope trust grant.
    TrustId
}

branded_id! {
    /// Identifier for a route policy.
    PolicyId
}

branded_id! {
    /// Identifier for a single access control evaluation.
    DecisionId
}

branded_id! {
    /// Identifier for a proposed or executed transfer workflow.
    TransferId
}

branded_id! {
    /// Identifier for an immutable audit or workflow event.
    EventId
}

branded_id! {
    /// Identifier for a running policy service instance.
    ServiceInstanceId
}

branded_id! {
    /// Identifier for a scoped runtime environment.
    EnvironmentId
}

branded_id! {
    /// Identifier for an outside-world edge policy.
    EdgeId
}

branded_id! {
    /// Identifier for a policy enforcer.
    EnforcerId
}

branded_id! {
    /// Identifier for a schema or policy manifest.
    ManifestId
}

branded_id! {
    /// Identifier for a governed policy exception.
    ExceptionId
}

branded_id! {
    /// Identifier for a human, service, or governance actor.
    ActorId
}

branded_id! {
    /// Identifier for a supply-chain artifact.
    ArtifactId
}
