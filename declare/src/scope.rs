use crate::name::DeclarationName;

/// Real-world observation shape a declaration is intended to constrain.
///
/// This is deliberately separate from `jw_guard_core::Scope`, which is a
/// zone-bound capability set. `ScopeKind` answers "what kind of evidence can
/// satisfy this declaration later?".
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum ScopeKind {
    /// Filesystem roots, mounts, paths, ACLs, and write/read/execute reach.
    Filesystem,
    /// Listeners, egress destinations, bind surfaces, and protocol reach.
    Network,
    /// Process launch, inspect, signal, sandbox, and privilege surfaces.
    Process,
    /// Credential storage, signing material custody, and authentication proof.
    CredentialCustody,
    /// Movement of artifacts or data across a declared route.
    ArtifactFlow,
    /// Audit log production, read visibility, and chain verification.
    AuditStream,
    /// Boundary-facing exposure such as visible paths, listeners, and caps.
    BoundarySurface,
}

/// Declaration object a scope requirement applies to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "kebab-case", tag = "kind", content = "name")
)]
pub enum ScopeTarget {
    /// Requirement applies inside a declared zone.
    Zone(DeclarationName),
    /// Requirement applies to one declared boundary.
    Boundary(DeclarationName),
    /// Requirement applies to one declared route.
    Route(DeclarationName),
}

impl ScopeKind {
    /// Returns true when this scope kind is meaningful for the target kind.
    pub const fn accepts_target(self, target: &ScopeTarget) -> bool {
        match self {
            Self::Filesystem
            | Self::Network
            | Self::Process
            | Self::CredentialCustody
            | Self::AuditStream => matches!(target, ScopeTarget::Zone(_)),
            Self::ArtifactFlow => matches!(target, ScopeTarget::Route(_)),
            Self::BoundarySurface => matches!(target, ScopeTarget::Boundary(_)),
        }
    }
}
