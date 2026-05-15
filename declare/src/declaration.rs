use alloc::vec::Vec;

use jw_guard_core::{
    composites::{ArtifactContract, TrustRequirement},
    enums::{Cadence, Capability, FailMode, LayerMechanism, VerificationKind, ZoneKind},
    scalars::{AbsolutePath, GateSequence, NonEmptyVec, SemVer, UtcTimestamp, ZonePurpose},
};

use crate::{
    name::{DeclarationName, Label},
    requirement::{HardnessRequirement, PresenceRequirement},
    scope::{ScopeKind, ScopeTarget},
};

/// Complete first-principles requirement declaration.
///
/// This is not the canonical core graph. It is the normative source of intent:
/// symbolic names, minimum requirements, and scope kinds that later mappers can
/// evaluate observations against.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SecurityDeclaration {
    /// Declaration schema version.
    pub declaration_version: SemVer,
    /// Zones named by this declaration.
    pub zones: Vec<ZoneDeclaration>,
    /// Boundaries named by this declaration.
    pub boundaries: Vec<BoundaryDeclaration>,
    /// Scope requirements named by this declaration.
    pub scopes: Vec<ScopeDeclaration>,
    /// Routes named by this declaration.
    pub routes: Vec<RouteDeclaration>,
    /// Route policies named by this declaration.
    pub route_policies: Vec<RoutePolicyDeclaration>,
}

/// Declared zone requirement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ZoneDeclaration {
    /// Stable symbolic zone name.
    pub name: DeclarationName,
    /// Optional human label.
    pub label: Option<Label>,
    /// Zone category from the core vocabulary.
    pub kind: ZoneKind,
    /// One-sentence scope declaration.
    pub purpose: ZonePurpose,
    /// Required trust level for this zone.
    pub trust_level: jw_guard_core::enums::TrustLevel,
    /// Required isolation mechanism for this zone.
    pub isolation: jw_guard_core::enums::IsolationMechanism,
    /// Filesystem roots this zone must own.
    pub filesystem_roots: NonEmptyVec<AbsolutePath>,
}

/// Reference to one end of a declared boundary or route.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "kebab-case", tag = "kind", content = "name")
)]
pub enum BoundaryEndRef {
    /// A declared zone.
    Zone(DeclarationName),
    /// The world outside the declared model.
    Outside,
}

/// Declared boundary requirement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BoundaryDeclaration {
    /// Stable symbolic boundary name.
    pub name: DeclarationName,
    /// Canonical side A, normally the higher-trust side.
    pub side_a: BoundaryEndRef,
    /// Canonical side B, normally the lower-trust side or outside.
    pub side_b: BoundaryEndRef,
    /// Protection mechanism requirements for this boundary.
    pub layer_requirements: Vec<LayerRequirement>,
}

/// Requirement for one protection mechanism on a boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LayerRequirement {
    /// Mechanism being constrained.
    pub mechanism: LayerMechanism,
    /// Whether this mechanism is required, forbidden, or optional.
    pub presence: PresenceRequirement,
    /// Required hardness relation when present.
    pub hardness: Option<HardnessRequirement>,
    /// Required failure behavior when present.
    pub fail_mode: Option<FailMode>,
}

/// Declared evaluation scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScopeDeclaration {
    /// Stable symbolic scope name.
    pub name: DeclarationName,
    /// Real-world observation shape this scope expects.
    pub kind: ScopeKind,
    /// Declaration object this scope constrains.
    pub target: ScopeTarget,
    /// Capabilities that must be available in this scope.
    pub required_capabilities: NonEmptyVec<Capability>,
    /// Capabilities that must not be available in this scope.
    pub forbidden_capabilities: Vec<Capability>,
}

/// Declared route requirement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RouteDeclaration {
    /// Stable symbolic route name.
    pub name: DeclarationName,
    /// Whether this route must exist, must not exist, or is advisory.
    pub presence: PresenceRequirement,
    /// Source end.
    pub from: BoundaryEndRef,
    /// Destination end.
    pub to: BoundaryEndRef,
    /// Boundary the route crosses.
    pub boundary: DeclarationName,
    /// Transfer cadence requirement.
    pub cadence: Cadence,
    /// Whether the declared route is expected to be enabled.
    pub enabled: bool,
}

/// Declared policy controlling a route.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RoutePolicyDeclaration {
    /// Stable symbolic policy name.
    pub name: DeclarationName,
    /// Route this policy constrains.
    pub route: DeclarationName,
    /// Payload contract required for this route.
    pub contract: ArtifactContract,
    /// Gate requirements evaluated in sequence.
    pub gates: NonEmptyVec<GateRequirement>,
    /// Trust required for passage.
    pub required_trust: NonEmptyVec<TrustRequirement>,
    /// Declaration timestamp.
    pub declared_at: UtcTimestamp,
}

/// Declared gate requirement on a route policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GateRequirement {
    /// Evaluation sequence.
    pub sequence: GateSequence,
    /// Required verification kinds.
    pub required_verifications: NonEmptyVec<VerificationKind>,
}
