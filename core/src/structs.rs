use alloc::vec::Vec;

use crate::{
    enums::{
        BindScope, Cadence, Capability, CredentialMechanism, CredentialStrength, DayOfWeek,
        FailMode, GateVerdict, IdentityKind, IsolationMechanism, LayerHardness, LayerMechanism,
        Protocol, SurfaceFacing, TrustBasis, TrustLevel, VerificationKind, ZoneKind,
    },
    error::{GuardError, GuardResult},
    id::{
        BoundaryId, CredentialId, GateId, IdentityId, LayerId, RouteId, ScopeId, SurfaceId,
        TrustId, ZoneId,
    },
    scalars::{
        AbsolutePath, DisplayName, GateSequence, Hostname, HourMinute, KeyFingerprint, NonEmptyVec,
        Port, Rate, UtcTimestamp, ZonePurpose,
    },
};

/// One side of a boundary.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BoundaryEnd {
    /// A zone inside the model.
    Zone(ZoneId),
    /// The world outside the model.
    Outside,
}

/// A bounded execution domain with a declared purpose.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Zone {
    /// Zone identifier.
    pub id: ZoneId,
    /// Zone category.
    pub kind: ZoneKind,
    /// One-sentence scope declaration.
    pub purpose: ZonePurpose,
    /// Trust level assigned to this zone.
    pub trust_level: TrustLevel,
    /// Concrete isolation mechanism.
    pub isolation: IsolationMechanism,
    /// Filesystem roots owned by this zone.
    pub filesystem_roots: NonEmptyVec<AbsolutePath>,
    /// Creation timestamp.
    pub created_at: UtcTimestamp,
}

impl Zone {
    /// Creates a zone and checks static zone invariants.
    pub fn new(
        id: ZoneId,
        kind: ZoneKind,
        purpose: ZonePurpose,
        trust_level: TrustLevel,
        isolation: IsolationMechanism,
        filesystem_roots: NonEmptyVec<AbsolutePath>,
        created_at: UtcTimestamp,
    ) -> GuardResult<Self> {
        if matches!(kind, ZoneKind::Signing)
            && !matches!(
                isolation,
                IsolationMechanism::Vm | IsolationMechanism::Physical
            )
        {
            return Err(GuardError::Invariant {
                field: "zone.signing_isolation",
            });
        }
        if matches!(kind, ZoneKind::Quarantine) && trust_level != TrustLevel::Untrusted {
            return Err(GuardError::Invariant {
                field: "zone.quarantine_trust_level",
            });
        }
        Ok(Self {
            id,
            kind,
            purpose,
            trust_level,
            isolation,
            filesystem_roots,
            created_at,
        })
    }
}

/// Interface between two adjacent zones, or a zone and the outside world.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Boundary {
    /// Boundary identifier.
    pub id: BoundaryId,
    /// Canonical side A, normally the higher-trust side.
    pub side_a: BoundaryEnd,
    /// Canonical side B, normally the lower-trust side or outside.
    pub side_b: BoundaryEnd,
}

impl Boundary {
    /// Creates a boundary and checks static boundary invariants.
    pub fn new(id: BoundaryId, side_a: BoundaryEnd, side_b: BoundaryEnd) -> GuardResult<Self> {
        if side_a == side_b {
            return Err(GuardError::Invariant {
                field: "boundary.distinct_sides",
            });
        }
        if matches!(
            (side_a, side_b),
            (BoundaryEnd::Outside, BoundaryEnd::Outside)
        ) {
            return Err(GuardError::Invariant {
                field: "boundary.zone_required",
            });
        }
        Ok(Self { id, side_a, side_b })
    }
}

/// Network listener visible through a surface.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ListenerExposure {
    /// Exposed port.
    pub port: Port,
    /// Exposed protocol.
    pub protocol: Protocol,
    /// Bind reachability.
    pub bind_scope: BindScope,
}

/// Exposed face of a boundary as seen from one side.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Surface {
    /// Surface identifier.
    pub id: SurfaceId,
    /// Referenced boundary.
    pub boundary_id: BoundaryId,
    /// Side this surface faces toward.
    pub facing: SurfaceFacing,
    /// Filesystem paths visible across this boundary.
    pub exposed_paths: Vec<AbsolutePath>,
    /// Network listeners visible across this boundary.
    pub exposed_listeners: Vec<ListenerExposure>,
    /// Capabilities reachable through this boundary face.
    pub exposed_capabilities: Vec<Capability>,
}

/// Protection mechanism applied to a boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Layer {
    /// Layer identifier.
    pub id: LayerId,
    /// Referenced boundary.
    pub boundary_id: BoundaryId,
    /// Protection mechanism.
    pub mechanism: LayerMechanism,
    /// Protection hardness.
    pub hardness: LayerHardness,
    /// Failure behavior.
    pub fail_mode: FailMode,
    /// Whether this layer is currently active.
    pub enforced: bool,
    /// Last verification timestamp.
    pub verified_at: Option<UtcTimestamp>,
}

/// Sanctioned one-way path for artifacts or data to cross a boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Route {
    /// Route identifier.
    pub id: RouteId,
    /// Source boundary end.
    pub from_zone: BoundaryEnd,
    /// Destination boundary end.
    pub to_zone: BoundaryEnd,
    /// Referenced boundary.
    pub boundary_id: BoundaryId,
    /// Transfer cadence.
    pub cadence: Cadence,
    /// Whether this route can currently carry transfers.
    pub enabled: bool,
    /// Declaration timestamp.
    pub declared_at: UtcTimestamp,
    /// Identity that declared the route.
    pub declared_by: IdentityId,
}

/// Directional route endpoints.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RouteEndpoints {
    /// Source boundary end.
    pub from: BoundaryEnd,
    /// Destination boundary end.
    pub to: BoundaryEnd,
}

impl RouteEndpoints {
    /// Creates directional endpoints and checks static endpoint invariants.
    pub fn new(from: BoundaryEnd, to: BoundaryEnd) -> GuardResult<Self> {
        if from == to {
            return Err(GuardError::Invariant {
                field: "route.distinct_ends",
            });
        }
        if matches!((from, to), (BoundaryEnd::Outside, BoundaryEnd::Outside)) {
            return Err(GuardError::Invariant {
                field: "route.zone_required",
            });
        }
        Ok(Self { from, to })
    }
}

/// Declaration attribution metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeclarationMetadata {
    /// Declaration timestamp.
    pub declared_at: UtcTimestamp,
    /// Declaring identity.
    pub declared_by: IdentityId,
}

impl Route {
    /// Creates a route and checks static route invariants.
    pub fn new(
        id: RouteId,
        endpoints: RouteEndpoints,
        boundary_id: BoundaryId,
        cadence: Cadence,
        enabled: bool,
        declaration: DeclarationMetadata,
    ) -> GuardResult<Self> {
        Ok(Self {
            id,
            from_zone: endpoints.from,
            to_zone: endpoints.to,
            boundary_id,
            cadence,
            enabled,
            declared_at: declaration.declared_at,
            declared_by: declaration.declared_by,
        })
    }
}

/// Checkpoint on a route where a verification decision is made.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Gate {
    /// Gate identifier.
    pub id: GateId,
    /// Referenced route.
    pub route_id: RouteId,
    /// Evaluation sequence.
    pub sequence: GateSequence,
    /// Required verification kinds.
    pub required_verifications: NonEmptyVec<VerificationKind>,
    /// Current gate verdict.
    pub verdict: GateVerdict,
}

/// Acting security principal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Identity {
    /// Identity identifier.
    pub id: IdentityId,
    /// Identity category.
    pub kind: IdentityKind,
    /// Display name.
    pub display_name: DisplayName,
    /// Zone this identity is bound to, if any.
    pub bound_to_zone: Option<ZoneId>,
    /// Whether this identity can gain higher privilege.
    pub can_escalate: bool,
    /// Creation timestamp.
    pub created_at: UtcTimestamp,
}

impl Identity {
    /// Creates an identity and checks static identity invariants.
    pub fn new(
        id: IdentityId,
        kind: IdentityKind,
        display_name: DisplayName,
        bound_to_zone: Option<ZoneId>,
        can_escalate: bool,
        created_at: UtcTimestamp,
    ) -> GuardResult<Self> {
        match kind {
            IdentityKind::ZoneAdmin | IdentityKind::Service if bound_to_zone.is_none() => {
                return Err(GuardError::Invariant {
                    field: "identity.bound_to_zone",
                });
            }
            IdentityKind::Root if bound_to_zone.is_some() || can_escalate => {
                return Err(GuardError::Invariant {
                    field: "identity.root",
                });
            }
            IdentityKind::ZoneAdmin if can_escalate => {
                return Err(GuardError::Invariant {
                    field: "identity.zone_admin_escalation",
                });
            }
            _ => {}
        }
        Ok(Self {
            id,
            kind,
            display_name,
            bound_to_zone,
            can_escalate,
            created_at,
        })
    }
}

/// Bounded permission context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Scope {
    /// Scope identifier.
    pub id: ScopeId,
    /// Zone this scope belongs to.
    pub zone_id: ZoneId,
    /// Operations available within this scope.
    pub capabilities: NonEmptyVec<Capability>,
    /// Restrictions that narrow those capabilities.
    pub constraints: Vec<ScopeConstraint>,
}

/// Restriction that narrows a scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "kind"))]
pub enum ScopeConstraint {
    /// Restricts operations to filesystem paths.
    PathRestricted {
        /// Allowed paths.
        paths: NonEmptyVec<AbsolutePath>,
    },
    /// Restricts operations to network ports.
    PortRestricted {
        /// Allowed ports.
        ports: NonEmptyVec<Port>,
    },
    /// Restricts operations to hostnames.
    HostRestricted {
        /// Allowed hosts.
        hosts: NonEmptyVec<Hostname>,
    },
    /// Restricts operations to UTC time windows.
    TimeRestricted {
        /// Allowed windows.
        windows: NonEmptyVec<TimeWindow>,
    },
    /// Restricts operations by hourly rate.
    RateLimited {
        /// Maximum events per hour.
        max_per_hour: Rate,
    },
}

/// UTC time window used by a scope constraint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TimeWindow {
    /// Day of week.
    pub day_of_week: DayOfWeek,
    /// Start time in UTC.
    pub start_utc: HourMinute,
    /// End time in UTC.
    pub end_utc: HourMinute,
}

/// Proof material bound to an identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Credential {
    /// Credential identifier.
    pub id: CredentialId,
    /// Identity this credential authenticates.
    pub identity_id: IdentityId,
    /// Credential mechanism.
    pub mechanism: CredentialMechanism,
    /// Credential strength.
    pub strength: CredentialStrength,
    /// Key fingerprint when this is a key-like credential.
    pub fingerprint: Option<KeyFingerprint>,
    /// Expiration timestamp.
    pub expires_at: Option<UtcTimestamp>,
    /// Last rotation timestamp.
    pub rotated_at: UtcTimestamp,
    /// Zone where this credential is stored.
    pub stored_in: ZoneId,
}

/// Identity and storage binding for a credential.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CredentialBinding {
    /// Identity this credential authenticates.
    pub identity_id: IdentityId,
    /// Zone where this credential is stored.
    pub stored_in: ZoneId,
}

/// Mechanism and evidence carried by a credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CredentialMaterial {
    /// Credential mechanism.
    pub mechanism: CredentialMechanism,
    /// Credential strength.
    pub strength: CredentialStrength,
    /// Key fingerprint when this is a key-like credential.
    pub fingerprint: Option<KeyFingerprint>,
}

/// Rotation and expiry metadata for a credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CredentialLifecycle {
    /// Expiration timestamp.
    pub expires_at: Option<UtcTimestamp>,
    /// Last rotation timestamp.
    pub rotated_at: UtcTimestamp,
}

impl Credential {
    /// Creates a credential and checks static credential invariants.
    pub fn new(
        id: CredentialId,
        binding: CredentialBinding,
        material: CredentialMaterial,
        lifecycle: CredentialLifecycle,
    ) -> GuardResult<Self> {
        if matches!(material.mechanism, CredentialMechanism::PasswordOffline)
            && material.strength != CredentialStrength::PrimaryHardware
        {
            return Err(GuardError::Invariant {
                field: "credential.password_offline_strength",
            });
        }
        if matches!(material.mechanism, CredentialMechanism::Biometric)
            && material.strength != CredentialStrength::Secondary
        {
            return Err(GuardError::Invariant {
                field: "credential.biometric_strength",
            });
        }
        if matches!(material.strength, CredentialStrength::Ephemeral)
            && lifecycle.expires_at.is_none()
        {
            return Err(GuardError::Invariant {
                field: "credential.ephemeral_expiry",
            });
        }
        Ok(Self {
            id,
            identity_id: binding.identity_id,
            mechanism: material.mechanism,
            strength: material.strength,
            fingerprint: material.fingerprint,
            expires_at: lifecycle.expires_at,
            rotated_at: lifecycle.rotated_at,
            stored_in: binding.stored_in,
        })
    }
}

/// Explicit identity-to-scope trust relationship.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Trust {
    /// Trust identifier.
    pub id: TrustId,
    /// Trusted identity.
    pub identity_id: IdentityId,
    /// Scope in which the identity is trusted.
    pub scope_id: ScopeId,
    /// Reason this trust exists.
    pub basis: TrustBasis,
    /// Granting identity.
    pub granted_by: IdentityId,
    /// Grant timestamp.
    pub granted_at: UtcTimestamp,
    /// Expiration timestamp.
    pub expires_at: Option<UtcTimestamp>,
    /// Minimum credential strength required to activate this trust.
    pub requires_credential: CredentialStrength,
    /// Whether this trust is currently active.
    pub active: bool,
}

/// Identity, scope, and grantor participating in a trust grant.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrustParties {
    /// Trusted identity.
    pub identity_id: IdentityId,
    /// Scope in which the identity is trusted.
    pub scope_id: ScopeId,
    /// Granting identity.
    pub granted_by: IdentityId,
}

/// Reason, timing, and activation requirements for a trust grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrustGrant {
    /// Reason this trust exists.
    pub basis: TrustBasis,
    /// Grant timestamp.
    pub granted_at: UtcTimestamp,
    /// Expiration timestamp.
    pub expires_at: Option<UtcTimestamp>,
    /// Minimum credential strength required to activate this trust.
    pub requires_credential: CredentialStrength,
    /// Whether this trust is currently active.
    pub active: bool,
}

impl Trust {
    /// Creates a trust grant and checks static trust invariants.
    pub fn new(id: TrustId, parties: TrustParties, grant: TrustGrant) -> GuardResult<Self> {
        if grant.requires_credential < CredentialStrength::PrimarySoftware {
            return Err(GuardError::Invariant {
                field: "trust.requires_credential",
            });
        }
        if parties.identity_id == parties.granted_by && grant.basis != TrustBasis::SystemBootstrap {
            return Err(GuardError::Invariant {
                field: "trust.self_grant",
            });
        }
        Ok(Self {
            id,
            identity_id: parties.identity_id,
            scope_id: parties.scope_id,
            basis: grant.basis,
            granted_by: parties.granted_by,
            granted_at: grant.granted_at,
            expires_at: grant.expires_at,
            requires_credential: grant.requires_credential,
            active: grant.active,
        })
    }
}
