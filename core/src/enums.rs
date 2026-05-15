/// Bounded execution domain category.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum ZoneKind {
    /// Credential and key custody zone.
    Identity,
    /// Read-only witness and log aggregation zone.
    Audit,
    /// Untrusted artifact intake zone.
    Quarantine,
    /// Source authoring and local runtime zone.
    Dev,
    /// Deterministic compilation and test execution zone.
    Build,
    /// Cryptographic signing operations zone.
    Signing,
    /// Publication zone for external consumers.
    Release,
    /// Deployed service execution zone.
    Runtime,
}

/// Concrete isolation mechanism realizing a zone.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum IsolationMechanism {
    /// Separate POSIX user and filesystem ACL boundary.
    UserAccount,
    /// Host sandbox profile such as sandbox-exec, AppArmor, or SELinux.
    SandboxProfile,
    /// Full hypervisor-backed virtual machine.
    Vm,
    /// Namespace and cgroup isolation.
    Container,
    /// Separate hardware or physical custody boundary.
    Physical,
}

/// Relative trust assigned to a zone or trust context.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[repr(u8)]
pub enum TrustLevel {
    /// No trust should be assumed.
    Untrusted = 0,
    /// Low trust for constrained activity.
    Low = 1,
    /// Standard trust for ordinary controlled work.
    Standard = 2,
    /// High trust for sensitive work.
    High = 3,
    /// Critical trust for root, custody, and signing boundaries.
    Critical = 4,
}

/// Directional face of a boundary.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SurfaceFacing {
    /// Surface facing boundary side A.
    #[cfg_attr(feature = "serde", serde(rename = "a"))]
    A,
    /// Surface facing boundary side B.
    #[cfg_attr(feature = "serde", serde(rename = "b"))]
    B,
}

/// Network bind reachability visible through a surface.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum BindScope {
    /// Listener bound only to loopback.
    Loopback,
    /// Listener bound to zone-local interfaces.
    ZoneLocal,
    /// Listener bound to host interfaces.
    Host,
    /// Listener publicly reachable.
    Public,
}

/// Network protocol for low-level listeners and routes.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

/// Protection mechanism applied to a boundary.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum LayerMechanism {
    /// Packet filter such as pf, iptables, or nftables.
    PacketFilter,
    /// Application-level outbound filtering proxy.
    EgressProxy,
    /// Mandatory access control such as SELinux, AppArmor, or macOS sandbox.
    MandatoryAccessControl,
    /// Capability or entitlement restriction.
    CapabilityRestriction,
    /// Code-signing enforcement such as Gatekeeper.
    CodeSigningEnforcement,
    /// Filesystem ACL or extended attribute control.
    FilesystemAcl,
    /// Volume encryption such as FileVault or LUKS.
    VolumeEncryption,
    /// Integrity protection such as SIP or dm-verity.
    IntegrityProtection,
    /// Separate UID/GID or account boundary.
    UserSeparation,
    /// Privilege boundary such as no-sudo enforcement or capability drop.
    PrivilegeBoundary,
    /// Consent gate such as TCC, polkit, or UAC.
    ConsentGate,
    /// Hypervisor-backed virtual machine boundary.
    Hypervisor,
    /// Namespace isolation such as containers.
    NamespaceIsolation,
    /// Air gap or separate physical device.
    PhysicalSeparation,
}

/// Protection hardness ordered from soft application controls to physical separation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum LayerHardness {
    /// Process or application-level controls.
    #[cfg_attr(feature = "serde", serde(rename = "H1"))]
    H1 = 1,
    /// User boundary or privilege separation.
    #[cfg_attr(feature = "serde", serde(rename = "H2"))]
    H2 = 2,
    /// Host-level kernel policy.
    #[cfg_attr(feature = "serde", serde(rename = "H3"))]
    H3 = 3,
    /// Virtual machine or kernel separation.
    #[cfg_attr(feature = "serde", serde(rename = "H4"))]
    H4 = 4,
    /// Air gap or physical separation.
    #[cfg_attr(feature = "serde", serde(rename = "H5"))]
    H5 = 5,
}

/// How a control behaves when it cannot evaluate.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum FailMode {
    /// Deny when evaluation fails or state is unknown.
    FailClosed,
    /// Permit when evaluation fails or state is unknown.
    FailOpen,
}

/// Route transfer cadence.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum Cadence {
    /// Source initiates transfer.
    Push,
    /// Destination polls for artifacts.
    Pull,
    /// Manual deposit through root-arbitrated staging.
    Airlock,
}

/// Verification kind required by a gate.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum VerificationKind {
    /// Artifact hash matches a manifest.
    HashIntegrity,
    /// Cryptographic signature verifies.
    SignatureValidity,
    /// Provenance chain from source to artifact verifies.
    ProvenanceChain,
    /// Behavioral or malware content scan passes.
    ContentScan,
    /// Explicit human review and sign-off exists.
    HumanApproval,
    /// Artifact matches its route artifact contract.
    ContractConformance,
    /// Caller proves the claimed identity.
    IdentityAuthentication,
}

/// Current gate decision.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum GateVerdict {
    /// Passage is permitted.
    Permit,
    /// Passage is denied.
    Deny,
    /// Passage has not yet been evaluated.
    Pending,
}

/// Principal category.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum IdentityKind {
    /// Floor-level system administrator.
    Root,
    /// Scoped operator of exactly one zone.
    ZoneAdmin,
    /// Automated process identity.
    Service,
    /// Read-only observer.
    Auditor,
}

/// Atomic operation that may be present in a scope.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Capability {
    /// Read filesystem data.
    #[cfg_attr(feature = "serde", serde(rename = "fs:read"))]
    FsRead,
    /// Write filesystem data.
    #[cfg_attr(feature = "serde", serde(rename = "fs:write"))]
    FsWrite,
    /// Execute filesystem data.
    #[cfg_attr(feature = "serde", serde(rename = "fs:execute"))]
    FsExecute,
    /// Listen on a network port.
    #[cfg_attr(feature = "serde", serde(rename = "net:listen"))]
    NetListen,
    /// Connect to an outbound network endpoint.
    #[cfg_attr(feature = "serde", serde(rename = "net:connect-outbound"))]
    NetConnectOutbound,
    /// Accept inbound network connections.
    #[cfg_attr(feature = "serde", serde(rename = "net:accept-inbound"))]
    NetAcceptInbound,
    /// Spawn a process.
    #[cfg_attr(feature = "serde", serde(rename = "proc:spawn"))]
    ProcSpawn,
    /// Signal a process.
    #[cfg_attr(feature = "serde", serde(rename = "proc:signal"))]
    ProcSignal,
    /// Inspect a process.
    #[cfg_attr(feature = "serde", serde(rename = "proc:inspect"))]
    ProcInspect,
    /// Create a cryptographic signature.
    #[cfg_attr(feature = "serde", serde(rename = "crypto:sign"))]
    CryptoSign,
    /// Verify a cryptographic signature.
    #[cfg_attr(feature = "serde", serde(rename = "crypto:verify"))]
    CryptoVerify,
    /// Encrypt data.
    #[cfg_attr(feature = "serde", serde(rename = "crypto:encrypt"))]
    CryptoEncrypt,
    /// Decrypt data.
    #[cfg_attr(feature = "serde", serde(rename = "crypto:decrypt"))]
    CryptoDecrypt,
    /// Generate cryptographic keys.
    #[cfg_attr(feature = "serde", serde(rename = "crypto:generate-key"))]
    CryptoGenerateKey,
    /// Propose a route transfer.
    #[cfg_attr(feature = "serde", serde(rename = "route:propose-transfer"))]
    RouteProposeTransfer,
    /// Approve a route transfer.
    #[cfg_attr(feature = "serde", serde(rename = "route:approve-transfer"))]
    RouteApproveTransfer,
    /// Execute a route transfer.
    #[cfg_attr(feature = "serde", serde(rename = "route:execute-transfer"))]
    RouteExecuteTransfer,
    /// Declare a zone.
    #[cfg_attr(feature = "serde", serde(rename = "zone:declare"))]
    ZoneDeclare,
    /// Modify a zone.
    #[cfg_attr(feature = "serde", serde(rename = "zone:modify"))]
    ZoneModify,
    /// Destroy a zone.
    #[cfg_attr(feature = "serde", serde(rename = "zone:destroy"))]
    ZoneDestroy,
    /// Read an audit log.
    #[cfg_attr(feature = "serde", serde(rename = "audit:read-log"))]
    AuditReadLog,
    /// Write an audit event.
    #[cfg_attr(feature = "serde", serde(rename = "audit:write-event"))]
    AuditWriteEvent,
    /// Verify an audit hash chain.
    #[cfg_attr(feature = "serde", serde(rename = "audit:verify-chain"))]
    AuditVerifyChain,
}

impl Capability {
    /// Returns true when this capability belongs to the audit family.
    pub const fn is_audit(self) -> bool {
        matches!(
            self,
            Self::AuditReadLog | Self::AuditWriteEvent | Self::AuditVerifyChain
        )
    }
}

/// Day-of-week selector for time restricted scopes.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum DayOfWeek {
    /// Monday.
    Mon,
    /// Tuesday.
    Tue,
    /// Wednesday.
    Wed,
    /// Thursday.
    Thu,
    /// Friday.
    Fri,
    /// Saturday.
    Sat,
    /// Sunday.
    Sun,
}

/// Credential mechanism.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum CredentialMechanism {
    /// Offline password stored on physical media or in a vault.
    PasswordOffline,
    /// FIDO2 resident hardware key.
    HardwareKeyFido2,
    /// Secure Enclave-bound key.
    HardwareKeySecureEnclave,
    /// SSH key backed by a hardware token.
    SshKeyHardware,
    /// SSH key stored in software.
    SshKeySoftware,
    /// Scoped token such as a PAT, API token, or session token.
    TokenScoped,
    /// Biometric factor that must augment a primary factor.
    Biometric,
    /// X.509 certificate.
    CertificateX509,
}

/// Credential strength ordered by standalone authentication strength.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[repr(u8)]
pub enum CredentialStrength {
    /// Secondary factor that cannot activate trust alone.
    Secondary = 0,
    /// Short-lived token that expires automatically.
    Ephemeral = 1,
    /// Software-stored primary credential.
    PrimarySoftware = 2,
    /// Hardware-bound primary credential.
    PrimaryHardware = 3,
}

/// Reason a trust grant exists.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum TrustBasis {
    /// Identity was assigned a role.
    RoleAssignment,
    /// Identity presented a valid credential.
    CredentialPresentation,
    /// Another trusted identity delegated authority.
    Delegation,
    /// Trust was established during system bootstrap.
    SystemBootstrap,
}

/// Lifecycle status of a route policy.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum PolicyStatus {
    /// Policy is being authored.
    Draft,
    /// Policy is currently enforced.
    Active,
    /// Policy remains readable but should be replaced.
    Deprecated,
    /// Policy is no longer valid.
    Retired,
}

/// Transfer workflow state.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum TransferState {
    /// Transfer has been proposed.
    Proposed,
    /// Intake checks passed.
    IntakeValidated,
    /// Verification is running.
    VerificationRunning,
    /// A human approval gate is waiting.
    AwaitingHumanApproval,
    /// Transfer is approved.
    Approved,
    /// Transfer is rejected.
    Rejected,
    /// Artifact has been promoted.
    Promoted,
    /// Transfer is archived and terminal.
    Archived,
}

/// Accepted or rejected route decision.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum RouteDecision {
    /// Route transfer was accepted.
    Accepted,
    /// Route transfer was rejected.
    Rejected,
}

/// Runtime policy service identity.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum ServiceId {
    /// Authorizes commands from model and policy.
    PolicyEngine,
    /// Runs hash, signature, and scan checks.
    VerificationEngine,
    /// Enforces quarantine promotion and rejection workflow.
    QuarantineGate,
    /// Performs allowed one-way transfers.
    RouteExecutor,
    /// Persists transfer aggregates and events.
    WorkflowStore,
    /// Maps workflow events into floor audit events.
    AuditBridge,
    /// Publishes signed zone and route declarations.
    ZoneRegistry,
}

/// Runtime mode of a policy service.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum ServiceMode {
    /// Service is fully active.
    Active,
    /// Service is degraded but still partially useful.
    Degraded,
    /// Service is read-only.
    ReadOnly,
    /// Service is offline.
    Offline,
}

/// Strict policy object category.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum PolicyType {
    /// Firewall policy.
    Firewall,
    /// Isolation policy.
    Isolation,
    /// Scoped rights policy.
    ScopedRights,
    /// Traceability policy.
    Traceability,
    /// Storage protection policy.
    Storage,
    /// Patch management policy.
    Patch,
    /// Exception policy.
    Exception,
    /// Observability policy.
    Observability,
    /// Route control policy.
    RouteControl,
}

/// Review cadence for governed policies.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum ReviewRate {
    /// Review every week.
    Weekly,
    /// Review every two weeks.
    Biweekly,
    /// Review every month.
    Monthly,
    /// Review every quarter.
    Quarterly,
}

/// Severity for controls and findings.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum Severity {
    /// Critical impact.
    Critical,
    /// High impact.
    High,
    /// Medium impact.
    Medium,
    /// Low impact.
    Low,
}

/// Schema layer gate status.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum LayerGateStatus {
    /// Promotion to this layer is blocked.
    Blocked,
    /// Promotion to this layer is ready.
    Ready,
}

/// Strict schema layer name.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum LayerName {
    /// Manifest layer.
    L0Manifest,
    /// Atomic type layer.
    L1Atoms,
    /// Structural object layer.
    L2Structural,
    /// Policy value envelope layer.
    L3PolicyValues,
    /// Policy object layer.
    L4PolicyObjects,
    /// Scoped environment layer.
    L5ScopeEnvironments,
    /// Enforcement layer.
    L6Enforcement,
    /// Observability layer.
    L7Observability,
    /// Governance layer.
    L8Governance,
}

/// Outside-world destination class.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum OutsideWorldClass {
    /// Tailscale control plane.
    TailscaleControl,
    /// Operating system update endpoint.
    OsUpdate,
    /// Time synchronization endpoint.
    TimeSync,
    /// Source hosting endpoint.
    SourceHosting,
    /// Package registry endpoint.
    PackageRegistry,
    /// Notarization endpoint.
    Notarization,
    /// Public release endpoint.
    PublicRelease,
    /// Blocked or unclassified endpoint.
    Blocked,
}

/// External edge protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum ExternalProtocol {
    /// TCP transport.
    Tcp,
    /// UDP transport.
    Udp,
    /// HTTPS over TCP.
    Https,
}

/// Default action for an external edge policy.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum DefaultAction {
    /// Allow by default for this declared edge.
    Allow,
    /// Deny by default for this declared edge.
    Deny,
}
