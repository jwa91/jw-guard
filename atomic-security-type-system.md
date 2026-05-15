# Atomic Security Type System

> **Status:** design draft v0.1
> **Supersedes:** drafts 03 and 10 as type-system authority.
> **Companion to:** 02-zone-model.md (containment model), 05-macos-supply-chain-hardening-map.md (hardness model).

---

## 1. Design Philosophy

This type system starts from a single premise: **security is the typed
restriction of movement across boundaries**. Everything else — identity,
policy, enforcement, governance — exists to decide whether a specific
movement is permitted. If we get the atoms right, the compositions follow
by necessity rather than by convention.

The approach borrows from three traditions. From Unix: the insight that
protection is a property of *boundaries between domains*, not of the
domains themselves — a file's permission bits live on the inode (the
boundary between process and data), not inside the process or the file.
From type theory: the discipline that every value inhabits exactly one
type, every composition is traceable to its atoms, and the type system
itself is the first validator — if it compiles, the structural invariants
hold. From the zone model (draft 02): containment is the safety property
and identity is the attribution property, and containment must be
established *before* identity has meaning.

We define ten atomic types and four fundamental compositions. Nothing
above this layer is specified here. The atoms are irreducible — you
cannot define one in terms of another at the same level. The fundamental
objects are the *first* meaningful compositions: the minimum structure
needed to express a security decision. Everything higher (workflows,
orchestration, governance) builds on these fundamentals but is out of
scope for this document.

---

## 2. Notation Conventions

Types use language-neutral algebraic notation. Read `|` as "or"
(discriminated union), `&` as "and" (intersection/product), `Type[]` as
"ordered sequence of Type". All fields are required unless marked with
`?`. Branded/nominal types use `Opaque<BaseType, Brand>` to prevent
accidental substitution. Nullable fields use `T | Null` explicitly —
this is distinct from optional (`?`). A nullable field must always be
present in the record but may hold `Null`; an optional field may be
absent entirely.

```
Opaque<T, Brand> = T & { readonly __brand: Brand }
```

Enums are closed unless explicitly marked `extensible`. No field ever
accepts an untyped string, untyped number, or open record.

Invariants are classified as **static** (checkable from the type
definition alone) or **semantic** (require cross-referencing other
objects or runtime state). Semantic invariants are marked with `[S]` in
their descriptions. A conforming implementation must enforce static
invariants at parse/construct time and semantic invariants at
write/commit time.

---

## 3. Scalar Foundations

Before atoms, we need the scalars they are built from. These are not
security concepts — they are the measurement units.

```
-- Time
UtcTimestamp    = Opaque<string, "UtcTimestamp">       -- RFC 3339, always UTC
Duration        = Opaque<number, "Duration">           -- seconds, >= 0

-- Cryptographic
Sha256          = Opaque<string, "Sha256">             -- lowercase hex, length 64
Signature       = Opaque<string, "Signature">          -- detached, base64
KeyFingerprint  = Opaque<string, "KeyFingerprint">     -- algorithm-prefixed fingerprint

-- Network
Hostname        = Opaque<string, "Hostname">           -- RFC 1123 hostname or wildcard pattern
Cidr            = Opaque<string, "Cidr">               -- x.x.x.x/n or x:x:.../n
Port            = Opaque<number, "Port">               -- 1..65535
Protocol        = "tcp" | "udp"

-- Filesystem
AbsolutePath    = Opaque<string, "AbsolutePath">       -- starts with /

-- Versioning
SemVer          = Opaque<string, "SemVer">             -- major.minor.patch
```

---

## 4. Atomic Types

### 4.1 Zone

**What it represents:** A bounded execution domain with a declared
purpose. A zone is a container — it defines what exists *inside* it and
what the inside is *for*. A zone says nothing about its relationship to
other zones; that is the job of Boundary and Route.

Think of it as: a Unix namespace + cgroup + chroot in one concept. On
macOS: a user account + sandbox profile + filesystem ACL scope.

```
ZoneId = Opaque<string, "ZoneId">                -- pattern: z-{name}

ZoneKind =
  | "identity"                                    -- credential/key custody
  | "audit"                                       -- log aggregation, read-only witness
  | "quarantine"                                  -- untrusted artifact intake
  | "dev"                                         -- source authoring, local runtime
  | "build"                                       -- deterministic compilation
  | "signing"                                     -- cryptographic signing operations
  | "release"                                     -- publication to external consumers
  | "runtime"                                     -- deployed service execution

IsolationMechanism =
  | "user-account"                                -- separate POSIX user, ACLs
  | "sandbox-profile"                             -- macOS sandbox-exec / AppArmor
  | "vm"                                          -- full hypervisor separation
  | "container"                                   -- namespace + cgroup isolation
  | "physical"                                    -- separate hardware

TrustLevel = "untrusted" | "low" | "standard" | "high" | "critical"

Zone = {
  id:                 ZoneId
  kind:               ZoneKind
  purpose:            Opaque<string, "ZonePurpose">  -- one-sentence scope declaration
  trustLevel:         TrustLevel
  isolation:          IsolationMechanism
  filesystemRoots:    AbsolutePath[]               -- non-empty; paths this zone owns
  createdAt:          UtcTimestamp
}
```

**Invariants:**

1. `filesystemRoots` must be non-empty — a zone without filesystem presence is not realized.
2. No two zones may share any prefix in their `filesystemRoots` — filesystem ownership is exclusive.
3. `id` is globally unique across all zones in a model.
4. A zone of kind `"signing"` must have `isolation` of `"vm"` | `"physical"` — soft isolation is insufficient for signing.
5. A zone of kind `"quarantine"` must have `trustLevel` of `"untrusted"`.

---

### 4.2 Boundary

**What it represents:** The interface between two adjacent zones, or
between a zone and the Outside. A boundary is the *place where
protection happens*. It exists independently of whether anything crosses
it — a boundary with no routes is a wall.

Think of it as: the kernel interface between two namespaces. The inode
that sits between process and file. The DMZ between two network
segments.

```
BoundaryId = Opaque<string, "BoundaryId">        -- pattern: b-{zoneA}-{zoneB}

Outside = { readonly tag: "outside" }             -- the world beyond the model

BoundaryEnd = ZoneId | Outside

Boundary = {
  id:                 BoundaryId
  side_a:             BoundaryEnd                  -- by convention, higher trust
  side_b:             BoundaryEnd                  -- by convention, lower trust or Outside
}
```

**Invariants:**

1. `side_a` and `side_b` must be different — a boundary cannot connect a zone to itself.
2. At most one Boundary exists between any two BoundaryEnds — boundaries are unique pairs.
3. If both sides are zones, the side with higher `trustLevel` is `side_a` (canonical ordering).
4. At least one side must be a ZoneId — there is no boundary between Outside and Outside.

---

### 4.3 Surface

**What it represents:** The exposed face of a boundary *as seen from one
side*. Every boundary has exactly two surfaces — one facing each side.
A surface declares what is visible, reachable, and exposed from a
particular zone's perspective.

Think of it as: what `/proc` shows you from inside a namespace. The set
of syscalls available after seccomp. The network interfaces visible in a
container.

```
SurfaceId = Opaque<string, "SurfaceId">          -- pattern: sf-{boundary}-{facing}

SurfaceFacing = "a" | "b"                        -- which side of the boundary this faces

ListenerExposure = {
  port:               Port
  protocol:           Protocol
  bindScope:          "loopback" | "zone-local" | "host" | "public"
}

Surface = {
  id:                 SurfaceId
  boundaryId:         BoundaryId
  facing:             SurfaceFacing                -- which side this surface faces toward
  exposedPaths:       AbsolutePath[]               -- filesystem paths visible across boundary
  exposedListeners:   ListenerExposure[]           -- network services visible across boundary
  exposedCapabilities: Capability[]                -- what operations are reachable (see §4.8)
}
```

**Invariants:**

1. Every Boundary has exactly two Surfaces — one with `facing: "a"`, one with `facing: "b"`.
2. `exposedPaths` must be a subset of (or empty relative to) the filesystem roots of the zone on the *opposite* side — you expose what belongs to the zone being looked *into*.
3. Surfaces are read-only declarations — they describe what *is* visible, not what *should* be. Policy (§5.1) governs what is *permitted*.

---

### 4.4 Layer

**What it represents:** A protection mechanism applied to a boundary.
Layers are the things that make boundaries *hard*. Multiple layers stack
on a single boundary; each adds a different kind of protection with a
measurable hardness.

Think of it as: one seccomp filter, one AppArmor profile, one firewall
rule set, one VM boundary. On macOS: SIP is a layer, Gatekeeper is a
layer, TCC is a layer, FileVault is a layer.

```
LayerId = Opaque<string, "LayerId">              -- pattern: ly-{boundary}-{mechanism}

LayerMechanism =
  -- Network protection
  | "packet-filter"                               -- pf, iptables, nftables
  | "egress-proxy"                                -- application-level outbound filtering
  -- Process protection
  | "mandatory-access-control"                    -- SELinux, AppArmor, macOS sandbox
  | "capability-restriction"                      -- Linux capabilities, macOS entitlements
  | "code-signing-enforcement"                    -- Gatekeeper, sigcheck
  -- Filesystem protection
  | "filesystem-acl"                              -- POSIX ACL, macOS extended attrs
  | "volume-encryption"                           -- FileVault, LUKS
  | "integrity-protection"                        -- SIP, dm-verity
  -- Identity protection
  | "user-separation"                             -- separate uid/gid
  | "privilege-boundary"                          -- no-sudo enforcement, capability drop
  | "consent-gate"                                -- TCC, polkit, UAC
  -- Isolation protection
  | "hypervisor"                                  -- VM boundary
  | "namespace-isolation"                         -- Linux namespaces, containers
  | "physical-separation"                         -- air gap, separate device

Hardness =
  | "H1"                                          -- process/app-level controls
  | "H2"                                          -- user boundary / privilege separation
  | "H3"                                          -- host-level kernel policy
  | "H4"                                          -- VM / kernel separation
  | "H5"                                          -- air-gap / physical separation

FailMode = "fail-closed" | "fail-open"

Layer = {
  id:                 LayerId
  boundaryId:         BoundaryId
  mechanism:          LayerMechanism
  hardness:           Hardness
  failMode:           FailMode
  enforced:           boolean                      -- is this layer currently active?
  verifiedAt?:        UtcTimestamp                  -- last verification timestamp; absent if never verified
}
```

**Invariants:**

1. `failMode` must be `"fail-closed"` for any layer on a boundary where either side has `trustLevel` of `"high"` or `"critical"`.
2. A layer's `hardness` must be consistent with its `mechanism` — e.g., `"hypervisor"` cannot be `"H1"` or `"H2"`.
3. Multiple layers on the same boundary must not have contradictory fail modes — if any layer is `"fail-closed"`, the boundary as a whole is fail-closed.

**Hardness-mechanism consistency rules:**

| Mechanism class | Minimum Hardness | Maximum Hardness |
|---|---|---|
| packet-filter, egress-proxy | H1 | H3 |
| mandatory-access-control, capability-restriction, code-signing-enforcement | H2 | H3 |
| filesystem-acl, volume-encryption, integrity-protection | H2 | H3 |
| user-separation, privilege-boundary, consent-gate | H2 | H2 |
| hypervisor, namespace-isolation | H3 | H4 |
| physical-separation | H5 | H5 |

---

### 4.5 Route

**What it represents:** A sanctioned, directional path for artifacts or
data to cross a boundary. Without a route, nothing crosses. Routes are
one-way; bidirectional movement requires two routes.

Think of it as: a Unix pipe, a socket pair, a sanctioned IPC channel.
The `connect()` syscall succeeding because the kernel permits it.

```
RouteId = Opaque<string, "RouteId">              -- pattern: r-{from}-{to}

Cadence =
  | "push"                                        -- source initiates transfer
  | "pull"                                        -- destination polls for artifacts
  | "airlock"                                     -- manual deposit at shared staging path

Route = {
  id:                 RouteId
  fromZone:           ZoneId | Outside
  toZone:             ZoneId | Outside
  boundaryId:         BoundaryId                   -- which boundary this route crosses
  cadence:            Cadence
  enabled:            boolean
  declaredAt:         UtcTimestamp
  declaredBy:         IdentityId
}
```

**Invariants:**

1. `fromZone` and `toZone` must be different.
2. `fromZone` and `toZone` must be the two ends of the referenced `boundaryId`.
3. A route with `enabled: false` must reject all transfer attempts unconditionally.
4. A route from or to a zone of kind `"signing"` must have `cadence: "airlock"`.
5. At most one of `fromZone` / `toZone` may be `Outside`.

---

### 4.6 Gate

**What it represents:** A checkpoint on a route where a verification
decision is made. Every route passes through at least one gate. A gate
has requirements — conditions that must be satisfied for passage. If any
gate on a route rejects, the transfer is denied.

Think of it as: the `setuid` bit check. The capability check in
`cap_capable()`. The MAC policy lookup in `security_file_open()`. On
macOS: the Gatekeeper check, the notarization staple verification, the
TCC prompt.

```
GateId = Opaque<string, "GateId">                -- pattern: g-{route}-{seq}

VerificationKind =
  | "hash-integrity"                              -- artifact hash matches manifest
  | "signature-validity"                           -- cryptographic signature verifies
  | "provenance-chain"                            -- full chain from source to artifact
  | "content-scan"                                -- behavioral/malware scan
  | "human-approval"                              -- explicit human review and sign-off
  | "contract-conformance"                        -- artifact matches ArtifactContract (§5.1)
  | "identity-authentication"                     -- caller proves identity

GateVerdict = "permit" | "deny" | "pending"

Gate = {
  id:                 GateId
  routeId:            RouteId
  sequence:           Opaque<number, "GateSequence">  -- order in which gates are evaluated
  requiredVerifications: VerificationKind[]        -- non-empty; all must pass
  verdict:            GateVerdict                   -- current state (pending until evaluated)
}
```

**Invariants:**

1. `requiredVerifications` must be non-empty — a gate that checks nothing is not a gate.
2. Every Route must have at least one Gate.
3. Gates on a route are evaluated in `sequence` order; evaluation stops at first `"deny"`.
4. A gate on any route entering a zone of kind `"quarantine"` must include `"content-scan"`.
5. A gate on any route leaving a zone of kind `"signing"` must include `"signature-validity"`.
6. `verdict` is `"pending"` until explicitly evaluated by a gate enforcer.

---

### 4.7 Identity

**What it represents:** A principal — who or what is acting. An identity
is not a person; it is a security principal that can be authenticated
and attributed. One human may operate multiple identities (one per zone
admin role).

Think of it as: a Unix uid. A Kerberos principal. A macOS user account +
Keychain identity.

```
IdentityId = Opaque<string, "IdentityId">        -- pattern: id-{name}

IdentityKind =
  | "root"                                        -- floor-level system administrator
  | "zone-admin"                                  -- scoped operator of a single zone
  | "service"                                     -- automated process identity
  | "auditor"                                     -- read-only observer

Identity = {
  id:                 IdentityId
  kind:               IdentityKind
  displayName:        Opaque<string, "DisplayName">
  boundToZone:        ZoneId | Null                -- Null only for root and auditor
  canEscalate:        boolean                      -- can this identity gain higher privilege?
  createdAt:          UtcTimestamp
}
```

**Invariants:**

1. An identity of kind `"zone-admin"` must have `boundToZone` set to a valid ZoneId — zone admins are always scoped.
2. An identity of kind `"root"` must have `boundToZone: null` and `canEscalate: false` — root *is* the highest level; it doesn't escalate.
3. An identity of kind `"zone-admin"` must have `canEscalate: false` — privilege escalation is only via root at the console.
4. `id` is globally unique across all identities in a model.
5. An identity of kind `"service"` must have `boundToZone` set — services run within zones.

---

### 4.8 Scope

**What it represents:** A bounded permission context — the set of
operations that are potentially available. A scope defines the
*universe* of actions; whether a specific identity can perform them is
determined by Trust (§4.10).

Think of it as: a Linux capability set. A SELinux security context. A
macOS entitlement bundle. The `rwx` permission model generalized.

```
ScopeId = Opaque<string, "ScopeId">              -- pattern: sc-{zone}-{domain}

Capability =
  -- Filesystem
  | "fs:read"
  | "fs:write"
  | "fs:execute"
  -- Network
  | "net:listen"
  | "net:connect-outbound"
  | "net:accept-inbound"
  -- Process
  | "proc:spawn"
  | "proc:signal"
  | "proc:inspect"
  -- Cryptographic
  | "crypto:sign"
  | "crypto:verify"
  | "crypto:encrypt"
  | "crypto:decrypt"
  | "crypto:generate-key"
  -- Route
  | "route:propose-transfer"
  | "route:approve-transfer"
  | "route:execute-transfer"
  -- Zone
  | "zone:declare"
  | "zone:modify"
  | "zone:destroy"
  -- Audit
  | "audit:read-log"
  | "audit:write-event"
  | "audit:verify-chain"

Scope = {
  id:                 ScopeId
  zoneId:             ZoneId                       -- scope is always bound to a zone
  capabilities:       Capability[]                 -- non-empty; what operations exist here
  constraints:        ScopeConstraint[]            -- further restrictions on capabilities
}

ScopeConstraint =
  | { kind: "path-restricted",    paths: AbsolutePath[] }
  | { kind: "port-restricted",    ports: Port[] }
  | { kind: "host-restricted",    hosts: Hostname[] }
  | { kind: "time-restricted",    windows: TimeWindow[] }
  | { kind: "rate-limited",       maxPerHour: Opaque<number, "Rate"> }

TimeWindow = {
  dayOfWeek:          "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun"
  startUtc:           Opaque<string, "HourMinute">  -- HH:MM
  endUtc:             Opaque<string, "HourMinute">
}
```

**Invariants:**

1. `capabilities` must be non-empty — a scope with no capabilities is meaningless.
2. `zoneId` must reference an existing zone — scopes are always zone-bound.
3. A scope in a zone of kind `"audit"` may only contain capabilities prefixed with `audit:` and `fs:read`.
4. A scope in a zone of kind `"signing"` must contain `"crypto:sign"` and must not contain `"net:connect-outbound"` or `"net:listen"`.
5. Constraints narrow capabilities; they cannot expand them.

---

### 4.9 Credential

**What it represents:** Proof that an identity is who it claims to be.
A credential is the *evidence* presented at authentication. It is bound
to exactly one identity and has a specific mechanism.

Think of it as: an entry in `/etc/shadow`. An SSH private key. A
Kerberos ticket. On macOS: a Keychain item, a Secure Enclave key,
a FIDO2 resident credential.

```
CredentialId = Opaque<string, "CredentialId">    -- pattern: cr-{identity}-{mechanism}

CredentialMechanism =
  | "password-offline"                            -- stored on paper/vault, never on device
  | "hardware-key-fido2"                          -- FIDO2 resident key (YubiKey, etc.)
  | "hardware-key-secure-enclave"                 -- macOS Secure Enclave bound key
  | "ssh-key-hardware"                            -- SSH key backed by hardware token
  | "ssh-key-software"                            -- SSH key in software keystore
  | "token-scoped"                                -- PAT, API token, session token
  | "biometric"                                   -- Touch ID, Face ID (always secondary)
  | "certificate-x509"                            -- PKI certificate

CredentialStrength =
  | "primary-hardware"                            -- hardware-bound, unforgeable
  | "primary-software"                            -- software-stored, copyable
  | "secondary"                                   -- augments a primary (biometric, TOTP)
  | "ephemeral"                                   -- short-lived token, auto-expires

Credential = {
  id:                 CredentialId
  identityId:         IdentityId
  mechanism:          CredentialMechanism
  strength:           CredentialStrength
  fingerprint:        KeyFingerprint | Null        -- Null for non-key credentials
  expiresAt:          UtcTimestamp | Null           -- Null = no expiry (hardware keys)
  rotatedAt:          UtcTimestamp                  -- last rotation timestamp
  storedIn:           ZoneId                        -- which zone holds this credential
}
```

**Invariants:**

1. A credential with `mechanism: "password-offline"` must have `strength: "primary-hardware"` — it is hardware in the sense of physical media.
2. A credential with `mechanism: "biometric"` must have `strength: "secondary"` — biometrics alone are insufficient.
3. `storedIn` must reference a zone of kind `"identity"` or `"signing"` — credentials do not live in dev/build/release zones.
4. A credential with `strength: "ephemeral"` must have `expiresAt` set.
5. `identityId` must reference an existing Identity.
6. An identity of kind `"root"` must have at least one credential with `mechanism: "password-offline"`.

---

### 4.10 Trust

**What it represents:** A directed relationship declaring that a
specific identity is trusted to operate within a specific scope. Trust
is the bridge between "who you are" (Identity) and "what you may do"
(Scope). Trust is never implicit — it must be explicitly declared,
scoped, and signed.

Think of it as: a Unix ACL entry. A DAC permission set. An SELinux
allow rule. The conjunction of uid + file permission bits + capability
set that determines whether `open()` succeeds.

```
TrustId = Opaque<string, "TrustId">              -- pattern: tr-{identity}-{scope}

TrustBasis =
  | "role-assignment"                             -- identity was assigned this role
  | "credential-presentation"                     -- identity presented valid credential
  | "delegation"                                  -- another trusted identity delegated
  | "system-bootstrap"                            -- trust established at system init

Trust = {
  id:                 TrustId
  identityId:         IdentityId                   -- who is trusted
  scopeId:            ScopeId                      -- what they are trusted to do
  basis:              TrustBasis                    -- why they are trusted
  grantedBy:          IdentityId                   -- who granted this trust
  grantedAt:          UtcTimestamp
  expiresAt:          UtcTimestamp | Null           -- Null = until explicitly revoked
  requiresCredential: CredentialStrength           -- minimum credential strength for activation
  active:             boolean                      -- can be suspended without deletion
}
```

**Invariants:**

1. `identityId` and `grantedBy` must be different, **unless** `basis` is `"system-bootstrap"` and the identity's `kind` is `"root"` — this is the only permitted self-grant, and it may only occur once per model.
2. `grantedBy` must itself have trust that includes `"zone:declare"` or `"zone:modify"` capability in the target scope's zone — trust can only be granted by someone with authority.
3. `requiresCredential` must be at least `"primary-software"` — no trust is activated without a primary credential.
4. A trust with `basis: "system-bootstrap"` may only be granted by an identity of kind `"root"`.
5. The scope's `zoneId` must match the `boundToZone` of the identity (or `boundToZone` must be `null` for root/auditor identities).

---

## 5. Fundamental Objects

These are the first compositions — built exclusively from atoms, they
represent the minimum abstractions needed to make security decisions.

### 5.1 ArtifactContract

**What it composes from:** A contract defines what is permitted to cross
a route. It is the "type signature" of a route's payload.

```
MediaType = Opaque<string, "MediaType">          -- IANA media type, e.g. "application/gzip"
GlobPattern = Opaque<string, "GlobPattern">      -- e.g. "**/.env", "**/*.pem"

ArtifactContract = {
  allowedMediaTypes:  MediaType[]                  -- non-empty; what can pass
  forbiddenGlobs:     GlobPattern[]                -- patterns that must not appear in content
  requiresHash:       boolean
  requiresSignature:  boolean
  maxBytes:           Opaque<number, "ByteSize"> | Null  -- Null = no size limit
}
```

**Invariants:**

1. `allowedMediaTypes` must be non-empty.
2. If `requiresSignature` is true, `requiresHash` must also be true — a signature implies a hash.

---

### 5.2 BoundarySpec

**What it composes from:** Boundary + Layer[] + Surface[2]. The complete
description of a boundary's protection posture.

```
BoundarySpec = {
  boundary:           Boundary
  layers:             Layer[]                      -- all layers protecting this boundary
  surfaces:           [Surface, Surface]           -- exactly two: facing a and facing b
  effectiveHardness:  Hardness                     -- max hardness among all layers
  effectiveFailMode:  FailMode                     -- "fail-closed" if any layer is fail-closed
}
```

**Invariants:**

1. `layers` may be empty (an unprotected boundary) but this must trigger a validation warning.
2. `effectiveHardness` equals the maximum `hardness` value among all layers (H5 > H4 > H3 > H2 > H1).
3. `effectiveFailMode` is `"fail-closed"` if any layer has `failMode: "fail-closed"`; otherwise `"fail-open"`.
4. `surfaces[0].facing` must be `"a"` and `surfaces[1].facing` must be `"b"`.
5. All layers must reference the same `boundaryId` as the boundary.

---

### 5.3 Policy

**What it composes from:** Route + ArtifactContract + Gate[] + Trust
requirements. A policy is a complete rule about what trust is required
for a specific crossing.

```
PolicyId = Opaque<string, "PolicyId">            -- pattern: pol-{route}-{version}

PolicyStatus = "draft" | "active" | "deprecated" | "retired"

Policy = {
  id:                 PolicyId
  routeId:            RouteId
  contract:           ArtifactContract             -- what may cross
  gates:              Gate[]                        -- ordered checkpoints
  requiredTrust:      TrustRequirement[]           -- who must be trusted, at what level
  status:             PolicyStatus
  version:            SemVer
  declaredAt:         UtcTimestamp
  declaredBy:         IdentityId
}

TrustRequirement = {
  role:               IdentityKind                  -- what kind of identity
  minimumCredential:  CredentialStrength            -- what credential strength
  requiredCapabilities: Capability[]               -- what capabilities they must hold
}
```

**Invariants:**

1. `gates` must be non-empty and ordered by `sequence`.
2. `requiredTrust` must be non-empty — no policy permits anonymous crossing.
3. `status` transitions are one-way: `draft -> active -> deprecated -> retired`.
4. A policy with `status: "retired"` must have its route `enabled: false`.
5. `declaredBy` must hold `"zone:declare"` capability.

---

### 5.4 AccessDecision

**What it composes from:** Identity + Credential + Scope + Gate →
Verdict. The record of a single access control evaluation. This is the
fundamental security event — the moment where identity, capability, and
boundary meet.

```
DecisionId = Opaque<string, "DecisionId">        -- pattern: d-{timestamp}-{seq}

-- An AccessDecision is either a pre-gate rejection (route/policy level)
-- or a gate-level evaluation. This discriminated union ensures that
-- pre-gate denials don't require a gateId.

AccessDecision =
  | PreGateDenial
  | GateEvaluation

PreGateDenial = {
  id:                 DecisionId
  identityId:         IdentityId                   -- who attempted access
  routeId:            RouteId                      -- which route was attempted
  verdict:            "deny"
  reason:             PreGateReason
  evaluatedAt:        UtcTimestamp
  chainHash:          Sha256
  prevChainHash:      Sha256
}

PreGateReason =
  | { kind: "route-disabled" }
  | { kind: "policy-not-active",         policyId: PolicyId }

GateEvaluation = {
  id:                 DecisionId
  identityId:         IdentityId                   -- who attempted access
  credentialId:       CredentialId                  -- what credential was presented
  scopeId:            ScopeId                      -- what scope was requested
  gateId:             GateId                        -- which gate evaluated this
  requestedCapabilities: Capability[]              -- specific capabilities requested
  verdict:            GateVerdict                   -- permit | deny | pending
  reason:             GateDenialReason | Null       -- Null if permitted
  evaluatedAt:        UtcTimestamp
  chainHash:          Sha256                        -- hash-chain link for audit integrity
  prevChainHash:      Sha256                        -- previous link
}

GateDenialReason =
  | { kind: "identity-not-trusted",      expectedTrust: TrustId | Null }
  | { kind: "credential-insufficient",   required: CredentialStrength, presented: CredentialStrength }
  | { kind: "capability-not-in-scope",   missing: Capability[] }
  | { kind: "scope-constraint-violated", constraint: ScopeConstraint }
  | { kind: "gate-verification-failed",  verification: VerificationKind }
  | { kind: "contract-violated",         detail: Opaque<string, "ContractViolation"> }
```

**Invariants:**

1. For `GateEvaluation`: if `verdict` is `"deny"`, `reason` must be non-Null.
2. For `GateEvaluation`: if `verdict` is `"permit"`, `reason` must be Null.
3. `chainHash` must equal `SHA256(prevChainHash || serialize(this without chainHash))` — this is a semantic invariant validated at write time, not at type-check time.
4. For `GateEvaluation`: `requestedCapabilities` must be a subset of the scope's `capabilities`.
5. Every AccessDecision (both variants) must be appended to an immutable, hash-chained audit log.
6. `PreGateDenial` always has `verdict: "deny"` — a pre-gate check that passes simply proceeds to the gate.

---

### 5.5 TrustChain

**What it composes from:** A sequence of Trust relationships from a
root identity to an edge identity, proving that trust is delegable and
traceable. This is how you answer "why does dev-admin have permission
to push to GitHub?" — you walk the chain from root.

```
TrustChain = {
  root:               Trust                        -- always basis: "system-bootstrap", grantedBy root
  links:              Trust[]                       -- ordered from root outward
  leaf:               Trust                         -- the terminal trust being validated
  chainValid:         boolean                       -- true iff every link's grantedBy holds sufficient trust
}
```

**Invariants:**

1. `root.basis` must be `"system-bootstrap"`.
2. `links[0].grantedBy` (if `links` is non-empty) must equal `root.identityId`. For each subsequent link at index `n > 0`: `links[n].grantedBy` must equal `links[n-1].identityId`.
3. `leaf` must equal the last element of `links` (or `root` if `links` is empty).
4. `chainValid` is false if any link in the chain has `active: false` or an expired `expiresAt`.
5. A broken chain (invalid at any link) invalidates all trust downstream of the break.

---

## 6. Unix and macOS Mapping Table

How atoms map to concrete enforcement mechanisms on the target platform:

| Atom | Unix/Linux | macOS addition |
|---|---|---|
| Zone | namespace + cgroup + chroot | separate user account + sandbox profile |
| Boundary | kernel interface between namespaces | XPC Mach port boundary |
| Surface | /proc visibility, mount propagation | TCC visibility, sandbox allow-list |
| Layer:packet-filter | iptables / nftables | pf (root-managed) |
| Layer:mandatory-access-control | SELinux, AppArmor | sandbox-exec profiles, SIP |
| Layer:capability-restriction | Linux capabilities, seccomp-bpf | entitlements, hardened runtime |
| Layer:code-signing-enforcement | — | Gatekeeper + syspolicyd |
| Layer:consent-gate | polkit | TCC (tccd) |
| Layer:integrity-protection | dm-verity, IMA | SIP (csrutil) |
| Layer:hypervisor | KVM/QEMU | Virtualization.framework |
| Route | Unix socket, pipe, shared-memory | XPC connection, named pipe |
| Gate | setuid check, capability check | Gatekeeper check, notarization verify |
| Identity | uid / gid | user account + Keychain identity |
| Credential | /etc/shadow, SSH key, Kerberos ticket | Keychain item, Secure Enclave key, FIDO2 |
| Scope | capability set, SELinux context | entitlement bundle + TCC grants |
| Trust | DAC permission + ACL entry + MAC rule | Keychain ACL + code-signing trust |

---

## 7. Worked Example

**Scenario:** Local automation (in z-dev) accesses a GitHub repository
using a scoped PAT stored in 1Password (in z-identity).

### 7.1 The zones involved

```
zone_identity: Zone = {
  id:               "z-identity"
  kind:             "identity"
  purpose:          "holds personal credentials, signing keys, 1Password session"
  trustLevel:       "critical"
  isolation:        "user-account"
  filesystemRoots:  ["/Users/identity-admin"]
  createdAt:        "2026-05-15T00:00:00Z"
}

zone_dev: Zone = {
  id:               "z-dev"
  kind:             "dev"
  purpose:          "source authoring, local runtime, editor, toolchains"
  trustLevel:       "standard"
  isolation:        "user-account"
  filesystemRoots:  ["/Users/dev-admin"]
  createdAt:        "2026-05-15T00:00:00Z"
}
```

### 7.2 The boundary and its surfaces

```
boundary_identity_dev: Boundary = {
  id:               "b-identity-dev"
  side_a:           "z-identity"        -- higher trust (critical)
  side_b:           "z-dev"             -- lower trust (standard)
}

surface_identity_facing_dev: Surface = {
  id:               "sf-b-identity-dev-b"
  boundaryId:       "b-identity-dev"
  facing:           "b"                  -- this is what dev sees when looking toward identity
  exposedPaths:     []                   -- no filesystem paths exposed
  exposedListeners: []                   -- no network listeners exposed
  exposedCapabilities: ["crypto:decrypt"]  -- only: ability to request a secret
}

surface_dev_facing_identity: Surface = {
  id:               "sf-b-identity-dev-a"
  boundaryId:       "b-identity-dev"
  facing:           "a"                  -- this is what identity sees when looking toward dev
  exposedPaths:     []
  exposedListeners: []
  exposedCapabilities: []                -- identity doesn't need to reach into dev
}
```

### 7.3 The layers on this boundary

```
layer_user_sep: Layer = {
  id:               "ly-b-identity-dev-usersep"
  boundaryId:       "b-identity-dev"
  mechanism:        "user-separation"
  hardness:         "H2"
  failMode:         "fail-closed"
  enforced:         true
  verifiedAt:       "2026-05-15T00:00:00Z"
}

layer_acl: Layer = {
  id:               "ly-b-identity-dev-acl"
  boundaryId:       "b-identity-dev"
  mechanism:        "filesystem-acl"
  hardness:         "H2"
  failMode:         "fail-closed"
  enforced:         true
  verifiedAt:       "2026-05-15T00:00:00Z"
}
```

### 7.4 The boundary spec (composed)

```
spec_identity_dev: BoundarySpec = {
  boundary:          boundary_identity_dev
  layers:            [layer_user_sep, layer_acl]
  surfaces:          [surface_dev_facing_identity, surface_identity_facing_dev]
  effectiveHardness: "H2"
  effectiveFailMode: "fail-closed"
}
```

### 7.5 The route: credential retrieval

```
route_cred_to_dev: Route = {
  id:               "r-identity-dev-cred"
  fromZone:         "z-identity"
  toZone:           "z-dev"
  boundaryId:       "b-identity-dev"
  cadence:          "pull"               -- dev requests, identity provides
  enabled:          true
  declaredAt:       "2026-05-15T00:00:00Z"
  declaredBy:       "id-root"
}
```

### 7.6 The gate on this route

```
gate_cred_retrieval: Gate = {
  id:                    "g-r-identity-dev-cred-1"
  routeId:               "r-identity-dev-cred"
  sequence:              1
  requiredVerifications:  ["identity-authentication", "contract-conformance"]
  verdict:               "pending"
}
```

### 7.7 The identities, credentials, and root bootstrap

```
id_root: Identity = {
  id:               "id-root"
  kind:             "root"
  displayName:      "root"
  boundToZone:      Null
  canEscalate:      false
  createdAt:        "2026-05-15T00:00:00Z"
}

cred_root_offline: Credential = {
  id:               "cr-root-password"
  identityId:       "id-root"
  mechanism:        "password-offline"
  strength:         "primary-hardware"
  fingerprint:      Null
  expiresAt:        Null
  rotatedAt:        "2026-05-15T00:00:00Z"
  storedIn:         "z-identity"
}
```

#### Zone admins and their credentials

```
id_dev_admin: Identity = {
  id:               "id-dev-admin"
  kind:             "zone-admin"
  displayName:      "dev-admin"
  boundToZone:      "z-dev"
  canEscalate:      false
  createdAt:        "2026-05-15T00:00:00Z"
}

cred_dev_hwkey: Credential = {
  id:               "cr-dev-admin-fido2"
  identityId:       "id-dev-admin"
  mechanism:        "hardware-key-fido2"
  strength:         "primary-hardware"
  fingerprint:      "SHA256:xK9v3a8b2c1d0e9f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4"
  expiresAt:        Null
  rotatedAt:        "2026-05-15T00:00:00Z"
  storedIn:         "z-identity"
}

-- The PAT itself, stored in 1Password within the identity zone
cred_github_pat: Credential = {
  id:               "cr-dev-admin-github-pat"
  identityId:       "id-dev-admin"
  mechanism:        "token-scoped"
  strength:         "ephemeral"
  fingerprint:      Null
  expiresAt:        "2026-06-15T00:00:00Z"
  rotatedAt:        "2026-05-15T00:00:00Z"
  storedIn:         "z-identity"
}
```

### 7.8 The scope and trust

```
scope_dev_git: Scope = {
  id:               "sc-dev-git-operations"
  zoneId:           "z-dev"
  capabilities:     ["net:connect-outbound", "fs:read", "fs:write", "proc:spawn", "crypto:decrypt"]
  constraints:      [
    { kind: "host-restricted", hosts: ["github.com"] },
    { kind: "port-restricted", ports: [443] }
  ]
}

-- Root's bootstrap scope (referenced in TrustChain)
scope_root_all: Scope = {
  id:               "sc-root-bootstrap"
  zoneId:           "z-identity"          -- root acts through identity zone for bootstrap
  capabilities:     ["zone:declare", "zone:modify", "zone:destroy",
                     "crypto:generate-key", "crypto:sign",
                     "audit:write-event", "audit:verify-chain"]
  constraints:      []                     -- root has no constraints at bootstrap
}

trust_dev_git: Trust = {
  id:               "tr-dev-admin-git"
  identityId:       "id-dev-admin"
  scopeId:          "sc-dev-git-operations"
  basis:            "role-assignment"
  grantedBy:        "id-root"
  grantedAt:        "2026-05-15T00:00:00Z"
  expiresAt:        null
  requiresCredential: "primary-hardware"
  active:           true
}
```

### 7.9 The artifact contract and policy

```
contract_cred_delivery: ArtifactContract = {
  allowedMediaTypes: ["application/json"]
  forbiddenGlobs:    ["**/*.pem", "**/.env"]
  requiresHash:      true
  requiresSignature: false
  maxBytes:          4096                 -- a PAT is tiny
}

policy_cred_retrieval: Policy = {
  id:               "pol-r-identity-dev-cred-1.0.0"
  routeId:          "r-identity-dev-cred"
  contract:         contract_cred_delivery
  gates:            [gate_cred_retrieval]
  requiredTrust:    [{
    role:                "zone-admin"
    minimumCredential:   "primary-hardware"
    requiredCapabilities: ["crypto:decrypt"]
  }]
  status:           "active"
  version:          "1.0.0"
  declaredAt:       "2026-05-15T00:00:00Z"
  declaredBy:       "id-root"
}
```

### 7.10 The access decision (what happens at runtime)

```
decision_pat_retrieval: GateEvaluation = {
  id:                   "d-20260515T100000Z-001"
  identityId:           "id-dev-admin"
  credentialId:         "cr-dev-admin-fido2"
  scopeId:              "sc-dev-git-operations"
  gateId:               "g-r-identity-dev-cred-1"
  requestedCapabilities: ["crypto:decrypt"]
  verdict:              "permit"
  reason:               Null
  evaluatedAt:          "2026-05-15T10:00:00Z"
  chainHash:            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  prevChainHash:        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
}
```

### 7.11 The trust chain (how we trace authority)

```
chain_dev_git: TrustChain = {
  root: {
    id: "tr-root-bootstrap", identityId: "id-root", scopeId: "sc-root-bootstrap",
    basis: "system-bootstrap", grantedBy: "id-root",
    grantedAt: "2026-05-15T00:00:00Z", expiresAt: null,
    requiresCredential: "primary-hardware", active: true
  }
  links: [trust_dev_git]
  leaf:  trust_dev_git
  chainValid: true
}
```

**Reading the chain:** Root bootstrapped its own trust at system init.
Root then granted dev-admin trust to operate within the git-operations
scope. Dev-admin authenticated with a FIDO2 hardware key (primary-hardware),
requested the PAT from the identity zone via the credential-retrieval
route, passed the gate's identity-authentication and contract-conformance
checks, and received a permit verdict. The entire decision is
hash-chained into the audit log.

---

## 8. What This Does Not Cover (By Design)

This document stops at the atomic and fundamental layers. The following
are explicitly out of scope and belong in higher-level documents:

- **Workflow state machines** (transfer lifecycle: proposed → verified → approved → promoted). See draft 03 §workflow/state model.
- **Service orchestration** (which runtime process enforces which gate). See draft 03 §system orchestration.
- **Governance** (review cadences, exception registration, compliance). See drafts 09 and 10.
- **Observability** (alerting, signal requirements, SLOs). See draft 09.
- **Patch management** (update cadence, rollback). See draft 09.
- **Environment scoping** (multi-machine, VPS, cloud). See draft 10 §L5.
- **Value envelopes** (default/preferred/constraint wrappers). See draft 10 §L3.
- **Zone realization** (concrete macOS/Linux implementation steps). See draft 02 §macOS realization.

Each of these layers composes from the atoms and fundamentals defined
here. If this layer is wrong, everything above it is wrong. Get this
right first.
