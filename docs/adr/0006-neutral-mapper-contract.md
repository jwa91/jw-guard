# ADR-0006: Neutral deterministic mapper contract

- Status: Accepted
- Date: 2026-05-16
- Codifies:
  - this change - Add neutral mapper contract.

## Context

`jw-guard` needs real-world inputs such as Docker Compose, SBOMs, cloud
inventory, and build metadata to become evidence that can be evaluated against
declared policy. The immediate risk is assigning too much authority to mappers:
if a Docker mapper emits labels such as `insecure_container` or
`memory_over_2gb`, it has silently become a policy classifier. That would
recreate the hidden-opinion problem that ADR-0001 and ADR-0004 reject.

At the same time, pushing every real-world parsing detail into declarations
would make declaration authors responsible for source-format mechanics. The
boundary needs to be strict:

```text
mapper: source fact -> model observation
declare: policy vocabulary and requirement intent
eval: deterministic comparison of observation against requirement
enforce: operational action for evaluated outcomes
```

## Decision

Introduce `jw-guard-mapper` as the first mapping-layer crate.

The mapper contract is:

1. A mapper is deterministic and versioned.
2. A mapper emits neutral mapped evidence: referents and property claims.
3. Mapper output uses canonical names and explicit typed values.
4. Mapper output is sorted and validated deterministically.
5. Mappers must not emit policy decisions, enforcement outcomes, or
   threshold-derived posture tags.

Allowed mapper output examples:

```text
subject=web, property=privileged, value=true
subject=web, property=image_tag, value=latest
subject=web, property=memory_limit_bytes, value=2147483648
```

Forbidden mapper output examples:

```text
subject=web, property=insecure_container, value=true
subject=web, property=memory_over_2gb, value=true
subject=web, property=policy_violation, value=true
```

The first implementation intentionally does not add Docker-specific behavior.
It establishes the reusable contract that a later Docker mapper must implement.

## Consequences

- Positive: source-format parsing can advance without giving mappers policy
  authority.
- Positive: declarers can still decide whether `privileged=true` is forbidden,
  allowed, or irrelevant for their scope.
- Positive: threshold choices such as memory limits remain declarations or
  profiles, not mapper constants.
- Negative: evaluator work becomes necessary before mapped facts can become
  security decisions.
- Accepted trade-off: explicit mapped properties are slightly more verbose than
  security tags, but preserve ownership boundaries and auditability.

## Evidence in code

- [mapper/src/lib.rs](../../mapper/src/lib.rs) - `Mapper` trait,
  `MappedEvidence`, `MappedReferent`, and `MappedPropertyClaim`.
- `MappedEvidence::new` sorts output deterministically and accumulates typed
  mapping violations for duplicate referents, duplicate property claims, and
  property claims whose subject is not mapped.
- [Cargo.toml](../../Cargo.toml) - `mapper` is a workspace member while `core`
  remains unchanged.

## What would re-open this decision

- A proposal for mappers to emit security verdicts such as `Satisfied`,
  `Violated`, `deny`, or `allow`.
- A proposal for mappers to emit threshold-derived posture tags where the
  threshold is not an observed source fact.
- A concrete mapper that cannot express its neutral observations as referents
  plus typed property claims without losing essential source meaning.
