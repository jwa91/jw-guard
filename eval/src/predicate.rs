use alloc::vec::Vec;

use jw_guard_core::{CanonicalName, MembershipPredicate, PredicateId, ReferentId};

/// Explicit tri-state membership semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Membership {
    Member,
    NonMember,
    Unknown,
}

/// Context used to evaluate membership for one referent.
#[derive(Debug, Clone)]
pub struct ReferentContext<'a> {
    referent_id: ReferentId,
    name: Option<&'a CanonicalName>,
    tags: Option<&'a [CanonicalName]>,
    predicate_refs: Option<&'a [PredicateId]>,
}

impl<'a> ReferentContext<'a> {
    #[must_use]
    pub const fn new(
        referent_id: ReferentId,
        name: Option<&'a CanonicalName>,
        tags: Option<&'a [CanonicalName]>,
        predicate_refs: Option<&'a [PredicateId]>,
    ) -> Self {
        Self {
            referent_id,
            name,
            tags,
            predicate_refs,
        }
    }

    #[must_use]
    pub const fn referent_id(&self) -> ReferentId {
        self.referent_id
    }
}

/// Membership output for one carrier referent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MembershipSelection {
    referent_id: ReferentId,
    membership: Membership,
}

impl MembershipSelection {
    #[must_use]
    pub const fn new(referent_id: ReferentId, membership: Membership) -> Self {
        Self {
            referent_id,
            membership,
        }
    }

    #[must_use]
    pub const fn referent_id(self) -> ReferentId {
        self.referent_id
    }

    #[must_use]
    pub const fn membership(self) -> Membership {
        self.membership
    }
}

#[must_use]
pub fn evaluate_membership(
    predicate: &MembershipPredicate,
    context: Option<&ReferentContext<'_>>,
) -> Membership {
    match predicate {
        MembershipPredicate::All => Membership::Member,
        MembershipPredicate::HasTag(expected_tag) => {
            let Some(context) = context else {
                return Membership::Unknown;
            };
            let Some(tags) = context.tags else {
                return Membership::Unknown;
            };
            if tags.iter().any(|tag| tag == expected_tag) {
                Membership::Member
            } else {
                Membership::NonMember
            }
        }
        MembershipPredicate::NameEquals(expected_name) => {
            let Some(context) = context else {
                return Membership::Unknown;
            };
            let Some(name) = context.name else {
                return Membership::Unknown;
            };
            if name == expected_name {
                Membership::Member
            } else {
                Membership::NonMember
            }
        }
        MembershipPredicate::PredicateRef(expected_predicate) => {
            let Some(context) = context else {
                return Membership::Unknown;
            };
            let Some(predicate_refs) = context.predicate_refs else {
                return Membership::Unknown;
            };
            if predicate_refs
                .iter()
                .any(|predicate| predicate == expected_predicate)
            {
                Membership::Member
            } else {
                Membership::NonMember
            }
        }
    }
}

#[must_use]
pub fn evaluate_membership_for_carrier(
    predicate: &MembershipPredicate,
    carrier_referent_ids: &[ReferentId],
    referent_contexts: &[ReferentContext<'_>],
) -> Vec<MembershipSelection> {
    carrier_referent_ids
        .iter()
        .copied()
        .map(|referent_id| {
            let context = referent_contexts
                .iter()
                .find(|context| context.referent_id() == referent_id);
            let membership = evaluate_membership(predicate, context);
            MembershipSelection::new(referent_id, membership)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::{evaluate_membership, Membership, ReferentContext};
    use jw_guard_core::{CanonicalName, MembershipPredicate, PredicateId, ReferentId};

    fn id16(value: u8) -> [u8; 16] {
        [value; 16]
    }

    #[test]
    fn has_tag_returns_unknown_when_evidence_is_missing() {
        let predicate = MembershipPredicate::HasTag(
            CanonicalName::new("hardened".to_string()).expect("valid tag"),
        );

        let membership = evaluate_membership(&predicate, None);

        assert_eq!(membership, Membership::Unknown);
    }

    #[test]
    fn name_equals_returns_member_on_exact_match() {
        let predicate = MembershipPredicate::NameEquals(
            CanonicalName::new("gateway".to_string()).expect("valid name"),
        );
        let referent_id = ReferentId::from_bytes(id16(1));
        let referent_name = CanonicalName::new("gateway".to_string()).expect("valid name");
        let context = ReferentContext::new(referent_id, Some(&referent_name), None, None);

        let membership = evaluate_membership(&predicate, Some(&context));

        assert_eq!(membership, Membership::Member);
    }

    #[test]
    fn predicate_ref_returns_non_member_when_not_listed() {
        let predicate_id = PredicateId::from_bytes(id16(9));
        let predicate = MembershipPredicate::PredicateRef(predicate_id);
        let referent_id = ReferentId::from_bytes(id16(2));
        let known_predicates = vec![
            PredicateId::from_bytes(id16(3)),
            PredicateId::from_bytes(id16(4)),
        ];
        let context =
            ReferentContext::new(referent_id, None, None, Some(known_predicates.as_slice()));

        let membership = evaluate_membership(&predicate, Some(&context));

        assert_eq!(membership, Membership::NonMember);
    }
}
