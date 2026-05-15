#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod document;
pub mod error;
pub mod kinds;
pub mod parse;

pub use document::*;
pub use error::*;
pub use kinds::*;
pub use parse::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "yaml")]
    #[test]
    fn parse_success_for_each_supported_kind() {
        let cases = [
            include_str!("../../policy/scope.yaml"),
            include_str!("../../policy/phase-separation.yaml"),
            include_str!("../../policy/edge-budget.yaml"),
            include_str!("../../policy/port-profile.yaml"),
            include_str!("../../policy/transport-routes.yaml"),
        ];

        for yaml in cases {
            let parsed = parse_policy_document(yaml).expect("yaml should parse");
            match parsed {
                PolicyDocument::ScopePolicy(document) => {
                    assert_eq!(document.kind, PolicyKind::ScopePolicy)
                }
                PolicyDocument::PhaseSeparationPolicy(document) => {
                    assert_eq!(document.kind, PolicyKind::PhaseSeparationPolicy)
                }
                PolicyDocument::EdgeBudgetPolicy(document) => {
                    assert_eq!(document.kind, PolicyKind::EdgeBudgetPolicy)
                }
                PolicyDocument::PortProfilePolicy(document) => {
                    assert_eq!(document.kind, PolicyKind::PortProfilePolicy)
                }
                PolicyDocument::TransportRoutesPolicy(document) => {
                    assert_eq!(document.kind, PolicyKind::TransportRoutesPolicy)
                }
            }
        }
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn rejects_unknown_kind() {
        let yaml = r#"
apiVersion: jw-guard/v1alpha1
kind: UnknownPolicy
metadata:
  name: unknown
  version: "1.0.0"
scope:
  target: workspace
requirements: []
"#;

        let error = parse_policy_document(yaml).expect_err("kind should be rejected");
        assert!(matches!(error, PolicySchemaError::YamlParse(message) if message.contains("UnknownPolicy")));
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn rejects_unknown_field() {
        let yaml = r#"
apiVersion: jw-guard/v1alpha1
kind: ScopePolicy
metadata:
  name: scope-policy
  version: "1.0.0"
scope:
  target: workspace
requirements:
  - selector: source
    constraint: in_scope
unexpected: true
"#;

        let error = parse_policy_document(yaml).expect_err("unknown fields should be rejected");
        assert!(matches!(error, PolicySchemaError::YamlParse(message) if message.contains("unexpected")));
    }
}
