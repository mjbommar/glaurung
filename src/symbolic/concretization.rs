//! Configurable model-value selection for symbolic exploration.
//!
//! The policy decides *which kind* of concrete value the explorer should ask
//! for. Solver interaction and path mutation remain in `explore`, so policies
//! cannot bypass the explorer's checked solve and trace boundaries.

use std::ffi::OsStr;
use std::fmt;

/// Preferred environment variable for selecting a concretization policy.
pub const CONCRETIZATION_POLICY_ENV: &str = "GLAURUNG_CONCRETIZATION_POLICY";
/// Backward-compatible environment variable used by the preregistered studies.
pub const LEGACY_CANONICAL_MODEL_CHOICE_ENV: &str = "GLAURUNG_CANONICAL_MODEL_CHOICE";

/// Stable policy identifier for backend-provided arbitrary models.
pub const ANY_MODEL_POLICY_ID: &str = "glaurung-any-model-v1";
/// Stable policy identifier for the least unsigned satisfying value.
pub const LEAST_UNSIGNED_POLICY_ID: &str = "glaurung-min-unsigned-v1";
/// Stable policy identifier for the greatest unsigned satisfying value.
pub const GREATEST_UNSIGNED_POLICY_ID: &str = "glaurung-max-unsigned-v1";
/// Stable policy identifier for the first complementary site schedule.
pub const SITE_HASH_ZERO_POLICY_ID: &str = "glaurung-site-hash-0-v1";
/// Stable policy identifier for the second complementary site schedule.
pub const SITE_HASH_ONE_POLICY_ID: &str = "glaurung-site-hash-1-v1";

const ANY_ADDRESS_TRACE_POLICY_ID: &str = "glaurung-any-address-v1";
const REPRESENTATIVE_VALUE_TRACE_POLICY_ID: &str = "glaurung-representative-value-v1";

/// The explorer seam requesting a concrete value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConcretizationSite {
    /// A symbolic memory address that will be bound on the current path.
    Address,
    /// A read-only representative value used by a lifecycle check.
    Representative,
}

/// Stable context supplied to a [`ConcretizationPolicy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConcretizationRequest<'a> {
    /// Kind of explorer seam requesting a value.
    pub site: ConcretizationSite,
    /// Stable semantic purpose, independent of expression allocation order.
    pub purpose: &'a str,
    /// Instruction address associated with the choice.
    pub location: u64,
}

/// Unsigned endpoint requested from the checked solver search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsignedExtremum {
    /// Least satisfying unsigned value.
    Minimum,
    /// Greatest satisfying unsigned value.
    Maximum,
}

/// Value-selection plan returned by a concretization policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConcretizationChoice {
    /// Evaluate the expression in the backend's arbitrary satisfying model.
    AnyModel,
    /// Search for one checked unsigned endpoint.
    UnsignedExtremum(UnsignedExtremum),
    /// Fork over a deterministic set of checked values (A3 execution work).
    BoundarySet(Vec<u128>),
    /// Keep the expression symbolic (A2 memory-model work).
    Defer,
}

/// Pluggable policy for model-driven explorer choices.
///
/// Implementations select a plan only. The explorer owns all solver calls,
/// model evaluation, equality binding, and ordered-trace emission.
pub trait ConcretizationPolicy: Send + Sync {
    /// Stable, versioned identifier recorded in run-level policy accounting.
    fn policy_id(&self) -> &'static str;

    /// Select how the request should be concretized.
    fn choose(&self, request: ConcretizationRequest<'_>) -> ConcretizationChoice;

    /// Stable identifier written to the ordered trace at this seam.
    fn trace_policy_id(&self, _site: ConcretizationSite) -> &'static str {
        self.policy_id()
    }
}

/// Built-in policies accepted by the production environment configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinConcretizationPolicy {
    /// Preserve the backend's arbitrary satisfying model.
    AnyModel,
    /// Choose the least unsigned satisfying value.
    LeastUnsigned,
    /// Choose the greatest unsigned satisfying value.
    GreatestUnsigned,
    /// Choose a stable min/max endpoint from the site hash.
    SiteHashZero,
    /// Choose the complementary endpoint at every site.
    SiteHashOne,
}

impl ConcretizationPolicy for BuiltinConcretizationPolicy {
    fn policy_id(&self) -> &'static str {
        match self {
            Self::AnyModel => ANY_MODEL_POLICY_ID,
            Self::LeastUnsigned => LEAST_UNSIGNED_POLICY_ID,
            Self::GreatestUnsigned => GREATEST_UNSIGNED_POLICY_ID,
            Self::SiteHashZero => SITE_HASH_ZERO_POLICY_ID,
            Self::SiteHashOne => SITE_HASH_ONE_POLICY_ID,
        }
    }

    fn choose(&self, request: ConcretizationRequest<'_>) -> ConcretizationChoice {
        let extremum = match self {
            Self::AnyModel => return ConcretizationChoice::AnyModel,
            Self::LeastUnsigned => UnsignedExtremum::Minimum,
            Self::GreatestUnsigned => UnsignedExtremum::Maximum,
            Self::SiteHashZero => site_hash_extremum(request.purpose, request.location, false),
            Self::SiteHashOne => site_hash_extremum(request.purpose, request.location, true),
        };
        ConcretizationChoice::UnsignedExtremum(extremum)
    }

    fn trace_policy_id(&self, site: ConcretizationSite) -> &'static str {
        if *self != Self::AnyModel {
            return self.policy_id();
        }
        match site {
            ConcretizationSite::Address => ANY_ADDRESS_TRACE_POLICY_ID,
            ConcretizationSite::Representative => REPRESENTATIVE_VALUE_TRACE_POLICY_ID,
        }
    }
}

/// Precise configuration failure for policy selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConcretizationConfigError(String);

impl fmt::Display for ConcretizationConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ConcretizationConfigError {}

/// Resolve the preferred and legacy environment values without reading global
/// process state. Supplying both is rejected so a trace never hides ambiguous
/// configuration.
pub fn resolve_concretization_policy(
    configured: Option<&OsStr>,
    legacy: Option<&OsStr>,
) -> Result<BuiltinConcretizationPolicy, ConcretizationConfigError> {
    if configured.is_some() && legacy.is_some() {
        return Err(ConcretizationConfigError(format!(
            "both {CONCRETIZATION_POLICY_ENV} and {LEGACY_CANONICAL_MODEL_CHOICE_ENV} are set; configure exactly one"
        )));
    }
    if let Some(value) = configured {
        return parse_policy(value, CONCRETIZATION_POLICY_ENV, false);
    }
    if let Some(value) = legacy {
        return parse_policy(value, LEGACY_CANONICAL_MODEL_CHOICE_ENV, true);
    }
    Ok(BuiltinConcretizationPolicy::AnyModel)
}

/// Resolve the active process policy, preserving the old environment variable
/// while making the new policy namespace authoritative when used alone.
pub fn active_concretization_policy() -> BuiltinConcretizationPolicy {
    resolve_concretization_policy(
        std::env::var_os(CONCRETIZATION_POLICY_ENV).as_deref(),
        std::env::var_os(LEGACY_CANONICAL_MODEL_CHOICE_ENV).as_deref(),
    )
    .unwrap_or_else(|error| panic!("{error}"))
}

fn parse_policy(
    value: &OsStr,
    variable: &str,
    legacy: bool,
) -> Result<BuiltinConcretizationPolicy, ConcretizationConfigError> {
    let Some(value) = value.to_str() else {
        return Err(ConcretizationConfigError(format!(
            "invalid non-Unicode {variable} value"
        )));
    };
    let policy = match value {
        "any-model" | ANY_MODEL_POLICY_ID if !legacy => BuiltinConcretizationPolicy::AnyModel,
        "" | "1" | "true" if legacy => BuiltinConcretizationPolicy::LeastUnsigned,
        "min-unsigned" | "least-unsigned" | LEAST_UNSIGNED_POLICY_ID => {
            BuiltinConcretizationPolicy::LeastUnsigned
        }
        "max-unsigned" | "greatest-unsigned" | GREATEST_UNSIGNED_POLICY_ID => {
            BuiltinConcretizationPolicy::GreatestUnsigned
        }
        "site-hash-0" | SITE_HASH_ZERO_POLICY_ID => BuiltinConcretizationPolicy::SiteHashZero,
        "site-hash-1" | SITE_HASH_ONE_POLICY_ID => BuiltinConcretizationPolicy::SiteHashOne,
        _ => {
            return Err(ConcretizationConfigError(format!(
                "invalid {variable}={value:?}; expected any-model, min-unsigned, max-unsigned, site-hash-0, or site-hash-1"
            )));
        }
    };
    Ok(policy)
}

/// Choose a stable mixed extremum from source-level choice-site identity.
///
/// Expression IDs, solver models, mutable counters, and process order are not
/// inputs. The complementary schedule flips every decision.
fn site_hash_extremum(purpose: &str, location: u64, complement: bool) -> UnsignedExtremum {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for byte in purpose.bytes().chain(location.to_le_bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    let choose_maximum = ((hash >> 63) != 0) ^ complement;
    if choose_maximum {
        UnsignedExtremum::Maximum
    } else {
        UnsignedExtremum::Minimum
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    fn request(
        site: ConcretizationSite,
        purpose: &'static str,
        location: u64,
    ) -> ConcretizationRequest<'static> {
        ConcretizationRequest {
            site,
            purpose,
            location,
        }
    }

    #[test]
    fn default_any_model_policy_preserves_both_legacy_trace_tags() {
        let policy = resolve_concretization_policy(None, None).expect("default policy");

        assert_eq!(policy.policy_id(), "glaurung-any-model-v1");
        assert_eq!(
            policy.choose(request(
                ConcretizationSite::Address,
                "canonical-address-extremum",
                0x1000,
            )),
            ConcretizationChoice::AnyModel,
        );
        assert_eq!(
            policy.trace_policy_id(ConcretizationSite::Address),
            "glaurung-any-address-v1",
        );
        assert_eq!(
            policy.trace_policy_id(ConcretizationSite::Representative),
            "glaurung-representative-value-v1",
        );
    }

    #[test]
    fn new_policy_config_selects_each_existing_builtin() {
        let cases = [
            ("any-model", "glaurung-any-model-v1"),
            ("min-unsigned", "glaurung-min-unsigned-v1"),
            ("max-unsigned", "glaurung-max-unsigned-v1"),
            ("site-hash-0", "glaurung-site-hash-0-v1"),
            ("site-hash-1", "glaurung-site-hash-1-v1"),
        ];

        for (configured, expected_id) in cases {
            let policy = resolve_concretization_policy(Some(OsStr::new(configured)), None)
                .expect("valid policy");
            assert_eq!(policy.policy_id(), expected_id);
        }
    }

    #[test]
    fn legacy_canonical_config_remains_compatible() {
        for configured in ["", "1", "true", "min-unsigned", "glaurung-min-unsigned-v1"] {
            let policy = resolve_concretization_policy(None, Some(OsStr::new(configured)))
                .expect("valid legacy policy");
            assert_eq!(policy.policy_id(), "glaurung-min-unsigned-v1");
        }
        for (configured, expected_id) in [
            ("max-unsigned", "glaurung-max-unsigned-v1"),
            ("site-hash-0", "glaurung-site-hash-0-v1"),
            ("site-hash-1", "glaurung-site-hash-1-v1"),
        ] {
            let policy = resolve_concretization_policy(None, Some(OsStr::new(configured)))
                .expect("valid legacy policy");
            assert_eq!(policy.policy_id(), expected_id);
        }
    }

    #[test]
    fn ambiguous_or_invalid_policy_config_fails_closed_with_precise_errors() {
        let conflict = resolve_concretization_policy(
            Some(OsStr::new("any-model")),
            Some(OsStr::new("min-unsigned")),
        )
        .expect_err("dual configuration must fail");
        assert!(conflict
            .to_string()
            .contains("both GLAURUNG_CONCRETIZATION_POLICY"));

        let invalid = resolve_concretization_policy(Some(OsStr::new("random")), None)
            .expect_err("unknown policy must fail");
        assert!(invalid
            .to_string()
            .contains("GLAURUNG_CONCRETIZATION_POLICY=\"random\""));
        assert!(invalid.to_string().contains("any-model"));
    }

    #[test]
    fn site_hash_policies_are_stable_complementary_and_mixed() {
        let sites = [
            ("canonical-address-extremum", 0x1c0001a54),
            ("canonical-address-extremum", 0x1c009bb90),
            ("canonical-representative-extremum", 0x1c0002234),
            ("canonical-representative-extremum", 0x1c007a7d0),
        ];
        let zero = resolve_concretization_policy(Some(OsStr::new("site-hash-0")), None)
            .expect("site hash zero");
        let one = resolve_concretization_policy(Some(OsStr::new("site-hash-1")), None)
            .expect("site hash one");

        let zero_choices = sites.map(|(purpose, location)| {
            zero.choose(request(ConcretizationSite::Address, purpose, location))
        });
        let one_choices = sites.map(|(purpose, location)| {
            one.choose(request(ConcretizationSite::Address, purpose, location))
        });

        assert_eq!(
            zero_choices,
            [
                ConcretizationChoice::UnsignedExtremum(UnsignedExtremum::Maximum),
                ConcretizationChoice::UnsignedExtremum(UnsignedExtremum::Maximum),
                ConcretizationChoice::UnsignedExtremum(UnsignedExtremum::Minimum),
                ConcretizationChoice::UnsignedExtremum(UnsignedExtremum::Minimum),
            ],
        );
        for (zero_choice, one_choice) in zero_choices.into_iter().zip(one_choices) {
            assert_ne!(zero_choice, one_choice);
        }
    }

    #[test]
    fn custom_policy_can_express_set_and_deferred_choices() {
        struct TestPolicy;

        impl ConcretizationPolicy for TestPolicy {
            fn policy_id(&self) -> &'static str {
                "test-boundary-set-v1"
            }

            fn choose(&self, request: ConcretizationRequest) -> ConcretizationChoice {
                match request.site {
                    ConcretizationSite::Address => {
                        ConcretizationChoice::BoundarySet(vec![0, u128::MAX])
                    }
                    ConcretizationSite::Representative => ConcretizationChoice::Defer,
                }
            }
        }

        let policy = TestPolicy;
        assert_eq!(
            policy.choose(request(ConcretizationSite::Address, "test", 0x1000)),
            ConcretizationChoice::BoundarySet(vec![0, u128::MAX]),
        );
        assert_eq!(
            policy.choose(request(ConcretizationSite::Representative, "test", 0x1000,)),
            ConcretizationChoice::Defer,
        );
    }
}
