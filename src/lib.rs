#![forbid(unsafe_code)]

//! Claim authorization — a technology of `xmip-core-authorize`.
//!
//! One policy: a claim the identity carries, its value against a rule. A
//! token names more than a subject — an issuer, an audience, the groups a
//! directory put the subject in, a tenant — and the verifier that accepted it
//! (`authenticate/jwt`, `authenticate/oidc`, `authenticate/saml`) records
//! each claim on the identity's evidence under the claim's own name, one
//! entry per value where a claim has several. This policy reads them there:
//! `iss`, `aud`, `groups`, `tenant`, or whatever name the token used.
//!
//! A [`Required`] claim must be present, and where it names a value, one of
//! the claim's values must equal it. Every required claim must be met; the
//! first that is not is the denial, and it says whether the claim was
//! missing or wrong and what it was, so a token from the right issuer with
//! the wrong audience reads differently from no token at all.
//!
//! Message layer (ADR-0050 section 5): the identity judged is the message
//! identity, and the capability consults this policy only where one exists.
//! Asked directly with none, it has no opinion. It may also be confined to
//! some of the three points; an action it is not confined to is left to the
//! next policy — `None` — because a claim needed to run work in a Process is
//! not a claim needed to post into a Receive Location.

use authorize::{Action, Attempt, Authorizer, Decision};
use context::{AuthenticatedIdentity, IdentityFacts};
use std::fmt;
use xcore::Layer;

/// The manifest leaf, and what a denial says it was denied by.
pub const NAME: &str = "claim";

/// One claim the identity must carry, and the value it must have if any.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Required {
    /// The claim's name as the token states it and the verifier recorded it.
    pub name: String,
    /// The value one of the claim's entries must equal, or any value.
    pub value: Option<String>,
}

impl Required {
    /// The claim must be present, whatever its value.
    #[must_use]
    pub fn present(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: None,
        }
    }

    /// The claim must be present with this value among its values.
    #[must_use]
    pub fn equal(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Some(value.into()),
        }
    }

    /// The values the identity carries for this claim.
    #[must_use]
    pub fn values<'a>(&self, identity: &'a AuthenticatedIdentity) -> Vec<&'a str> {
        identity
            .evidence
            .iter()
            .filter(|(name, _)| *name == self.name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// Why this identity does not meet the requirement, or `None` where it
    /// does.
    #[must_use]
    pub fn unmet_by(&self, identity: &AuthenticatedIdentity) -> Option<String> {
        let values = self.values(identity);

        if values.is_empty() {
            return Some(format!(
                "the message identity carries no claim '{}'",
                self.name
            ));
        }

        match &self.value {
            Some(expected) if !values.contains(&expected.as_str()) => Some(format!(
                "claim '{}' is '{}', and this requires '{expected}'",
                self.name,
                values.join(", ")
            )),
            _ => None,
        }
    }
}

impl fmt::Display for Required {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Some(value) => write!(f, "{} = '{value}'", self.name),
            None => f.write_str(&self.name),
        }
    }
}

/// The claims the message identity must carry, at the points this applies.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Claim {
    required: Vec<Required>,
    /// The points this policy speaks at. Empty means all three.
    actions: Vec<Action>,
}

impl Claim {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn requiring(mut self, required: Required) -> Self {
        self.required.push(required);
        self
    }

    /// Confine the policy to this point. Unconfined, it speaks at all three.
    #[must_use]
    pub fn at(mut self, action: Action) -> Self {
        if !self.actions.contains(&action) {
            self.actions.push(action);
        }

        self
    }

    #[must_use]
    pub fn required(&self) -> &[Required] {
        &self.required
    }

    fn applies_to(&self, action: Action) -> bool {
        self.actions.is_empty() || self.actions.contains(&action)
    }
}

impl Authorizer for Claim {
    fn name(&self) -> &str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Message
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        if !self.applies_to(attempt.action) {
            return None;
        }

        let message = identity.message.as_ref()?;

        let unmet = self
            .required
            .iter()
            .find_map(|required| required.unmet_by(message));

        Some(match unmet {
            Some(reason) => Decision::denied(NAME, reason),
            None => Decision::Allowed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::{Alignment, Verified};
    use xcore::{Established, PartyId, mechanism};

    fn tls() -> AuthenticatedIdentity {
        AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=gateway.example",
            Established::Passed,
            Verified::Proven,
        )
        .resolving_to(PartyId::new(1))
    }

    fn token(claims: &[(&str, &str)]) -> IdentityFacts {
        let mut identity = AuthenticatedIdentity::new(
            mechanism::jwt(),
            "alice",
            Established::Passed,
            Verified::Proven,
        );

        for (name, value) in claims {
            identity = identity.with_evidence(*name, *value);
        }

        IdentityFacts::evaluate(Alignment::None, tls(), Some(identity))
    }

    fn approvers() -> Claim {
        Claim::new()
            .requiring(Required::equal("iss", "https://idp.example"))
            .requiring(Required::equal("groups", "approvers"))
            .requiring(Required::present("tenant"))
            .at(Action::Process)
    }

    #[test]
    fn an_identity_carrying_every_required_claim_is_allowed() {
        let facts = token(&[
            ("iss", "https://idp.example"),
            ("groups", "staff"),
            ("groups", "approvers"),
            ("tenant", "acme"),
        ]);

        let decision = approvers().decide(&facts, &Attempt::new(Action::Process, "Approval"));

        assert_eq!(decision, Some(Decision::Allowed));
    }

    #[test]
    fn a_missing_claim_is_denied_by_claim_naming_it() {
        let facts = token(&[("iss", "https://idp.example"), ("groups", "approvers")]);

        let decision = approvers().decide(&facts, &Attempt::new(Action::Process, "Approval"));

        assert_eq!(
            decision,
            Some(Decision::denied(
                NAME,
                "the message identity carries no claim 'tenant'"
            ))
        );
    }

    #[test]
    fn a_claim_with_the_wrong_value_is_denied_saying_what_it_was() {
        // Present and wrong is a different fault from absent, and the reason
        // has to let an operator tell a token from the wrong issuer apart from
        // a rule that names the wrong one.
        let facts = token(&[("iss", "https://other.example"), ("tenant", "acme")]);

        let decision = approvers().decide(&facts, &Attempt::new(Action::Process, "Approval"));

        assert_eq!(
            decision.map(|decision| decision.to_string()),
            Some(
                "denied by claim: claim 'iss' is 'https://other.example', and this requires \
                 'https://idp.example'"
                    .to_string()
            )
        );
    }

    #[test]
    fn a_point_the_policy_is_confined_away_from_is_left_to_the_next_policy() {
        let facts = token(&[]);

        let decision = approvers().decide(&facts, &Attempt::new(Action::Receive, "partner-x"));

        assert_eq!(decision, None);
    }

    #[test]
    fn with_no_message_identity_there_is_nothing_to_judge() {
        let facts = IdentityFacts::evaluate(Alignment::None, tls(), None);

        let decision = Claim::new()
            .requiring(Required::present("iss"))
            .decide(&facts, &Attempt::new(Action::Process, "Approval"));

        assert_eq!(decision, None);
        assert_eq!(Claim::new().layer(), Layer::Message);
        assert_eq!(Claim::new().name(), "claim");
    }

    #[test]
    fn a_requirement_reads_as_its_name_and_the_value_it_wants() {
        assert_eq!(Required::present("tenant").to_string(), "tenant");
        assert_eq!(Required::equal("aud", "xmip").to_string(), "aud = 'xmip'");
    }
}
