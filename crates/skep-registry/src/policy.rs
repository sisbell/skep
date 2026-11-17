//! The door's policy document, as a parsed value.
//!
//! A door's admission policy is a published document of its
//! binding-writing account whose whole content is one object in the
//! registry bodies' form, `type` `"admission-policy"` (REG-1.86's table;
//! REG-4.131): the admission mode, the approval's hand, the intake homes,
//! the rate limit's terms, three intervals, the out-of-band contact and the
//! citable grounds. It is no record of the registry range and no deposit:
//! the daemon reads no byte of it, and it carries no `sig` member, its
//! authenticity its home's and its publication's. This module is the one
//! parser a console, a sign-up page and a guest reader share
//! ([`parse_policy`], with [`encode_policy`] its writer), under the bodies'
//! canonical rule and through `body.rs`'s machinery; where the document
//! lives, and which version stands at a position, are its reader's.
//!
//! The parse checks each member's form and never its admissibility. One
//! term is read past the parse: the approval's hand
//! ([`AdmissionPolicy::approval_hand`]), which honors `"auto"` only where
//! the admission is open and opens no approval for a value it does not know
//! (REG-4.108).
//!
//! The cap is the registry records' own, `MAX_REGISTRY_RECORD_BYTES`,
//! 16 KiB: a document past it is refused before any tree is built, ahead of
//! every other stage, and reads as no policy, as an empty document does.
//! A door whose document is absent, holds no version, or whose standing
//! version this parse refuses has no policy: no request is admitted there
//! and no approval is written (REG-4.139). Which version stands is the
//! reader's.

use serde_json::{Map, Value};
use skep_address::Address;

use crate::body::{
    address_of, holds_a_refused_number, names_only, object_under, string_member, strings_member,
    Member, ParseRefusal, MAX_REGISTRY_RECORD_BYTES,
};
use crate::registration::{digits_member, push_string, push_strings, required_string, Digits};

/// The `type` member's string: the document names itself, as every body
/// does (REG-1.86).
pub const POLICY_TYPE: &str = "admission-policy";

/// The document's members, in the order its row lists them.
const MEMBERS: [Member; 13] = [
    Member::Admission,
    Member::Vouches,
    Member::Approval,
    Member::Intake,
    Member::IntakeRate,
    Member::IntakeWindow,
    Member::IntakePerDevice,
    Member::CollectionInterval,
    Member::StaleRequestInterval,
    Member::TranscriptionInterval,
    Member::Contact,
    Member::Sponsors,
    Member::Grounds,
];

/// A door's admission mode (REG-4.131).
///
/// The N of an n-vouches door rides the mode: `vouches` is a member of the
/// document only with `"n-vouches"`, and always with it (REG-4.185).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// `"invitation-only"`.
    InvitationOnly,
    /// `"n-vouches"`, with `vouches`, the N.
    NVouches(Digits),
    /// `"open"`.
    Open,
}

impl Admission {
    /// Returns the `admission` member's string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Admission::InvitationOnly => "invitation-only",
            Admission::NVouches(_) => "n-vouches",
            Admission::Open => "open",
        }
    }
}

/// The hand an approval is written by (REG-4.108).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalHand {
    /// An officer's signed session.
    Officer,
    /// An unattended console that is a labeled registrar device key.
    Unattended,
}

/// A door's policy document: its members, each the value it spells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionPolicy {
    /// The admission mode, with its N under n-vouches.
    pub admission: Admission,
    /// The `approval` member, as written. The parse admits any string; the
    /// hand it names is read by [`AdmissionPolicy::approval_hand`].
    pub approval: String,
    /// The intake homes: the scribe accounts' addresses, in the local form
    /// of the board the document is on, in the document's order.
    pub intake: Vec<Address>,
    /// The requests the scribe writes at this door per window.
    pub intake_rate: Digits,
    /// The window, in whole seconds.
    pub intake_window: Digits,
    /// The requests per window for one device-key fingerprint.
    pub intake_per_device: Digits,
    /// The collection interval, in whole seconds.
    pub collection_interval: Digits,
    /// The stale-request interval, in whole seconds.
    pub stale_request_interval: Digits,
    /// The transcription interval, in whole seconds.
    pub transcription_interval: Digits,
    /// How to reach the registrar out of band, as written.
    pub contact: String,
    /// At depth only, which of the residence class the door takes a
    /// sponsorship or a vouch from, as written. Its values are unpinned:
    /// the parse admits any one string, and a root document carries none.
    pub sponsors: Option<String>,
    /// The clauses a denial, a decline, an expulsion and a restoration
    /// cite, each by the version's address and its position in this list.
    pub grounds: Vec<String>,
}

impl AdmissionPolicy {
    /// Returns the hand this door's approvals are written by, if any.
    ///
    /// `"officer"` is the officer's hand under every admission mode.
    /// `"auto"` is honored only where the admission is open — the
    /// unattended console's — and under every other mode fails closed to
    /// the officer's hand. Any other value opens no approval: `None`
    /// (REG-4.108).
    pub fn approval_hand(&self) -> Option<ApprovalHand> {
        match (self.approval.as_str(), &self.admission) {
            ("officer", _) => Some(ApprovalHand::Officer),
            ("auto", Admission::Open) => Some(ApprovalHand::Unattended),
            ("auto", _) => Some(ApprovalHand::Officer),
            _ => None,
        }
    }
}

/// Parses the policy document `bytes` are.
///
/// A policy is answered only where `bytes` are [`encode_policy`] of what
/// they spell, so the document has one form; a malformed document is
/// refused whole. Total over any bytes: no panic, and no tree past the cap.
/// A document it refuses is no policy to any reader: the empty document,
/// `not_json`, among them (REG-4.139).
///
/// # Errors
///
/// The first stage to fault names the refusal, in this order:
///
/// 1. The cap, `MAX_REGISTRY_RECORD_BYTES`, 16 KiB: `past_cap`.
/// 2. The text, the value and the object: `not_utf8`, `not_json`,
///    `not_an_object`.
/// 3. The number scan: `number` for any JSON number, wherever it stands.
/// 4. `type`: `wrong_type` where the member is absent, no string, or not
///    `"admission-policy"`.
/// 5. The member set: `unknown_member` for a member the document does not
///    name, `sig` among them.
/// 6. Each member's form, in the document's order, a required member's
///    absence answered at its own turn (`missing_member`): `admission` one
///    of its three values (`unknown_value`); `vouches` at `admission`'s
///    turn — required with `"n-vouches"` and decimal digits (`not_digits`),
///    and beside either other mode a member the document does not name
///    (`unknown_member`); `approval` a string, any string; `intake` an
///    array of strings (`not_strings`), each an address in its one spelling
///    (`not_an_address`); the three intake terms and the three intervals
///    decimal digits; `contact` a string; `sponsors`, where present, a
///    string; `grounds` an array of strings.
/// 7. The canonical compare: `not_canonical`, another member order among
///    its causes.
pub fn parse_policy(bytes: &[u8]) -> Result<AdmissionPolicy, ParseRefusal> {
    let (text, mut object) = object_under(MAX_REGISTRY_RECORD_BYTES, bytes)?;
    if holds_a_refused_number(&object, &[]) {
        return Err(ParseRefusal::Number);
    }
    if object.get("type").and_then(Value::as_str) != Some(POLICY_TYPE) {
        return Err(ParseRefusal::WrongType);
    }
    if !names_only(&object, &MEMBERS) {
        return Err(ParseRefusal::UnknownMember);
    }
    let policy = policy_of(&mut object)?;
    if encode_policy(&policy) != text {
        return Err(ParseRefusal::NotCanonical);
    }
    Ok(policy)
}

/// The document's members, each in its turn.
fn policy_of(object: &mut Map<String, Value>) -> Result<AdmissionPolicy, ParseRefusal> {
    let admission = required_string(object, Member::Admission)?;
    let admission = match admission.as_str() {
        "invitation-only" => Admission::InvitationOnly,
        "n-vouches" => Admission::NVouches(digits_member(object, Member::Vouches)?),
        "open" => Admission::Open,
        _ => return Err(ParseRefusal::UnknownValue(Member::Admission)),
    };
    // `vouches` is a member only with n-vouches: beside any other mode it
    // is a member the document does not name.
    if object.contains_key(Member::Vouches.name()) {
        return Err(ParseRefusal::UnknownMember);
    }
    let approval = required_string(object, Member::Approval)?;
    let intake = strings_member(object, Member::Intake)?
        .ok_or(ParseRefusal::MissingMember(Member::Intake))?
        .iter()
        .map(|home| address_of(home).ok_or(ParseRefusal::NotAnAddress(Member::Intake)))
        .collect::<Result<Vec<Address>, ParseRefusal>>()?;
    let intake_rate = digits_member(object, Member::IntakeRate)?;
    let intake_window = digits_member(object, Member::IntakeWindow)?;
    let intake_per_device = digits_member(object, Member::IntakePerDevice)?;
    let collection_interval = digits_member(object, Member::CollectionInterval)?;
    let stale_request_interval = digits_member(object, Member::StaleRequestInterval)?;
    let transcription_interval = digits_member(object, Member::TranscriptionInterval)?;
    let contact = required_string(object, Member::Contact)?;
    let sponsors = string_member(object, Member::Sponsors)?;
    let grounds = strings_member(object, Member::Grounds)?
        .ok_or(ParseRefusal::MissingMember(Member::Grounds))?;
    Ok(AdmissionPolicy {
        admission,
        approval,
        intake,
        intake_rate,
        intake_window,
        intake_per_device,
        collection_interval,
        stale_request_interval,
        transcription_interval,
        contact,
        sponsors,
        grounds,
    })
}

/// Encodes a policy in its canonical form: the document's whole content.
///
/// It is the one byte string the policy has — `{"type":"admission-policy"`,
/// then its members in the document's order, `vouches` only under
/// n-vouches and `sponsors` only where the policy carries one, `}` — and
/// what [`parse_policy`] holds its input to. Total, and it measures
/// nothing: every policy a caller can build encodes, and the result is a
/// document at [`parse_policy`] exactly where it is at most the cap,
/// `MAX_REGISTRY_RECORD_BYTES`. The measure is the writer's.
pub fn encode_policy(policy: &AdmissionPolicy) -> String {
    let mut out = String::with_capacity(512);
    out.push_str("{\"type\":\"");
    out.push_str(POLICY_TYPE);
    out.push('"');
    push_string(Member::Admission, policy.admission.as_str(), &mut out);
    if let Admission::NVouches(vouches) = &policy.admission {
        push_string(Member::Vouches, vouches.as_str(), &mut out);
    }
    push_string(Member::Approval, &policy.approval, &mut out);
    let intake: Vec<String> = policy.intake.iter().map(ToString::to_string).collect();
    push_strings(Member::Intake, intake.iter().map(String::as_str), &mut out);
    push_string(Member::IntakeRate, policy.intake_rate.as_str(), &mut out);
    push_string(Member::IntakeWindow, policy.intake_window.as_str(), &mut out);
    push_string(Member::IntakePerDevice, policy.intake_per_device.as_str(), &mut out);
    push_string(Member::CollectionInterval, policy.collection_interval.as_str(), &mut out);
    push_string(Member::StaleRequestInterval, policy.stale_request_interval.as_str(), &mut out);
    push_string(Member::TranscriptionInterval, policy.transcription_interval.as_str(), &mut out);
    push_string(Member::Contact, &policy.contact, &mut out);
    if let Some(sponsors) = &policy.sponsors {
        push_string(Member::Sponsors, sponsors, &mut out);
    }
    push_strings(Member::Grounds, policy.grounds.iter().map(String::as_str), &mut out);
    out.push('}');
    out
}
