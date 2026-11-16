//! The registration kind's six bodies, under the canonical rule.
//!
//! They are the bodies of the registration's deposit-carrying rows
//! (REG-1.86's table; REG-1.14, REG-1.15): a request in each of its kinds,
//! [`Fresh`] and [`BoardCarriesOn`]; the three answers on its thread,
//! [`Approved`], [`Refused`] and [`Denied`]; and the [`Vouch`]. Each is one
//! flat JSON object naming its own row in `type` — `"fresh"` and never
//! `"request"`, `"approved"` and never `"reply"` — its members in the order
//! its row lists them, then `replaces` where the row carries one, then
//! `sig` where signed, and nothing else. The kind's own row, its parent
//! rows `request` and `reply`, and the approval, a link alone, carry no
//! body, and no `type` string names one (REG-1.18, REG-1.86 (a)).
//!
//! The rule is `body.rs`'s, through its own machinery: [`parse_registration`]
//! answers a record only where the bytes are [`encode_registration`] of
//! what they spell, so each body has one form and a signature over its
//! sig-less projection ranges over bytes every reader re-derives. The types
//! are this module's own: [`RegistrationKind`], [`RegistrationBody`] and
//! [`RegistrationRecord`] stand beside `body.rs`'s `BodyKind`, `Body` and
//! `Record`, which keep the binding and the endpoint alone.
//!
//! What the parse checks is each member's form, never its admissibility
//! (REG-1.86 (h)), and what it checks the types carry: a freshness value
//! and a fingerprint are a [`Hex64`], a signature a [`HexDigits`], a count
//! or an interval a [`Digits`], a principal a [`Principal`], an address
//! member the `Address` it spells, the approved answer's three board
//! members one [`ProvisionedBoard`] or none. So every body a caller can
//! build encodes to bytes the parse admits, the cap aside. Whether a
//! request's `door` is this door's, its `fresh` unspent, its enrolments
//! honored and its `signer` enrolled by them, whether its `shape` names the
//! row its link is typed, whether a vouch's fingerprints key a request and
//! whether a denial's clause exists are each a reader's: the board's at its
//! registry sequence, or a console's.
//!
//! One number rides these bodies (REG-1.86 (d)): a principal id, the
//! approved answer's `node_principal` and `board_principal`, each a JSON
//! number inside the exactly-representable range (AUTH-5.20). Every count
//! and interval is a string of decimal digits, and a number anywhere else
//! refuses the body.
//!
//! The cap is per kind (REG-1.86 (h)): [`MAX_REGISTRATION_REQUEST_BYTES`]
//! for a request of either kind, and `MAX_REGISTRY_RECORD_BYTES` for every
//! other body, `sig` counted inside each.

use std::fmt::Write as _;

use serde_json::{Map, Value};
use skep_address::Address;

use crate::body::{
    address_member, escape_json_string, exactly_representable, holds_a_refused_number, names_only,
    object_under, push_member_opening, string_member, strings_member, Member, ParseRefusal,
    MAX_EXACT_NUMBER, MAX_REGISTRY_RECORD_BYTES,
};
use crate::rows::{row_at, Row, Subtype};

/// The most bytes a registration request's body may carry, `sig` included.
///
/// It is 64 KiB, 65,536 bytes — a term of the format (REG-1.86 (h)), for a
/// request of either kind and for no other body: a request carries one or
/// two whole enrolments, each of up to three hybrid keys with their
/// self-signatures, where every other registry body is a few hundred bytes
/// and its `sig`. The larger cap stands behind two guards its readers keep
/// (REG-4.78): a request is parsed only from an admitted home, and its
/// shape is checked before its bytes. A body past it is refused
/// ([`ParseRefusal::PastCap`]) before any tree is built.
pub const MAX_REGISTRATION_REQUEST_BYTES: usize = 64 * 1024;

/// The six kinds whose bodies this module parses, one a deposit-carrying
/// row of the registration kind.
///
/// It is the kind the caller names for a parse, read off the link's type
/// slot (REG-1.86 (a)) and never off the body: the body's own `type` member
/// is what [`parse_registration`] holds against the kind named.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistrationKind {
    /// A request from an org with no board yet: both pairs, `board` present.
    Fresh,
    /// A request from an org that keeps its own board: the node pair alone.
    BoardCarriesOn,
    /// The approved answer.
    Approved,
    /// The refused answer.
    Refused,
    /// The denied answer.
    Denied,
    /// The vouch.
    Vouch,
}

impl RegistrationKind {
    /// Every kind, in the order REG-1.15 lists the rows.
    pub const ALL: &'static [RegistrationKind] = &[
        RegistrationKind::Fresh,
        RegistrationKind::BoardCarriesOn,
        RegistrationKind::Approved,
        RegistrationKind::Refused,
        RegistrationKind::Denied,
        RegistrationKind::Vouch,
    ];

    /// Returns the subtype row the kind's deposits ride.
    pub fn subtype(self) -> Subtype {
        match self {
            RegistrationKind::Fresh => Subtype::RequestFresh,
            RegistrationKind::BoardCarriesOn => Subtype::RequestBoardCarriesOn,
            RegistrationKind::Approved => Subtype::ReplyApproved,
            RegistrationKind::Refused => Subtype::ReplyRefused,
            RegistrationKind::Denied => Subtype::ReplyDenied,
            RegistrationKind::Vouch => Subtype::Vouch,
        }
    }

    /// Returns the kind's row in the table, held.
    pub fn row(self) -> &'static Row {
        self.subtype().row()
    }

    /// Returns the kind whose row's address is `a`, by equality.
    ///
    /// `None` for every other address: the registration's own row, its
    /// parent rows `request` and `reply` and its approval, which carry no
    /// body, an address beneath a row, and every row outside the kind.
    pub fn at(a: &Address) -> Option<RegistrationKind> {
        let of = row_at(a)?.of.subtype()?;
        RegistrationKind::ALL.iter().copied().find(|kind| kind.subtype() == of)
    }

    /// Returns whether the kind is a request's: fresh or board-carries-on.
    pub fn is_request(self) -> bool {
        matches!(self, RegistrationKind::Fresh | RegistrationKind::BoardCarriesOn)
    }

    /// Returns the kind's cap, in bytes (REG-1.86 (h)).
    ///
    /// It is [`MAX_REGISTRATION_REQUEST_BYTES`] for a request of either
    /// kind and `MAX_REGISTRY_RECORD_BYTES` for an answer and for the vouch.
    pub fn cap(self) -> usize {
        if self.is_request() {
            MAX_REGISTRATION_REQUEST_BYTES
        } else {
            MAX_REGISTRY_RECORD_BYTES
        }
    }

    /// The `type` member's string, read off the kind's own row.
    fn type_value(self) -> &'static str {
        self.row().type_value.expect("a deposit-carrying registration row carries a body")
    }

    /// The row's own members, in the order its row lists them.
    fn members(self) -> &'static [Member] {
        match self {
            RegistrationKind::Fresh => &[
                Member::Door,
                Member::Fresh,
                Member::Shape,
                Member::Node,
                Member::Board,
                Member::Signer,
                Member::Signature,
            ],
            RegistrationKind::BoardCarriesOn => &[
                Member::Door,
                Member::Fresh,
                Member::Shape,
                Member::Node,
                Member::Signer,
                Member::Signature,
            ],
            RegistrationKind::Approved => &[
                Member::Prefix,
                Member::NodeAddress,
                Member::NodePrincipal,
                Member::BoardAddress,
                Member::BoardPrincipal,
                Member::BoardOrigin,
                Member::DoorOrigin,
                Member::CollectionInterval,
                Member::Disposition,
                Member::Policy,
            ],
            RegistrationKind::Refused => &[Member::Fault],
            RegistrationKind::Denied => &[Member::Policy, Member::Clause],
            RegistrationKind::Vouch => &[Member::Fingerprints, Member::Replaces],
        }
    }
}

/// Sixty-four lowercase hex characters: thirty-two bytes as a body spells
/// them.
///
/// It is the form of a request's freshness value (REG-4.84) and of a key's
/// fingerprint — a request's `signer`, an entry of a vouch's `fingerprints`
/// (REG-1.86). Whether the bytes are a fingerprint any key has is no
/// question of the form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hex64(String);

impl Hex64 {
    /// Returns `s` as the value it spells, `None` where it is not
    /// sixty-four characters of `0`–`9` and `a`–`f`.
    pub fn new(s: impl Into<String>) -> Option<Hex64> {
        let s = s.into();
        let lowercase_hex = |b: &u8| b.is_ascii_digit() || (b'a'..=b'f').contains(b);
        (s.len() == 64 && s.as_bytes().iter().all(lowercase_hex)).then_some(Hex64(s))
    }

    /// Returns the sixty-four characters.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Hex digits of either case, any count.
///
/// It is the form of a request's `signature`, the applicant's one signature
/// over the frame: the parse holds it to hex digits and to no width, which
/// is the verifier's to hold against the signer's own algorithm (REG-1.86).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HexDigits(String);

impl HexDigits {
    /// Returns `s` as the value it spells, `None` where a character of it
    /// is no hex digit.
    pub fn new(s: impl Into<String>) -> Option<HexDigits> {
        let s = s.into();
        s.as_bytes().iter().all(u8::is_ascii_hexdigit).then_some(HexDigits(s))
    }

    /// Returns the digits as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A string of decimal digits, at least one, as written.
///
/// It is the form of every count and interval a body carries (REG-1.86
/// (d)): none is a JSON number. The digits stand as the writer wrote them,
/// a leading zero included, with no bound but the body's cap, so a copy of
/// one — an approved answer's `collection_interval`, copied from the policy
/// version — is the same string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digits(String);

impl Digits {
    /// Returns `s` as the value it spells, `None` where it is empty or a
    /// character of it is no decimal digit.
    pub fn new(s: impl Into<String>) -> Option<Digits> {
        let s = s.into();
        (!s.is_empty() && s.as_bytes().iter().all(u8::is_ascii_digit)).then_some(Digits(s))
    }

    /// Returns the digits as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the number the digits spell, `None` where it is past `u64`.
    pub fn value(&self) -> Option<u64> {
        self.0.parse().ok()
    }
}

/// A principal id inside the exactly-representable range.
///
/// It is the one JSON number a registry body carries (REG-1.86 (d);
/// AUTH-6.2): an account's principal id as the wire spells it, an integer
/// from zero to [`Principal::MAX`] (AUTH-5.20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Principal(u64);

impl Principal {
    /// The largest principal id a body carries: `2^53 − 1`.
    pub const MAX: u64 = MAX_EXACT_NUMBER;

    /// Returns `id` as a principal, `None` where it is past
    /// [`Principal::MAX`].
    pub fn new(id: u64) -> Option<Principal> {
        exactly_representable(id).then_some(Principal(id))
    }

    /// Returns the id.
    pub fn get(self) -> u64 {
        self.0
    }
}

/// A fresh request's body: a request from an org with no board yet.
///
/// The frame's fields are the body's members (REG-4.73): `door`, `fresh`,
/// `shape`, `node` and `board`, with `signer` and `signature` beside them,
/// and no opaque copy of the frame. The `to` rides the link's slot and is
/// no member, and the body carries no `replaces` (REG-1.86 (g)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fresh {
    /// The door identifier the request is framed for, as written.
    pub door: String,
    /// The freshness value: thirty-two random bytes from the applicant's
    /// own client.
    pub fresh: Hex64,
    /// The address of the body's own row, by its ordinal path, as written.
    pub shape: String,
    /// The node account's self-signed enrolment, as the JSON text it is.
    pub node: String,
    /// The board root's self-signed enrolment, as the JSON text it is.
    pub board: String,
    /// The fingerprint of the key that signed the frame.
    pub signer: Hex64,
    /// The applicant's one signature over the frame.
    pub signature: HexDigits,
}

/// A board-carries-on request's body: a request from an org that keeps its
/// own board.
///
/// It is the fresh kind's members less `board`, in the same order
/// (REG-1.86; REG-4.204): the request generates the node pair alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardCarriesOn {
    /// The door identifier the request is framed for, as written.
    pub door: String,
    /// The freshness value.
    pub fresh: Hex64,
    /// The address of the body's own row, by its ordinal path, as written.
    pub shape: String,
    /// The node account's self-signed enrolment, as the JSON text it is.
    pub node: String,
    /// The fingerprint of the key that signed the frame.
    pub signer: Hex64,
    /// The applicant's one signature over the frame.
    pub signature: HexDigits,
}

/// A request's members, read off either kind.
///
/// It is what [`RegistrationBody::request`] answers: the members a reader
/// re-builds the frame from — `door`, `fresh`, `shape`, `node` and, on a
/// fresh request, `board` — with the `signer` and the `signature` it
/// verifies under and over them (REG-4.73).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestMembers<'a> {
    /// The door identifier.
    pub door: &'a str,
    /// The freshness value.
    pub fresh: &'a Hex64,
    /// The row the request's signed `shape` names.
    pub shape: &'a str,
    /// The node account's enrolment.
    pub node: &'a str,
    /// The board root's enrolment; `None` where the board carries on.
    pub board: Option<&'a str>,
    /// The fingerprint of the key that signed.
    pub signer: &'a Hex64,
    /// The signature over the frame.
    pub signature: &'a HexDigits,
}

impl<'a> RequestMembers<'a> {
    /// Returns the frame's fields, in the frame's order.
    ///
    /// They are `door`, `fresh`, `shape`, `node` and, where the request
    /// carries one, `board` — each the member of that name as written, the
    /// field left out where the member is (REG-1.86; REG-4.67). A reader
    /// frames their UTF-8 bytes under the admission tag to verify.
    pub fn frame_fields(&self) -> Vec<&'a str> {
        let mut fields = vec![self.door, self.fresh.as_str(), self.shape, self.node];
        fields.extend(self.board);
        fields
    }
}

/// What an approved answer's disposition names (REG-4.91, REG-4.128).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Disposition {
    /// `"retirement"`.
    Retirement,
    /// `"retirement-and-teardown"`, where a container was provisioned.
    RetirementAndTeardown,
}

impl Disposition {
    /// Every disposition.
    pub const ALL: &'static [Disposition] =
        &[Disposition::Retirement, Disposition::RetirementAndTeardown];

    /// Returns the member's string.
    pub fn as_str(self) -> &'static str {
        match self {
            Disposition::Retirement => "retirement",
            Disposition::RetirementAndTeardown => "retirement-and-teardown",
        }
    }
}

/// The board a replying console provisioned, as an approved answer states
/// it: the board root's address and principal id, and the board's origin.
///
/// The three ride together or not at all (REG-1.86; REG-4.90): at depth,
/// where the parent's console orders its own host, and never at the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedBoard {
    /// `board_address`: the board root's address, in the local form of the
    /// board it is on.
    pub address: Address,
    /// `board_principal`: the board root's principal id.
    pub principal: Principal,
    /// `board_origin`: the provisioned board's origin, as written.
    pub origin: String,
}

/// The approved answer's body: flat members named by role (REG-4.90).
///
/// The `to` rides the link's slot — one address, the request's link's — and
/// the body carries no `replaces`, no realm member and no prose member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    /// The prefix the answer carries once.
    pub prefix: Address,
    /// The node account's address.
    pub node_address: Address,
    /// The node account's principal id.
    pub node_principal: Principal,
    /// The provisioned board's three members, where the replying console
    /// provisioned one.
    pub board: Option<ProvisionedBoard>,
    /// At depth, the delegating board's origin, as written.
    pub door_origin: Option<String>,
    /// The collection interval, whole seconds, copied from the policy
    /// version at the approval.
    pub collection_interval: Digits,
    /// The disposition.
    pub disposition: Disposition,
    /// The version address of the policy version the two were read off.
    pub policy: Address,
}

/// The refused answer's fault: a fact about the payload, never a judgment
/// of the person (REG-4.85).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fault {
    /// `"not-this-door"`: the payload is not framed for this door.
    NotThisDoor,
    /// `"freshness-spent"`: the freshness value is spent.
    FreshnessSpent,
    /// `"enrolment-not-honored"`: an enrolment the console does not honor.
    EnrolmentNotHonored,
}

impl Fault {
    /// Every fault.
    pub const ALL: &'static [Fault] =
        &[Fault::NotThisDoor, Fault::FreshnessSpent, Fault::EnrolmentNotHonored];

    /// Returns the member's string.
    pub fn as_str(self) -> &'static str {
        match self {
            Fault::NotThisDoor => "not-this-door",
            Fault::FreshnessSpent => "freshness-spent",
            Fault::EnrolmentNotHonored => "enrolment-not-honored",
        }
    }
}

/// The refused answer's body: its fault, and no other member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// The fault.
    pub fault: Fault,
}

/// The denied answer's body: a citation of a clause of the door's policy
/// (REG-4.99).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    /// The version address of the policy version cited.
    pub policy: Address,
    /// The position of the ground in that version's `grounds`, counted
    /// from 1. Whether the position exists is the reader's.
    pub clause: Digits,
}

/// The vouch's body: the fingerprints that key the request vouched for.
///
/// The voucher is the vouch's home and never a member (REG-4.185). The
/// array is carried as written: the parse holds each entry to its form and
/// the list to no order, so a list out of order or repeating a fingerprint
/// is a vouch, and keys no request — the match against a thread's key is
/// array equality, a reader's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vouch {
    /// The fingerprints, in the order the body lists them.
    pub fingerprints: Vec<Hex64>,
    /// The link's address of the vouch this one follows; `None` on a first
    /// vouch.
    pub replaces: Option<Address>,
}

/// A body of one of the six kinds, its `sig` aside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationBody {
    /// A fresh request.
    Fresh(Fresh),
    /// A board-carries-on request.
    BoardCarriesOn(BoardCarriesOn),
    /// An approved answer.
    Approved(Approved),
    /// A refused answer.
    Refused(Refused),
    /// A denied answer.
    Denied(Denied),
    /// A vouch.
    Vouch(Vouch),
}

impl RegistrationBody {
    /// Returns the body's kind: the `type` member it is encoded under.
    pub fn kind(&self) -> RegistrationKind {
        match self {
            RegistrationBody::Fresh(_) => RegistrationKind::Fresh,
            RegistrationBody::BoardCarriesOn(_) => RegistrationKind::BoardCarriesOn,
            RegistrationBody::Approved(_) => RegistrationKind::Approved,
            RegistrationBody::Refused(_) => RegistrationKind::Refused,
            RegistrationBody::Denied(_) => RegistrationKind::Denied,
            RegistrationBody::Vouch(_) => RegistrationKind::Vouch,
        }
    }

    /// Returns a request's members, for a request of either kind; `None`
    /// for an answer and for the vouch.
    pub fn request(&self) -> Option<RequestMembers<'_>> {
        match self {
            RegistrationBody::Fresh(r) => Some(RequestMembers {
                door: &r.door,
                fresh: &r.fresh,
                shape: &r.shape,
                node: &r.node,
                board: Some(&r.board),
                signer: &r.signer,
                signature: &r.signature,
            }),
            RegistrationBody::BoardCarriesOn(r) => Some(RequestMembers {
                door: &r.door,
                fresh: &r.fresh,
                shape: &r.shape,
                node: &r.node,
                board: None,
                signer: &r.signer,
                signature: &r.signature,
            }),
            RegistrationBody::Approved(_)
            | RegistrationBody::Refused(_)
            | RegistrationBody::Denied(_)
            | RegistrationBody::Vouch(_) => None,
        }
    }
}

/// A parsed registration record: its body, and the `sig` member's string as
/// it stands — present or absent, the empty string included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationRecord {
    /// The body.
    pub body: RegistrationBody,
    /// The `sig` member, where the body carries one.
    pub sig: Option<String>,
}

impl RegistrationRecord {
    /// Returns the sig-less canonical projection (REG-1.86 (e)).
    ///
    /// It is [`encode_registration`] of the body with no `sig`: the bytes a
    /// record-grade signature ranges over, framed as the `record` grammar's
    /// row (5).
    pub fn canonical_sigless(&self) -> String {
        encode_registration(&self.body, None)
    }
}

/// Parses the record `bytes` spell under the kind the caller names.
///
/// A record is answered only where `bytes` are [`encode_registration`] of
/// what they spell (REG-1.86 (h)). Total over any bytes: no panic, and no
/// tree past the kind's cap. A record is of the kind named —
/// `record.body.kind() == kind` — so bytes that are a record under one kind
/// are `wrong_type` under every other.
///
/// The value stage is `serde_json`'s, with the choices `parse`'s doc states
/// for the binding and the endpoint: a member spelled twice is kept at its
/// last occurrence.
///
/// # Errors
///
/// The first stage to fault names the refusal, in this order:
///
/// 1. The cap, [`RegistrationKind::cap`]: `past_cap`.
/// 2. The text, the value and the object: `not_utf8`, `not_json`,
///    `not_an_object`.
/// 3. The number scan, over the whole value: `number` for any JSON number
///    but an approved answer's `node_principal` or `board_principal`
///    standing directly at its member, and for one of those that is no
///    integer from zero to [`Principal::MAX`].
/// 4. `type`: `wrong_type` where the member is absent, no string, or not
///    the kind's own row's name — another row's, or a parent row's,
///    `"request"` or `"reply"`.
/// 5. The member set: `unknown_member` for a member beside the row's own
///    and `sig` — `board` under a board-carries-on request, a realm member
///    under an approved answer, `replaces` under every kind but the vouch.
/// 6. Each member's form, one member at a time: `replaces`, then `sig`,
///    then the row's own in the row's order, a required member's absence
///    answered at its own turn (`missing_member`). A request's `door`,
///    `shape`, `node` and `board` are strings; `fresh` and `signer` are
///    sixty-four lowercase hex characters and `signature` hex digits of
///    either case (`not_hex`). An approved answer's `prefix`,
///    `node_address`, `board_address` and `policy` are addresses in their
///    one spelling (`not_an_address`); its principals are numbers
///    (`not_a_number`); its three board members stand together or not at
///    all, one absent beside another answered `missing_member`;
///    `collection_interval` is decimal digits (`not_digits`) and
///    `disposition` one of its two values (`unknown_value`). A refused
///    answer's `fault` is one of its three values (`unknown_value`). A
///    denied answer's `policy` is an address and its `clause` decimal
///    digits. A vouch's `fingerprints` is an array of strings
///    (`not_strings`), each sixty-four lowercase hex characters
///    (`not_hex`), in any order and any number.
/// 7. The canonical compare: `not_canonical`.
pub fn parse_registration(
    kind: RegistrationKind,
    bytes: &[u8],
) -> Result<RegistrationRecord, ParseRefusal> {
    let (text, mut object) = object_under(kind.cap(), bytes)?;
    let principals: &[Member] = match kind {
        RegistrationKind::Approved => &[Member::NodePrincipal, Member::BoardPrincipal],
        _ => &[],
    };
    if holds_a_refused_number(&object, principals) {
        return Err(ParseRefusal::Number);
    }
    if object.get("type").and_then(Value::as_str) != Some(kind.type_value()) {
        return Err(ParseRefusal::WrongType);
    }
    let known: Vec<Member> = kind.members().iter().copied().chain([Member::Sig]).collect();
    if !names_only(&object, &known) {
        return Err(ParseRefusal::UnknownMember);
    }
    let replaces = match kind {
        RegistrationKind::Vouch => address_member(&object, Member::Replaces)?,
        _ => None,
    };
    let sig = string_member(&mut object, Member::Sig)?;
    let body = match kind {
        RegistrationKind::Fresh => {
            let door = required_string(&mut object, Member::Door)?;
            let fresh = hex64_member(&mut object, Member::Fresh)?;
            let shape = required_string(&mut object, Member::Shape)?;
            let node = required_string(&mut object, Member::Node)?;
            let board = required_string(&mut object, Member::Board)?;
            let signer = hex64_member(&mut object, Member::Signer)?;
            let signature = signature_member(&mut object)?;
            RegistrationBody::Fresh(Fresh { door, fresh, shape, node, board, signer, signature })
        }
        RegistrationKind::BoardCarriesOn => {
            let door = required_string(&mut object, Member::Door)?;
            let fresh = hex64_member(&mut object, Member::Fresh)?;
            let shape = required_string(&mut object, Member::Shape)?;
            let node = required_string(&mut object, Member::Node)?;
            let signer = hex64_member(&mut object, Member::Signer)?;
            let signature = signature_member(&mut object)?;
            RegistrationBody::BoardCarriesOn(BoardCarriesOn {
                door,
                fresh,
                shape,
                node,
                signer,
                signature,
            })
        }
        RegistrationKind::Approved => RegistrationBody::Approved(approved_of(&mut object)?),
        RegistrationKind::Refused => {
            let fault = required_string(&mut object, Member::Fault)?;
            let fault = Fault::ALL
                .iter()
                .copied()
                .find(|f| f.as_str() == fault)
                .ok_or(ParseRefusal::UnknownValue(Member::Fault))?;
            RegistrationBody::Refused(Refused { fault })
        }
        RegistrationKind::Denied => {
            let policy = required_address(&object, Member::Policy)?;
            let clause = digits_member(&mut object, Member::Clause)?;
            RegistrationBody::Denied(Denied { policy, clause })
        }
        RegistrationKind::Vouch => {
            let fingerprints = strings_member(&mut object, Member::Fingerprints)?
                .ok_or(ParseRefusal::MissingMember(Member::Fingerprints))?
                .into_iter()
                .map(|f| Hex64::new(f).ok_or(ParseRefusal::NotHex(Member::Fingerprints)))
                .collect::<Result<Vec<Hex64>, ParseRefusal>>()?;
            RegistrationBody::Vouch(Vouch { fingerprints, replaces })
        }
    };
    // The admission sentence: admit only where the input is the canonical
    // re-encoding of what it spells, by the public encoder itself.
    if encode_registration(&body, sig.as_deref()) != text {
        return Err(ParseRefusal::NotCanonical);
    }
    Ok(RegistrationRecord { body, sig })
}

/// An approved answer's members, each in its turn.
fn approved_of(object: &mut Map<String, Value>) -> Result<Approved, ParseRefusal> {
    let prefix = required_address(object, Member::Prefix)?;
    let node_address = required_address(object, Member::NodeAddress)?;
    let node_principal = principal_member(object, Member::NodePrincipal)?
        .ok_or(ParseRefusal::MissingMember(Member::NodePrincipal))?;
    // The board's three members ride together or not at all: where any one
    // stands, each of the three is required at its own turn.
    let trio = [Member::BoardAddress, Member::BoardPrincipal, Member::BoardOrigin];
    let board = if trio.iter().any(|m| object.contains_key(m.name())) {
        let address = required_address(object, Member::BoardAddress)?;
        let principal = principal_member(object, Member::BoardPrincipal)?
            .ok_or(ParseRefusal::MissingMember(Member::BoardPrincipal))?;
        let origin = required_string(object, Member::BoardOrigin)?;
        Some(ProvisionedBoard { address, principal, origin })
    } else {
        None
    };
    let door_origin = string_member(object, Member::DoorOrigin)?;
    let collection_interval = digits_member(object, Member::CollectionInterval)?;
    let disposition = required_string(object, Member::Disposition)?;
    let disposition = Disposition::ALL
        .iter()
        .copied()
        .find(|d| d.as_str() == disposition)
        .ok_or(ParseRefusal::UnknownValue(Member::Disposition))?;
    let policy = required_address(object, Member::Policy)?;
    Ok(Approved {
        prefix,
        node_address,
        node_principal,
        board,
        door_origin,
        collection_interval,
        disposition,
        policy,
    })
}

/// A string member the row requires.
pub(crate) fn required_string(
    object: &mut Map<String, Value>,
    member: Member,
) -> Result<String, ParseRefusal> {
    string_member(object, member)?.ok_or(ParseRefusal::MissingMember(member))
}

/// An address member the row requires.
fn required_address(object: &Map<String, Value>, member: Member) -> Result<Address, ParseRefusal> {
    address_member(object, member)?.ok_or(ParseRefusal::MissingMember(member))
}

/// A required member of sixty-four lowercase hex characters.
fn hex64_member(object: &mut Map<String, Value>, member: Member) -> Result<Hex64, ParseRefusal> {
    Hex64::new(required_string(object, member)?).ok_or(ParseRefusal::NotHex(member))
}

/// A request's `signature`: required, hex digits of either case.
fn signature_member(object: &mut Map<String, Value>) -> Result<HexDigits, ParseRefusal> {
    let member = Member::Signature;
    HexDigits::new(required_string(object, member)?).ok_or(ParseRefusal::NotHex(member))
}

/// A required member of decimal digits.
pub(crate) fn digits_member(
    object: &mut Map<String, Value>,
    member: Member,
) -> Result<Digits, ParseRefusal> {
    Digits::new(required_string(object, member)?).ok_or(ParseRefusal::NotDigits(member))
}

/// A principal member: the principal its number spells, `None` where the
/// body carries no such member.
///
/// The number scan has held every number standing at a principal member to
/// the range, so a number that reaches here is a principal; a member of
/// another JSON type is `not_a_number`.
fn principal_member(
    object: &Map<String, Value>,
    member: Member,
) -> Result<Option<Principal>, ParseRefusal> {
    match object.get(member.name()) {
        None => Ok(None),
        Some(Value::Number(n)) => {
            n.as_u64().and_then(Principal::new).map(Some).ok_or(ParseRefusal::Number)
        }
        Some(_) => Err(ParseRefusal::NotANumber(member)),
    }
}

/// Encodes a body in its canonical form, with its `sig` where one is given.
///
/// It is the one byte string the body has: what a signer composes (with
/// `None`, then with the `sig` it made), what a verifier re-spells, and
/// what [`parse_registration`] holds its input to. Total, and it measures
/// nothing: every body encodes, with any `sig`, and the result is a record
/// at [`parse_registration`] under `body.kind()` exactly where it is at
/// most the kind's cap ([`RegistrationKind::cap`]). The measure is the
/// composer's, taken on the signed bytes.
pub fn encode_registration(body: &RegistrationBody, sig: Option<&str>) -> String {
    let mut out = String::with_capacity(512);
    out.push_str("{\"type\":\"");
    out.push_str(body.kind().type_value());
    out.push('"');
    match body {
        RegistrationBody::Fresh(r) => {
            push_string(Member::Door, &r.door, &mut out);
            push_string(Member::Fresh, r.fresh.as_str(), &mut out);
            push_string(Member::Shape, &r.shape, &mut out);
            push_string(Member::Node, &r.node, &mut out);
            push_string(Member::Board, &r.board, &mut out);
            push_string(Member::Signer, r.signer.as_str(), &mut out);
            push_string(Member::Signature, r.signature.as_str(), &mut out);
        }
        RegistrationBody::BoardCarriesOn(r) => {
            push_string(Member::Door, &r.door, &mut out);
            push_string(Member::Fresh, r.fresh.as_str(), &mut out);
            push_string(Member::Shape, &r.shape, &mut out);
            push_string(Member::Node, &r.node, &mut out);
            push_string(Member::Signer, r.signer.as_str(), &mut out);
            push_string(Member::Signature, r.signature.as_str(), &mut out);
        }
        RegistrationBody::Approved(a) => {
            push_string(Member::Prefix, &a.prefix.to_string(), &mut out);
            push_string(Member::NodeAddress, &a.node_address.to_string(), &mut out);
            push_number(Member::NodePrincipal, a.node_principal, &mut out);
            if let Some(board) = &a.board {
                push_string(Member::BoardAddress, &board.address.to_string(), &mut out);
                push_number(Member::BoardPrincipal, board.principal, &mut out);
                push_string(Member::BoardOrigin, &board.origin, &mut out);
            }
            if let Some(door_origin) = &a.door_origin {
                push_string(Member::DoorOrigin, door_origin, &mut out);
            }
            push_string(Member::CollectionInterval, a.collection_interval.as_str(), &mut out);
            push_string(Member::Disposition, a.disposition.as_str(), &mut out);
            push_string(Member::Policy, &a.policy.to_string(), &mut out);
        }
        RegistrationBody::Refused(r) => push_string(Member::Fault, r.fault.as_str(), &mut out),
        RegistrationBody::Denied(d) => {
            push_string(Member::Policy, &d.policy.to_string(), &mut out);
            push_string(Member::Clause, d.clause.as_str(), &mut out);
        }
        RegistrationBody::Vouch(v) => {
            push_strings(Member::Fingerprints, v.fingerprints.iter().map(Hex64::as_str), &mut out);
            if let Some(replaces) = &v.replaces {
                push_string(Member::Replaces, &replaces.to_string(), &mut out);
            }
        }
    }
    if let Some(sig) = sig {
        push_string(Member::Sig, sig, &mut out);
    }
    out.push('}');
    out
}

/// Writes a string member: its opening, then the string in the canonical
/// escaping.
pub(crate) fn push_string(member: Member, value: &str, out: &mut String) {
    push_member_opening(member, out);
    escape_json_string(value, out);
}

/// Writes an array-of-strings member: its opening, then each string in the
/// canonical escaping, comma-separated and bracketed.
pub(crate) fn push_strings<'s>(
    member: Member,
    values: impl IntoIterator<Item = &'s str>,
    out: &mut String,
) {
    push_member_opening(member, out);
    out.push('[');
    for (i, value) in values.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        escape_json_string(value, out);
    }
    out.push(']');
}

/// Writes a principal member: its opening, then the id in decimal — the one
/// spelling of the number the canonical form admits.
fn push_number(member: Member, principal: Principal, out: &mut String) {
    push_member_opening(member, out);
    let _ = write!(out, "{}", principal.get());
}

// What only this module's privates can show: the kinds' member lists
// against the rows' `type` strings. The bodies' public face is tested from
// outside, in `tests/it/registration.rs`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rows::{rows, Kind};

    /// Every deposit-carrying row of the registration kind that carries a
    /// body is a kind here, each read back off its row's address; the rows
    /// that carry none — the kind's own, its parent rows and the approval —
    /// answer no kind, and neither does a row outside the kind.
    #[test]
    fn every_body_bearing_registration_row_is_a_kind() {
        let registration: Vec<&Row> =
            rows().iter().filter(|r| r.of.kind() == Kind::Registration).collect();
        let bodied: Vec<&&Row> =
            registration.iter().filter(|r| r.type_value.is_some()).collect();
        assert_eq!(bodied.len(), RegistrationKind::ALL.len(), "one kind a body-bearing row");
        for &kind in RegistrationKind::ALL {
            let row = kind.row();
            assert_eq!(RegistrationKind::at(&row.address), Some(kind));
            assert_eq!(row.type_value, Some(kind.type_value()));
            assert!(row.carries_deposits(), "{kind:?}: a body rides a row that carries deposits");
        }
        for r in rows() {
            let bodied_registration = r.of.kind() == Kind::Registration && r.type_value.is_some();
            assert_eq!(RegistrationKind::at(&r.address).is_some(), bodied_registration, "{}", r.address);
        }
    }

    /// The kinds' member lists name each member once, `sig` never, and
    /// `replaces` at the vouch alone (REG-1.86 (g)).
    #[test]
    fn each_kind_lists_its_rows_own_members_once() {
        for &kind in RegistrationKind::ALL {
            let members = kind.members();
            for (i, m) in members.iter().enumerate() {
                assert!(!members[i + 1..].contains(m), "{kind:?}: {m:?} twice");
            }
            assert!(!members.contains(&Member::Sig), "{kind:?}");
            assert_eq!(
                members.contains(&Member::Replaces),
                kind == RegistrationKind::Vouch,
                "{kind:?}"
            );
        }
    }
}
