//! The admission frame and its terms — the syntax of a registration request.
//!
//! An applicant holds keys and no account, so what it sends a door is a
//! payload its device key signs: its self-signed enrolments, framed under
//! [`REGISTRATION_TAG`] over the door it is for, a freshness value and the
//! request's own shape (REG-4.67; AUTH-1.11).
//! This module is that payload's syntax and no more:
//!
//! * [`AdmissionFrame`], the bytes the one signature is made over —
//!   `framed(REGISTRATION_TAG, [door, fresh, shape, node, board])`, each
//!   field the UTF-8 bytes of the request body's member of that name
//!   (REG-4.73), `board` left out where the applicant's board carries on;
//! * [`DoorId`], the door identifier's one readable string,
//!   `realm:<64 lowercase hex> door:<address>`, with `fork:<address>`
//!   between the two on a forked lineage (REG-4.74);
//! * [`Freshness`], the freshness value's form, 64 lowercase hex, and its
//!   comparison (REG-4.84);
//! * [`thread_key`], the key a request's thread is found by and a vouch is
//!   matched on (REG-4.78, REG-4.185);
//! * [`enrolled_signer`], the test that every enrolment a request carries
//!   enrols the key that signed it (REG-1.86).
//!
//! It verifies nothing: this crate links no signature library (AUTH-2.1),
//! so the signature over the frame is checked by a caller that links one,
//! under the key [`enrolled_signer`] answers. And it keeps no state: which
//! freshness values a door has seen, and which door a reader is, are the
//! reader's.

use core::fmt;

use skep_address::{validate, Address, Nat, Tumbler};

use crate::framing::{framed, REGISTRATION_TAG};
use crate::key::{Fingerprint, PublicKey};
use crate::payload::Enrollment;

/// The fields an applicant's one signature is made over, as a request's
/// body carries them.
///
/// Each is the member of that name, as written: a verifier re-builds the
/// frame from the members it parsed and frames no second encoding of them
/// (REG-4.73). `shape` is the address of the request's own row in the
/// registry range, by its ordinal path — `3.54.1.1` for a fresh request,
/// `3.54.1.2` where the board carries on (REG-4.104) — so the kind a request
/// asks for rides inside the signature, which a link's type, the writing
/// hand's, does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionFrame<'a> {
    /// The door identifier the request is framed for ([`DoorId`]).
    pub door: &'a str,
    /// The freshness value ([`Freshness`]).
    pub fresh: &'a str,
    /// The request's own row, by its ordinal path.
    pub shape: &'a str,
    /// The node account's self-signed enrolment record, as its text.
    pub node: &'a str,
    /// The board root's self-signed enrolment record, as its text; `None`
    /// where the applicant's board carries on, the field left out of the
    /// frame as the member is left out of the body.
    pub board: Option<&'a str>,
}

impl AdmissionFrame<'_> {
    /// Returns the frame's bytes: what the applicant's device key signs.
    ///
    /// They are `framed(REGISTRATION_TAG, [door, fresh, shape, node, board])`
    /// — four fields where `board` is `None`, five where it is `Some` — each
    /// field the UTF-8 bytes of its member (AUTH-1.12). The framing is
    /// injective, so two requests that differ in any field, or in whether
    /// they carry a board root, differ in these bytes: a payload framed for
    /// one door, or under one freshness value, verifies under no other.
    ///
    /// # Panics
    ///
    /// Panics where a field is 2^32 bytes or longer, as [`framed`] does; a
    /// request's members are held to its body's cap before they are framed.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut fields: Vec<&[u8]> = vec![
            self.door.as_bytes(),
            self.fresh.as_bytes(),
            self.shape.as_bytes(),
            self.node.as_bytes(),
        ];
        if let Some(board) = self.board {
            fields.push(board.as_bytes());
        }
        framed(REGISTRATION_TAG, &fields)
    }
}

/// A door identifier: the realm, the fork point on a forked lineage, and
/// the door's binding-writing account (REG-4.74).
///
/// It is board-and-realm qualified, so a payload lifted from one door's
/// public queue and sponsored at another is framed for the door its `door`
/// names and for no other. The identifier is one readable string with one
/// spelling, [`DoorId::parse`]'s and this type's `Display`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DoorId {
    /// The realm id's genesis fingerprint, as the root hint spells it
    /// (REG-3.40).
    pub realm: Fingerprint,
    /// The fork point, on a forked lineage; `None` on an unforked one.
    pub fork: Option<Address>,
    /// The door's binding-writing account, in full form (REG-1.66).
    pub door: Address,
}

impl DoorId {
    /// Parses a door identifier in its one spelling.
    ///
    /// The spelling is `realm:<64 lowercase hex> door:<address>`, with
    /// `fork:<address>` between the two terms on a forked lineage, one space
    /// between terms and none around them, each address in dotted decimal.
    /// `None` for every other string: a missing term, a term twice or out of
    /// its place, a second space, upper-case hex, a realm of another length,
    /// an address that is not T4-valid or not its own rendering. The test is
    /// the rendering compare — a string is an identifier only where it is
    /// the `Display` of what it spells — so two strings that name one door
    /// are one string.
    ///
    /// Whether the identifier names *this* door is its reader's: a request
    /// framed for another door parses, and is refused as framed for it.
    pub fn parse(s: &str) -> Option<DoorId> {
        let mut terms = s.split(' ');
        let realm = Fingerprint::parse_hex(terms.next()?.strip_prefix("realm:")?)?;
        let second = terms.next()?;
        let (fork, door) = match second.strip_prefix("fork:") {
            Some(fork) => (Some(address_of(fork)?), terms.next()?),
            None => (None, second),
        };
        let door = address_of(door.strip_prefix("door:")?)?;
        if terms.next().is_some() {
            return None;
        }
        let id = DoorId { realm, fork, door };
        (id.to_string() == s).then_some(id)
    }
}

/// The identifier's one spelling, as [`DoorId::parse`] reads it back.
impl fmt::Display for DoorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "realm:{}", self.realm.to_hex())?;
        if let Some(fork) = &self.fork {
            write!(f, " fork:{fork}")?;
        }
        write!(f, " door:{}", self.door)
    }
}

/// The address `s` spells in dotted decimal, where `s` is that address's
/// own rendering; `None` for any other string.
fn address_of(s: &str) -> Option<Address> {
    let comps: Option<Vec<Nat>> = s.split('.').map(|c| c.parse::<Nat>().ok()).collect();
    let address = validate(Tumbler::new(comps?).ok()?).ok()?;
    (address.to_string() == s).then_some(address)
}

/// A freshness value: thirty-two random bytes from the applicant's own
/// client, as 64 lowercase hex characters (REG-4.84).
///
/// Two values are equal where their spellings are, and the form has one
/// spelling, so the comparison a door's freshness set is kept by is this
/// type's equality. The set itself — every `fresh` of every request from an
/// admitted home at a door, never expiring, the first by journal order
/// standing — is its reader's to hold.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Freshness(String);

impl Freshness {
    /// Parses a freshness value: exactly 64 characters of `0`–`9` and
    /// `a`–`f`. `None` for every other string, upper-case hex among them.
    pub fn parse(s: &str) -> Option<Freshness> {
        let lowercase_hex = |b: &u8| b.is_ascii_digit() || (b'a'..=b'f').contains(b);
        (s.len() == 64 && s.as_bytes().iter().all(lowercase_hex)).then(|| Freshness(s.to_owned()))
    }

    /// Returns the value's 64 lowercase hex characters.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The value's 64 lowercase hex characters.
impl fmt::Display for Freshness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Returns a request thread's key: the fingerprints of every key the
/// request's enrolments name, ascending, each once.
///
/// `keys` is every entry of every enrolment the request carries — the node
/// account's, and the board root's where the request generates one. The key
/// is what an applicant holding no account finds its own thread by
/// (REG-4.78) and what a vouch's `fingerprints` array must equal, entry for
/// entry, to be a vouch of this request (REG-4.185): each fingerprint is
/// spelled as its 64 lowercase hex characters ([`Fingerprint::to_hex`]), in
/// ascending order — the order of the bytes and of their hex alike — and a
/// key two enrolments both name, the device key, is counted once.
pub fn thread_key<'e>(keys: impl IntoIterator<Item = &'e Enrollment>) -> Vec<Fingerprint> {
    let mut key: Vec<Fingerprint> = keys.into_iter().map(|e| Fingerprint::of(&e.key)).collect();
    key.sort();
    key.dedup();
    key
}

/// Returns the signing key where every enrolment present enrols it.
///
/// `signer` is the request's `signer` member, the fingerprint of the key
/// that signed the frame: the applicant's device key, which every enrolment
/// the request carries must enrol (REG-1.86). `enrolments` is each of them
/// in turn — the node account's, then the board root's where the request
/// carries one. `Some(key)` where at least one enrolment is given and each
/// holds an entry whose key's fingerprint is `signer`: the key the frame's
/// signature is then verified under. `None` where no enrolment names the
/// signer, where one of them does not — a signer the node enrolment alone
/// names — and where none is given.
pub fn enrolled_signer<'e>(
    signer: &Fingerprint,
    enrolments: &[&'e [Enrollment]],
) -> Option<&'e PublicKey> {
    let enrolled_by = |enrolment: &'e [Enrollment]| {
        enrolment.iter().map(|e| &e.key).find(|key| Fingerprint::of(key) == *signer)
    };
    let mut keys = enrolments.iter().map(|enrolment| enrolled_by(enrolment));
    let first = keys.next()??;
    keys.all(|key| key.is_some()).then_some(first)
}
