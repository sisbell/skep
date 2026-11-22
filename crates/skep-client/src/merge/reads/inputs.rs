//! A merge's inputs and its composition's result (the merge record's §7).
//!
//! [`Inputs`] is what the caller names — the trunk, its head, the sides,
//! the switches, the record's kind and, to be checked, a base; each
//! [`Side`] has its [`Role`] in the record; [`Merged`] is what
//! [`compose`](super::compose) answers before anything is written, each run
//! of M with its [`Family`]. How the base and the one position P are derived
//! is the `reads` module's doc.

use skep_address::Address;

use crate::merge::compose::{Composed, Options};
use crate::merge::record::{Record, RecordKey};

use super::reader::Imaged;

// ── the inputs ────────────────────────────────────────────────────────────

/// What a merge is composed from (the merge record's §7, `Inputs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inputs {
    /// The trunk document `D`.
    pub doc: Address,
    /// The head member `D.h` — side A in every shape the record draws.
    ///
    /// No read answers a bare document's head member (unverified-here 7), so
    /// the caller names it, from its own knowledge or from [`head_of`].
    ///
    /// [`head_of`]: super::head_of
    pub head: Address,
    /// The base, where the caller names it.
    ///
    /// Derived where `None`, from where each side's line of recorded bases ends
    /// (the `reads` module's doc) — a member, or the document itself where a
    /// side was begun before its first version — so no merge needs one named
    /// (§1.2). A named one is checked against the derived base and refused
    /// where it disagrees: beside a draft side [`Refusal::DraftBaseDisagrees`],
    /// beside member sides alone [`Refusal::NamedBaseDisagrees`]; beside a fork
    /// side it is refused unread ([`Refusal::ForkBaseNamed`]).
    ///
    /// [`Refusal::DraftBaseDisagrees`]: super::Refusal::DraftBaseDisagrees
    /// [`Refusal::NamedBaseDisagrees`]: super::Refusal::NamedBaseDisagrees
    /// [`Refusal::ForkBaseNamed`]: super::Refusal::ForkBaseNamed
    pub base: Option<Address>,
    /// The other sides, in commit order.
    ///
    /// At most 255: every list a merge composes is numbered by one byte,
    /// the head's first, and [`compose`] refuses more before any read.
    ///
    /// [`compose`]: super::compose
    pub sides: Vec<Side>,
    /// The composition's switches and the merger's resolutions.
    pub options: Options,
    /// The merge record kind's type address.
    ///
    /// It is the link's type slot and the record's class. Decision 9's row is
    /// interim and unpinned, so the embedder names it.
    pub kind: Address,
}

/// One side of a merge besides the head (the merge record's §7, `Side`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Side {
    /// A member of the document's chain.
    ///
    /// It is a daughter, or a daughter's daughter, its line of recorded
    /// bases walked from itself (the `reads` module's doc).
    Member(Address),
    /// A draft of the trunk owner's account (§1.2 shape (2)).
    ///
    /// It is read as of `position` where one is given — which is then the one
    /// position P every read of the composition is made at — else at the
    /// position the composition's first read answers, its base and its image
    /// alike. Its anchor is the base the board records for it — the `base`
    /// member of its `doc_metadata`, the member or the bare document it was
    /// staged from, moved to the member each publication it rendered minted
    /// (wire.md §Namespace, `stage`) — read as of the same position, so a
    /// record's side, which carries the position its draft was read at,
    /// composes against the base that stood then; the merge's base is derived
    /// up the recorded bases from it (the `reads` module's doc), so a draft
    /// staged before the document's first version merges over the document's
    /// own arrangement from before that version, whether it is still
    /// unpublished or its publication landed as version 1's daughter. A draft
    /// the board records no base for, or whose recorded base lies in another
    /// document, is refused [`Refusal::BaseUnknown`]; a base the caller names
    /// beside it must be the one the records derive
    /// ([`Refusal::DraftBaseDisagrees`]).
    ///
    /// [`Refusal::BaseUnknown`]: super::Refusal::BaseUnknown
    /// [`Refusal::DraftBaseDisagrees`]: super::Refusal::DraftBaseDisagrees
    Draft {
        /// The draft's address.
        at: Address,
        /// The commit position the draft is read at; `None` for the position
        /// the composition's first read answers.
        ///
        /// The record's side carries the position read either way: this
        /// one, or the one the first read answered.
        position: Option<u64>,
    },
    /// A cross-owner fork of the document (§1.2 shape (4), case (j)).
    ///
    /// It is another account's document, whose words the merge keeps as
    /// windows onto it. One of the trunk owner's own account is refused
    /// [`Refusal::ForkOfOwner`] before any `image`: the owner's draft is the
    /// [`Side::Draft`] side, whose words the shot re-mints as the document's
    /// own. The account is compared exactly, so a sub-account's or an
    /// agent's document stays a fork. One in the document's own tree — the
    /// document, a member of its chain or an address within either — is
    /// refused [`Refusal::BaseUnknown`] before any read.
    ///
    /// Its anchor is where the board records it standing (the owner's ruling of
    /// 2026-11-19; skep #1106): the base the board records for it where it
    /// records one — the `base` member of its `doc_metadata`, the member or the
    /// bare document another account's `stage` copied into it, or the base it
    /// inherited as an alternative, moved to the head by each landing into it —
    /// else its source, the `source` member, the version member or the bare
    /// document a `version` minted it sharing. Both are read off the fork's one
    /// `doc_metadata` at the composition's position, a recorded base never
    /// passed over for the source. The merge's base is derived up the recorded
    /// bases from the anchor (the `reads` module's doc), never the caller's to
    /// name ([`Refusal::ForkBaseNamed`]): a fork taken before the document's
    /// first version merges over the document's own arrangement from before
    /// that version. One the board records neither for, or whose recorded base,
    /// else source, lies in another document — a staged fork published as an
    /// edition of its own among them, its base moved to that edition's member —
    /// is refused [`Refusal::BaseUnknown`]. Read as named: a published fork
    /// with members of its own would float to its head, so the caller names the
    /// member of it it means. Its state — the position its text last changed
    /// at, `arranged_at` on the same `doc_metadata` — is recorded beside it
    /// ([`SideAt::Fork`](super::record::SideAt::Fork)), so a verifier tells a
    /// fork edited since the merge from a record that is wrong
    /// ([`Verdict::SideMoved`](super::record::Verdict::SideMoved)).
    ///
    /// [`Refusal::ForkOfOwner`]: super::Refusal::ForkOfOwner
    /// [`Refusal::BaseUnknown`]: super::Refusal::BaseUnknown
    /// [`Refusal::ForkBaseNamed`]: super::Refusal::ForkBaseNamed
    Fork(Address),
}

impl Side {
    /// Returns the side's address — the member, the draft, the fork.
    pub fn address(&self) -> &Address {
        match self {
            Side::Member(a) | Side::Fork(a) => a,
            Side::Draft { at, .. } => at,
        }
    }

    /// Returns the side's role in the record's `sides` (§4).
    pub fn role(&self) -> Role {
        match self {
            Side::Member(_) => Role::Alternative,
            Side::Draft { .. } => Role::Draft,
            Side::Fork(_) => Role::Fork,
        }
    }

    /// Returns the position a draft side is read at.
    pub(super) fn position(&self) -> Option<u64> {
        match self {
            Side::Draft { position, .. } => *position,
            Side::Member(_) | Side::Fork(_) => None,
        }
    }

    /// Returns the noun a refusal names the side by: `version`, `draft` or
    /// `fork`.
    pub(super) fn noun(&self) -> &'static str {
        match self {
            Side::Member(_) => "version",
            Side::Draft { .. } => "draft",
            Side::Fork(_) => "fork",
        }
    }
}

/// A side's role, as the record spells it (the merge record's §4, `role`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The head member, side A.
    Head,
    /// A daughter of the document's chain.
    Alternative,
    /// A draft of the trunk owner's account.
    Draft,
    /// A cross-owner fork, of an account other than the trunk owner's.
    Fork,
}

impl Role {
    /// Returns the role's spelling in the record.
    ///
    /// It is `head`, `alternative`, `draft` or `fork`.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Head => "head",
            Role::Alternative => "alternative",
            Role::Draft => "draft",
            Role::Fork => "fork",
        }
    }

    /// Returns the role a spelling names, `None` for any other text.
    pub fn parse(text: &str) -> Option<Role> {
        match text {
            "head" => Some(Role::Head),
            "alternative" => Some(Role::Alternative),
            "draft" => Some(Role::Draft),
            "fork" => Some(Role::Fork),
            _ => None,
        }
    }
}

/// A run's family in the shot (the merge record's §1.5).
///
/// The three families the wire states: the document's own I-space placed
/// by reference, a window onto another document, or a staging draft's text
/// re-inserted as fresh identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// The document's own I-space, by reference — its bytes signed by value.
    Own,
    /// Another document's I-space, kept as a window — signed by address.
    Window,
    /// A draft side's fresh text, re-inserted by the shot.
    ///
    /// It lands under the document's own I-space, its bytes signed by value.
    DraftNative,
}

/// What [`compose`] returns before anything is written.
///
/// It is the core's result wrapped with what the landing needs (the merge
/// record's §1.5, "What the library returns before the write"; §7,
/// `Merged`).
///
/// [`compose`]: super::compose
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merged {
    /// The inputs as composed.
    pub inputs: Inputs,
    /// The core's result.
    ///
    /// It is M, the gap report, the counts, the value log, the resolutions
    /// not applied.
    pub composed: Composed,
    /// Each run of M's family, parallel to `composed.runs`.
    pub families: Vec<Family>,
    /// The key the record is current under, `record`'s own.
    ///
    /// It is `(doc, base, {sides}, {states})` ([`Record::key`]). A fork's
    /// and a draft's state are terms of it, so a merge composed over a side
    /// whose text has changed since is another key.
    pub key: RecordKey,
    /// The cap `composed.counts.m` is checked against at the landing.
    ///
    /// It is [`SHOT_RUN_CAP`]. The count is carried whatever it is, so a face
    /// can show it; the refusal is the landing's.
    ///
    /// [`SHOT_RUN_CAP`]: super::SHOT_RUN_CAP
    pub cap: usize,
    /// The record the landing will write, unlanded.
    ///
    /// Its `landed` is none, its `claims` none, its `replaces` the prior
    /// record's link where one stands, its draft side at `as_of`, the one
    /// position the draft was read at, and its fork and draft sides with
    /// their states as of it. The landing fills `landed` and
    /// `claims`, and sets `replaces` from its own read of the merger's
    /// newest record for the key (the `land` module's doc; P20).
    pub record: Record,
    /// The one position the shape's reads were taken at, P.
    ///
    /// It is the position the draft side named, else the `as_of` the first
    /// read answered; every frame the composition sent was answered at it
    /// (the `reads` module's doc). It is never the highest `as_of` any read
    /// answered: the prior records' lookup reads the journal at the head
    /// and raises no position here. The draft landing is typed against it.
    pub as_of: u64,
    /// The standing record for the key, where one is current.
    ///
    /// It is §3's "What a second agent sees", under the reader's currency
    /// (the trunk owner's records first) at the composition — a record of
    /// the key, its sides' states included, so a record composed over a
    /// fork or a draft side read in another state is none. The landing never
    /// lands by it: it reads the merger's own newest record for the key
    /// when it lands (the `land` module's doc).
    pub prior: Option<Record>,
    /// The head's content extent as read — the shot's `base_extent`.
    pub head_extent: u64,
    /// The head's and each side's image, in side order.
    ///
    /// The landing reads the shot's values through them.
    pub(in crate::merge) maps: Vec<Imaged>,
}
