//! THE ENTRY FRAME (signed ops; the design record §2.5, §4.2 (C)'s ENTRY row)
//! — the bytes a publish-class entry's signature, or under the `record` token
//! a record's `sig` (the frame merge, fm-I), is made over — and THE BYTE
//! FORMS of its members (D24's pins, the seam build's own of 2026-09-25,
//! re-pinned in place under `skep-entry-v1` by the publish re-pin and the
//! frame merge of 2026-09-29 — l6-A3: no `v1` signature is held before the
//! first served board, and dev boards regenerate): stated ONCE here, by
//! encoding and not by member, so the signer (a client, the test signer) and
//! the verifier (the daemon's check, a mirror beside the table) compose one
//! preimage from one description. Values in, bytes out: this crate reads no
//! world and holds no key (AUTH-2.1); what it fixes is how a value the caller
//! already holds is spelled into the frame, and [`entry_frame`] spells EVERY
//! member itself, so no caller spells one.
//!
//! THE FRAME. `framed(ENTRY_TAG, [alg, board, account, doc, op, body])`
//! (AUTH-1.12's framing: the tag, then each member — a FIELD, in AUTH-1.12's
//! word — as `be32(len) ‖ bytes`), every member a compiled constant, a
//! client-named address, a client-composed byte string or the board's
//! [`BoardTerm`], fixed from the board claim on — no fact the daemon assigns
//! at the entry's own commit (a minted address, a position, a seq) enters it,
//! which is what lets a client sign BEFORE the commit with no round trip and
//! the daemon verify AT the commit with no lookup, and what makes the
//! signature POSITION-FREE, in the design record's word: free of the entry's
//! own LOG position, so two identical writes sign identical bytes wherever in
//! the journal the commit lands them.
//!
//! THE ROWS, by encoding:
//!
//! * THE TOKEN ROW — `alg` (the `ALGS` token of the signing key) and `op`
//!   (the token naming the body's GRAMMAR, which each body's [`EntryBody`]
//!   carries beside it): the token's ASCII bytes as they stand. For the entry
//!   grade the token is the op-kind token as the wire spells it, one per
//!   publish-class op kind, each named beside its body in THE BODIES, below.
//!   ONE EXCEPTION (the frame merge, fm-I): `record` names the RECORD grade's
//!   body and no wire op — a record deposit rides an `insert` and a
//!   `make_link` on the wire, and its signature is the atom's own `sig`, made
//!   over the frame this token selects.
//! * THE ADDRESS ROW — `account` (at the ENTRY grade the act's principal's
//!   account in the board's local form; at the RECORD grade the HOME's
//!   account, never the depositing principal's — [`RecordFrame`]), `doc` (per
//!   op cell, the address the entry writes into — an `insert`'s or a
//!   `publish`'s target as its TRUNK, a link write's or a record's home, and
//!   at the three mints the PARENT ACCOUNT the minted document lands in, never
//!   `version`'s `d_src`; one address at every cell but `edit_link`'s, whose
//!   two homes are the pair's row, below), and every address inside a body:
//!   the dotted-decimal ASCII rendering M1's `Display` gives a tumbler
//!   (`1.0.1.0.1`) — lossless by T3, and the ONE spelling of the address among
//!   the several a string can carry: a component written with a leading zero
//!   (`1.01.0.1`) names the same address (`1.1.0.1`). So the frame spells the
//!   ADDRESS and never a string — [`entry_frame`], the insert's declared type,
//!   the windows, the base group and the `record` body's rows take `Address`
//!   values, and the slots `Span`s, whose start and width tumblers M1's
//!   `Display` spells the same one way — and a signer holding the address it
//!   named signs the bytes the verifier composes, whichever spelling carried
//!   it on the wire.
//! * THE BOARD ROW — `board`, the BOARD TERM ([`BoardTerm`]), `H.1`'s
//!   committed `(position, chain)` pair (D13, RULED) — its position a LOG
//!   position, never an element position: eight big-endian bytes, then the
//!   chain's thirty-two raw bytes — forty bytes, [`board_bytes`].
//! * THE VALUE-SEQUENCE ROW — content values in V-order WITH THEIR COUNT:
//!   `be64(count)` then, per value, `be32(len) ‖ bytes` — [`ValueSequence`],
//!   written whole by [`push_value_sequence`] and one value at a time by
//!   [`PublishBody`], which writes one such row per value STRETCH of a
//!   `publish` body. The count leads so a reader knows how many values the
//!   row holds before reading one.
//! * THE SLOT ROW — a link slot AS STORED (the design record §2.5's slot
//!   row as ruled — ap6-3, reading (i), and D24's byte form, d24-2): the
//!   stored endset's spans, verbatim and in stored order — one form byte,
//!   `0x03`, then `be64(n)`, then each span as its START and its WIDTH, each
//!   tumbler in the address row's dotted-decimal spelling and each
//!   length-delimited — [`push_slot`] over a borrowed walk of the stored
//!   spans (an [`EntrySlot`]'s slice, or M7's own `&Endset` where it lies),
//!   the count the walk's own. ONE form byte, for "as stored": a frame
//!   composed over a request's form fails at the row's first byte. The EMPTY
//!   slot has ONE spelling, `0x03 ‖ be64(0)`. A slot the client named by
//!   ADDRESS is stored as one unit subtree span per address ([`unit_span`],
//!   the spelling M7's `enc` gives), so its row is those spans; a slot the
//!   client sent as V-specs is stored as the I-extents the transaction
//!   resolves them to, so its row is those: the SIGNER resolves against the
//!   base the transaction will take and signs the resolved spans, the daemon
//!   composes the row from the endset its own transaction deposits (a
//!   mismatch is `attestation_invalid:signature`, the frame re-composed and
//!   re-signed), and a verifier composes the same row from the stored link
//!   alone.
//! * THE ADDRESS-LIST ROW — a list of addresses: one form byte, `0x01`, then
//!   `be64(n)`, then each address as the address row, length-delimited —
//!   [`push_address_list`]. Never a link slot's row: it spells the `record`
//!   body's two slot rows — a credential deposit's slots are address-form,
//!   the write path refusing any other (`resolved_from`), and store as the
//!   addresses named, so the row stands as pinned (d24-4) — the one address
//!   an optional-address row or the base group names, and THE PAIR'S ROW.
//! * THE PAIR'S ROW — an `edit_link`'s `doc` term, the one member of the
//!   frame naming TWO documents: the successor's home then the supersession
//!   claim's home, the op's own order, as an address-list row of two
//!   elements — `0x01 ‖ be64(2) ‖ be32(len) ‖ d_s ‖ be32(len) ‖ d_a`
//!   (d24-1), no new form byte and no separator, so a build that sent two
//!   members, a separator or one address fails at the row's second byte —
//!   [`DocTerm::Pair`]. Every other op's `doc` is one address, the address
//!   row ([`DocTerm::One`]), and [`entry_frame`] holds each body to its own
//!   shape.
//! * THE OPTIONAL-ADDRESS ROW — ONE length-delimited group, EMPTY (`be32(0)`)
//!   where no address is named, and otherwise holding the one address named
//!   as an address-list row of one element — [`push_optional_address`].
//!   The `make_link` body's `replaces` row (PUB-5.15, RES-308/310: the state
//!   the record REPLACES) and the `record` body's `replaces` and LINEAGE rows
//!   share it (fm-I's Q8: one form for the two optional rows). The group is
//!   what keeps the absent bytes apart from every present spelling: a present
//!   group whose list named nothing would still hold nine bytes, where the
//!   absent group holds none.
//! * THE WINDOW ROW — a run the MINTED MEMBER (the version a `publish` mints)
//!   holds BY ADDRESS: the run's I-START as the address row, length-delimited,
//!   then `be64(width)` — [`push_window`]. Which runs those are is the
//!   `publish` body's rule, stated in the child module `publish`.
//!
//! THE BODIES, per grammar — each an [`EntryBody`], the token paired with
//! its body, so a body is never framed under another token. The ten
//! publish-class op kinds each have a cell; `delete`, `copy` and `rearrange`
//! have none, since the store refuses every one of them into a published
//! document and the frame's domain holds no entry of those kinds:
//!
//! * `create_new_document`, `fork`, `version` — [`entry_body_empty`], under
//!   the op's own token: THE EMPTY BODY, the member PRESENT and empty —
//!   `be32(0)` in the frame — so what is attested is that this principal
//!   performed this kind of act on this board against this parent account
//!   (`doc`, the account the minted document lands in: the request's at
//!   `create_new_document`, the principal's own at `fork` and `version`),
//!   and nothing else; two such acts by one principal sign identical bytes
//!   (the design record §2.5's cell; D24's cells (1)–(3)). `version`'s
//!   `d_src` enters no row.
//! * `insert` — [`entry_body_insert`]: the DECLARED TYPE ADDRESS (the address
//!   row, length-delimited; empty where the insert declares none) then the
//!   values placed as a value sequence.
//! * `make_link` — over a [`LinkSlots`]: the type slot, then the `from` slot,
//!   then the `to` slot, each a slot row — the slots taken by name, so this
//!   order is spelled here and nowhere else — then the `replaces` row, an
//!   optional-address row: [`entry_body_make_link`] where the op carries no
//!   `replaces` member, [`entry_body_make_link_replacing`] where it names one.
//!   So a body with no `replaces` member is the three slots and an EMPTY
//!   group, never the three slots alone.
//! * `emit`, `nullify`, `assert_sup` — [`entry_body_emit`],
//!   [`entry_body_nullify`], [`entry_body_assert_sup`]: the `make_link`
//!   body's four rows over the STORED link, under the op's own token — the
//!   type slot, `from`, `to`, each a slot row, then the `replaces` row EMPTY
//!   by kind, none of the three carrying the member (D24's cells (4)–(6)).
//!   `nullify`'s rows are the retraction link M7 deposits, `(unit(home),
//!   unit(target), retraction)` — the type the retraction class's one unit
//!   span, fixed by kind; `assert_sup`'s `(unit(old), unit(new),
//!   supersedes)`; `emit`'s `(unit(from), unit(each of to), ty)`, the type
//!   the request's spans verbatim as M7 stores them, and `to` EMPTY at a
//!   Unary class. The request shapes differ from `make_link`'s and the
//!   frame never sees them: the rows are the stored link's, so a verifier
//!   composes them from `read_link` alone.
//! * `edit_link` — [`entry_body_edit_link`]: FIVE rows (D24's cell (7),
//!   d24-6) — the successor as a `make_link` body, its type, `from` and `to`
//!   slots AS STORED (the I-extents the V-specs resolve to; the type as
//!   named, or resolved) and its `replaces` row EMPTY by kind, then THE
//!   FIFTH ROW, the SUPERSESSION CLAIM's `from` slot as stored: `original`'s
//!   one unit span. The supersession claim's `to` — the successor's address,
//!   minted inside the transaction — and its type, the supersedes constant,
//!   are NO rows. Its `doc` is the pair's row.
//! * `publish` — [`entry_body_publish`], or piece by piece under a byte
//!   budget by [`PublishBody`]: the count of positions placed, the shot's
//!   runs as segments — each a value stretch or a window behind its class
//!   byte — then the base group. Its grammar is stated beside its builder,
//!   in the child module `publish`, the one module the builder's fields are
//!   visible to.
//! * `record` — [`entry_body_record`] over a [`RecordRows`]: THE RECORD
//!   GRADE's body (the frame merge, fm-I, RULED 2026-09-29; its design record
//!   §3), under the `record` token. A record deposit's `sig` rides the atom,
//!   canonically last, and the marker slot stays EMPTY at both of its
//!   commits; the entry frame over this body — what the design record called
//!   "the record frame", [`RecordFrame`] — is the preimage that `sig` is made
//!   over. The body's FIVE rows, taken by name as `make_link`'s slots are, in
//!   this order: (1) the TYPE slot row — the link's type address as an
//!   address-list row of one element; (2) the `to` slot row — the link's
//!   target slot as an address-list row, EMPTY (`0x01 ‖ be64(0)`) at a
//!   targetless kind — both rows standing under `0x01` (d24-4: a credential
//!   deposit's slots are address-form, the write path refusing any other, and
//!   store as the addresses named, so no `record` preimage moved with the
//!   slot row's re-pin); (3) the `replaces` row, an optional-address row as
//!   `make_link`'s is (l6-A1; EMPTY by kind at a credential deposit); (4) the
//!   LINEAGE row, an optional-address row — the EMPTY group on a lineage that
//!   has not forked, else the fork point's address (D2); (5) the BODY-BYTES
//!   row — the sig-less canonical record bytes
//!   ([`canonical_record`](crate::canonical_record) with no `sig`), one
//!   length-delimited element. `from` — the atom the `sig` rides, whose
//!   address does not exist when the `sig` is composed — is NO row, and the
//!   subject needs none: it is the `to` slot at a credential deposit and the
//!   frame's `account` at a registry deposit or a targetless kind. This crate
//!   pins the grammar and, in [`RecordFrame`], the frame's two address
//!   members: `account` the HOME's account and `doc` the home — a credential
//!   record's own doc 1 (AUTH-2.127). Who signs and verifies over it, and
//!   what a record carrying no `sig` is answered, is the record grade's (2a)
//!   and the host's: the crate-level composition note says where skepd does.
//!
//! Every length-delimited element is written by [`push_delimited`], the one
//! function [`framed`] delimits its own fields with, and a spelling that
//! carries no length of its own — a token, an address, a value — is written
//! only as such an element. Every other row is self-delimiting — fixed-width
//! fields and delimited elements, with a count ahead of any element that
//! repeats — and stands where its grammar puts it. The one run with no count
//! of its segments ahead is a `publish` body's: each segment opens with its
//! class byte and carries at least one position, so the run ends where the
//! positions its segments carry reach the body's leading `be64(placed)`, the
//! base group following it. So every body is uniquely decodable from its
//! front, and the composition is injective at every level: two distinct
//! inputs never spell one preimage.

use skep_address::{subtree_of, Address, Span};

use crate::framing::{framed, push_delimited, ENTRY_TAG};

mod publish;

pub use publish::{entry_body_publish, PublishBody, PublishRefusal, ShotBase, ShotSegmentPiece};

/// THE ENTRY FRAME: `framed(ENTRY_TAG, [alg, board, account, doc, op, body])`
/// (AUTH-1.12's framing), EVERY member spelled here from the value the caller
/// holds, so a signer and a verifier holding the same values compose the same
/// bytes and no caller spells a member for itself:
///
/// * `alg` — the signing key's `ALGS` token, its ASCII bytes;
/// * `board` — the [`BoardTerm`] (D13): `be64(log_position) ‖ chain`, forty
///   bytes;
/// * `account` — the ADDRESS in its dotted-decimal spelling (`1.0.1.0.1`),
///   the one spelling of the address whatever string named it: the act's
///   principal's account at the entry grade, the HOME's account at the record
///   grade ([`RecordFrame`], which takes it by name);
/// * `doc` — the [`DocTerm`]: one address as the address row, or an
///   `edit_link`'s two homes as the pair's row;
/// * `op`, `body` — the [`EntryBody`]'s token and bytes, which its builder
///   ([`entry_body_empty`], [`entry_body_insert`], [`entry_body_make_link`],
///   [`entry_body_make_link_replacing`], [`entry_body_emit`],
///   [`entry_body_nullify`], [`entry_body_assert_sup`],
///   [`entry_body_edit_link`], [`entry_body_publish`], [`PublishBody`],
///   [`entry_body_record`]) pairs.
///
/// PRECONDITION — as [`framed`]'s: every member is shorter than 2^32 bytes.
/// A longer member PANICS, naming the obligation — a caller's bug and never
/// an outcome. The body is the one member that grows with the write, and no
/// body the daemon composes reaches the bound: each grammar's is held to a
/// bound of its own before it is framed ([`framed`]'s card names them).
///
/// PRECONDITION — `doc` is the shape `body`'s grammar takes: the pair's row
/// ([`DocTerm::Pair`]) under an `edit_link` body, the one op naming two homes
/// (d24-1), and one address ([`DocTerm::One`]) under every other. A frame of
/// the other shape is one no verifier composes — every signature over it is
/// refused `attestation_invalid:signature`, nothing naming the term — so it
/// is a caller's bug and never an outcome: it PANICS, naming the obligation.
pub fn entry_frame(
    alg: &str,
    board: BoardTerm,
    account: &Address,
    doc: DocTerm<'_>,
    body: &EntryBody,
) -> Vec<u8> {
    let doc_names_two_homes = matches!(doc, DocTerm::Pair { .. });
    assert!(
        doc_names_two_homes == body.grammar.names_two_homes(),
        "entry_frame: the `doc` term is the grammar's — the pair's row for an `edit_link` body \
         and one address for every other (d24-1) — and this `{}` body was framed under {}",
        body.op(),
        if doc_names_two_homes { "the pair's row" } else { "one address" }
    );
    framed(
        ENTRY_TAG,
        &[
            alg.as_bytes(),
            &board_bytes(&board),
            &address_bytes(account),
            &doc_bytes(doc),
            body.op().as_bytes(),
            &body.bytes,
        ],
    )
}

/// THE FRAME'S `doc` TERM — the address an entry writes INTO, per op cell
/// (the design record's "address term"): ONE address for every op but one —
/// an `insert`'s or a `publish`'s target as its TRUNK, a link write's home, a
/// mint's PARENT ACCOUNT (never `version`'s `d_src`), a record's home —
/// spelled as the address row; and for `edit_link`, the one op that writes
/// TWO homes, the successor's and the supersession claim's, spelled as THE
/// PAIR'S ROW (d24-1), `0x01 ‖ be64(2) ‖ be32(len) ‖ d_s ‖ be32(len) ‖ d_a`.
/// The two homes are taken BY NAME: the op's own order, `d_s` then `d_a`, is
/// spelled once, in `doc_bytes`, and a call site that named them the other
/// way round would be a frame every verifier refuses. The shape is the body's
/// grammar's, and [`entry_frame`] holds each body to its own. `Copy`, as the
/// addresses it borrows are: a view of the caller's term, never an owner of
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocTerm<'a> {
    /// One address — a document, or a mint's parent account: the address row.
    One(&'a Address),
    /// An `edit_link`'s two homes: the pair's row.
    Pair {
        /// The successor's home, `d_s` — first, the op's own order.
        d_s: &'a Address,
        /// The supersession claim's home, `d_a`.
        d_a: &'a Address,
    },
}

/// The `doc` member's bytes: the address row, or the pair's row.
fn doc_bytes(doc: DocTerm<'_>) -> Vec<u8> {
    match doc {
        DocTerm::One(a) => address_bytes(a),
        DocTerm::Pair { d_s, d_a } => {
            let mut out = Vec::new();
            push_address_list(&mut out, [d_s, d_a]);
            out
        }
    }
}

/// THE UNIT SPAN at `a` — the one subtree span an address names when a link
/// slot is given BY ADDRESS, the spelling M7's `enc` stores for it: the
/// address's own tumbler as the start and the unit at its own length as the
/// width (`1.0.1` is the span from `1.0.1` of width `0.0.1`). A link slot
/// named by address stores as one of these per address, so the slot row of
/// such a slot — `make_link`'s address form, `nullify`'s and `assert_sup`'s
/// one-address slots, `emit`'s `from` and `to`, the `edit_link` supersession
/// claim's `from` — is these spans. Spelled here so a signer holding the
/// address alone and a verifier holding the stored link compose one row;
/// skepd's composer holds it equal to M7's own `enc`.
pub fn unit_span(a: &Address) -> Span {
    subtree_of(a.tumbler())
}

/// THE BOARD TERM (signed ops; the design record §2.5, D13, RULED): the
/// committed `(position, chain)` pair `H.1` — the head document's first chain
/// member — NAMES, fixed from the board claim on for the life of the board.
/// It is the entry frame's `board` member ([`entry_frame`]) at both grades —
/// an entry's, and a record's under the `record` token ([`RecordFrame`]; the
/// design record §4.2 (C), the frame merge, fm-I) — one term, one frame. It is
/// NEVER the live pair `/health` serves, nor the pair any later head names: a
/// signature framed over either is refused `attestation_invalid:signature`.
/// A value: two terms are equal iff both halves are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoardTerm {
    /// The LOG position `H.1` names — a point in the journal, M2's `Seq` and
    /// the axis the wire serves as `/health`'s `log_position` — never an
    /// element position, which is what bare "position" means everywhere else
    /// in this crate ([`Values`](crate::Values)).
    pub log_position: u64,
    /// The whole-log chain value at that LOG position, thirty-two raw bytes.
    pub chain: [u8; 32],
}

/// ONE entry's `op` and `body` members, held together because they are one
/// fact: each grammar has its own body, and the `op` token names which.
/// Built only by [`entry_body_empty`], [`entry_body_insert`], the two
/// `make_link` builders ([`entry_body_make_link`],
/// [`entry_body_make_link_replacing`]), the three other link writes'
/// ([`entry_body_emit`], [`entry_body_nullify`], [`entry_body_assert_sup`]),
/// [`entry_body_edit_link`], [`PublishBody`] — [`entry_body_publish`] among
/// its builds — and [`entry_body_record`], so a body cannot be framed under
/// another grammar's token, and a `publish` body cannot be finished over
/// fewer pieces than its builder was offered. The tokens are the op-kind
/// names as the wire spells them — `create_new_document`, `fork`,
/// `version`, `insert`, `make_link`, `emit`, `nullify`, `assert_sup`,
/// `edit_link`, `publish` — and the record grade's `record`, spelled HERE,
/// once each, in the one private match over the GRAMMARS they select,
/// because they are members of a signed preimage that a reader beside the
/// table recomposes from this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryBody {
    grammar: Grammar,
    bytes: Vec<u8>,
}

impl EntryBody {
    /// The frame's `op` member: the token naming the body's grammar — the
    /// op-kind token as the wire spells it, or `record`.
    pub fn op(&self) -> &'static str {
        self.grammar.token()
    }

    /// The frame's `body` member: the body in its grammar's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The body GRAMMARS — one per cell of the frame, the record grade's
/// included — each naming its frame's `op` token and the shape of its `doc`
/// term. Private: a body is minted only by its own builder, which names its
/// grammar, and a caller reads the token ([`EntryBody::op`]). Each answer
/// below is an exhaustive match, so a grammar added here does not compile
/// until it spells its token and says whether its frame names one home or
/// two — the question [`entry_frame`] asks of every body it frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grammar {
    /// The three mints' EMPTY body ([`entry_body_empty`]), each under its
    /// op's own token.
    ContentFree(ContentFreeOp),
    /// `insert`'s: the declared type, then the values.
    Insert,
    /// `make_link`'s, with its `replaces` row EMPTY or naming the member.
    MakeLink,
    /// `emit`'s, over the tuple M7 deposits.
    Emit,
    /// `nullify`'s, over the retraction link M7 deposits.
    Nullify,
    /// `assert_sup`'s, over the supersession claim M7 deposits.
    AssertSup,
    /// `edit_link`'s: the successor's rows, then the supersession claim's
    /// `from` — the one grammar whose frame names two homes.
    EditLink,
    /// `publish`'s, built piece by piece by [`PublishBody`].
    Publish,
    /// The record grade's body — the one token no wire op spells.
    Record,
}

impl Grammar {
    /// The frame's `op` member: the op-kind token as the wire spells it, or
    /// `record` — each spelled here, once.
    fn token(self) -> &'static str {
        match self {
            Grammar::ContentFree(ContentFreeOp::CreateNewDocument) => "create_new_document",
            Grammar::ContentFree(ContentFreeOp::Fork) => "fork",
            Grammar::ContentFree(ContentFreeOp::Version) => "version",
            Grammar::Insert => "insert",
            Grammar::MakeLink => "make_link",
            Grammar::Emit => "emit",
            Grammar::Nullify => "nullify",
            Grammar::AssertSup => "assert_sup",
            Grammar::EditLink => "edit_link",
            Grammar::Publish => "publish",
            Grammar::Record => "record",
        }
    }

    /// Whether the frame's `doc` term is the pair's row (d24-1) rather than
    /// one address: `edit_link`'s alone, the one op writing two homes.
    fn names_two_homes(self) -> bool {
        match self {
            Grammar::EditLink => true,
            Grammar::ContentFree(_)
            | Grammar::Insert
            | Grammar::MakeLink
            | Grammar::Emit
            | Grammar::Nullify
            | Grammar::AssertSup
            | Grammar::Publish
            | Grammar::Record => false,
        }
    }
}

/// THE BOARD ROW: `be64(log_position) ‖ chain` — forty bytes.
fn board_bytes(board: &BoardTerm) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..8].copy_from_slice(&board.log_position.to_be_bytes());
    out[8..].copy_from_slice(&board.chain);
    out
}

/// THE ADDRESS ROW: the dotted-decimal ASCII of the address.
fn address_bytes(a: &Address) -> Vec<u8> {
    a.to_string().into_bytes()
}

/// THE VALUE-SEQUENCE ROW, written onto a body's buffer one value at a time:
/// `be64(count)` then each value length-delimited, in the order pushed. The
/// count LEADS but is known only once the values are down, so its eight bytes
/// are held where the row begins and written back by [`ValueSequence::close`]:
/// the values are walked once, as they come, and never collected. The ONE
/// statement of the row's layout — [`push_value_sequence`] writes a whole
/// sequence through it, [`PublishBody`] one value at a time.
#[derive(Debug)]
struct ValueSequence {
    /// Where the row, and so its held count, begins in the buffer.
    at: usize,
    count: u64,
}

impl ValueSequence {
    /// Open the row at the end of `out`, its count held.
    fn open(out: &mut Vec<u8>) -> ValueSequence {
        let at = out.len();
        out.extend_from_slice(&0u64.to_be_bytes());
        ValueSequence { at, count: 0 }
    }

    /// One more value, length-delimited, after the last.
    fn push(&mut self, out: &mut Vec<u8>, value: &[u8]) {
        push_delimited(out, value);
        self.count += 1;
    }

    /// Write the count back where the row began.
    fn close(self, out: &mut [u8]) {
        let count = self.count.to_be_bytes();
        out[self.at..self.at + count.len()].copy_from_slice(&count);
    }
}

/// THE VALUE-SEQUENCE ROW over a whole sequence, onto `out`.
fn push_value_sequence<'a>(out: &mut Vec<u8>, values: impl IntoIterator<Item = &'a [u8]>) {
    let mut row = ValueSequence::open(out);
    for v in values {
        row.push(out, v);
    }
    row.close(out);
}

/// A link slot AS STORED — the ONE form a slot row takes: the endset's
/// spans, verbatim and in stored order, as M7 holds them (`Endset`,
/// verbatim at rest) and as `read_link` serves them. A slot named by
/// address is one [`unit_span`] per address; a slot sent as V-specs is the
/// I-extents the transaction resolved them to. The request's forms enter no
/// frame. `Copy`, as the slice it borrows is: a view of the caller's spans,
/// never an owner of them.
///
/// It is the slot as a SLICE of those spans — one of the walks a
/// [`LinkSlots`] takes, for a caller holding them so (a signer composing
/// from a request, a mirror from `read_link`'s answer); a caller holding the
/// store's own slot, M7's `&Endset`, passes that instead, in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntrySlot<'a>(pub &'a [Span]);

/// The slot's spans, walked in stored order — what its slot row is written
/// from.
impl<'a> IntoIterator for EntrySlot<'a> {
    type Item = &'a Span;
    type IntoIter = core::slice::Iter<'a, Span>;

    fn into_iter(self) -> core::slice::Iter<'a, Span> {
        self.0.iter()
    }
}

/// A link write's three link slots, BY NAME. They are three values of one
/// type, and the body lays them out in an order of its own — the TYPE slot
/// first (the design record §2.5) — while every other place the workspace
/// names a link's slots names them `from`, `to`, `ty`: M7's `Link::triple`
/// and `LinkWriter::makelink`, M10's `Op::MakeLink` and `SuccessorSpec`, this
/// crate's own [`LinkDeposit`](crate::LinkDeposit). Taken positionally, the
/// natural transcription of any of those would compile, frame the slots out
/// of order, and have every attested link write its signer made refused
/// `attestation_invalid:signature`, with nothing naming the order. By field,
/// the call site says which slot is which, and the order is spelled once, in
/// the one body every link-write builder writes through.
///
/// Each slot is a borrowed WALK of its spans as stored, in stored order —
/// `S` is whatever the caller holds the three in: [`EntrySlot`]s over
/// slices, or M7's own `&Endset`s, read off a stored link where they lie. A
/// slot row needs the walk and nothing more, so a composer framing the link
/// its transaction will deposit hands the store's slots over in place and
/// copies no span into a slice to have it framed.
///
/// Not `#[non_exhaustive]`: every caller builds one, and a link has exactly
/// these three slots. The body's fourth row, the `replaces` member, is no
/// slot of the link the record is: it names the state the record replaces,
/// and what it deposits is a SECOND link (PUB-5.15). So it is not a field
/// here — its presence is the builder's choice,
/// [`entry_body_make_link_replacing`] against [`entry_body_make_link`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkSlots<S> {
    /// The `from` slot.
    pub from: S,
    /// The `to` slot.
    pub to: S,
    /// The type slot.
    pub ty: S,
}

/// The slot row's ONE form byte: the stored spans.
const SLOT_FORM_STORED: u8 = 0x03;

/// The address-list row's form byte.
const ADDRESS_LIST_FORM: u8 = 0x01;

/// THE SLOT ROW, onto `out`: the form byte `0x03`, `be64(n)`, then each span
/// as its start and its width, each tumbler in the address row's spelling,
/// each length-delimited — the module doc's row. `slot` is any borrowed walk
/// of the stored spans, so `n` is the walk's own: held where the row begins
/// and written back once the spans are down, as [`ValueSequence`] holds the
/// value-sequence row's — never a length the walk claims.
fn push_slot<'s>(out: &mut Vec<u8>, slot: impl IntoIterator<Item = &'s Span>) {
    out.push(SLOT_FORM_STORED);
    let at = out.len();
    out.extend_from_slice(&0u64.to_be_bytes());
    let mut n: u64 = 0;
    for span in slot {
        push_delimited(out, span.start().to_string().as_bytes());
        push_delimited(out, span.width().to_string().as_bytes());
        n += 1;
    }
    out[at..at + 8].copy_from_slice(&n.to_be_bytes());
}

/// THE ADDRESS-LIST ROW, onto `out`: the form byte `0x01`, `be64(n)`, then
/// each address as the address row, length-delimited. `addrs` is any borrowed
/// walk of known length — a slice, or addresses held apart (the pair's two
/// homes, one named address) listed by reference, never cloned to be listed.
fn push_address_list<'a, I>(out: &mut Vec<u8>, addrs: I)
where
    I: IntoIterator<Item = &'a Address>,
    I::IntoIter: ExactSizeIterator,
{
    let addrs = addrs.into_iter();
    out.push(ADDRESS_LIST_FORM);
    out.extend_from_slice(&(addrs.len() as u64).to_be_bytes());
    for a in addrs {
        push_delimited(out, &address_bytes(a));
    }
}

/// THE OPTIONAL-ADDRESS ROW, onto `out`: ONE length-delimited group — EMPTY
/// where no address is named, else the address as an address-list row of
/// one element. Delimited as a whole so that no present spelling can meet
/// the absent one: the least a present group holds is an address-list row's
/// form byte and count, nine bytes. The `make_link` body's `replaces` row and
/// the `record` body's `replaces` and lineage rows are each one of these.
fn push_optional_address(out: &mut Vec<u8>, named: Option<&Address>) {
    let mut group = Vec::new();
    if let Some(a) = named {
        push_address_list(&mut group, [a]);
    }
    push_delimited(out, &group);
}

/// THE WINDOW ROW, onto `out`: the run's I-start in its dotted-decimal
/// spelling, length-delimited, then `be64(width)`. `start` arrives spelled
/// because [`PublishBody::window`] has already measured it against the
/// budget.
fn push_window(out: &mut Vec<u8>, start: &[u8], width: u64) {
    push_delimited(out, start);
    out.extend_from_slice(&width.to_be_bytes());
}

/// THE THREE CONTENT-FREE OPS — the mints whose cell is the EMPTY body
/// ([`entry_body_empty`]): each selects its own `op` token, the op-kind
/// token as the wire spells it, so a `fork`'s empty body is never framed as
/// a `version`'s. Which of the three a write is, and that it is one of them
/// at all, is the caller's to say — this crate spells what it is handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentFreeOp {
    /// `create_new_document` — a mint born published.
    CreateNewDocument,
    /// `fork` — the content-empty mint into the principal's own account.
    Fork,
    /// `version` — the content-sharing fork, owned or cross-owner alike.
    Version,
}

/// THE EMPTY BODY, under `op`'s token: no bytes at all, the member PRESENT
/// and empty — `be32(0)` where [`entry_frame`] frames it (the design record
/// §2.5's cell; D24's cells (1)–(3), b2). A mint born published, a `fork`
/// and a `version` sign it over their parent account: the signature attests
/// that THIS principal performed THIS kind of act on THIS board against
/// THIS parent, and nothing else — no content, and no minted address, a
/// daemon fact the frame cannot carry. So two such acts by one principal on
/// one board sign identical bytes, which is the ruled residue ("2 keep
/// signed"), and `version`'s `d_src` enters no row.
pub fn entry_body_empty(op: ContentFreeOp) -> EntryBody {
    EntryBody { grammar: Grammar::ContentFree(op), bytes: Vec::new() }
}

/// THE `insert` BODY, under the `insert` token: the declared type address in
/// its dotted-decimal spelling, length-delimited (empty where undeclared),
/// then the values placed as a value sequence — `be64(count)`, then each
/// value as `be32(len) ‖ bytes`.
///
/// PRECONDITION — every value, and the declared type's spelling, is shorter
/// than 2^32 bytes: its length is [`framed`]'s `be32`, and a longer element
/// PANICS, naming the obligation, rather than truncate it.
pub fn entry_body_insert<'a>(
    declared_type: Option<&Address>,
    values: impl IntoIterator<Item = &'a [u8]>,
) -> EntryBody {
    let mut out = Vec::new();
    match declared_type {
        Some(ty) => push_delimited(&mut out, &address_bytes(ty)),
        None => push_delimited(&mut out, &[]),
    }
    push_value_sequence(&mut out, values);
    EntryBody { grammar: Grammar::Insert, bytes: out }
}

/// THE `make_link` BODY of an op carrying NO `replaces` member — the EMPTY
/// state (PUB-5.15: a first share names it by the member's absence), under
/// the `make_link` token: the TYPE slot, then the `from` slot, then the `to`
/// slot — the body's order, whatever order the caller names them in — each
/// AS STORED, a slot row: the form byte `0x03`, `be64(n)`, then each span's
/// start and width, each in its dotted-decimal spelling and
/// length-delimited; then the `replaces` row EMPTY, `be32(0)`.
///
/// PRECONDITION — every tumbler's spelling (a span's start or width) is
/// shorter than 2^32 bytes, as [`entry_body_insert`]'s values are; a longer
/// one PANICS, naming the obligation.
pub fn entry_body_make_link<'s>(slots: LinkSlots<impl IntoIterator<Item = &'s Span>>) -> EntryBody {
    link_write_body(Grammar::MakeLink, slots, None)
}

/// THE `make_link` BODY of an op whose `replaces` member names `replaces` —
/// the record the one being written follows (PUB-5.15 (iv): the revocation a
/// re-share follows): [`entry_body_make_link`]'s three slots, then the
/// `replaces` row holding the member as an address-list row of one element,
/// the whole group length-delimited. So the member is inside the signed
/// bytes, and a hand that edits it breaks the signature.
///
/// PRECONDITION — as [`entry_body_make_link`]'s, and the `replaces` row's
/// group shorter than 2^32 bytes as well: the member's spelling and the
/// thirteen bytes its one-element address-list row puts around it (a form
/// byte, a `be64` count, a `be32` length) together. A longer one PANICS,
/// naming the obligation.
pub fn entry_body_make_link_replacing<'s>(
    slots: LinkSlots<impl IntoIterator<Item = &'s Span>>,
    replaces: &Address,
) -> EntryBody {
    link_write_body(Grammar::MakeLink, slots, Some(replaces))
}

/// THE `emit` BODY, under the `emit` token: the `make_link` body's four rows
/// over the tuple M7 deposits — the type slot the request's spans VERBATIM,
/// as M7 stores `ty` for e₃; `from` the one address's unit span; `to` one
/// unit span per address, EMPTY (`0x03 ‖ be64(0)`) at a Unary class — and
/// the `replaces` row EMPTY by kind: an `emit` carries no member, and one
/// typed the `replaces` class is refused. PRECONDITION as
/// [`entry_body_make_link`]'s.
pub fn entry_body_emit<'s>(slots: LinkSlots<impl IntoIterator<Item = &'s Span>>) -> EntryBody {
    link_write_body(Grammar::Emit, slots, None)
}

/// THE `nullify` BODY, under the `nullify` token: the `make_link` body's four
/// rows over the retraction link M7 deposits, `(unit(home), unit(target),
/// retraction)` — the type slot the retraction class's one unit span, a
/// constant fixed by kind; `from` the home's unit span, the frame's own `doc`
/// again, kept so the body IS the stored link; `to` the nullified link's unit
/// span — and the `replaces` row EMPTY by kind. PRECONDITION as
/// [`entry_body_make_link`]'s.
pub fn entry_body_nullify<'s>(slots: LinkSlots<impl IntoIterator<Item = &'s Span>>) -> EntryBody {
    link_write_body(Grammar::Nullify, slots, None)
}

/// THE `assert_sup` BODY, under the `assert_sup` token: the `make_link`
/// body's four rows over the supersession claim M7 deposits, `(unit(old),
/// unit(new), supersedes)` — the type slot the supersedes class's one unit
/// span, fixed by kind; `from` the superseded link's unit span; `to` its
/// successor's — and the `replaces` row EMPTY by kind. PRECONDITION as
/// [`entry_body_make_link`]'s.
pub fn entry_body_assert_sup<'s>(
    slots: LinkSlots<impl IntoIterator<Item = &'s Span>>,
) -> EntryBody {
    link_write_body(Grammar::AssertSup, slots, None)
}

/// THE `edit_link` BODY, under the `edit_link` token — FIVE rows (the design
/// record §2.5's cell; D24's cell (7), d24-6): the SUCCESSOR as a
/// `make_link` body — its type, `from` and `to` slots AS STORED, the
/// I-extents its V-specs resolve to (the type as named, or resolved), and its
/// `replaces` row EMPTY by kind, a `replaces`-typed successor being refused
/// — then THE FIFTH ROW, the SUPERSESSION CLAIM's `from` slot as stored:
/// `original`'s one unit span, which the caller passes as the span
/// ([`unit_span`]) so this builder spells no address. The supersession
/// claim's `to` — the successor's address, minted inside the transaction —
/// and its type, the supersedes constant, are no rows: a verifier reads the
/// supersession claim's `from` off `read_link` at its home, `d_a`, as it
/// reads the successor's slots off the successor's, one composer for the
/// five rows. The body's `doc` is the pair's row ([`DocTerm::Pair`]).
/// PRECONDITION as [`entry_body_make_link`]'s.
pub fn entry_body_edit_link<'s>(
    successor: LinkSlots<impl IntoIterator<Item = &'s Span>>,
    original: &Span,
) -> EntryBody {
    let mut body = link_write_body(Grammar::EditLink, successor, None);
    push_slot(&mut body.bytes, [original]);
    body
}

/// The one link-write body every link-write builder writes through, so the
/// slots' order and the `replaces` row's place after them are spelled once,
/// under the grammar the builder names.
fn link_write_body<'s>(
    grammar: Grammar,
    slots: LinkSlots<impl IntoIterator<Item = &'s Span>>,
    replaces: Option<&Address>,
) -> EntryBody {
    let LinkSlots { from, to, ty } = slots;
    let mut out = Vec::new();
    push_slot(&mut out, ty);
    push_slot(&mut out, from);
    push_slot(&mut out, to);
    push_optional_address(&mut out, replaces);
    EntryBody { grammar, bytes: out }
}

/// A `record` body's FIVE ROWS, BY NAME — the one argument
/// [`entry_body_record`] takes. Two of them share a type: the `replaces` row
/// and the LINEAGE row are each an optional address, the first EMPTY by kind
/// at a credential deposit (l6-A1), the second EMPTY on a lineage that has
/// not forked (D2). Taken positionally, the two would stand side by side as
/// two unlabelled `None`s at every call, and the first caller to name one —
/// a forked lineage's fork point — would choose between two adjacent
/// positions no call site labels: the wrong one compiles, frames the address
/// in the other row, and has every record so signed refused
/// `attestation_invalid:signature`, with nothing naming the order. By field,
/// as [`LinkSlots`] takes a link's slots, the call site says which row is
/// which, and names the body-bytes row the SIG-LESS record at every call —
/// never the atom its `sig` rides.
///
/// Not `#[non_exhaustive]`: every composer builds one, and a row the grammar
/// gains is one every composer — signer and verifier alike — must name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordRows<'a> {
    /// Row (1): the link's type address — an address-list row of one
    /// element.
    pub ty: &'a Address,
    /// Row (2): the link's target slot — an address-list row, EMPTY at a
    /// targetless kind.
    pub to: &'a [Address],
    /// Row (3): the state the record replaces — the EMPTY group where `None`.
    pub replaces: Option<&'a Address>,
    /// Row (4): the address the lineage forked at — the EMPTY group on a
    /// lineage that has not forked (D2).
    pub lineage_fork_point: Option<&'a Address>,
    /// Row (5): the SIG-LESS CANONICAL RECORD, the record with its `sig`
    /// member removed ([`canonical_record`](crate::canonical_record) over its
    /// entries with no `sig`) — one length-delimited element.
    pub sigless_canonical_record: &'a [u8],
}

/// THE `record` BODY, under the `record` token — the record grade's preimage
/// (the frame merge, fm-I; its design record §3): the [`RecordRows`] in the
/// body's order — the TYPE slot row and the `to` slot row, each an
/// ADDRESS-LIST row (the `to` row EMPTY, `0x01 ‖ be64(0)`, at a targetless
/// kind; both under `0x01`, d24-4), the `replaces` row and the LINEAGE row
/// (each an optional-address row: the EMPTY group where nothing is named,
/// else the address as an address-list row of one element, delimited), then
/// the sig-less canonical record as one length-delimited element. `from` is
/// no row.
///
/// PRECONDITION — every address's spelling, and the sig-less canonical
/// record, is shorter than 2^32 bytes, and so is each optional row's group:
/// a named address's spelling and the thirteen bytes its one-element
/// address-list row puts around it (a form byte, a `be64` count, a `be32`
/// length). A longer one PANICS, naming the obligation.
pub fn entry_body_record(rows: RecordRows<'_>) -> EntryBody {
    let RecordRows { ty, to, replaces, lineage_fork_point, sigless_canonical_record } = rows;
    let mut out = Vec::new();
    push_address_list(&mut out, [ty]);
    push_address_list(&mut out, to);
    push_optional_address(&mut out, replaces);
    push_optional_address(&mut out, lineage_fork_point);
    push_delimited(&mut out, sigless_canonical_record);
    EntryBody { grammar: Grammar::Record, bytes: out }
}

/// THE RECORD FRAME — the record grade's preimage but for its `alg` (the
/// frame merge, fm-I; its design record §3): the entry frame under the
/// `record` grammar, its two address members FIXED BY THE GRADE and taken BY
/// NAME. `account` is the HOME's account — never the depositing principal's,
/// the entry grade's member, which enters no record frame (the design record
/// §4.5's clause (a)) — and `doc` is the home, one address, never the pair's
/// row. The two are addresses of one type, so a frame with them traded
/// compiles, signs and never verifies: by field, as [`RecordRows`] takes the
/// body's rows, the call site says which is which.
///
/// Every party to a record composes this one value — the signer before its
/// deposit, the daemon at the record's `make_link`, a mirror off `find_links`
/// and `retrieve` — each READING the members its own way (`H.1` off its
/// board, the home's account by ω); what fills which member is the grammar's,
/// spelled here once. `Copy`, as the views it holds are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordFrame<'a> {
    /// The frame's `board`: `H.1`'s pair (D13).
    pub board: BoardTerm,
    /// The frame's `account`: the HOME's account — ω over the home, the
    /// fold's own H (AUTH-2.35) — which at every honored credential record is
    /// the account whose doc 1 the home is (AUTH-2.126, AUTH-2.127).
    pub home_account: &'a Address,
    /// The frame's `doc`: the link's home.
    pub home: &'a Address,
    /// The body's five rows, under the `record` token.
    pub rows: RecordRows<'a>,
}

impl RecordFrame<'_> {
    /// The frame's bytes under `alg`, the signing key's `ALGS` token:
    /// [`entry_frame`] over [`entry_body_record`] of the rows, the home's
    /// account as `account` and the home as `doc`. A verifier asks once per
    /// candidate key, under that key's own token; the body is spelled at each
    /// ask — one more copy of the rows beside the one [`entry_frame`] makes,
    /// and the verify's own pass over the frame.
    ///
    /// PRECONDITION — as [`entry_frame`]'s and [`entry_body_record`]'s: it
    /// PANICS where either does.
    pub fn to_bytes(&self, alg: &str) -> Vec<u8> {
        let body = entry_body_record(self.rows);
        entry_frame(alg, self.board, self.home_account, DocTerm::One(self.home), &body)
    }
}

#[cfg(test)]
mod tests;
