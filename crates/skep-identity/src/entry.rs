//! THE ENTRY FRAME (signed ops; the design record §2.5, §4.2 (C)'s ENTRY row)
//! — the bytes a publish-class entry's signature is made over — and THE BYTE
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
//! [`BoardTerm`], fixed from the claim on — no fact the daemon assigns at the
//! entry's own commit (a minted address, a position, a seq) enters it, which
//! is what lets a client sign BEFORE the commit with no round trip and the
//! daemon verify AT the commit with no lookup, and what makes the signature
//! POSITION-FREE, in the design record's word: free of the entry's own LOG
//! position, so two identical writes sign identical bytes wherever in the
//! journal the commit lands them.
//!
//! THE ROWS, by encoding:
//!
//! * THE TOKEN ROW — `alg` (the `ALGS` token of the signing key) and `op`
//!   (the token naming the body's GRAMMAR, which each body's [`EntryBody`]
//!   carries beside it): the token's ASCII bytes as they stand. For the entry
//!   grade the token is the op-kind token as the wire spells it — `insert`,
//!   `make_link`, `publish`. ONE EXCEPTION (the frame merge, fm-I): `record`
//!   names the RECORD grade's body and no wire op — a record deposit rides an
//!   `insert` and a `make_link` on the wire, and its signature is the atom's
//!   own `sig`, made over the frame this token selects.
//! * THE ADDRESS ROW — `account` (the act's principal's account in the
//!   board's local form), `doc` (the document the entry writes: an `insert`'s
//!   or a `publish`'s target as its TRUNK, a `make_link`'s or a record's
//!   home), and every address inside a body: the dotted-decimal ASCII
//!   rendering M1's `Display` gives a tumbler (`1.0.1.0.1`) — lossless by T3,
//!   and the ONE spelling of the address among the several a string can
//!   carry: a component written with a leading zero (`1.01.0.1`) names the
//!   same address (`1.1.0.1`). So the frame spells the ADDRESS and never a
//!   string — [`entry_frame`], the insert's declared type, the slots and the
//!   windows all take `Address` values — and a signer holding the address it
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
//! * THE SLOT ROW — a link slot in the form the client sent it: one form
//!   byte (`0x01` the address form, `0x02` the resolve form), `be64(n)`, then
//!   each element — an address as the address row, a V-spec as its source
//!   address, its span's start and its span's width, each length-delimited —
//!   [`push_slot`]. A `Resolve` slot's V-specs are the client's own; the
//!   endsets the transaction resolves them to are the transaction's and
//!   enter no frame.
//! * THE OPTIONAL-ADDRESS ROW — ONE length-delimited group, EMPTY (`be32(0)`)
//!   where no address is named, and otherwise holding the one address named
//!   as an address-form slot row of one element — [`push_optional_address`].
//!   The `make_link` body's `replaces` row (PUB-5.15, RES-308/310: the state
//!   the record REPLACES) and the `record` body's `replaces` and LINEAGE rows
//!   share it (fm-I's Q8: one form for the two optional rows). The group is
//!   what keeps the absent bytes apart from every present spelling: a present
//!   group whose slot named nothing would still hold nine bytes, where the
//!   absent group holds none.
//! * THE WINDOW ROW — a run the MINTED MEMBER (the version a `publish` mints)
//!   holds BY ADDRESS: the run's I-START as the address row, length-delimited,
//!   then `be64(width)` — [`push_window`]. Which runs those are is the
//!   `publish` body's rule, below.
//!
//! THE BODIES, per grammar — each an [`EntryBody`], the token paired with
//! its body, so a body is never framed under another token:
//!
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
//! * `publish` — [`entry_body_publish`]: THE COUNT, then THE RUNS THE CLIENT
//!   PLACED IN THE ADDRESS FORM — the SHOT's address form (l6-A4), its runs
//!   classed by value and by address — then THE BASE EXTENT (the design
//!   record §2.5's `publish` cell as ruled: V — fam1-Q part (1) — binds the
//!   shot's base extent; fam2-Q's arm A with l6-A4 reads WHICH runs are
//!   signed by value and which by address AT THE MINTED MEMBER, the version
//!   the shot mints; D25's (c′) journals the two terms a verifier needs beyond
//!   that member's runs, `placed` and `base_extent`, in M5's placing record).
//!   In order:
//!     * `be64(placed)` — the positions the client placed, Σ width of its
//!       runs, and so how many of the minted member's positions the segments
//!       below spell;
//!     * then the minted member's first `placed` positions as SEGMENTS, in
//!       V-order, each opening with ONE CLASS BYTE: `0x02` a VALUE STRETCH —
//!       the maximal run of consecutive positions the commit COPIES IN (the
//!       shot document's own I-space placed by reference, the staging draft's
//!       re-inserted as fresh identity — at the minted member, one origin, the
//!       document's own) as one value-sequence row; `0x01` a WINDOW — one run
//!       onto ANOTHER document's I-space, which the commit keeps as a
//!       reference — as one window row. The segments are the runs AS THE
//!       MINTED MEMBER'S ARRANGEMENT HOLDS THEM, maximally merged (M5's
//!       run-list merges I-adjacent runs of one origin), so two I-adjacent
//!       windows are one segment and a stretch never meets a stretch;
//!     * then the BASE-EXTENT GROUP, one length-delimited group: EMPTY
//!       (`be32(0)`) where the shot has no base — the birth bit — else
//!       `be32(8) ‖ be64(base_extent)` — [`push_base_extent`].
//!
//!   `base` itself is spelled NOWHERE in the frame (fam1-L1): a verifier
//!   derives it from the minted member's address — a trunk member `D.k+1`
//!   was minted against `D.k`, a daughter `X.m` against `X`, a birth version
//!   against the memberless document, or against nothing where the group is
//!   EMPTY. So a verifier holding the MINTED MEMBER composes this body with
//!   no request in hand: it reads that member's first `placed` positions,
//!   classes each run by its origin — the member's own trunk BY VALUE, any
//!   other document BY ADDRESS — reads a stretch's values there and spells a
//!   window from the run that member holds. A replayed shot names a base its
//!   own commit left no longer the head, and so mints that base's daughter,
//!   never the trunk's next. [`PublishBody`] builds the body one value and
//!   one window at a time under a byte budget, for a verifier re-composing it
//!   off a store, and refuses it WHOLE at the first piece it cannot take —
//!   past that budget, past the count's `be64`, or a window of no positions —
//!   naming which ([`PublishRefusal`]). Every segment is self-delimiting
//!   behind its class byte and the group opens with a zero byte, which no
//!   class byte is, so the body is uniquely decodable from its front.
//! * `record` — [`entry_body_record`]: THE RECORD GRADE's body (the frame
//!   merge, fm-I, RULED 2026-09-29; its design record §3), under the
//!   `record` token. A record deposit's `sig` rides the atom, canonically
//!   last, and the marker slot stays EMPTY at both of its commits; this body
//!   is the preimage that `sig` is made over — what the design record called
//!   "the record frame". FIVE rows in this order: (1) the TYPE slot row — the
//!   link's type address as an address-form slot row of one element; (2) the
//!   `to` slot row — the link's target slot, address-form, EMPTY
//!   (`0x01 ‖ be64(0)`) at a targetless kind; (3) the `replaces` row, an
//!   optional-address row as `make_link`'s is (l6-A1; EMPTY by kind at a
//!   credential deposit); (4) the LINEAGE row, an optional-address row — the
//!   EMPTY group on a lineage that has not forked, else the fork point's
//!   address (D2); (5) the BODY-BYTES row — the sig-less canonical record
//!   bytes ([`canonical_record`](crate::canonical_record) with no `sig`), one
//!   length-delimited element. `from` — the atom the `sig` rides, whose
//!   address does not exist when the `sig` is composed — is NO row, and the
//!   subject needs none: it is the `to` slot at a credential deposit and the
//!   frame's `account` at a registry deposit or a targetless kind. This crate
//!   pins the grammar; the frame's `account` is the HOME's account and its
//!   `doc` the home — a credential record's own doc 1 (AUTH-2.127), so both
//!   are read off the link's address. Who signs and verifies over it, and
//!   what a record carrying no `sig` is answered, is the record grade's (2a)
//!   and the host's: the crate-level composition note says where skepd does.
//!
//! Every length-delimited element is written by [`push_delimited`], the one
//! function [`framed`] delimits its own fields with, and a spelling that
//! carries no length of its own — a token, an address, a value — is written
//! only as such an element. Every other row is self-delimiting — fixed-width
//! fields and delimited elements, with a count ahead of any element that
//! repeats — and stands where its grammar puts it. The one run with no count
//! ahead is a `publish` body's segments: each opens with its class byte, and
//! the run ends at the base-extent group, whose opening zero byte is no class
//! byte. So every body is uniquely decodable from its front, and the
//! composition is injective at every level: two distinct inputs never spell
//! one preimage.

use core::fmt;

use skep_address::{Address, Span};

use crate::framing::{delimited_len, framed, push_delimited, ENTRY_TAG};

/// THE ENTRY FRAME: `framed(ENTRY_TAG, [alg, board, account, doc, op, body])`
/// (AUTH-1.12's framing), EVERY member spelled here from the value the caller
/// holds, so a signer and a verifier holding the same values compose the same
/// bytes and no caller spells a member for itself:
///
/// * `alg` — the signing key's `ALGS` token, its ASCII bytes;
/// * `board` — the [`BoardTerm`] (D13): `be64(log_position) ‖ chain`, forty
///   bytes;
/// * `account`, `doc` — each ADDRESS in its dotted-decimal spelling
///   (`1.0.1.0.1`), the one spelling of the address whatever string named it;
/// * `op`, `body` — the [`EntryBody`]'s token and bytes, which its builder
///   ([`entry_body_insert`], [`entry_body_make_link`],
///   [`entry_body_make_link_replacing`], [`entry_body_publish`],
///   [`PublishBody`], [`entry_body_record`]) pairs.
///
/// PRECONDITION — as [`framed`]'s: every member is shorter than 2^32 bytes.
/// A longer member PANICS, naming the obligation — a caller's bug and never
/// an outcome. The body is the one member that grows with the write, and no
/// body the daemon composes comes near the bound ([`framed`]'s card says
/// why).
pub fn entry_frame(
    alg: &str,
    board: BoardTerm,
    account: &Address,
    doc: &Address,
    body: &EntryBody,
) -> Vec<u8> {
    framed(
        ENTRY_TAG,
        &[
            alg.as_bytes(),
            &board_bytes(&board),
            &address_bytes(account),
            &address_bytes(doc),
            body.op.as_bytes(),
            &body.bytes,
        ],
    )
}

/// THE BOARD TERM (signed ops; the design record §2.5, D13, RULED): the
/// committed `(position, chain)` pair `H.1` — the head document's first chain
/// member — NAMES, fixed from the claim on for the life of the board. It is
/// the ENTRY frame's `board` member ([`entry_frame`]), and the design
/// record's RECORD-grade frame names it too (§4.2 (C)) — one term, both
/// grades. It is NEVER the live pair `/health` serves, nor the pair any later
/// head names: a signature framed over either is refused
/// `attestation_invalid:signature`. A value: two terms are equal iff both
/// halves are.
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
/// Built only by [`entry_body_insert`], the two `make_link` builders
/// ([`entry_body_make_link`], [`entry_body_make_link_replacing`]),
/// [`PublishBody`] — [`entry_body_publish`] among its builds — and
/// [`entry_body_record`], so a body cannot be framed under another grammar's
/// token, and a `publish` body cannot be finished over fewer pieces than its
/// builder was offered. The tokens are the op-kind names as the wire
/// spells them — `insert`, `make_link`, `publish` — and the record grade's
/// `record`, spelled HERE, once each, beside the grammar each selects,
/// because they are members of a signed preimage that a reader beside the
/// table recomposes from this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryBody {
    op: &'static str,
    bytes: Vec<u8>,
}

impl EntryBody {
    /// The frame's `op` member: the token naming the body's grammar — the
    /// op-kind token as the wire spells it, or `record`.
    pub fn op(&self) -> &'static str {
        self.op
    }

    /// The frame's `body` member: the body in its grammar's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
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

/// A link slot as the client composed it — the two wire forms. `Copy`, as the
/// slices it borrows are: a view of the caller's slot, never an owner of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntrySlot<'a> {
    /// `{"addrs": [...]}` — address names, deposited verbatim.
    Addrs(&'a [Address]),
    /// A V-spec array — `(source document, span)` per spec, resolved by the
    /// store against the transaction's base.
    Resolve(&'a [(Address, Span)]),
}

/// A `make_link`'s three link slots, BY NAME. They are three values of one
/// type, and the body lays them out in an order of its own — the TYPE slot
/// first (the design record §2.5) — while every other place the workspace
/// names a link's slots names them `from`, `to`, `ty`: M7's `Link::triple`
/// and `LinkWriter::makelink`, M10's `Op::MakeLink` and `SuccessorSpec`, this
/// crate's own [`LinkDeposit`](crate::LinkDeposit). Taken positionally, the
/// natural transcription of any of those would compile, frame the slots out
/// of order, and have every attested `make_link` its signer made refused
/// `attestation_invalid:signature`, with nothing naming the order. By field,
/// the call site says which slot is which, and the order is spelled once, in
/// the one body both `make_link` builders write through.
///
/// Not `#[non_exhaustive]`: every caller builds one, and a link has exactly
/// these three slots. The body's fourth row, the `replaces` member, is no
/// slot of the link the record is: it names the state the record replaces,
/// and what it deposits is a SECOND link (PUB-5.15). So it is not a field
/// here — its presence is the builder's choice,
/// [`entry_body_make_link_replacing`] against [`entry_body_make_link`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkSlots<'a> {
    /// The `from` slot.
    pub from: EntrySlot<'a>,
    /// The `to` slot.
    pub to: EntrySlot<'a>,
    /// The type slot.
    pub ty: EntrySlot<'a>,
}

/// The slot row's form bytes.
const SLOT_FORM_ADDRS: u8 = 0x01;
const SLOT_FORM_RESOLVE: u8 = 0x02;

/// The `publish` body's segment CLASS bytes: a WINDOW, a run held BY
/// ADDRESS, and a VALUE STRETCH, positions held BY VALUE. The same two values
/// as the slot row's form bytes and in the same sense — `0x01` names
/// addresses, `0x02` what they resolve to — though the two rows never meet in
/// one body.
const SEGMENT_WINDOW: u8 = 0x01;
const SEGMENT_VALUE_STRETCH: u8 = 0x02;

/// THE SLOT ROW, onto `out`: the form byte, `be64(n)`, then each element as
/// the module doc states it.
fn push_slot(out: &mut Vec<u8>, slot: EntrySlot<'_>) {
    match slot {
        EntrySlot::Addrs(addrs) => {
            out.push(SLOT_FORM_ADDRS);
            out.extend_from_slice(&(addrs.len() as u64).to_be_bytes());
            for a in addrs {
                push_delimited(out, &address_bytes(a));
            }
        }
        EntrySlot::Resolve(specs) => {
            out.push(SLOT_FORM_RESOLVE);
            out.extend_from_slice(&(specs.len() as u64).to_be_bytes());
            for (source, span) in specs {
                push_delimited(out, &address_bytes(source));
                push_delimited(out, span.start().to_string().as_bytes());
                push_delimited(out, span.width().to_string().as_bytes());
            }
        }
    }
}

/// THE OPTIONAL-ADDRESS ROW, onto `out`: ONE length-delimited group — EMPTY
/// where no address is named, else the address as an address-form slot row
/// of one element. Delimited as a whole so that no present spelling can meet
/// the absent one: the least a present group holds is a slot row's form
/// byte and count, nine bytes. The `make_link` body's `replaces` row and the
/// `record` body's `replaces` and lineage rows are each one of these.
fn push_optional_address(out: &mut Vec<u8>, named: Option<&Address>) {
    let mut group = Vec::new();
    if let Some(a) = named {
        push_slot(&mut group, EntrySlot::Addrs(std::slice::from_ref(a)));
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

/// THE BASE-EXTENT GROUP, onto `out`: ONE length-delimited group — EMPTY
/// (`be32(0)`) where the shot has no base, the birth bit — else
/// `be64(base_extent)`, so a present group is twelve bytes and an absent one
/// four. Either opens with a zero byte, which no segment's class byte is:
/// that is what ends the `publish` body's segments without a count of them.
fn push_base_extent(out: &mut Vec<u8>, base_extent: Option<u64>) {
    match base_extent {
        None => push_delimited(out, &[]),
        Some(extent) => push_delimited(out, &extent.to_be_bytes()),
    }
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
    EntryBody { op: "insert", bytes: out }
}

/// THE `make_link` BODY of an op carrying NO `replaces` member — the EMPTY
/// state (PUB-5.15: a first share names it by the member's absence), under
/// the `make_link` token: the TYPE slot, then the `from` slot, then the `to`
/// slot — the body's order, whatever order the caller names them in — each
/// as its form byte (`0x01` the address form, `0x02` the resolve form),
/// `be64(n)`, then each element length-delimited — an address in its
/// dotted-decimal spelling, a V-spec as its source address, its span's start
/// and its span's width; then the `replaces` row EMPTY, `be32(0)`.
///
/// PRECONDITION — every element's spelling (an address, a span's start or
/// width) is shorter than 2^32 bytes, as [`entry_body_insert`]'s values are;
/// a longer one PANICS, naming the obligation.
pub fn entry_body_make_link(slots: LinkSlots<'_>) -> EntryBody {
    make_link_body(slots, None)
}

/// THE `make_link` BODY of an op whose `replaces` member names `replaces` —
/// the record the one being written follows (PUB-5.15 (iv): the revocation a
/// re-share follows): [`entry_body_make_link`]'s three slots, then the
/// `replaces` row holding the member as an address-form slot row of one
/// element, the whole group length-delimited. So the member is inside the
/// signed bytes, and a hand that edits it breaks the signature.
///
/// PRECONDITION — as [`entry_body_make_link`]'s, the member's spelling
/// included.
pub fn entry_body_make_link_replacing(slots: LinkSlots<'_>, replaces: &Address) -> EntryBody {
    make_link_body(slots, Some(replaces))
}

/// The one `make_link` body both builders write through, so the slots' order
/// and the `replaces` row's place after them are spelled once.
fn make_link_body(slots: LinkSlots<'_>, replaces: Option<&Address>) -> EntryBody {
    let mut out = Vec::new();
    push_slot(&mut out, slots.ty);
    push_slot(&mut out, slots.from);
    push_slot(&mut out, slots.to);
    push_optional_address(&mut out, replaces);
    EntryBody { op: "make_link", bytes: out }
}

/// One piece the `publish` body's SEGMENTS are built from — a piece of the
/// shot's ADDRESS FORM (l6-A4), taken in V-order: one position the commit
/// copies in, by its value, or one window onto another document's I-space, by
/// its address. The pieces are not the segments: consecutive values make ONE
/// value stretch, and each window makes a segment of its own. `Copy`, as the
/// slices it borrows are: a view of the caller's piece, never an owner of it.
///
/// The classing is the minted member's: a run whose origin is that member's
/// own trunk — the shot document's own I-space placed by reference, or the
/// staging draft's text re-inserted as fresh identity under that trunk — is
/// read out as [`ShotSegmentPiece::Value`]s, one per position; a run whose
/// origin is any other document is one [`ShotSegmentPiece::Window`]. Which of
/// a shot's runs is which, and where two I-adjacent windows become one, is
/// M5's to say (`skep-arrangement`'s `Shot::address_form`); this crate spells
/// what it is handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShotSegmentPiece<'a> {
    /// One position the commit COPIES IN — its value, read at the minted
    /// member.
    Value(&'a [u8]),
    /// A WINDOW — one run onto another document's I-space, kept by the
    /// commit as a reference: its I-start and its width, as the minted
    /// member's arrangement holds the run, clipped to the client's placed
    /// positions.
    Window {
        /// The run's first I-address.
        start: &'a Address,
        /// The run's width, at least one.
        width: u64,
    },
}

/// THE `publish` BODY, under the `publish` token: `be64(placed)`, then the
/// body's segments built from `pieces` in the order given — each run of
/// consecutive values ONE value stretch, its class byte and one value-sequence
/// row; each window its class byte and one window row — then the base-extent
/// group. It is [`PublishBody`] under a budget no body reaches: over pieces a
/// budget admits, the two build one body.
///
/// PRECONDITIONS — every value and every window's start spelling is shorter
/// than 2^32 bytes, as [`entry_body_insert`]'s values are; every window's
/// width is at least one, a run's own invariant; and the positions the
/// pieces cover sum below 2^64 — the count's width. A caller breaking one
/// PANICS, naming the obligation.
pub fn entry_body_publish<'a>(
    pieces: impl IntoIterator<Item = ShotSegmentPiece<'a>>,
    base_extent: Option<u64>,
) -> EntryBody {
    pieces
        .into_iter()
        .try_fold(PublishBody::within(usize::MAX, base_extent), |body, piece| match piece {
            ShotSegmentPiece::Value(value) => body.push(value),
            ShotSegmentPiece::Window { start, width } => body.window(start, width),
        })
        .expect(
            "a budget of usize::MAX refuses no piece past it — a saturated length never passes \
             it — so the refusal named here is a caller's broken precondition",
        )
        .finish()
}

/// THE `record` BODY, under the `record` token — the record grade's preimage
/// (the frame merge, fm-I; its design record §3): the TYPE slot row (`ty` as
/// an address-form slot row of one element), the `to` slot row (`to` as an
/// address-form slot row — EMPTY, `0x01 ‖ be64(0)`, at a targetless kind),
/// the `replaces` row and the LINEAGE row (each an optional-address row: the
/// EMPTY group where nothing is named, else the address as an address-form
/// slot row of one element, delimited; the lineage row names
/// `lineage_fork_point`, the address the lineage forked at, and is EMPTY on a
/// lineage that has not forked, D2), then `sigless_canonical_record` — the
/// SIG-LESS CANONICAL RECORD, the record with its `sig` member removed
/// ([`canonical_record`](crate::canonical_record) over its entries with no
/// `sig`) — as one length-delimited element. `from` is no row.
///
/// PRECONDITION — every address's spelling, and `sigless_canonical_record`,
/// is shorter than 2^32 bytes; a longer one PANICS, naming the obligation.
pub fn entry_body_record(
    ty: &Address,
    to: &[Address],
    replaces: Option<&Address>,
    lineage_fork_point: Option<&Address>,
    sigless_canonical_record: &[u8],
) -> EntryBody {
    let mut out = Vec::new();
    push_slot(&mut out, EntrySlot::Addrs(std::slice::from_ref(ty)));
    push_slot(&mut out, EntrySlot::Addrs(to));
    push_optional_address(&mut out, replaces);
    push_optional_address(&mut out, lineage_fork_point);
    push_delimited(&mut out, sigless_canonical_record);
    EntryBody { op: "record", bytes: out }
}

/// A `publish` BODY built one piece at a time under a byte BUDGET — for the
/// verifier that re-composes a shot's body off its own store, where each
/// value arrives by a read that can fail and a body past the budget must be
/// REFUSED rather than built. [`PublishBody::push`] and
/// [`PublishBody::window`] measure the budget in the body's own layout and
/// NAME what they refuse ([`PublishRefusal`]), so no caller restates that
/// layout, or the count's arithmetic, to learn which refusal it met; the
/// caller keeps its walk, its own answer for a value it could not read and
/// for each refusal, and collects nothing ahead of the build.
///
/// Its standing INVARIANT is the one the budget exists for: the body built so
/// far, its leading count and the base-extent group [`PublishBody::finish`]
/// appends included, never passes `budget` bytes — [`PublishBody::within`]'s
/// PRECONDITION establishes it at the type's one mint site, and every push
/// keeps it or refuses, so `finish` never answers a body past its budget.
///
/// A refused push CONSUMES the builder, and the type is not `Clone` — the
/// compile-time check beside it holds that — so the only body that can be
/// finished is one that took EVERY piece it was offered, in order. A body
/// that skipped a piece, or stopped short of one, would be the preimage of a
/// different, shorter publish: every other member of the frame is fixed for
/// one principal's publishes into one trunk under one key, so a signature
/// made for that publish would verify over it. [`entry_body_publish`] is this
/// builder under a budget no body reaches, so over pieces the budget admits
/// the two build one body.
///
/// Consecutive values join ONE stretch — the row opened by the first of them
/// and closed by the next window or by `finish` — so a stretch is always
/// maximal, whatever run boundaries the caller walked them in; windows are
/// taken as given, one segment each, and are the minted member's own maximal
/// runs by the caller's obligation ([`ShotSegmentPiece`]).
#[derive(Debug)]
pub struct PublishBody {
    bytes: Vec<u8>,
    /// The open value stretch — the segment the latest values joined, still
    /// taking values until a window or `finish` closes it.
    stretch: Option<ValueSequence>,
    /// The positions the pieces so far cover — the leading count, written
    /// back at `finish`.
    placed: u64,
    /// The base-extent group `finish` appends, spelled at `within` so its
    /// bytes count against the budget from the start.
    base_extent_group: Vec<u8>,
    budget: usize,
}

impl PublishBody {
    /// A body of no segments yet — the leading count's eight bytes, and the
    /// base-extent group held for `finish` — whose pushes admit no piece that
    /// would carry the FINISHED body past `budget` bytes. `base_extent` is the
    /// shot's: `None` in the birth shape, the EMPTY group.
    ///
    /// PRECONDITION — `budget` holds those bytes. The body of no segments is
    /// the least a builder can finish to, so below it the builder would
    /// start past its own budget and [`PublishBody::finish`] would answer an
    /// over-budget body no push had refused. A caller's bug and never an
    /// outcome: it PANICS, naming the obligation.
    pub fn within(budget: usize, base_extent: Option<u64>) -> PublishBody {
        let bytes = 0u64.to_be_bytes().to_vec();
        let mut base_extent_group = Vec::new();
        push_base_extent(&mut base_extent_group, base_extent);
        assert!(
            bytes.len() + base_extent_group.len() <= budget,
            "PublishBody::within: a budget of {budget} bytes cannot hold the body of no \
             segments, {} bytes",
            bytes.len() + base_extent_group.len()
        );
        PublishBody { bytes, stretch: None, placed: 0, base_extent_group, budget }
    }

    /// What the body would measure if finished now: the bytes down, and the
    /// group `finish` appends.
    fn finished_len(&self) -> usize {
        self.bytes.len() + self.base_extent_group.len()
    }

    /// Append `value` as the body's next position — joining the open value
    /// stretch, or opening one after a window or at the body's start — and
    /// hand the builder back; else the cause ([`PublishRefusal`]) and the
    /// builder GONE: a body that refused a piece can be neither continued
    /// nor finished. [`PublishRefusal::Unspellable`] where the positions
    /// placed would pass 2^64 − 1, the count's width; else
    /// [`PublishRefusal::PastBudget`] where the finished body would pass its
    /// budget. No value is free — an empty one costs its length prefix, and
    /// the first of a stretch its class byte and count besides — so a budget
    /// admits at most a quarter as many values as it has bytes, whatever the
    /// values hold.
    ///
    /// PRECONDITION — as [`entry_body_publish`]'s: `value` is shorter than
    /// 2^32 bytes, else PANICS; under any budget below that bound, this
    /// refuses such a value first.
    #[must_use = "push takes the builder: the body goes on in the one it returns"]
    pub fn push(mut self, value: &[u8]) -> Result<PublishBody, PublishRefusal> {
        let placed = self.placed.checked_add(1).ok_or(PublishRefusal::Unspellable)?;
        let opening: usize = if self.stretch.is_some() { 0 } else { 1 + 8 };
        let cost = opening.saturating_add(delimited_len(value.len()));
        if self.finished_len().saturating_add(cost) > self.budget {
            return Err(PublishRefusal::PastBudget);
        }
        let mut stretch = match self.stretch.take() {
            Some(open) => open,
            None => {
                self.bytes.push(SEGMENT_VALUE_STRETCH);
                ValueSequence::open(&mut self.bytes)
            }
        };
        stretch.push(&mut self.bytes, value);
        self.stretch = Some(stretch);
        self.placed = placed;
        Ok(self)
    }

    /// Append a WINDOW — the run from `start` of `width` positions, held by
    /// address — closing any open value stretch first, and hand the builder
    /// back; else the cause and the builder GONE, as after a refused push:
    /// [`PublishRefusal::EmptyWindow`] where `width` is zero — a run holds at
    /// least one position — then [`PublishRefusal::Unspellable`] where the
    /// positions placed would pass 2^64 − 1, then
    /// [`PublishRefusal::PastBudget`]. A window costs its class byte, its
    /// start's delimited spelling and eight bytes of width, whatever its
    /// width.
    ///
    /// PRECONDITION — `start`'s spelling is shorter than 2^32 bytes, else
    /// PANICS.
    #[must_use = "window takes the builder: the body goes on in the one it returns"]
    pub fn window(mut self, start: &Address, width: u64) -> Result<PublishBody, PublishRefusal> {
        if width == 0 {
            return Err(PublishRefusal::EmptyWindow);
        }
        let placed = self.placed.checked_add(width).ok_or(PublishRefusal::Unspellable)?;
        let start = address_bytes(start);
        let cost = 1usize.saturating_add(delimited_len(start.len())).saturating_add(8);
        if self.finished_len().saturating_add(cost) > self.budget {
            return Err(PublishRefusal::PastBudget);
        }
        if let Some(open) = self.stretch.take() {
            open.close(&mut self.bytes);
        }
        self.bytes.push(SEGMENT_WINDOW);
        push_window(&mut self.bytes, &start, width);
        self.placed = placed;
        Ok(self)
    }

    /// The body, under the `publish` token: the count of positions the
    /// pieces this builder took cover, the segments built from them in the
    /// order pushed — the open stretch closed — then the base-extent group;
    /// never past its budget, by the standing invariant.
    pub fn finish(self) -> EntryBody {
        let PublishBody { mut bytes, stretch, placed, base_extent_group, .. } = self;
        if let Some(open) = stretch {
            open.close(&mut bytes);
        }
        bytes[..8].copy_from_slice(&placed.to_be_bytes());
        bytes.extend_from_slice(&base_extent_group);
        EntryBody { op: "publish", bytes }
    }
}

/// [`PublishBody`] is not `Clone`, and this block stops compiling the moment
/// it is: a copy taken before a push would outlive that push's refusal, and
/// finish to the shorter body the refusal exists to forbid. The `_` below is
/// inferred while the blanket impl is the only one that applies; a `Clone`
/// type meets the second as well, and the path is ambiguous.
const _: fn() = || {
    trait AmbiguousIfClone<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    #[allow(dead_code)]
    struct IsClone;
    impl<T: Clone> AmbiguousIfClone<IsClone> for T {}
    let _ = <PublishBody as AmbiguousIfClone<_>>::check;
};

/// Why [`PublishBody`] refused a piece — the builder GONE with it, as every
/// refusal leaves it — NAMED, because a caller answers the three differently:
/// a body PAST ITS BUDGET is the one the builder exists to refuse rather than
/// build; a count past the body's leading `be64` names positions no store
/// holds; a window of no positions is a run no arrangement holds. What each
/// is answered is the caller's: a refusal reaches no wire from here.
///
/// The causes are tested in ONE order, the piece's own first — an empty
/// window, then the count, then the budget — so a piece the body could not
/// spell at any budget is never answered as past this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublishRefusal {
    /// The FINISHED body — its leading count and its base-extent group
    /// included — would pass the builder's budget.
    PastBudget,
    /// The positions placed would pass 2^64 − 1, the most the body's leading
    /// `be64(placed)` spells.
    Unspellable,
    /// A window of width zero: a run holds at least one position
    /// ([`ShotSegmentPiece::Window`]'s obligation).
    EmptyWindow,
}

/// Prose, never a wire vocabulary: each caller answers a refusal in its own
/// terms.
impl fmt::Display for PublishRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PublishRefusal::PastBudget => "the finished body would pass its budget",
            PublishRefusal::Unspellable => "the positions placed would pass 2^64 - 1",
            PublishRefusal::EmptyWindow => "a window holds no position",
        })
    }
}

impl std::error::Error for PublishRefusal {}

#[cfg(test)]
mod tests;
