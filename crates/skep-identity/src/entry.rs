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
//!   carries beside it): the token's ASCII bytes, bare. For the entry grade
//!   the token is the op-kind token as the wire spells it — `insert`,
//!   `make_link`, `publish`. ONE EXCEPTION (the frame merge, fm-I): `record`
//!   names the RECORD grade's body and no wire op — a record deposit rides an
//!   `insert` and a `make_link` on the wire, and its signature is the atom's
//!   own `sig`, made over the frame this token selects.
//! * THE ADDRESS ROW — `account` (the act's principal's account in the
//!   board's local form), `doc` (the target or home document's bare address),
//!   and every address inside a body: the dotted-decimal ASCII rendering M1's
//!   `Display` gives a tumbler (`1.0.1.0.1`) — lossless by T3, and the ONE
//!   spelling of the address among the several a string can carry: a
//!   component written with a leading zero (`1.01.0.1`) names the same
//!   address (`1.1.0.1`). So the frame spells the ADDRESS and never a string
//!   — [`entry_frame`], the insert's declared type, the slots and the windows
//!   all take `Address` values — and a signer holding the address it named
//!   signs the bytes the verifier composes, whichever spelling carried it on
//!   the wire.
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
//!   where the member is absent, and otherwise holding the one address named
//!   as an address-form slot row of one element — [`push_optional_address`].
//!   The `make_link` body's `replaces` row (PUB-5.15, RES-308/310: the state
//!   the record REPLACES) and the `record` body's `replaces` and LINEAGE rows
//!   share it (fm-I's Q8: one form for the two optional rows). The group is
//!   what keeps the absent bytes apart from every present spelling: a present
//!   member whose slot named nothing would still be a nine-byte group, never
//!   the empty one.
//! * THE WINDOW ROW — a `publish` run the member holds BY ADDRESS: the run's
//!   I-START as the address row, length-delimited, then `be64(width)` —
//!   [`push_window`]. Which runs those are is the `publish` body's rule,
//!   below.
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
//!   member, [`entry_body_make_link_replacing`] where it names one. So a
//!   member-less body is the three slots and an EMPTY group, never the three
//!   slots alone.
//! * `publish` — [`entry_body_publish`]: THE COUNT, then THE RUNS THE CLIENT
//!   PLACED IN THE ADDRESS FORM, then THE BASE EXTENT (the design record
//!   §2.5's `publish` cell as ruled: V — fam1-Q part (1) — binds the shot's
//!   base extent; fam2-Q's arm A with l6-A4 reads WHICH runs are signed by
//!   value and which by address AT THE MEMBER; D25's (c′) journals the two
//!   terms a verifier needs beyond the member's runs, `placed` and
//!   `base_extent`, in M5's placing record). In order:
//!     * `be64(placed)` — the positions the client placed, Σ width of its
//!       runs: the count the row has always led with;
//!     * then the member's first `placed` positions as SEGMENTS, in V-order,
//!       each opening with ONE CLASS BYTE: `0x02` a VALUE STRETCH — the
//!       maximal run of consecutive positions the commit COPIES IN (the shot
//!       document's own I-space placed by reference, the staging draft's
//!       re-inserted as fresh identity — at the member, one origin, the
//!       document's own) as one value-sequence row; `0x01` a WINDOW — one
//!       run onto ANOTHER document's I-space, which the commit keeps as a
//!       reference — as one window row. The segments are the runs AS THE
//!       MEMBER's ARRANGEMENT HOLDS THEM, maximally merged (M5's run-list
//!       merges I-adjacent runs of one origin), so two I-adjacent windows are
//!       one segment and a stretch never meets a stretch;
//!     * then the BASE-EXTENT GROUP, one length-delimited group: EMPTY
//!       (`be32(0)`) where the shot has no base — the birth bit — else
//!       `be32(8) ‖ be64(base_extent)` — [`push_base_extent`].
//!   `base` itself is NO member (fam1-L1): a verifier derives it from the
//!   minted member's address — a trunk member `D.k+1` was minted against
//!   `D.k`, a daughter `X.m` against `X`, a birth version against the
//!   memberless document, or against nothing where the group is EMPTY. So a
//!   verifier holding the MEMBER composes this body with no request in hand:
//!   it reads the member's first `placed` positions, classes each run by its
//!   origin — the member's own trunk BY VALUE, any other document BY ADDRESS
//!   — reads a stretch's values at the member and spells a window from the
//!   member's own run. A replayed shot names a base its own commit left no
//!   longer the head, and so mints that base's daughter, never the trunk's
//!   next. [`PublishBody`] builds the body one value and one window at a
//!   time under a byte budget, and refuses it WHOLE at the first segment past
//!   that budget, for a verifier re-composing it off a store. Every segment
//!   is self-delimiting behind its class byte and the group opens with a
//!   zero byte, which no class byte is, so the body is uniquely decodable
//!   from its front.
//! * `record` — [`entry_body_record`]: THE RECORD GRADE's body (the frame
//!   merge, fm-I, RULED 2026-09-29; its record §3), under the `record`
//!   token. A record deposit's `sig` rides the atom, canonically last, and
//!   the marker slot stays EMPTY at both of its positions; this body is the
//!   preimage that `sig` is made over — what the design record called "the
//!   record frame". FIVE rows in this order: (1) the TYPE slot row — the
//!   link's type address as an address-form slot row of one element; (2) the
//!   `to` slot row — the record's target slot, address-form, EMPTY
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
//!   are read off the link's address — and the daemon composes it at every
//!   credential deposit above the claim (the record grade, 2a: the signer
//!   embeds the `sig` the frame's signature makes, the write path verifies it
//!   at the link under the set that opens the home, and a record carrying
//!   none is refused `attestation_required`).
//!
//! Every length-delimited element is written by [`push_delimited`], the one
//! function [`framed`] delimits its own fields with, and every row is written
//! the same way — onto the one buffer its body builds ([`ValueSequence`],
//! [`push_slot`], [`push_window`]), never built apart and copied in — so the
//! composition is injective at every level: two distinct inputs never spell
//! one preimage.

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
/// token, and a `publish` body cannot be finished over fewer segments than
/// its builder was offered. The tokens are the op-kind names as the wire
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

/// The `publish` body's segment CLASS bytes: a run held BY ADDRESS (a
/// window) and a stretch held BY VALUE. The same two values as the slot
/// row's form bytes and in the same sense — `0x01` names addresses, `0x02`
/// what they resolve to — though the two rows never meet in one body.
const SEGMENT_WINDOW: u8 = 0x01;
const SEGMENT_VALUES: u8 = 0x02;

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

/// One segment of a `publish` body's ADDRESS FORM (l6-A4), as the member
/// holds it: one position the commit copies in, by its value, or one window
/// onto another document's I-space, by its address. `Copy`, as the slices it
/// borrows are: a view of the caller's segment, never an owner of it.
///
/// The classing is the MEMBER's: a run whose origin is the member's own
/// trunk — the shot document's own I-space placed by reference, or the
/// staging draft's text re-inserted as fresh identity under that trunk — is
/// a stretch of [`ShotSegment::Value`]s; a run whose origin is any other
/// document is one [`ShotSegment::Window`]. Which of a shot's runs is which,
/// and where two I-adjacent windows become one, is M5's to say
/// (`skep-arrangement`'s address form); this crate spells what it is handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShotSegment<'a> {
    /// One position the commit COPIES IN — its value, read at the member.
    Value(&'a [u8]),
    /// A WINDOW — one run onto another document's I-space, kept by the
    /// commit as a reference: its I-start and its width, as the member's
    /// arrangement holds the run, clipped to the client's placed positions.
    Window {
        /// The run's first I-address.
        start: &'a Address,
        /// The run's width, at least one.
        width: u64,
    },
}

/// THE `publish` BODY, under the `publish` token: `be64(placed)`, the
/// segments in the order given — each value stretch as its class byte and
/// one value-sequence row, each window as its class byte and one window row
/// — then the base-extent group. It is [`PublishBody`] under a budget no
/// body reaches: over segments a budget admits, the two build one body.
///
/// PRECONDITIONS — every value and every window's start spelling is shorter
/// than 2^32 bytes, as [`entry_body_insert`]'s values are; every window's
/// width is at least one, a run's own invariant; and the positions the
/// segments cover sum below 2^64 — the count's width. A caller breaking one
/// PANICS, naming the obligation.
pub fn entry_body_publish<'a>(
    segments: impl IntoIterator<Item = ShotSegment<'a>>,
    base_extent: Option<u64>,
) -> EntryBody {
    segments
        .into_iter()
        .try_fold(PublishBody::within(usize::MAX, base_extent), |body, segment| match segment {
            ShotSegment::Value(value) => body.push(value),
            ShotSegment::Window { start, width } => body.window(start, width),
        })
        .expect(
            "a budget of usize::MAX refuses no segment: a saturated length never passes it, so \
             the refusal is the count's — the positions placed pass 2^64 − 1, or a window has no \
             width — a caller's broken precondition",
        )
        .finish()
}

/// THE `record` BODY, under the `record` token — the record grade's preimage
/// (the frame merge, fm-I; its record §3): the TYPE slot row (`ty` as an
/// address-form slot row of one element), the `to` slot row (`to` as an
/// address-form slot row — EMPTY, `0x01 ‖ be64(0)`, at a targetless kind),
/// the `replaces` row and the LINEAGE row (each an optional-address row: the
/// EMPTY group where nothing is named, else the address as an address-form
/// slot row of one element, delimited), then `canonical` — the sig-less
/// canonical record bytes — as one length-delimited element. `from` is no
/// row.
///
/// PRECONDITION — every address's spelling, and `canonical`, is shorter than
/// 2^32 bytes; a longer one PANICS, naming the obligation.
pub fn entry_body_record(
    ty: &Address,
    to: &[Address],
    replaces: Option<&Address>,
    lineage: Option<&Address>,
    canonical: &[u8],
) -> EntryBody {
    let mut out = Vec::new();
    push_slot(&mut out, EntrySlot::Addrs(std::slice::from_ref(ty)));
    push_slot(&mut out, EntrySlot::Addrs(to));
    push_optional_address(&mut out, replaces);
    push_optional_address(&mut out, lineage);
    push_delimited(&mut out, canonical);
    EntryBody { op: "record", bytes: out }
}

/// A `publish` BODY built one segment at a time under a byte BUDGET — for
/// the verifier that re-composes a shot's body off its own store, where each
/// value arrives by a read that can fail and a body past the budget must be
/// REFUSED rather than built. [`PublishBody::push`] and
/// [`PublishBody::window`] measure the budget in the body's own layout, so no
/// caller restates that layout; the caller keeps its walk, and its own answer
/// for a value it could not read, and collects nothing ahead of the build.
///
/// Its standing INVARIANT is the one the budget exists for: the body built so
/// far, its leading count and the base-extent group [`PublishBody::finish`]
/// appends included, never passes `budget` bytes — [`PublishBody::within`]'s
/// PRECONDITION establishes it at the type's one mint site, and every push
/// keeps it or refuses, so `finish` never answers a body past its budget.
///
/// A refused push CONSUMES the builder, and the type is not `Clone` — the
/// compile-time check beside it holds that — so the only body that can be
/// finished is one that took EVERY segment it was offered, in order. A body
/// that skipped a segment, or stopped short of one, would be the preimage of
/// a different, shorter publish: every other member of the frame is fixed
/// for one principal's publishes into one trunk under one key, so a
/// signature made for that publish would verify over it.
/// [`entry_body_publish`] is this builder under a budget no body reaches, so
/// over segments the budget admits the two build one body.
///
/// Consecutive values join ONE stretch — the row opened by the first of them
/// and closed by the next window or by `finish` — so a stretch is always
/// maximal, whatever run boundaries the caller walked them in; windows are
/// taken as given, one segment each, and are the member's own maximal runs
/// by the caller's obligation ([`ShotSegment`]).
#[derive(Debug)]
pub struct PublishBody {
    bytes: Vec<u8>,
    /// The value stretch the last segment opened, still taking values.
    stretch: Option<ValueSequence>,
    /// The positions the segments so far cover — the leading count, written
    /// back at `finish`.
    placed: u64,
    /// The base-extent group `finish` appends, spelled at `within` so its
    /// bytes count against the budget from the start.
    tail: Vec<u8>,
    budget: usize,
}

impl PublishBody {
    /// A body of no segments yet — the leading count's eight bytes, and the
    /// base-extent group held for `finish` — whose pushes admit no segment
    /// that would carry the FINISHED body past `budget` bytes. `base_extent`
    /// is the shot's: `None` in the birth shape, the EMPTY group.
    ///
    /// PRECONDITION — `budget` holds those bytes. The body of no segments is
    /// the least a builder can finish to, so below it the builder would
    /// start past its own budget and [`PublishBody::finish`] would answer an
    /// over-budget body no push had refused. A caller's bug and never an
    /// outcome: it PANICS, naming the obligation.
    pub fn within(budget: usize, base_extent: Option<u64>) -> PublishBody {
        let bytes = 0u64.to_be_bytes().to_vec();
        let mut tail = Vec::new();
        push_base_extent(&mut tail, base_extent);
        assert!(
            bytes.len() + tail.len() <= budget,
            "PublishBody::within: a budget of {budget} bytes cannot hold the body of no \
             segments, {} bytes",
            bytes.len() + tail.len()
        );
        PublishBody { bytes, stretch: None, placed: 0, tail, budget }
    }

    /// What the body would measure if finished now: the bytes down, and the
    /// group `finish` appends.
    fn finished_len(&self) -> usize {
        self.bytes.len() + self.tail.len()
    }

    /// Append `value` as the body's next position — joining the open value
    /// stretch, or opening one after a window or at the body's start — and
    /// hand the builder back; unless the finished body would then pass its
    /// budget, where the answer is `None` and the builder is GONE: a body that
    /// refused a segment can be neither continued nor finished. No value is
    /// free — an empty one costs its length prefix, and the first of a
    /// stretch its class byte and count besides — so a budget admits at most
    /// a quarter as many values as it has bytes, whatever the values hold.
    ///
    /// PRECONDITION — as [`entry_body_publish`]'s: `value` is shorter than
    /// 2^32 bytes, else PANICS; under any budget below that bound, this
    /// refuses such a value first. `None` is also the answer where the
    /// positions placed would pass 2^64 − 1, the count's width.
    #[must_use = "push takes the builder: the body goes on in the one it returns"]
    pub fn push(mut self, value: &[u8]) -> Option<PublishBody> {
        let opening: usize = if self.stretch.is_some() { 0 } else { 1 + 8 };
        let cost = opening.saturating_add(delimited_len(value.len()));
        if self.finished_len().saturating_add(cost) > self.budget {
            return None;
        }
        let placed = self.placed.checked_add(1)?;
        let mut stretch = match self.stretch.take() {
            Some(open) => open,
            None => {
                self.bytes.push(SEGMENT_VALUES);
                ValueSequence::open(&mut self.bytes)
            }
        };
        stretch.push(&mut self.bytes, value);
        self.stretch = Some(stretch);
        self.placed = placed;
        Some(self)
    }

    /// Append a WINDOW — the run from `start` of `width` positions, held by
    /// address — closing any open value stretch first, and hand the builder
    /// back; unless the finished body would then pass its budget, where the
    /// answer is `None` and the builder is GONE, as after a refused push. A
    /// window costs its class byte, its start's delimited spelling and eight
    /// bytes of width, whatever its width.
    ///
    /// PRECONDITION — `start`'s spelling is shorter than 2^32 bytes, else
    /// PANICS. `None` is also the answer where `width` is zero — a run holds
    /// at least one position — or where the positions placed would pass
    /// 2^64 − 1.
    #[must_use = "window takes the builder: the body goes on in the one it returns"]
    pub fn window(mut self, start: &Address, width: u64) -> Option<PublishBody> {
        let start = address_bytes(start);
        let cost = 1usize.saturating_add(delimited_len(start.len())).saturating_add(8);
        if self.finished_len().saturating_add(cost) > self.budget || width == 0 {
            return None;
        }
        let placed = self.placed.checked_add(width)?;
        if let Some(open) = self.stretch.take() {
            open.close(&mut self.bytes);
        }
        self.bytes.push(SEGMENT_WINDOW);
        push_window(&mut self.bytes, &start, width);
        self.placed = placed;
        Some(self)
    }

    /// The body, under the `publish` token: the count of positions the
    /// segments this builder took cover, those segments in the order pushed
    /// — the open stretch closed — then the base-extent group; never past
    /// its budget, by the standing invariant.
    pub fn finish(self) -> EntryBody {
        let PublishBody { mut bytes, stretch, placed, tail, .. } = self;
        if let Some(open) = stretch {
            open.close(&mut bytes);
        }
        bytes[..8].copy_from_slice(&placed.to_be_bytes());
        bytes.extend_from_slice(&tail);
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

#[cfg(test)]
mod tests {
    use skep_address::{validate, Nat, Tumbler};

    use super::*;

    fn addr(comps: &[u32]) -> Address {
        validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).unwrap()).unwrap()
    }

    /// The value-sequence row alone, as the pins below state it.
    fn value_sequence<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        push_value_sequence(&mut out, values);
        out
    }

    /// The slot row alone, as the pins below state it.
    fn slot_bytes(slot: EntrySlot<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        push_slot(&mut out, slot);
        out
    }

    /// The optional-address row alone, as the pins below state it.
    fn optional_address_bytes(named: Option<&Address>) -> Vec<u8> {
        let mut out = Vec::new();
        push_optional_address(&mut out, named);
        out
    }

    /// The window row alone, as the pins below state it.
    fn window_bytes(start: &Address, width: u64) -> Vec<u8> {
        let mut out = Vec::new();
        push_window(&mut out, &address_bytes(start), width);
        out
    }

    /// The rows, byte for byte, at one small instance each — the pins a
    /// second implementation composes against — and the token each body
    /// carries into the frame's `op` member. The two insert pins put the
    /// value sequence after a prefix, so a count written back anywhere but
    /// where its row began is caught; the slot row is pinned at TWO elements
    /// as well as one, since only a second element can show the ORDER the row
    /// keeps.
    #[test]
    fn the_rows_spell_as_the_module_doc_states() {
        assert_eq!(
            board_bytes(&BoardTerm { log_position: 12, chain: [0xAB; 32] })[..],
            [&[0u8, 0, 0, 0, 0, 0, 0, 12][..], &[0xAB; 32][..]].concat()[..]
        );
        assert_eq!(address_bytes(&addr(&[1, 0, 1, 0, 1])), b"1.0.1.0.1");
        assert_eq!(
            value_sequence([&b"ab"[..], &b""[..], &b"c"[..]]),
            [
                &[0u8, 0, 0, 0, 0, 0, 0, 3][..],
                &[0, 0, 0, 2, b'a', b'b'][..],
                &[0, 0, 0, 0][..],
                &[0, 0, 0, 1, b'c'][..],
            ]
            .concat()
        );
        let element = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
        assert_eq!(
            slot_bytes(EntrySlot::Addrs(std::slice::from_ref(&element))),
            [&[0x01u8, 0, 0, 0, 0, 0, 0, 0, 1][..], &[0, 0, 0, 15][..], b"1.0.1.0.1.0.1.1"].concat()
        );
        // …and at TWO elements, in the order given: DESCENDING both in address
        // order (30 > 2) and in spelled order ("1.0.30" > "1.0.2"), so a row
        // that sorted its elements by either comparison spells other bytes.
        // `30` is a component only base ten spells `30`, so the row's DECIMAL
        // shows here too.
        let pair = [addr(&[1, 0, 30]), addr(&[1, 0, 2])];
        assert_eq!(
            slot_bytes(EntrySlot::Addrs(&pair)),
            [
                &[0x01u8, 0, 0, 0, 0, 0, 0, 0, 2][..],
                &[0, 0, 0, 6][..],
                b"1.0.30",
                &[0, 0, 0, 5][..],
                b"1.0.2",
            ]
            .concat(),
            "the slot row keeps its elements in the order given"
        );
        let span = Span::new(
            Tumbler::new([1u32, 1].map(Nat::from)).unwrap(),
            Tumbler::new([0u32, 2].map(Nat::from)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            slot_bytes(EntrySlot::Resolve(&[(addr(&[1, 0, 1, 0, 1]), span)])),
            [
                &[0x02u8, 0, 0, 0, 0, 0, 0, 0, 1][..],
                &[0, 0, 0, 9][..],
                b"1.0.1.0.1",
                &[0, 0, 0, 3][..],
                b"1.1",
                &[0, 0, 0, 3][..],
                b"0.2",
            ]
            .concat()
        );
        assert_eq!(
            entry_body_insert(None, [&b"x"[..]]).as_bytes(),
            [&[0u8, 0, 0, 0][..], &value_sequence([&b"x"[..]])[..]].concat()
        );
        assert_eq!(
            entry_body_insert(Some(&addr(&[1, 1, 0, 1, 0, 1, 0, 3, 1])), []).as_bytes(),
            [&[0u8, 0, 0, 17][..], b"1.1.0.1.0.1.0.3.1", &[0u8; 8][..]].concat()
        );
        // THE PUBLISH BODY. One value in the birth shape: the count, one
        // stretch — its class byte and a value-sequence row of one — and the
        // EMPTY base-extent group.
        assert_eq!(
            entry_body_publish([ShotSegment::Value(b"q")], None).as_bytes(),
            [
                &[0u8, 0, 0, 0, 0, 0, 0, 1][..],
                &[SEGMENT_VALUES][..],
                &value_sequence([&b"q"[..]])[..],
                &[0, 0, 0, 0][..],
            ]
            .concat(),
            "one value, no base: count 1, one stretch, the EMPTY group"
        );
        // The window row: the start's spelling, delimited, then be64(width).
        let window_start = addr(&[1, 0, 2, 0, 1, 4]);
        assert_eq!(
            window_bytes(&window_start, 3),
            [&[0u8, 0, 0, 11][..], b"1.0.2.0.1.4", &[0, 0, 0, 0, 0, 0, 0, 3][..]].concat()
        );
        // All three classes with a base: two values (one stretch), a window
        // of three positions, one more value (a SECOND stretch, since the
        // window parted them), base extent 5 — six positions in all. The
        // count is the positions, not the segments; the class byte precedes
        // each segment; the group closes the body.
        let mixed = entry_body_publish(
            [
                ShotSegment::Value(b"a"),
                ShotSegment::Value(b"b"),
                ShotSegment::Window { start: &window_start, width: 3 },
                ShotSegment::Value(b"c"),
            ],
            Some(5),
        );
        assert_eq!(
            mixed.as_bytes(),
            [
                &[0u8, 0, 0, 0, 0, 0, 0, 6][..],
                &[SEGMENT_VALUES][..],
                &value_sequence([&b"a"[..], &b"b"[..]])[..],
                &[SEGMENT_WINDOW][..],
                &window_bytes(&window_start, 3)[..],
                &[SEGMENT_VALUES][..],
                &value_sequence([&b"c"[..]])[..],
                &[0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 5][..],
            ]
            .concat(),
            "values, a window, a value, then the base-extent group"
        );
        // Two windows in a row stay two segments: the builder merges no
        // addresses — the member's arrangement did, before they got here.
        let second = addr(&[1, 0, 3, 0, 1, 1]);
        assert_eq!(
            entry_body_publish(
                [
                    ShotSegment::Window { start: &window_start, width: 3 },
                    ShotSegment::Window { start: &second, width: 1 },
                ],
                Some(0),
            )
            .as_bytes(),
            [
                &[0u8, 0, 0, 0, 0, 0, 0, 4][..],
                &[SEGMENT_WINDOW][..],
                &window_bytes(&window_start, 3)[..],
                &[SEGMENT_WINDOW][..],
                &window_bytes(&second, 1)[..],
                &[0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0][..],
            ]
            .concat()
        );
        // The empty shot: the count zero, no segment, the group — the group's
        // leading zero byte is what tells it from a segment.
        assert_eq!(entry_body_publish([], None).as_bytes(), [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // Three DISTINCT slots, named in the workspace's `from, to, ty` order:
        // the body lays out the type slot first whatever order they are named
        // in, and a builder that wrote them in any other order spells other
        // bytes here. Then the `replaces` row: EMPTY where the op carries no
        // member, so a member-less body is never the three slots alone.
        let (ty, from) = ([element], [addr(&[1, 0, 1])]);
        let empty = EntrySlot::Addrs(&[]);
        let slots =
            LinkSlots { from: EntrySlot::Addrs(&from), to: empty, ty: EntrySlot::Addrs(&ty) };
        assert_eq!(optional_address_bytes(None), [0u8, 0, 0, 0], "absent: the EMPTY group");
        assert_eq!(
            entry_body_make_link(slots).as_bytes(),
            [
                slot_bytes(slots.ty),
                slot_bytes(slots.from),
                slot_bytes(slots.to),
                optional_address_bytes(None)
            ]
            .concat(),
            "the type slot, then from, then to, then the member's EMPTY group"
        );
        // …and a member PRESENT: the one address as an address-form slot row,
        // the whole row one group, length-delimited.
        let revocation = addr(&[1, 0, 1, 0, 1, 0, 2, 9]);
        // Group length 28: the form byte, `be64(1)`, then `be32(15)` and the
        // fifteen bytes of the address's spelling.
        let present = [
            &[0u8, 0, 0, 28][..],
            &[0x01, 0, 0, 0, 0, 0, 0, 0, 1][..],
            &[0, 0, 0, 15][..],
            b"1.0.1.0.1.0.2.9",
        ]
        .concat();
        assert_eq!(optional_address_bytes(Some(&revocation)), present, "present: one group");
        assert_eq!(
            entry_body_make_link_replacing(slots, &revocation).as_bytes(),
            [slot_bytes(slots.ty), slot_bytes(slots.from), slot_bytes(slots.to), present.clone()]
                .concat(),
            "the three slots, then the member's group"
        );
        // A PRESENT group holding an EMPTY slot row — a spelling no op makes,
        // the wire's member being one address — is still not the absent bytes:
        // the group's length tells the two apart.
        let mut present_and_empty = Vec::new();
        push_delimited(&mut present_and_empty, &slot_bytes(empty));
        assert_eq!(present_and_empty, [&[0u8, 0, 0, 9][..], &slot_bytes(empty)[..]].concat());
        assert_ne!(present_and_empty, optional_address_bytes(None), "present-and-empty is never absent");
        // THE RECORD BODY: the type slot row, the `to` slot row, the
        // `replaces` row, the lineage row, the canonical bytes — here a
        // targeted kind with neither optional row named…
        let (record_ty, subject) = (addr(&[1, 1, 0, 1, 0, 1, 0, 3, 1]), [addr(&[1, 0, 2])]);
        assert_eq!(
            entry_body_record(&record_ty, &subject, None, None, b"{}").as_bytes(),
            [
                slot_bytes(EntrySlot::Addrs(std::slice::from_ref(&record_ty))),
                slot_bytes(EntrySlot::Addrs(&subject)),
                vec![0, 0, 0, 0],
                vec![0, 0, 0, 0],
                vec![0, 0, 0, 2, b'{', b'}'],
            ]
            .concat(),
            "type, to, the EMPTY replaces group, the EMPTY lineage group, the bytes"
        );
        // …and a targetless kind naming both: the `to` row is the EMPTY slot
        // (nine bytes, never absent), each optional row its one address in
        // the `replaces` row's own spelling, and `from` is nowhere.
        let fork_point = addr(&[1, 0, 1, 0, 1, 3]);
        let lineage_group = [
            &[0u8, 0, 0, 24][..],
            &[0x01, 0, 0, 0, 0, 0, 0, 0, 1][..],
            &[0, 0, 0, 11][..],
            b"1.0.1.0.1.3",
        ]
        .concat();
        assert_eq!(
            entry_body_record(&record_ty, &[], Some(&revocation), Some(&fork_point), b"r")
                .as_bytes(),
            [
                slot_bytes(EntrySlot::Addrs(std::slice::from_ref(&record_ty))),
                slot_bytes(empty),
                present,
                lineage_group,
                vec![0, 0, 0, 1, b'r'],
            ]
            .concat()
        );
        assert_eq!(
            [
                entry_body_insert(None, []).op(),
                entry_body_make_link(LinkSlots { from: empty, to: empty, ty: empty }).op(),
                entry_body_make_link_replacing(
                    LinkSlots { from: empty, to: empty, ty: empty },
                    &revocation
                )
                .op(),
                entry_body_publish([], None).op(),
                entry_body_record(&record_ty, &[], None, None, b"").op(),
            ],
            ["insert", "make_link", "make_link", "publish", "record"],
            "each body carries its own grammar's token"
        );
    }

    /// [`PublishBody`] under its budget: it finishes to [`entry_body_publish`]'s
    /// body over the segments it took, and the budget is the FINISHED body's
    /// length, the base-extent group included — a value landing the body
    /// exactly on it is taken, one byte more is refused, at the budget not
    /// even an empty value fits (its length prefix costs four bytes), and a
    /// window is refused by the same measure. A refusal CONSUMES the builder,
    /// so no body is finished over a sequence that skipped a segment or
    /// stopped short of one: the third row offers `cd` between `ab` and `c`,
    /// and a builder that let the walk go on past its refusal would finish to
    /// `[ab, c]`'s body — the preimage of another publish, whose signature
    /// verifies over it.
    #[test]
    fn a_publish_body_built_within_its_budget_is_the_whole_sequences_body() {
        let start = addr(&[1, 0, 2, 0, 1, 4]);
        let whole = entry_body_publish(
            [
                ShotSegment::Value(b"ab"),
                ShotSegment::Window { start: &start, width: 2 },
                ShotSegment::Value(b"c"),
            ],
            Some(7),
        );
        let budget = whole.as_bytes().len();
        let fed = |segments: &[ShotSegment<'_>]| {
            segments.iter().try_fold(PublishBody::within(budget, Some(7)), |body, s| match *s {
                ShotSegment::Value(v) => body.push(v),
                ShotSegment::Window { start, width } => body.window(start, width),
            })
        };
        let window = ShotSegment::Window { start: &start, width: 2 };
        assert!(
            fed(&[ShotSegment::Value(b"ab"), window, ShotSegment::Value(b"cd")]).is_none(),
            "one byte past the budget"
        );
        assert!(
            fed(&[ShotSegment::Value(b"ab"), window, ShotSegment::Value(b"c"), ShotSegment::Value(b"")])
                .is_none(),
            "an empty value costs its length prefix"
        );
        assert!(
            fed(&[ShotSegment::Value(b"ab"), window, ShotSegment::Value(b"cd"), ShotSegment::Value(b"c")])
                .is_none(),
            "a refusal ends the body: nothing finishes over the segments around it"
        );
        assert!(
            fed(&[ShotSegment::Value(b"ab"), window, ShotSegment::Value(b"c"), window]).is_none(),
            "a window is measured by the same budget"
        );
        assert_eq!(
            fed(&[ShotSegment::Value(b"ab"), window, ShotSegment::Value(b"c")])
                .map(PublishBody::finish),
            Some(whole),
            "exactly on it"
        );
        // The base-extent group is counted from the start: the same segments
        // under a budget one byte short of the group's present spelling are
        // refused at the first segment, not at `finish`.
        let birth = entry_body_publish([ShotSegment::Value(b"ab")], None).as_bytes().len();
        assert!(
            PublishBody::within(birth, Some(7)).push(b"ab").is_none(),
            "a present group costs eight bytes more than the EMPTY one"
        );
        assert!(PublishBody::within(budget, Some(7)).window(&start, 0).is_none(), "no run is empty");
    }

    /// The frame is `framed(ENTRY_TAG, …)` over the six members in order and
    /// nothing else: the tag, then each member length-delimited — the board
    /// term as the board row, the two addresses as the address row, the op
    /// and body the [`EntryBody`]'s own.
    #[test]
    fn the_frame_is_framed_under_the_entry_tag_over_six_members() {
        let body = EntryBody { op: "insert", bytes: b"B".to_vec() };
        let term = BoardTerm { log_position: 1, chain: [0; 32] };
        let frame = entry_frame(
            "mldsa65-ed25519",
            term,
            &addr(&[1, 0, 1]),
            &addr(&[1, 0, 1, 0, 1]),
            &body,
        );
        let board = board_bytes(&term);
        let mut want = b"skep-entry-v1".to_vec();
        for m in [
            &b"mldsa65-ed25519"[..],
            &board[..],
            b"1.0.1",
            b"1.0.1.0.1",
            b"insert",
            b"B",
        ] {
            want.extend_from_slice(&(m.len() as u32).to_be_bytes());
            want.extend_from_slice(m);
        }
        assert_eq!(frame, want);
    }
}
