//! The landing's writer and the ids its writes carry.
//!
//! [`Writer`] holds the merger and a reader under its token, and the
//! landing, the undo and the withdrawal write through it: one write's
//! answer, the check of a journal named, the head the shot signs over and
//! its `attest`. [`Stem`] spells each write's per-session ids (the `land`
//! module's doc).

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use skep_address::Address;
use skep_identity::{entry_frame, BoardTerm, DocTerm, EntryBody};

use crate::address::parse_address;
use crate::board::{Answer, Board, BoardHead};
use crate::halt::Halt;
use crate::merge::reads::{session_ended, OnEnd, Reader, Refusal};
use crate::sign::sig_hex;

use super::faults::{head_owed, own_fault_face, Unfit};
use super::landing::Merger;

/// The stem of a landing write's per-session ids (wire.md §Correlation and
/// idempotency; the merge record's §1.5).
///
/// It is `merge:` and the lowercase hex of the SHA-256 of the text naming the
/// write (the `land` module's doc), 70 bytes whatever the text, so every id a
/// landing sends stays inside the 256-byte id cap skepd holds at parse
/// (skep-febe's `MAX_REQ_ID_BYTES`; a longer id is refused `malformed`),
/// however many sides the key spells and however deep their addresses. Equal
/// texts give equal stems and distinct texts distinct ones, so the board's memo
/// answers a second call over one write and never another write's.
pub(in crate::merge) struct Stem(String);

impl Stem {
    /// Returns the stem of the write `text` names.
    pub(in crate::merge) fn of(text: &str) -> Stem {
        Stem(format!("merge:{}", crate::hex::encode(&Sha256::digest(text.as_bytes()))))
    }

    /// Returns the id `<stem>.<suffix>` of one of the write's frames.
    pub(in crate::merge) fn id(&self, suffix: &str) -> String {
        format!("{}.{suffix}", self.0)
    }

    /// Returns the stem's text.
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The landing's writer: the merger and a reader under its token.
///
/// The undo and the withdrawal (the `undo` module) write through it too:
/// the journal's check, the one write and the record are theirs as the
/// landing's. Its reads and writes face a session's end alike, for the
/// one act it was built for: its reader's [`OnEnd`].
pub(in crate::merge) struct Writer<'a> {
    pub(in crate::merge) board: &'a Board,
    pub(in crate::merge) merger: Merger<'a>,
    pub(in crate::merge) reader: Reader<'a>,
}

impl<'a> Writer<'a> {
    /// Returns a writer over `board` as `merger`, its reader under the
    /// merger's token, for an act whose session's end leaves `on_end`.
    pub(in crate::merge) fn new(board: &'a Board, merger: Merger<'a>, on_end: OnEnd) -> Writer<'a> {
        Writer { board, merger, reader: Reader::new(board, Some(merger.token), on_end) }
    }
}

impl Writer<'_> {
    /// Sends one write under the merger's token.
    ///
    /// Its answer is the response document.
    ///
    /// # Errors
    ///
    /// The death signal under the token, [`Refusal::SessionEnded`] naming
    /// the write `during` names, faced for the writer's act; otherwise
    /// [`Board::op`]'s errors.
    pub(in crate::merge) fn answered_write(&self, frame: &Value, during: &str) -> Result<Value, Refusal> {
        match self.board.op(Some(self.merger.token), frame)? {
            Answer::Closed => Err(session_ended(during, self.reader.on_end())),
            Answer::Document(v) => Ok(v),
        }
    }

    /// Checks a journal the caller named before the act's first write (P13).
    ///
    /// The record goes into the journal after the act's write, so a journal
    /// that cannot take it is refused before that write, never met after
    /// it: one `doc_metadata` of `journal` at the head, judged in the board's
    /// own order for the atom's insert ([`Unfit`]) — the read answered, then
    /// the owner, then the published bit. `None`, the account's own journal
    /// found or minted at the record, is not read. `blocked` names what the
    /// refusal stops, after the journal's reason in the face's state.
    ///
    /// # Errors
    ///
    /// In this order, nothing sent:
    ///
    /// - a journal this merger may not read, one this board does not
    ///   register, or another account's, as [`Refusal::Halt`] with a face
    ///   naming the journal and the check it fails;
    /// - a merger's account this client cannot spell, as the library's own
    ///   fault;
    /// - a published journal of the merger's own, as
    ///   [`Refusal::PublishedJournal`] naming it: a merge record is kept only
    ///   in a private document;
    /// - the read's other refusals and halts; the death signal,
    ///   [`Refusal::SessionEnded`].
    pub(in crate::merge) fn check_journal(
        &self,
        journal: Option<&Address>,
        blocked: &str,
    ) -> Result<(), Refusal> {
        let Some(journal) = journal else {
            return Ok(());
        };
        let (unfit, found) = match self.reader.metadata(journal, None) {
            Err(Refusal::Unreadable(_)) => {
                (Unfit::Withheld, "its `doc_metadata` answered withheld".to_string())
            }
            Err(Refusal::NoSuchDocument(_)) => {
                (Unfit::Unregistered, "its `doc_metadata` answered doc_not_registered".to_string())
            }
            Err(e) => return Err(e),
            Ok(meta) => {
                let account = parse_address(self.merger.account).ok_or_else(|| {
                    own_fault_face(
                        "the merger's account cannot be spelled",
                        self.merger.account.to_string(),
                    )
                })?;
                if parse_address(&meta.owner).as_ref() != Some(&account) {
                    (Unfit::Foreign, format!("its `doc_metadata` names the owner {}, and only a document's owner writes into it (not_owner)", meta.owner))
                } else if meta.published {
                    return Err(Refusal::PublishedJournal { journal: journal.clone() });
                } else {
                    return Ok(());
                }
            }
        };
        Err(Halt::face(
            format!("{}, so {blocked}", unfit.reason(journal)),
            format!("the merge's record goes into the journal named after the act's write, so the journal is read before any write: {found}"),
            "name as the journal a draft this account owns, or none for the account's own; nothing was written",
        )
        .into())
    }

    /// Returns the term the shot signs over (SP-14).
    ///
    /// It is `H.1`'s pair, or `None` on a board no one has claimed, which
    /// takes the shot without an `attest` (`Board::board_head`). The shot
    /// reads it first, and again where it went unsigned and a claim landed
    /// past that read ([`Writer::attest_after_claim`]); no other write of a
    /// merge is signed, so none reads it (the `land` module's doc).
    ///
    /// # Errors
    ///
    /// A claimed board serving no head record, faced as [`head_owed`], with
    /// nothing sent; `Board::board_head`'s halts, a head record that stands
    /// and cannot be read among them.
    pub(super) fn signing_term(&self) -> Result<Option<BoardTerm>, Refusal> {
        let claimant = match self.board.board_head()? {
            BoardHead::Term(term) => return Ok(Some(term)),
            BoardHead::Unclaimed => return Ok(None),
            BoardHead::Owed { claimant } => claimant,
        };
        Err(head_owed(format!("the board names {claimant} its claimant and serves no head record (`H.1`), and the shot signs over that record's pair (signed ops), so it is not sent before the board writes it")).into())
    }

    /// Returns the `attest` member over `body`.
    ///
    /// It is for a write whose `doc` row is `doc`: the entry frame under
    /// `term` — `H.1`'s pair as [`Writer::signing_term`] read it — the
    /// merger's account and the row, signed by the merger's signer (signed
    /// ops; `skep_identity::entry_frame`, the one composer). `None` where
    /// `term` is none: a board no one has claimed, which drops the member
    /// unread.
    ///
    /// # Errors
    ///
    /// A merger's account this client cannot spell, as the library's own
    /// fault.
    pub(in crate::merge) fn attest(
        &self,
        term: Option<BoardTerm>,
        doc: &Address,
        body: &EntryBody,
    ) -> Result<Option<Value>, Refusal> {
        let Some(term) = term else { return Ok(None) };
        let account = parse_address(self.merger.account).ok_or_else(|| {
            own_fault_face(
                "the merger's account cannot be spelled",
                self.merger.account.to_string(),
            )
        })?;
        let alg = self.merger.signer.public_key().alg().to_string();
        let bytes = entry_frame(&alg, term, &account, DocTerm::One(doc), body);
        Ok(Some(json!({"alg": alg, "sig": sig_hex(&self.merger.signer.sign(&bytes))})))
    }
}
