//! THE FRAMES over the claimant's ONE content-scoped signed session
//! (wire.md §Sessions: a content-scoped session "reads, holds its draft
//! visibility, writes content, publishes, grants and closes exactly as a
//! full session does" — the tool deposits no credential, so Content is its
//! scope, and it works on an ENFORCING board too). Every write the tool
//! makes, each as a suite of the workspace already spells it, with the
//! envelope's `id` on every write (§Correlation and idempotency) and the
//! `attest` member on every publish-class one:
//!
//! * the staging draft's mint — `create_new_document` flagless, no attest
//!   (a draft's mint is outside the publish-class gate);
//! * the per-byte `insert` — the string form, one value per byte — in
//!   frames of at most [`INSERT_CHUNK`] bytes at consecutive ordinals (the
//!   search budgets' `try_insert`), `{"hex"}` where a stretch is not UTF-8;
//! * the edition's mint — `create_new_document` with `published: true`, the
//!   attest over `entry_body_empty(CreateNewDocument)`, `doc` the account;
//! * THE SHOT — `publish` naming the staging `draft`, so its runs are
//!   "re-inserted as fresh identity under `doc`'s own I-space" and a GUEST
//!   reads them (the search suite's `published()` form — never the budgets
//!   harness's `publish_windows`, whose runs stay windows a guest meets as
//!   `withheld`); attested over `entry_body_publish`: one value per byte for
//!   every run the commit copies in — the document's own I-space placed by
//!   reference and the draft's re-inserted — a WINDOW for a run onto any
//!   other document, signed by where it quotes from, and the base group
//!   where `base` and `base_extent` are named ("either both or neither");
//! * the attested `make_link` — the from-end a V-SPEC the tool resolves
//!   through `image` "against the base the transaction will take" into the
//!   I-extent spans the daemon stores (the daemon suite's `extent_span`:
//!   the run's start, a width of zeros but the last component), the to-end
//!   and the type address-form, their unit spans; the body
//!   `entry_body_make_link` over the three slot rows, the `replaces` row
//!   empty; `doc` the home;
//! * the reads: `image`, `retrieve_doc_v_span_set`, `doc_metadata` as a
//!   guest, `principal_prefix`, `/chain?at=0`'s reclaim floor; and the bare
//!   sessions the second account takes on a permissive board.
//!
//! THE RETRY, as L14b's harness retries (`skepd/tests/it/resolve.rs`
//! `op_as_written_retrying_write_busy`): `503 write_busy`, `durability` and
//! `attestation_invalid:board_unavailable` — the three transient tokens —
//! are sent again after [`WRITE_BUSY_BACKOFF_FIRST`], doubling to
//! [`WRITE_BUSY_BACKOFF_CAP`], until answered otherwise or
//! [`WRITE_BUSY_PATIENCE`] runs out, each counted ([`Retries`]); a stall is
//! said as it begins and at most once per [`STALL_SAID_EVERY`] after, each
//! line naming the token, the write's op and envelope id, its refusals so
//! far and the run's; a write the patience ran out on halts naming its op,
//! its envelope id, the token as the board spells it and why the board kept
//! answering it. Every other rejection stops the run as the board's own
//! refusal (exit 1, its `code:detail` verbatim) — a `poisoned` one holding
//! its write as IN FLIGHT, since a restart may land it — transport as exit
//! 4, the write whose request it may have carried held so too
//! ([`Writer::take_in_flight`]), and the death signal as a halt. A halt
//! that echoes a board's answer echoes no more of it than [`clipped`] keeps.

use std::num::NonZeroU64;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_address::{Address, Nat, Span, Tumbler};
use skep_client::address::parse_address;
use skep_client::board::{
    acked_addr, frames, Answer, Board, ChainAtAnswer, Opened, Rejection, Scope, SessionBody, Token,
};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::dial::DialError;
use skep_client::sign::{sig_hex, Signer};
use skep_client::Halt;
use skep_identity::{
    entry_body_empty, entry_body_make_link, entry_body_publish, entry_frame, unit_span, BoardTerm,
    ContentFreeOp, DocTerm, EntryBody, EntrySlot, LinkSlots, ShotBase, ShotSegmentPiece,
};

use crate::shared::clipped;
use crate::terminal::talk;

/// The most bytes one `insert` frame carries: 128 KiB, the search budgets'
/// chunk — one transaction is bounded by the kernel's `MAX_TXN_BYTES`, and
/// the codec's `MAX_INSERT_VALUES` caps a frame at 2¹⁸ values; a run of
/// single-byte values costs the journal its bytes and two records, so the
/// chunk sits well inside both, and the per-value cap is the one it meets
/// first.
pub const INSERT_CHUNK: usize = 1 << 17;

/// The first pause before a transient refusal is sent again.
pub const WRITE_BUSY_BACKOFF_FIRST: Duration = Duration::from_millis(1);

/// The pause's cap, the backoff doubling up to it.
pub const WRITE_BUSY_BACKOFF_CAP: Duration = Duration::from_millis(64);

/// How long one write is retried before the run stops.
pub const WRITE_BUSY_PATIENCE: Duration = Duration::from_secs(60);

/// The least time between two lines a stall says: a stall is said as it
/// begins, then at most once per this span while refusals keep coming — a
/// storm says one line per ten seconds, never one per write, and a stall
/// met again later in the run is said again.
pub const STALL_SAID_EVERY: Duration = Duration::from_secs(10);

/// THE CITATION TYPE: the commons' `3.13 citation` under the registry
/// document's subspace 3, as the wire spells its pinned classes
/// (`1.1.0.1.0.1.0.3.<n>`) — every link the tool writes is typed it.
pub const CITATION_TYPE: &str = "1.1.0.1.0.1.0.3.13";

/// The retries made, by token.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Retries {
    pub write_busy: u64,
    pub durability: u64,
    pub board_unavailable: u64,
}

/// One run of an arrangement as the wire carries it: its origin — the
/// document that minted its addresses — its first I-address and its width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub origin: String,
    pub i_start: String,
    pub width: u64,
}

/// One run PLACED in a shot, in V-order: the run, and the bytes at its
/// positions where the commit copies them in — the document's own run and
/// the staging draft's — or none for a window onto another document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placed {
    pub run: Run,
    pub bytes: Option<Vec<u8>>,
}

/// A V-spec: `width` content positions of `source` from ordinal `from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VSpec<'a> {
    pub source: &'a str,
    pub from: u64,
    pub width: u64,
}

/// The transient tokens, retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transient {
    WriteBusy,
    Durability,
    BoardUnavailable,
}

impl Transient {
    /// The token as the board answers it (wire.md §HTTP status codes,
    /// §Rejection codes), as the board's own operator stream names it.
    fn token(self) -> &'static str {
        match self {
            Transient::WriteBusy => "write_busy",
            Transient::Durability => "durability",
            Transient::BoardUnavailable => "attestation_invalid:board_unavailable",
        }
    }

    /// Why the board kept answering it, in the wire's terms.
    fn cause(self) -> &'static str {
        match self {
            Transient::WriteBusy => "the board's write permit pool stayed full: other writers held every permit, and the write was refused before any lock, nothing committed",
            Transient::Durability => {
                "the commit's durability barrier kept failing and the write did nothing — at a full volume no retry succeeds until the operator frees room, which the board's operator stream names"
            }
            Transient::BoardUnavailable => {
                "the board has no H.1 for the attest to name: on a claimed board only the one write after a refused H.1 answers so, and that write's own turn writes the head — a refusal that persists is a journal damaged below H.1"
            }
        }
    }
}

impl Retries {
    /// One retry of `transient` counted.
    fn tally(&mut self, transient: Transient) {
        match transient {
            Transient::WriteBusy => self.write_busy += 1,
            Transient::Durability => self.durability += 1,
            Transient::BoardUnavailable => self.board_unavailable += 1,
        }
    }

    /// The retries of every token.
    pub fn total(&self) -> u64 {
        self.write_busy + self.durability + self.board_unavailable
    }
}

/// Whether a transport halt's exchange may have carried its request to the
/// board: every phase but the four that end before a byte of it is written —
/// a scheme no transport holds, a host unresolved, a connection refused, a
/// request this client refuses to write.
fn may_have_sent(d: &DialError) -> bool {
    !matches!(d, DialError::NotHeld(_) | DialError::Resolve(_) | DialError::Connect(_) | DialError::Request(_))
}

/// A write frame IN FLIGHT: sent, and its fate one the run cannot read off
/// its answer — the one write a run stopped there may have landed with no
/// line of the manifest recording it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlight {
    /// The frame's envelope id.
    pub id: String,
    /// Why its fate is unread.
    pub unsettled: Unsettled,
}

/// Why an [`InFlight`] frame's fate is unread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsettled {
    /// Its answer was never read: a transport halt broke the exchange after
    /// the request may have been written ([`may_have_sent`]).
    Unanswered,
    /// Answered `poisoned`: the write that halted the kernel inside its
    /// commit may leave its frames in the journal, which the restart's open
    /// then lands (wire.md §Rejection codes; the shell's held burst `sent:
    /// true`, `client.md` §3c.2) — and the run cannot tell that write from
    /// one refused at a kernel already halted.
    Poisoned,
}

/// The claimant's one content-scoped signed session over the board, the
/// device key that signs its attested writes, and the counts.
pub struct Writer<'b> {
    board: &'b Board,
    session: Session<'b>,
    signer: Box<dyn Signer>,
    account: String,
    term: BoardTerm,
    pub retries: Retries,
    /// The write frames sent, retries included.
    pub writes: u64,
    /// The read frames sent, under the session or as a guest.
    pub reads: u64,
    /// When a stall was last said ([`STALL_SAID_EVERY`]).
    stall_said: Option<Instant>,
    /// The write frame sent whose fate is unread: set as each write frame
    /// goes out, cleared as its answer — an ack, a rejection, a refusal, the
    /// death signal — comes back, and held where a transport halt broke the
    /// exchange after the request may have been written ([`may_have_sent`])
    /// or the answer was `poisoned` ([`Unsettled`]).
    in_flight: Option<InFlight>,
}

impl<'b> Writer<'b> {
    /// The session opened: `H.1`'s term read (a board without one has no
    /// term for an attest to name), then the handshake at CONTENT scope —
    /// the pre-check's halts as the library renders them.
    pub fn open(
        board: &'b Board,
        signer: Box<dyn Signer>,
        principal: u64,
    ) -> Result<Writer<'b>, Halt> {
        let term = board.board_term()?.ok_or_else(|| {
            Halt::face(
                "this board has no H.1",
                "the head document's first member — the term every attested write names — is not readable: the board is unclaimed, or its journal is damaged below H.1",
                "claim the board first (`skep claim`), or restore it (RUNBOOK.md §2)",
            )
        })?;
        let session = handshake(board, Scope::Content, &*signer, principal, Site::Session)?;
        let account = session.account().to_string();
        Ok(Writer {
            board,
            session,
            signer,
            account,
            term,
            retries: Retries::default(),
            writes: 0,
            reads: 0,
            stall_said: None,
            in_flight: None,
        })
    }

    /// The write frame IN FLIGHT, taken: where a transport halt broke its
    /// exchange after the request may have been written, or its answer was
    /// `poisoned` — the one write a run stopped there may have landed, or
    /// may land at the board's restart, with no line of the manifest
    /// recording it.
    pub fn take_in_flight(&mut self) -> Option<InFlight> {
        self.in_flight.take()
    }

    /// `next_account_prefix(parent)`, the library's namespace read, counted.
    pub fn next_account_prefix(&mut self, parent: &str) -> Result<Option<String>, Halt> {
        self.reads += 1;
        self.board.next_account_prefix(parent)
    }

    /// `principal_prefix(principal)`, the library's namespace read, counted.
    pub fn principal_prefix(&mut self, principal: u64) -> Result<Option<String>, Halt> {
        self.reads += 1;
        self.board.principal_prefix(principal)
    }

    /// The session's ordinary end.
    pub fn close(self) -> Result<(), Halt> {
        self.session.close()?;
        Ok(())
    }

    /// The `attest` member over `body` for a write whose `doc` row is `doc`:
    /// the entry frame under `H.1`'s pair, the account and the row, signed
    /// by the device key.
    fn attest(&self, doc: &str, body: &EntryBody) -> Result<Value, Halt> {
        let account = address(&self.account)?;
        let doc = address(doc)?;
        let alg = self.signer.public_key().alg();
        let frame = entry_frame(alg, self.term, &account, DocTerm::One(&doc), body);
        Ok(json!({"alg": alg, "sig": sig_hex(&self.signer.sign(&frame))}))
    }

    /// ONE WRITE under the session — `id` its envelope key — the three
    /// transient tokens retried: the ack, or the halt.
    pub fn write(&mut self, frame: Value, id: &str) -> Result<Value, Halt> {
        let token = self.session.token().clone();
        self.write_as(&token, frame, id)
    }

    /// [`Writer::write`] under `token`'s session — the bare sessions the
    /// second account takes. Each frame is held IN FLIGHT from its sending
    /// to its answer ([`Writer::take_in_flight`]). A stall is said as its
    /// first refusal is met and at most once per [`STALL_SAID_EVERY`] while
    /// it lasts, a recurrence later in the run said again — naming the
    /// token, the write's op and envelope id, its refusals and seconds so
    /// far, and the run's retries by token: a storm is otherwise a minute of
    /// silence per write, its count said only at the end.
    pub fn write_as(&mut self, token: &Token, mut frame: Value, id: &str) -> Result<Value, Halt> {
        frame["id"] = Value::String(id.to_string());
        let began = Instant::now();
        let deadline = began + WRITE_BUSY_PATIENCE;
        let mut backoff = WRITE_BUSY_BACKOFF_FIRST;
        let mut refused = 0u64;
        loop {
            self.writes += 1;
            self.in_flight =
                Some(InFlight { id: id.to_string(), unsettled: Unsettled::Unanswered });
            let answer = self.board.op(Some(token), &frame);
            if !matches!(&answer, Err(Halt::Dial(d)) if may_have_sent(d)) {
                self.in_flight = None;
            }
            let transient = match answer {
                Ok(Answer::Document(v)) => match Rejection::of(&v) {
                    None => return Ok(v),
                    Some(r) if r.key() == "durability" => Transient::Durability,
                    Some(r) if r.token() == "attestation_invalid:board_unavailable" => {
                        Transient::BoardUnavailable
                    }
                    Some(r) => {
                        if r.key() == "poisoned" {
                            self.in_flight = Some(InFlight {
                                id: id.to_string(),
                                unsettled: Unsettled::Poisoned,
                            });
                        }
                        return Err(r.refused(&v));
                    }
                },
                Ok(Answer::Closed) => return Err(session_closed()),
                Err(Halt::Refused(r)) if r.status == 503 && r.code == "write_busy" => {
                    Transient::WriteBusy
                }
                Err(h) => return Err(h),
            };
            refused += 1;
            self.retries.tally(transient);
            if self.stall_said.is_none_or(|at| at.elapsed() >= STALL_SAID_EVERY) {
                self.stall_said = Some(Instant::now());
                talk(format!(
                    "the board answered `{}` to `{}` (envelope id `{id}`), {refused} time{} over {:.1} s for this write; this run's \
                     retries so far: write_busy {}, durability {}, board_unavailable {} — a write is retried for up to {} s",
                    transient.token(),
                    frame["op"].as_str().unwrap_or("?"),
                    if refused == 1 { "" } else { "s" },
                    began.elapsed().as_secs_f64(),
                    self.retries.write_busy,
                    self.retries.durability,
                    self.retries.board_unavailable,
                    WRITE_BUSY_PATIENCE.as_secs()
                ));
            }
            if Instant::now() >= deadline {
                return Err(Halt::face(
                    format!(
                        "the board refused `{}` (envelope id `{id}`) as `{}` for {} s, {refused} times",
                        frame["op"].as_str().unwrap_or("?"),
                        transient.token(),
                        WRITE_BUSY_PATIENCE.as_secs()
                    ),
                    transient.cause(),
                    "read the board's operator stream (a full volume is named there), then run again: the manifest holds what landed",
                ));
            }
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(WRITE_BUSY_BACKOFF_CAP);
        }
    }

    /// One READ under the session: the answer, a rejection the board's
    /// refusal.
    pub fn read(&mut self, frame: &Value) -> Result<Value, Halt> {
        self.reads += 1;
        match self.session.op(frame)? {
            Answer::Document(v) => match Rejection::of(&v) {
                Some(r) => Err(r.refused(&v)),
                None => Ok(v),
            },
            Answer::Closed => Err(session_closed()),
        }
    }

    /// One token-free read: the answer, a rejection included.
    pub fn guest(&mut self, frame: &Value) -> Result<Value, Halt> {
        self.reads += 1;
        self.board.guest(frame)
    }

    /// A private draft minted into `account`: flagless, no attest.
    pub fn mint_draft(&mut self, account: &str, id: &str) -> Result<String, Halt> {
        let v = self.write(json!({"op": "create_new_document", "account": account}), id)?;
        minted(&v)
    }

    /// An EDITION minted into the claimant's account: `published: true`,
    /// attested over the empty body, `doc` the account.
    pub fn mint_edition(&mut self, id: &str) -> Result<String, Halt> {
        let account = self.account.clone();
        let mut frame = json!({"op": "create_new_document", "account": account, "published": true});
        frame["attest"] =
            self.attest(&account, &entry_body_empty(ContentFreeOp::CreateNewDocument))?;
        let v = self.write(frame, id)?;
        minted(&v)
    }

    /// `bytes` inserted PER-BYTE into `doc` from content ordinal `ordinal`,
    /// in frames of at most [`INSERT_CHUNK`] bytes at consecutive ordinals
    /// — the envelope id `id` on the first frame, `id:2`, `id:3`, … on the
    /// rest; under `token` where one is given, else the session. The next
    /// fresh ordinal.
    pub fn insert(
        &mut self,
        token: Option<&Token>,
        doc: &str,
        ordinal: u64,
        bytes: &[u8],
        id: &str,
    ) -> Result<u64, Halt> {
        let token = token.cloned().unwrap_or_else(|| self.session.token().clone());
        let mut from = 0usize;
        let mut at = ordinal;
        let mut chunk = 0u64;
        while from < bytes.len() {
            chunk += 1;
            let mut end = (from + INSERT_CHUNK).min(bytes.len());
            let value = match std::str::from_utf8(bytes) {
                Ok(text) => {
                    while !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    Value::String(text[from..end].to_string())
                }
                Err(_) => json!({"hex": hex(&bytes[from..end])}),
            };
            let frame = json!({
                "op": "insert",
                "doc": doc,
                "at": {"subspace": "1", "ordinal": at.to_string()},
                "values": [value],
            });
            let chunk_id = if chunk == 1 { id.to_string() } else { format!("{id}:{chunk}") };
            self.write_as(&token, frame, &chunk_id)?;
            at += (end - from) as u64;
            from = end;
        }
        Ok(at)
    }

    /// `image` over content ordinals `from ..` of `doc`, `width` of them:
    /// the V→I runs, each with its origin.
    pub fn image(&mut self, doc: &str, from: u64, width: u64) -> Result<Vec<Run>, Halt> {
        let v = self.read(&frames::image(doc, from, width))?;
        let runs = v["runs"].as_array().ok_or_else(|| unexpected("image", &v))?;
        runs.iter()
            .map(|r| {
                let i_start =
                    r["i_start"].as_str().ok_or_else(|| unexpected("image", &v))?.to_string();
                let width = r["width"]
                    .as_str()
                    .and_then(|w| w.parse().ok())
                    .ok_or_else(|| unexpected("image", &v))?;
                let origin = origin_of(&i_start).ok_or_else(|| unexpected("image", &v))?;
                Ok(Run { origin, i_start, width })
            })
            .collect()
    }

    /// THE SHOT: the next member of `doc`'s chain, its arrangement `placed`
    /// in V-order, `draft` the staging draft whose runs are re-inserted,
    /// `base` the member staged from with its extent or none for the birth
    /// version — attested over the body the module doc states. The member's
    /// address.
    pub fn shot(
        &mut self,
        doc: &str,
        draft: &str,
        base: Option<(&str, u64)>,
        placed: &[Placed],
        id: &str,
    ) -> Result<String, Halt> {
        let starts: Vec<Option<Address>> = placed
            .iter()
            .map(|p| if p.bytes.is_none() { parse_address(&p.run.i_start) } else { None })
            .collect();
        let mut pieces: Vec<ShotSegmentPiece<'_>> = Vec::new();
        for (p, start) in placed.iter().zip(&starts) {
            match (&p.bytes, start) {
                (Some(bytes), _) => pieces
                    .extend(bytes.iter().map(|b| ShotSegmentPiece::Value(std::slice::from_ref(b)))),
                (None, Some(start)) => {
                    let width = NonZeroU64::new(p.run.width).ok_or_else(|| {
                        Halt::face(
                            "a window of width 0",
                            format!("the run at {} has no positions", p.run.i_start),
                            "this is the tool's fault; nothing was written",
                        )
                    })?;
                    pieces.push(ShotSegmentPiece::Window { start, width });
                }
                (None, None) => {
                    return Err(Halt::face(
                        format!("`{}` is not an address", p.run.i_start),
                        "a window's I-start could not be parsed",
                        "this is the tool's fault; nothing was written",
                    ))
                }
            }
        }
        let member = base.map(|(m, _)| address(m)).transpose()?;
        let shot_base =
            base.zip(member.as_ref()).map(|((_, extent), member)| ShotBase { member, extent });
        let body = entry_body_publish(pieces, shot_base);
        let runs: Vec<Value> = placed.iter().map(|p| json!({"origin": p.run.origin, "i_start": p.run.i_start, "width": p.run.width.to_string()})).collect();
        let mut frame = json!({"op": "publish", "doc": doc, "draft": draft, "runs": runs});
        if let Some((member, extent)) = base {
            frame["base"] = Value::String(member.to_string());
            frame["base_extent"] = Value::String(extent.to_string());
        }
        frame["attest"] = self.attest(doc, &body)?;
        let v = self.write(frame, id)?;
        minted(&v)
    }

    /// An attested citation link homed in `home`: `from` a V-spec, resolved
    /// through `image` into the spans the daemon stores — its source a
    /// VERSION address, which `image` and the store's own resolution read
    /// alike, where a bare published address would float to the head under
    /// `image` alone; `to` and the type address-form. The link's address.
    pub fn link(
        &mut self,
        home: &str,
        from: VSpec<'_>,
        to: &str,
        id: &str,
    ) -> Result<String, Halt> {
        let runs = self.image(from.source, from.from, from.width)?;
        let from_spans: Vec<Span> = runs
            .iter()
            .map(|r| extent_span(&r.i_start, r.width))
            .collect::<Option<_>>()
            .ok_or_else(|| {
                Halt::face(
                    "a run `image` answered is no content extent",
                    clipped(&format!("{runs:?}")),
                    "this is a board fault; nothing was written",
                )
            })?;
        let to_spans = [unit_span(&address(to)?)];
        let ty_spans = [unit_span(&address(CITATION_TYPE)?)];
        let body = entry_body_make_link(LinkSlots {
            from: EntrySlot(&from_spans),
            to: EntrySlot(&to_spans),
            ty: EntrySlot(&ty_spans),
        });
        let mut frame = json!({
            "op": "make_link",
            "home": home,
            "from": [{"source": from.source, "span": {"start": format!("1.{}", from.from), "width": format!("0.{}", from.width)}}],
            "to": {"addrs": [to]},
            "ty": {"addrs": [CITATION_TYPE]},
        });
        frame["attest"] = self.attest(home, &body)?;
        let v = self.write(frame, id)?;
        minted(&v)
    }

    /// Whether `doc` is registered: `doc_metadata` as a guest answers its
    /// state, or `doc_not_registered`.
    pub fn registered(&mut self, doc: &str) -> Result<bool, Halt> {
        let v = self.guest(&frames::doc_metadata(doc))?;
        match Rejection::of(&v) {
            None => Ok(true),
            Some(r) if r.key() == "doc_not_registered" => Ok(false),
            Some(r) => Err(r.refused(&v)),
        }
    }

    /// A BARE session as `principal` — honoured on a CLAIMED-PERMISSIVE
    /// board, refused on an ENFORCING one: `None` then.
    pub fn bare(&self, principal: u64) -> Result<Option<Token>, Halt> {
        match self.board.session_open(SessionBody::Bare { principal })? {
            Opened::Token(t) => Ok(Some(t)),
            Opened::Rejected | Opened::Blocked { .. } => Ok(None),
        }
    }

    /// The journal's RECLAIM FLOOR — the oldest position `/chain?at` still
    /// answers — read off `/chain?at=0`'s `410 history_reclaimed` answer
    /// (the library's `Board::chain_at`); `0` where genesis is retained. The
    /// one retry-class answer, `503 history_busy` (every reconstruction
    /// permit in use; wire.md §Reading history), is a halt saying so: it
    /// comes after every write is recorded, so the run after it writes
    /// nothing and reads the floor again.
    pub fn reclaim_floor(&mut self) -> Result<u64, Halt> {
        self.reads += 1;
        match self.board.chain_at(0)? {
            ChainAtAnswer::Chain { .. } => Ok(0),
            ChainAtAnswer::HistoryReclaimed { floor } => Ok(floor.unwrap_or(0)),
            ChainAtAnswer::Busy => Err(Halt::face(
                "/chain?at=0 answered 503 history_busy",
                "the board was busy reading history — every reconstruction permit in use (a retry-class 503, wire.md §HTTP status \
                 codes) — and took nothing; every write of this seed is recorded",
                "run again: the manifest holds every write, so the next run writes nothing and reads this again",
            )),
            other => Err(Halt::face(
                format!("/chain?at=0 answered {}", clipped(&format!("{other:?}"))),
                "position 0 is no position a board refuses as beyond its head or between commits",
                "this board is not speaking the wire this tool expects",
            )),
        }
    }
}

/// The halt the death signal comes to: the session is dead, and the run
/// stops where it stands.
fn session_closed() -> Halt {
    Halt::face(
        "the board closed this session",
        "the death signal rode the answer: a daemon restart, the key's retirement, a block or a genesis at the account ended the token",
        "run again: the manifest holds what landed, and the run resumes after it",
    )
}

/// An answer without the member the frame's `resp` promises, its opening
/// echoed.
fn unexpected(op: &str, v: &Value) -> Halt {
    Halt::face(
        format!("`{op}` answered a document this tool cannot read"),
        clipped(&v.to_string()),
        "this board is not speaking the wire this tool expects; nothing more was written",
    )
}

/// An `ack_addr`'s minted address, or the halt an ack without one is.
fn minted(v: &Value) -> Result<String, Halt> {
    acked_addr(v).map(str::to_string).ok_or_else(|| unexpected("the write", v))
}

/// `text` as an address, or the halt a board answering no address is.
fn address(text: &str) -> Result<Address, Halt> {
    parse_address(text).ok_or_else(|| {
        Halt::face(
            format!("`{text}` is not an address"),
            "an address this tool composed or the board answered does not parse",
            "this is a tool or board fault; nothing more was written",
        )
    })
}

/// The document a content I-address was minted under: the prefix before
/// its last `.0.1.`.
pub fn origin_of(i_addr: &str) -> Option<String> {
    i_addr.rfind(".0.1.").map(|at| i_addr[..at].to_string())
}

/// A tumbler from its dotted decimal.
fn tumbler(text: &str) -> Option<Tumbler> {
    let comps: Option<Vec<Nat>> =
        text.split('.').map(|c| c.parse::<u64>().ok().map(Nat::from)).collect();
    Tumbler::new(comps?).ok()
}

/// A stored content extent from a run as `image` answers it — its I-start
/// and its width in positions: the start's own tumbler, and a width of
/// zeros at every component but the last, which holds the count (the
/// daemon suite's `extent_span`).
fn extent_span(i_start: &str, width: u64) -> Option<Span> {
    let start = tumbler(i_start)?;
    let mut comps = vec![Nat::from(0u64); start.len()];
    *comps.last_mut()? = Nat::from(width);
    Span::new(start, Tumbler::new(comps).ok()?).ok()
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
