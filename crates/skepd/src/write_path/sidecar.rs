//! The commit-metadata sidecar (wire v6): `commits.log` in the data dir —
//! one JSON line per committed write `(position, op kind, affected docs,
//! unix millis, testimony, signedness, the op's own terms)`, appended by the
//! write path at ack time and replayed on reopen. This is daemon-owned
//! TRANSPORT METADATA, never substrate state (wire.md §The change feed) —
//! exempt from the no-second-persistence-layer rule for the same reason as
//! the kernel's journal-lock file: it persists nothing about the WORLD,
//! since two daemons replaying one journal still converge on byte-identical
//! worlds. The sidecar is the daemon's testimony about its own service, and
//! it feeds `GET /changes` and `/health`'s `head_time`.
//!
//! This file is the feed's AUTHORITY file: what a position's entry SAYS —
//! its op, its docs, its time, its key, WHETHER and HOW its entry is signed
//! (`signed`, the daemon's own assertion at commit of why the wire's `key` is
//! absent: the marker slot filled, or the credential record's own `sig` —
//! never on the wire itself), and the op's own terms (a `delegate`'s minted
//! pair, a `make_link`'s minted link address, a `publish`'s placed count and
//! base extent — AUTH-6.36, the design record's D25 and r6-2a) — is recorded
//! here and nowhere else. The feed's four DERIVED sidecars (`feed/derived.rs`:
//! the per-document position index, the offset array, the masked-position
//! bitmap and the per-owner draft streams; PUB-7.19) are projections of this
//! file and the journal, rebuilt from them on loss; the fifth file beside
//! them, the ATTEST STORE (`feed-attest.log`), mirrors the marker slot's
//! signature per attested position and is NOT a projection below the
//! reclaim floor (`feed/attest.rs` states its class); `feed.rs` composes the
//! six. THE SIGNATURE ITSELF IS NEVER A MEMBER OF THIS FILE: here it would be
//! a rewritable sidecar assertion of the very class the marker exists to be
//! told apart from; this file records only that the marker was filled, which
//! is what lets the feed render a lost store line as `attest: null` (LOST)
//! rather than absent (a verdict).
//!
//! A LINE WRITTEN BEFORE THE SIGNEDNESS AND THE TERMS (no `signed`, no
//! terms) parses as it did: its row renders `key` as recorded and the op's
//! terms absent — dev boards regenerate (no-versioning); `attest` is the
//! store's to answer for such a row, as for every row.
//!
//! Crash honesty is the contract:
//!
//! * A torn tail is truncated at the last whole record on open — trust ends
//!   at the first unparseable line; the daemon never wedges on its own
//!   testimony. The cut is said on the operator stream once, with the last
//!   trusted position and the bytes ([`Cut`]), and its case: the cut part
//!   is re-derived as bare entries by the walk below.
//! * Positions whose record was lost, or that predate the feature, are
//!   reconstructed as BARE positions and answer `docs`/`key`/`time` as
//!   `null`. NEVER an invented value. The op's own TERMS, and the op where
//!   the journal names one alone, ARE answered on a bare row — from the
//!   journal, as the position's class is (`classify::derived_journal`;
//!   as7-F3): a `delegate`'s pair, a `make_link`'s link, a `publish`'s count
//!   and extent, so a feed-only mirror's Π is whole across a bare span. They
//!   ride the bare line under one `journal` member, written by the walk that
//!   derived them so the two reconstructions are paid once; `null` stays
//!   where the journal cannot answer.
//! * Reconstruction uses the two public journal-fed surfaces the daemon
//!   already holds — the kernel's one-scan boundary list
//!   (`Kernel::boundaries_above`, every committed boundary above the file's
//!   coverage from one base) and its bounded replay (`Kernel::world_at`):
//!   the list names the boundaries, an `Ok` replay of each PROVES it, and a
//!   refusal (reclaimed, corrupt, I/O) honestly ends the feed's reach below
//!   the boundary it refused — recorded as the smallest `since` this feed
//!   can honor, under which `/changes` answers the same 410 discipline as
//!   `/op-at`. The kernel's own journal reader stays closed. THE WALK RUNS
//!   BEHIND THE LISTENER (`operations.md` §3.3 step 2; §4 row 16): the open
//!   records the uncovered region `(low, head]` as PENDING and returns with
//!   the file as parsed; a thread of the write path's walks it while reads
//!   are served and writes admitted, and lands it by ONE whole rewrite of
//!   this file ([`CommitsLog::land`]), so the walk runs once per uncovered
//!   region, not once per open. While the region is pending, a page of
//!   `/changes` whose rows would have to come from it is refused
//!   retry-class (`feed_rebuilding`), a write's record is kept in memory
//!   alone until the landing writes it (a crash before then re-covers it
//!   BARE at the next open), and a kill mid-walk leaves the file unchanged,
//!   the next open walking again from `low`.
//! * A bare position CLASSIFIES FROM THE JOURNAL (PUB-6.45: "a lost sidecar
//!   never unmasks a draft write"): the walk holds the world at each
//!   boundary and the one below it, and the diff of the two — the drafts
//!   minted, the links deposited (their homes, and a retraction's targets'
//!   homes), the drafts whose arrangement moved (`classify::derived_docs`)
//!   — is the set of documents the feed's mask classifies the position by.
//!   The wire entry still answers `docs: null` (lost testimony is never
//!   invented); what the journal supplies is the CLASS, so a draft write
//!   whose record was lost is omitted from a guest's page exactly as a
//!   recorded one is. A boundary whose predecessor world the journal can no
//!   longer answer (the oldest boundary above a reclaimed region) is
//!   UNCLASSIFIABLE and is served to every class: it discloses its position
//!   alone, which `/events` and `head_time` already disclose board-wide
//!   (PUB-6.52's accepted residue), and nothing of what it wrote.
//!
//! The file — and the entries replayed from it — are bounded by the
//! journal's own retention, not by the world's age. Positions the journal has
//! reclaimed are unanswerable across the whole history surface, so the
//! sidecar drops its entries below that floor and rewrites itself around
//! them — at open (see [`CommitsLog::open`]) and, the floor moving at a
//! checkpoint and at no other moment, after each checkpoint the daemon's
//! checkpoint thread lands ([`CommitsLog::compact_to`], under the feed's
//! lock). Without that the feed's memory would be the only structure in the
//! daemon that grows with total commits ever made rather than with commits
//! still reachable, and it is fully resident. A rewrite that fails PAST its
//! rename while serving leaves the append handle naming the replaced file,
//! so it STOPS this file for the uptime as a failed append does — said once,
//! the next open re-deriving — and never fails an op (P22).
//!
//! The sidecar is written under the write path's serialization lock — held
//! by `write_path/`, which takes that lock and calls the feed's `record`
//! in one operation — so file order is position order and recorded times
//! are monotone non-decreasing in position (wall-clock reads are
//! additionally clamped against the last recorded time). Appends are
//! flushed to the OS but not fsynced — a lost tail answers bare, which is
//! the honest trade for not doubling every write's fsync cost on testimony.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(any(test, feature = "test-hooks"))]
use parking_lot::{Condvar, Mutex};
use serde_json::Value;
use skep_address::Address;
use skep_engine::{Engine, HistoryError, World};
use skep_kernel::{Attestation, Kernel, Seq};
use skep_util::json::obj;
use skep_util::notice::Class;

use super::classify::{derived_journal, parse_dotted};
use super::Lines;
use crate::codec::{j_attest, to_bytes};
use crate::limits::{FEED_WALK_PROGRESS_BOUNDARIES, FEED_WALK_PROGRESS_INTERVAL};
use crate::serial::SerialGuard;

/// The sidecar's file name inside the data dir (beside the kernel's own
/// journal/checkpoint files, which this crate never touches).
const SIDECAR_FILE: &str = "commits.log";

/// The wall-clock reading a commit's `time` is stamped with — unix
/// milliseconds, the wire's unit (wire.md §The change feed), `0` for a clock
/// set before the epoch. The write path's ONE reading of that clock because
/// two readers must agree on it: [`CommitsLog::record`] stamps every commit
/// with it, and the published head writer measures its hour FROM such a
/// stamp — its resume takes the last head's time off the head's own entry —
/// against its own reading. Two copies of this expression would agree only
/// until one was edited or seamed, and the head's hour would then subtract
/// one clock from another with nothing to say so. The media gate reads the
/// wall clock for itself (`media::gate::wall_clock_ms`, seamed apart for its
/// leases and expiries), and no reading of the one is ever compared with a
/// reading of the other.
pub(super) fn wall_clock_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// THE CARRIER of an entry's signature — what the file's `signed` field
/// records and the wire never carries: the daemon's own assertion at commit
/// of WHY the row's `key` is absent (D12; AUTH-6.15: "a signed entry has one
/// authority for its hand, its own signature, and the daemon asserts no
/// second beside it"). Two spellings in the file, `"marker"` and `"record"` —
/// the design record's own tokens (e-N2), carried by every signed line on
/// disk, so a variant's name never moves them: a token this parser stopped
/// spelling would leave each line carrying it torn at open — and, on every
/// unsigned line, the field's absence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Carrier {
    /// The entry's marker slot is filled — the value the plain sequence's
    /// check admitted and handed the kernel, mirrored by the attest store.
    /// A row recorded so whose slot the store cannot answer renders
    /// `attest: null`, LOST.
    Marker,
    /// The entry's signature is its CREDENTIAL record's own `sig` member (a
    /// credential record deposit, D26) — never this file's record, which
    /// holds no signature: at the atom's `insert` the credential record
    /// CARRIES one, verified at its `make_link` one position later under the
    /// set that opens its home (the record grade, 2a) — or refused there, the
    /// atom then an orphan no link names, the reader's UNDETERMINABLE HERE;
    /// at the `make_link` the `sig` VERIFIED. Neither row carries `attest`:
    /// the credential record's `sig` is the deposit's one carrier, covering
    /// both positions (D26, D27; e-Q2).
    RecordSig,
}

impl Carrier {
    /// The file's spelling.
    fn token(self) -> &'static str {
        match self {
            Carrier::Marker => "marker",
            Carrier::RecordSig => "record",
        }
    }

    fn of_token(token: &str) -> Option<Carrier> {
        match token {
            "marker" => Some(Carrier::Marker),
            "record" => Some(Carrier::RecordSig),
            _ => None,
        }
    }
}

/// THE OP'S OWN TERMS on a row — what a feed-only mirror needs from the row
/// alone (r6-2a; AUTH-6.36; the design record's D25 and §5.2), recorded at
/// commit as `docs` is, the daemon's testimony of what it committed. One
/// variant per op kind that carries any, rendered as [`OpTerms::members`] on
/// the wire's row and the file's line alike; every other kind carries none,
/// and its row renders none. A BARE row renders what THE JOURNAL answers
/// ([`JournalTerms`]) and `null` for every member it cannot
/// ([`OpTerms::MEMBER_NAMES`]): lost testimony is never invented, and the
/// journal's answer is no invention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum OpTerms {
    /// `delegate`: the minted account address in the board's local form (the
    /// `ack_addr` the op answers) and the principal id it seated —
    /// AUTH-6.36's members by name. `new_id` is a JSON number: it was held to
    /// 2^53 − 1 at the parse, the wire's exactly-representable range.
    Delegate { new_prefix: String, new_id: u64 },
    /// `make_link`: the minted link's address, the `ack_addr` the op answers.
    /// For a replacing grant this is THE GRANT RECORD's address; its
    /// `replaces` link sits at the next address, read by adjacency.
    MakeLink { link: String },
    /// `publish`: D25's two client terms exactly as `doc_metadata` serves
    /// them for the minted member — the count the client placed, and the
    /// extent of the base the staged copy took, `None` in the birth shape
    /// (the absence IS the birth bit). Both decimal strings, `Nat`'s wire
    /// form.
    Publish { placed: String, base_extent: Option<String> },
}

impl OpTerms {
    /// Every member any op's terms render under — what a BARE row renders
    /// `null`, its op (and so which of them it carried) unknown. Held to the
    /// union of [`OpTerms::members`] over the variants by the sidecar test
    /// `a_bare_row_nulls_exactly_the_members_the_terms_render`.
    const MEMBER_NAMES: [&'static str; 5] =
        ["new_prefix", "new_id", "link", "placed", "base_extent"];

    /// The members these terms render as — on the wire's row and in the
    /// file's line alike, one spelling for both, which [`parse_line`] reads
    /// back: a `publish`'s birth extent is `null`, the absence being the
    /// birth bit.
    fn members(&self) -> Vec<(&'static str, Value)> {
        match self {
            OpTerms::Delegate { new_prefix, new_id } => vec![
                ("new_prefix", Value::String(new_prefix.clone())),
                ("new_id", Value::Number((*new_id).into())),
            ],
            OpTerms::MakeLink { link } => vec![("link", Value::String(link.clone()))],
            OpTerms::Publish { placed, base_extent } => vec![
                ("placed", Value::String(placed.clone())),
                ("base_extent", base_extent.clone().map(Value::String).unwrap_or(Value::Null)),
            ],
        }
    }
}

/// THE JOURNAL'S ANSWER on a BARE position (as7-F3; SO-I5 (e)): the op's
/// own terms as the recorded row would have carried them, and the op where
/// the journal's facts name one op alone — derived by
/// `classify::derived_journal` at the open that reconstructs the position,
/// from the two worlds the walk already holds, and persisted on the bare
/// line under the `journal` member so the walk is paid once. Not testimony
/// — the daemon witnessed nothing — and never rendered as such: `docs`,
/// `key` and `time` stay `null` beside it. Empty where the journal answers
/// nothing, which renders as the bare row always did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct JournalTerms {
    /// The op the journal names, where it names one alone: `delegate`,
    /// `publish`, `version`, `nullify`, a replacing `make_link`; `None` for
    /// an op the facts leave ambiguous (`classify::derived_journal`'s terms
    /// say which).
    pub op: Option<String>,
    /// The terms the journal answers — a seated principal's pair, a minted
    /// member's count and extent, a deposited link.
    pub terms: Option<OpTerms>,
}

impl JournalTerms {
    /// Nothing derived: the row renders as a bare row always did.
    fn is_empty(&self) -> bool {
        self.op.is_none() && self.terms.is_none()
    }

    /// The `journal` member's object — `op` where named, then the terms'
    /// members in the wire's own spelling.
    fn members(&self) -> Vec<(&'static str, Value)> {
        let mut pairs = Vec::new();
        if let Some(op) = &self.op {
            pairs.push(("op", Value::String(op.clone())));
        }
        if let Some(terms) = &self.terms {
            pairs.extend(terms.members());
        }
        pairs
    }

    /// The inverse of [`JournalTerms::members`], over a bare line's
    /// `journal` object: `op` an optional string, the terms by the members
    /// present — a `delegate`'s pair together (one without the other is
    /// torn), a `link`, a `placed` with `base_extent` beside it (`null`
    /// the birth shape). `None` is the torn verdict.
    fn parse(m: &serde_json::Map<String, Value>) -> Option<JournalTerms> {
        let field = |k: &str| match m.get(k) {
            None | Some(Value::Null) => None,
            Some(v) => Some(v),
        };
        let op = match field("op") {
            None => None,
            Some(op) => Some(op.as_str()?.to_string()),
        };
        let terms = match (field("new_prefix"), field("new_id"), field("link"), field("placed")) {
            (Some(p), Some(i), None, None) => {
                Some(OpTerms::Delegate { new_prefix: p.as_str()?.to_string(), new_id: i.as_u64()? })
            }
            (None, None, Some(l), None) => Some(OpTerms::MakeLink { link: l.as_str()?.to_string() }),
            (None, None, None, Some(p)) => Some(OpTerms::Publish {
                placed: p.as_str()?.to_string(),
                base_extent: match field("base_extent") {
                    None => None,
                    Some(e) => Some(e.as_str()?.to_string()),
                },
            }),
            (None, None, None, None) => None,
            _ => return None,
        };
        Some(JournalTerms { op, terms })
    }
}

/// One committed position's metadata — and this file's crash-honesty rule
/// as a type. A position is either one the daemon OBSERVED committing,
/// carrying all of op/docs/time, or a BARE one reconstructed from the
/// journal, carrying none of them. Three independent `Option`s would admit
/// six more combinations, and this file has a meaning for neither the
/// half-recorded position nor the record that remembers when but not what.
#[derive(Clone, Debug)]
pub(super) enum CommitMeta {
    /// Reconstructed, not witnessed: served as explicit `null`s, never as
    /// an invented value — beside what THE JOURNAL answers for it
    /// ([`JournalTerms`]: the op's terms, and the op where named). Its
    /// CLASS — which documents the journal shows it touched — lives in the
    /// feed's classification map, not here: this file records testimony,
    /// and the journal's answer is not testimony.
    Bare {
        journal: JournalTerms,
    },
    /// Witnessed by the daemon's own write path as the write commits — a
    /// session write's at its ack, the published head writer's own in its
    /// turn. `key` is the AUTH testimony (AUTH-4.48; wire.md §The change
    /// feed), one of THREE values: the fingerprint hex of the enrolled key
    /// that established the authoring session, `"bare"` for a bare one, or
    /// `"system"` for the published head writer's own commits, which have no
    /// session (`SYSTEM_TESTIMONY`, `write_path/head.rs`) — the value that
    /// writer's resume READS BACK through this field to tell its own commits
    /// from the ones its count bound counts. `None` only for a line written
    /// before the feature — served as the reserved null (AUTH-1.52's
    /// lost-metadata meaning), never for a commit this daemon served since.
    /// Recorded on every line, a signed entry's included: the file is the
    /// daemon's own, and the resume above reads it; what D12 keeps off the
    /// WIRE is decided at [`CommitMeta::entry`] by `signed`, the carrier of
    /// the entry's signature where it has one. `terms` are the op's own
    /// ([`OpTerms`]); `None` on an op that carries none, and on a line
    /// written before they were recorded.
    Recorded {
        op: String,
        docs: Vec<String>,
        time: u64,
        key: Option<String>,
        signed: Option<Carrier>,
        terms: Option<OpTerms>,
    },
}

impl CommitMeta {
    /// One `GET /changes` entry: the position, the four fields, and —
    /// wire v7.11 — the members a reader needs to judge and to place the
    /// entry from the feed alone. A bare position renders its testimony as
    /// explicit `null`s — `docs`, `key`, `time` — and the op and its terms
    /// AS THE JOURNAL ANSWERS THEM (as7-F3; [`JournalTerms`]): where the
    /// journal names the op, exactly that op's members, as the recorded row
    /// carries them; where it names a deposited link alone, `link`, the
    /// members no link write carries ABSENT as on a recorded row; where it
    /// answers nothing, every term `null` — the crash-honesty rule of this
    /// file, expressed where the rule is stated rather than at the handler.
    /// `reduced` is the record's own docs REDUCED to the requester's
    /// readable ones (PUB-6.45), which is what a recorded entry renders —
    /// never `Recorded.docs`, which is the WHOLE list and which rendering
    /// here would hand a requester the home of a draft-homed record they may
    /// not read (PUB-6.47 licenses their learning it exists, never its home).
    /// It is ignored for a bare position, whose docs are the reserved null
    /// whatever its class. Deliberately NOT [`entry_line`]'s convention,
    /// which omits absent fields: the file is daemon-private and
    /// [`parse_line`] reads absent and null alike, so the shorter line costs
    /// nothing there, while a client reading the wire is owed the field it
    /// asked about.
    ///
    /// THE MEMBERS THAT ARE ABSENT RATHER THAN NULL, and why:
    ///
    /// * `key` (D12; AUTH-6.15): PRESENT IFF the entry carries no signature —
    ///   absent on a row whose `signed` names a carrier (a marker-signed
    ///   row; a credential record deposit's LINK row, as7-E2 (a) — its ATOM
    ///   row is admitted unsigned and serves its `key`), served as recorded
    ///   on every other row, a bare row's reserved `null` included (lost
    ///   testimony stays lost; the store's slot is a fact of the journal, not
    ///   testimony this file can restore).
    /// * `attest` (the design record §7.3 (i)): the marker slot as the store
    ///   holds it, `{"alg", "sig"}`, on any row the store answers; `null` —
    ///   LOST — where the line records the marker filled and the store cannot
    ///   answer; ABSENT on every other row: an unsigned entry, a credential
    ///   record deposit's two rows (the deposit's slot is empty; its signature
    ///   is the credential record's own `sig`), the ceremony's rows, the head
    ///   writer's — and a row whose `docs` the requester's class REDUCES
    ///   (PUB-6.47's straddles; SO-I5 (e)), its signature a function of the
    ///   home the row withholds, where the feed's page removes the member
    ///   this method renders.
    ///   Absence on the origin's own feed, on a row served WHOLE at the
    ///   reader's own class, is A6's verdict, so a store line is served
    ///   wherever one is held and never dropped.
    /// * the op's terms ([`OpTerms::members`], the file line's spelling too):
    ///   present on the row of the op that carries them, absent on every
    ///   other op's; on a bare row the journal's answer ([`JournalTerms`]),
    ///   and `null` for every member it does not reach
    ///   ([`OpTerms::MEMBER_NAMES`]).
    ///
    /// `attest` is the store's answer for this position, looked up by the
    /// feed beside the line: the signature is never a member of this file.
    pub fn entry(&self, at: u64, reduced: Vec<String>, attest: Option<&Attestation>) -> Value {
        let mut pairs = vec![("at", Value::Number(at.into()))];
        let carrier = match self {
            CommitMeta::Bare { journal } => {
                pairs.extend(["docs", "key", "time"].into_iter().map(|k| (k, Value::Null)));
                pairs.push(("op", journal.op.clone().map(Value::String).unwrap_or(Value::Null)));
                match &journal.terms {
                    // The journal names the terms: the op's own members, the
                    // rest ruled out by the witness that named them.
                    Some(terms) => pairs.extend(terms.members()),
                    // The journal names the op and the op carries none —
                    // `nullify`, `version` — so none renders; the journal
                    // names nothing — every term stays the reserved null.
                    None if journal.op.is_some() => {}
                    None => pairs.extend(OpTerms::MEMBER_NAMES.into_iter().map(|k| (k, Value::Null))),
                }
                None
            }
            CommitMeta::Recorded { op, time, key, signed, terms, .. } => {
                pairs.push(("docs", Value::Array(reduced.into_iter().map(Value::String).collect())));
                pairs.push(("op", Value::String(op.clone())));
                pairs.push(("time", Value::Number((*time).into())));
                if signed.is_none() {
                    pairs.push(("key", key.clone().map(Value::String).unwrap_or(Value::Null)));
                }
                if let Some(terms) = terms {
                    pairs.extend(terms.members());
                }
                *signed
            }
        };
        match (attest, carrier) {
            (Some(a), _) => pairs.push(("attest", j_attest(a))),
            (None, Some(Carrier::Marker)) => pairs.push(("attest", Value::Null)),
            (None, Some(Carrier::RecordSig) | None) => {}
        }
        obj(pairs)
    }

    /// The recorded wall-clock time, or `None` for a bare position — the one
    /// reading of it, which the head writer's resume asks too.
    pub fn time(&self) -> Option<u64> {
        match self {
            CommitMeta::Bare { .. } => None,
            CommitMeta::Recorded { time, .. } => Some(*time),
        }
    }

    /// A bare position the journal answered nothing for.
    pub fn bare() -> CommitMeta {
        CommitMeta::Bare { journal: JournalTerms::default() }
    }
}

/// One line's byte offset in `commits.log`.
///
/// A newtype because it travels beside a committed POSITION of the same
/// width — out of [`CommitsLog::record`], through
/// [`super::feed::Feed::record`], into the feed's own indexing — and the two
/// mean opposite things. Transposed, the position index, the bitmap and the
/// owner streams key on a byte offset while `feed-offsets.log` records a
/// position: the first half is loud, since the change feed's pages compare
/// byte for byte, and the second is SILENT, since nothing in this build
/// seeks by an offset (the card on `CommitsLog`'s `offsets` field says so).
/// The device [`crate::serial::SerialGuard`] already is, applied to data
/// rather than to a guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct LineOffset(pub u64);

/// What [`CommitsLog::record`] did with a NEW position: appended its line,
/// at the [`LineOffset`] it landed at, or HELD it in the resident entries
/// alone while the walk's region is pending — the line written, and its
/// offset assigned, by the landing's rewrite ([`CommitsLog::land`]). The
/// feed folds a held position into its twins and appends nothing to the
/// four derived files, whose lines the same landing rewrites whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Recorded {
    Appended(LineOffset),
    Held,
}

/// One replayed file record.
#[derive(Debug)]
enum Record {
    Entry(u64, CommitMeta),
    /// The smallest `since` this feed can honor — see [`CommitsLog::min_since`].
    MinSince(u64),
}

/// One bare position the reconstruction walk covered, with the journal's
/// classification of it: the documents the commit touched as the world diff
/// shows them (`Some`, possibly empty), or `None` where the world below the
/// boundary could not be answered — unclassifiable, served to every class
/// (the module doc's residue) — and, off the same two worlds, the journal's
/// terms for its row ([`JournalTerms`]; empty where the world below could
/// not be answered).
#[derive(Debug)]
pub(super) struct Walked {
    pub at: u64,
    pub docs: Option<Vec<Address>>,
    pub journal: JournalTerms,
}

/// The replayed `commits.log`: the file handle, every enumerable entry above
/// the fence, and the bookkeeping the feed's derived structures key on.
pub(super) struct CommitsLog {
    file: File,
    /// The data dir the file lives in — what a rewrite re-creates it under.
    dir: PathBuf,
    /// Every enumerable position above `min_since`, in order — and every one
    /// of them this file stands behind: `Recorded` means testimony whose
    /// document names this daemon has PARSED, [`demote_malformed_names`]
    /// having demoted the rest at open. So a consumer that renders a
    /// `Recorded` entry, or classifies by its names, needs no second check of
    /// its own.
    ///
    /// Read outside this file through `entries()` alone, as `min_since` is
    /// through its two: no file but this one can add an entry this card does
    /// not stand behind.
    entries: BTreeMap<u64, CommitMeta>,
    /// Each entry's line's byte offset in the file — the offset array's
    /// in-memory twin (PUB-7.19), learned from the replay itself and
    /// advanced by every append; a rewrite recomputes it whole.
    ///
    /// NOTHING IN THIS BUILD SEEKS BY IT. `commits.log`'s reader is the
    /// resident `entries` map above, so a position is answered from memory
    /// and no read takes an offset; this map's ONE consumer is
    /// `feed-offsets.log` (`feed/derived.rs`), whose own consumer is the
    /// non-resident reader that file exists for. It is kept because that
    /// file must be right the day one appears, and it costs one `u64` per
    /// retained commit plus maintenance at four sites: the replay, the
    /// head clamp, a rewrite — the walk's landing among them, which assigns
    /// every offset at once — and [`CommitsLog::record`]. A reader looking
    /// for the lookup will not find one.
    ///
    /// Position → [`LineOffset`], which is what keeps the two apart: they
    /// are the same width and mean opposite things, and the map's own key
    /// and value are the pair a transposition swaps.
    offsets: BTreeMap<u64, LineOffset>,
    /// The smallest admissible `since`: coverage is complete over
    /// `(min_since, head]`; below it the walk was stopped (reclaimed or
    /// unreadable journal) and `/changes` answers 410. Deliberately not
    /// called a floor — the wire's `floor` is the oldest position still
    /// ANSWERABLE, whereas this is the highest one that is not.
    ///
    /// INVARIANT: `min_since <= head` always. A fence above the head is not
    /// a fact about this journal and is discarded at open, exactly as an
    /// entry above it is — the coverage clause above means something only
    /// under that.
    ///
    /// Read from outside this file through [`CommitsLog::admits_since`] and
    /// [`CommitsLog::floor`], the predicate and the datum this fence
    /// answers: the distinction from the wire's `floor` is this file's to
    /// keep, and so is every comparison against it.
    min_since: u64,
    /// The journal head at open — the fence between replayed history and
    /// this uptime's commits. An ack carrying a position at or below it
    /// (an idempotency-memo replay, `emit`'s incumbent ack) is never a
    /// new commit and is never re-recorded.
    open_head: u64,
    /// Whether this open REWROTE the file — compaction to the journal's
    /// retention, or the purge of a foreign fence — so every offset moved
    /// and the derived offset array must be rewritten with it.
    rewritten: bool,
    /// THE REGION PENDING — `(low, head]`, the positions the file did not
    /// cover at open, which the walk behind the listener re-covers
    /// ([`reconstruct`]) and the landing writes ([`CommitsLog::land`]);
    /// `None` where the file covered the head, and again once the landing
    /// has written. `low` is COVERED (the highest surviving entry, or the
    /// fence), `head` UNCOVERED, the last of the region. While it stands:
    /// `entries` lacks every position in it; [`CommitsLog::record`] keeps a
    /// new position in memory alone (`Recorded::Held`); the file takes no
    /// line; and the feed refuses a page whose rows would have to come from
    /// it. Read outside this file through [`CommitsLog::pending_region`].
    pending: Option<(u64, u64)>,
    /// Monotone clamp for recorded wall-clock times.
    last_time: u64,
    /// The file's length — the offset the next appended line lands at.
    len: u64,
    /// The classed door with the daemon's record ([`Lines`]): what the
    /// rewrite's stop is said through, once per uptime.
    lines: Lines,
    /// Set by the first FAILED append of this uptime — or a compaction's
    /// rewrite failed PAST its rename ([`CommitsLog::compact_to`]), after
    /// which the handle names a file no open reads — after which this file
    /// takes no further line.
    ///
    /// THE REOPEN WALK CANNOT REACH AN INTERIOR LOSS. [`CommitsLog::open`]
    /// walks `(low, head]` where `low` is the HIGHEST surviving entry, so a
    /// position lost BELOW a later successful append is re-derived by
    /// nothing: absent from `entries`, hence from every feed source (the
    /// published stream and the bitmap are built from these keys, the index
    /// from their classifications, the streams filtered against them), hence
    /// from every page at every class, permanently, with no error anywhere.
    /// Stopping the file keeps `low` BELOW the loss, so the walk re-covers
    /// that position and every one after it as BARE entries — which is what
    /// [`CommitsLog::record`]'s failure path promises, and what the derived
    /// layer's own stop rule (`feed/derived.rs`) buys for the same
    /// condition. The resident `entries` map is written ahead of every
    /// append, so this uptime answers with full testimony; what stops is
    /// what the next open reads. `Some` carries THE POSITION THE STOP WAS SET
    /// AT — the position the stop's own line names, an ordering the standing
    /// line re-says the stop by (`operations.md` §1 THE RATES, `{file}
    /// stopped since position {p}`): the failed append's position, or the
    /// fence a rewrite failed past its rename at, which is what the next
    /// open re-derives from.
    stopped: Option<u64>,
    /// The test seam behind `crate::Daemon::fail_the_feeds_next_rewrite_past_rename`:
    /// the next compaction's rewrite fails AFTER its rename, at the reopen
    /// of the new file, so the stop that failure carries is reachable
    /// without a disk that fails on cue.
    #[cfg(any(test, feature = "test-hooks"))]
    fail_next_rewrite_past_rename: bool,
}

impl CommitsLog {
    /// Replay (truncating a torn tail), drop everything the file says about
    /// a journal other than this one — entries beyond the head AND a fence
    /// above it — and record any uncovered `(last recorded, head]` region as
    /// PENDING, to be reconstructed as bare positions by the walk behind the
    /// listener ([`reconstruct`]) and written by its landing
    /// ([`CommitsLog::land`]). Returns the replayed log with the file AS
    /// PARSED: no bare line appended, no fence line written.
    ///
    /// COST — the open's own: O(the file) to replay it, and the floor
    /// probe. THE WALK IS NOT THE OPEN's (`operations.md` §3.3 step 2; §4
    /// row 16): reconstruction spends one whole-world `Kernel::world_at` per
    /// uncovered boundary — a checkpoint deserialize plus a journal fold
    /// each — plus one world diff per boundary for its classification
    /// (`derived_docs` states that cost), so a dir with NO coverage (a
    /// sidecar deleted, arrived corrupt, or written before this feature)
    /// pays that for every boundary the journal still holds; paid INSIDE
    /// the open it held the listener unbound for the walk's length, so a
    /// supervisor that killed a slow start restarted the walk from zero. It
    /// is paid on a thread of the write path's instead, the board serving
    /// meanwhile, and lands by ONE rewrite, so a covered region is walked
    /// once ever rather than once per open. The region is bounded below by
    /// journal reclamation, so the ceiling is the retained window, which
    /// `server.rs` chooses as `CHECKPOINT_EVERY_COMMITS ×
    /// RETAINED_CHECKPOINTS` commits.
    ///
    /// COMPACTION runs at the other end, and is what bounds the file and
    /// the resident entries: positions the journal has reclaimed are refused by
    /// `/op-at` and `/dump?at` alike, so an entry naming one describes a
    /// commit no client can reach by any route. Those entries are dropped
    /// and the file rewritten around them, leaving retention exactly where
    /// wire.md puts it — the feed's memory is the sidecar plus what the
    /// journal can still reconstruct, and below that the same `410
    /// history_reclaimed` discipline `/op-at` answers with. A region whose
    /// lower edge the open's compaction passes is narrowed to the fence in
    /// force, and dropped where the fence passes its head.
    ///
    /// The floor is learned by probing position 0, which costs nothing:
    /// genesis is its own base, so a healthy store folds no journal to
    /// answer, and a reclaimed one refuses from the checkpoint listing
    /// alone. The rewrite goes to a temp file and is renamed over the
    /// original, so a crash mid-compaction leaves the whole old file or
    /// the whole new one — never a half of either.
    ///
    /// DISPOSITION, deliberately the opposite of [`CommitsLog::record`]'s:
    /// every I/O failure here is fatal and reaches the caller as
    /// `DaemonError::Sidecar`. At ack time the ack is already owed, so lost
    /// testimony degrades to bare; at open nothing is owed yet, and a data
    /// dir that cannot take a write the kernel just performed is an operator
    /// condition worth reporting rather than limping past. Every failure
    /// NAMES THIS FILE, the kind kept (`operations.md` §1.1 row 2): one
    /// closure wraps each `?` the open takes on the file, as the blocked
    /// list's read wraps its path, so the daemon's `change-feed sidecar:
    /// {e}` reads `commits.log: {e}`.
    ///
    /// `lines` is the classed door: a torn tail is said through it once
    /// ([`LogCutLine`]) — at the open, BEFORE the walk, with the walk's own
    /// fence `low` as the last trusted position — and the malformed names
    /// once with their count ([`demote_malformed_names`]); the log keeps a
    /// clone for its stop and its landing.
    pub(super) fn open(dir: &Path, engine: &Engine, lines: &Lines) -> io::Result<CommitsLog> {
        let with_file = |e: io::Error| io::Error::new(e.kind(), format!("{SIDECAR_FILE}: {e}"));
        let path = dir.join(SIDECAR_FILE);
        let mut file = open_sidecar(&path).map_err(with_file)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(with_file)?;
        let (records, valid_end) = parse_records(&bytes);
        let cut = if valid_end < bytes.len() {
            // The torn (or corrupt) tail: truncate at the last whole record.
            // Anything the dropped lines described is re-covered as bare
            // positions by the walk below — said once the walk's own fence
            // `low` is known, which is the position trust ends at.
            file.set_len(valid_end as u64).map_err(with_file)?;
            Some((valid_end as u64, bytes.len() as u64))
        } else {
            None
        };
        let len = valid_end as u64;
        let mut entries = BTreeMap::new();
        let mut offsets = BTreeMap::new();
        let mut min_since = 0u64;
        for (offset, record) in records {
            match record {
                Record::Entry(at, meta) => {
                    entries.insert(at, meta);
                    offsets.insert(at, LineOffset(offset as u64));
                }
                Record::MinSince(s) => min_since = min_since.max(s),
            }
        }
        let head = engine.kernel().current_seq().0;
        // Entries beyond this journal's head describe a different journal
        // (an operator swapped files under the sidecar); never serve them.
        if head < u64::MAX {
            let dropped = entries.split_off(&(head + 1));
            for at in dropped.keys() {
                offsets.remove(at);
            }
        }
        // A fence above the head describes that other journal too, and is
        // the half the entry clamp above does not reach. Left standing it
        // makes `(min_since, head]` empty, so `changes` refuses every
        // position this journal HAS — permanently, since nothing re-derives
        // a fence the file already holds — while `/events` announces them
        // and `/op-at` serves them. Discarded, the walk below covers
        // `(last entry, head]` from scratch and the retention probe
        // re-derives the true fence for THIS journal, which is what keeps
        // `min_since <= head`.
        let stale_fence = min_since > head;
        if stale_fence {
            min_since = 0;
        }
        let low = entries.keys().next_back().copied().unwrap_or(0).max(min_since);
        if let Some((valid_end, before)) = cut {
            // Row 9 for this file: the last trusted position is the walk's
            // own fence, the highest surviving record at or below the head
            // (or the fence record), from which the cut part is re-derived.
            lines.say(Class::Failure, LogCutLine { cut: Cut { valid_end, len: before, trusted: low } });
        }
        // THE REGION, PENDING: what the file does not cover, `(low, head]`,
        // is the walk thread's to re-cover and its landing's to write — the
        // file takes no line here. `None` where the file covers the head.
        let pending = (head > low).then_some((low, head));
        // Compaction: everything the journal has reclaimed leaves the feed
        // with it. The probe answers the oldest position still answerable,
        // so the smallest admissible `since` is the fence just under it —
        // asking `since = F - 1` still yields the whole surviving feed. A
        // reclaimed journal that can name no floor at all leaves this at 0
        // and prunes nothing: the sidecar's own testimony is the half of
        // the feed's memory that does not depend on the journal, and
        // discarding it over a floor nobody can locate would lose the only
        // record of those commits that still exists.
        let floor_fence = reclaim_floor(engine).map(|floor| floor.saturating_sub(1));
        // Built with no region, so the open's own compaction below REWRITES
        // the file — it is the open's to write, before the listener — where
        // the same method defers its rewrite while a region is pending.
        let mut log = CommitsLog {
            file,
            dir: dir.to_path_buf(),
            entries,
            offsets,
            min_since,
            open_head: head,
            rewritten: false,
            pending: None,
            last_time: 0,
            len,
            lines: lines.clone(),
            stopped: None,
            #[cfg(any(test, feature = "test-hooks"))]
            fail_next_rewrite_past_rename: false,
        };
        // The compaction is the same rewrite the thread runs after each
        // checkpoint, through the same method; at open a failure is fatal
        // either side of the rename — the bare I/O error either side
        // (`RewriteFail::into_io` names no file), wrapped here with this
        // file's name as every other failure of the open is. The rewrite is
        // unconditional under a discarded fence, so a journal that later
        // grows past that number cannot resurrect it from the file — the one
        // forcing the thread's compaction never makes, since a fence above
        // the head is a thing only an open meets. It writes the file WITHOUT
        // the region, which is what the file held: the region is the walk's.
        log.compact_inner(floor_fence.unwrap_or(0), stale_fence)
            .map_err(|failed| with_file(failed.into_io()))?;
        // The region's lower edge is the fence in force where the compaction
        // passed it — a position at or below the fence answers 410 before
        // any page reaches it — and a fence past the head leaves no region.
        if let Some((low, head)) = pending {
            let low = low.max(log.min_since);
            log.pending = (head > low).then_some((low, head));
        }
        // The entries are final here, and this is where they become ones this
        // file stands behind: a line whose document names are malformed is
        // testimony this daemon cannot repeat, and it answers BARE — in
        // memory alone, AFTER any rewrite above, which writes the line as it
        // was read: this file is the sole surviving record of those commits.
        demote_malformed_names(&mut log.entries, lines);
        log.last_time = log.entries.values().filter_map(CommitMeta::time).max().unwrap_or(0);
        Ok(log)
    }

    /// THE REGION PENDING, as a read: `(low, head]`, the positions the walk
    /// behind the listener has yet to land, or `None` — the `pending`
    /// field's card. `low` is covered, `head` the last of the region.
    pub(super) fn pending_region(&self) -> Option<(u64, u64)> {
        self.pending
    }

    /// THE LANDING (`operations.md` §3.3 step 2: "the walk accumulates in
    /// memory and lands by ONE whole rewrite of `commits.log` under the
    /// feed's lock"): fold the walk's boundaries into the resident entries as
    /// BARE positions carrying the journal's answer — beside every position
    /// recorded in memory while the region was pending — move the fence to
    /// the greatest of the fence in force, the walk's own (`walk_min_since`,
    /// where the journal stopped answering) and the reclaim floor's as read
    /// AT the landing (`floor_fence`, a checkpoint having landed meanwhile),
    /// drop what lies at or below it, and REWRITE the file whole through
    /// [`rewrite`]'s path: one `min_since` line, then every entry in position
    /// order — so file order is position order, and every offset, the
    /// held positions' among them, is assigned here. Answers the fence the
    /// file was written behind, which the feed trims its twins to.
    ///
    /// The region is CLEARED whatever the rewrite answers: the resident
    /// entries are complete from here, and this uptime serves them. A
    /// rewrite that fails BEFORE its rename leaves the old file whole —
    /// torn at `low`, the held positions unwritten — and STOPS this file,
    /// said once: a later append would raise the file's highest entry past
    /// the region, which the next open's walk could then never re-cover
    /// (the `stopped` field's card), where a stopped file keeps `low` where
    /// it was and the next open walks again from it. One that fails PAST
    /// its rename is [`CommitsLog::rewrite_whole`]'s stop, said there.
    pub(super) fn land(
        &mut self,
        walked: &[Walked],
        walk_min_since: Option<u64>,
        floor_fence: Option<u64>,
    ) -> Result<u64, RewriteFail> {
        let Some((low, _)) = self.pending.take() else {
            return Ok(self.min_since);
        };
        for w in walked {
            // A position the walk proved; never over one recorded meanwhile,
            // which cannot share it — the region lies at or below the head
            // at open, a record above it.
            self.entries.entry(w.at).or_insert_with(|| CommitMeta::Bare { journal: w.journal.clone() });
        }
        let fence = self.min_since.max(walk_min_since.unwrap_or(0)).max(floor_fence.unwrap_or(0));
        self.min_since = fence;
        self.entries = self.entries.split_off(&fence.saturating_add(1));
        match self.rewrite_whole() {
            Ok(()) => Ok(fence),
            Err(RewriteFail::BeforeRename(e)) => {
                let first = self.stopped.is_none();
                self.stopped = Some(low);
                if first {
                    self.lines.say(Class::Failure, LandingRefusedLine { low, error: &e });
                }
                Err(RewriteFail::BeforeRename(e))
            }
            Err(past) => Err(past),
        }
    }

    /// COMPACT the log to the reclaim floor's fence: drop every entry at or
    /// below `min_since` and rewrite the file around the survivors behind
    /// that fence — `true` when anything was dropped, `false` when the file
    /// already stood above the fence and nothing was written. The ONE
    /// rewrite the log has, run at two moments by one method: at
    /// [`CommitsLog::open`], where the reclaim floor is probed once and a
    /// failure is fatal, and after each checkpoint the daemon's checkpoint
    /// thread lands, under the feed's lock, where the floor has just moved
    /// and a failure is the thread's to report. The fence never recedes: a
    /// `min_since` below the one in force is the floor as it was, and drops
    /// nothing.
    ///
    /// THE STOP, carried in from the open where it was moot: a rewrite that
    /// fails BEFORE its rename leaves the old file whole and this handle
    /// naming it — nothing lost, the next checkpoint's compaction tries
    /// again; one that fails PAST its rename leaves this handle naming the
    /// REPLACED file, which no open reads, so the file is STOPPED for the
    /// uptime as a failed append stops it — the resident entries are
    /// trimmed all the same and serve this uptime, and the next open
    /// re-derives from the rewritten file's own fence. Said ONCE PER UPTIME
    /// (`operations.md` §1.1 row 29): this method has no stop guard, so a
    /// stopped log is rewritten at every compacting landing — each rewrite
    /// running, the stop's position moving to the newest fence — and the
    /// line is said at the stop's transition alone, the standing line
    /// re-saying it while it stands.
    pub(super) fn compact_to(&mut self, min_since: u64) -> Result<bool, RewriteFail> {
        self.compact_inner(min_since, false)
    }

    /// [`CommitsLog::compact_to`], with the open's one extra: `force` writes
    /// the file even where nothing is dropped — a fence that described
    /// another journal has been discarded from memory and must leave the
    /// file too. The fence in force never recedes, and may ADVANCE past a
    /// run of positions nobody recorded: a fence below the oldest entry
    /// drops nothing, writes nothing unforced, and is kept as the smallest
    /// `since` the feed honors.
    ///
    /// WHILE THE WALK's REGION IS PENDING the rewrite is DEFERRED to the
    /// landing ([`CommitsLog::land`]): the fence moves and the entries at or
    /// below it are dropped, in memory, and the file — which the landing
    /// rewrites whole behind the fence as it then stands — takes nothing.
    /// The open's own compaction runs before the region is recorded, so it
    /// writes.
    fn compact_inner(&mut self, min_since: u64, force: bool) -> Result<bool, RewriteFail> {
        let fence = min_since.max(self.min_since);
        let drops = self.entries.keys().next().is_some_and(|&oldest| oldest <= fence);
        self.min_since = fence;
        if !force && !drops {
            return Ok(false);
        }
        self.entries = self.entries.split_off(&fence.saturating_add(1));
        if self.pending.is_some() {
            return Ok(true);
        }
        self.rewrite_whole()?;
        Ok(true)
    }

    /// The fence in force — [`CommitsLog::min_since`]'s number, read by the
    /// feed's landing where the log's own landing refused, to trim the twins
    /// to what the entries hold.
    pub(super) fn min_since_in_force(&self) -> u64 {
        self.min_since
    }

    /// Rewrite the whole file from the resident entries behind the fence in
    /// force ([`rewrite`]), the handle, the offsets and the length moving
    /// with it; the stop on a failure past the rename.
    fn rewrite_whole(&mut self) -> Result<(), RewriteFail> {
        #[cfg(any(test, feature = "test-hooks"))]
        let fail_past_rename = std::mem::take(&mut self.fail_next_rewrite_past_rename);
        #[cfg(not(any(test, feature = "test-hooks")))]
        let fail_past_rename = false;
        match rewrite(&self.dir, &self.entries, self.min_since, fail_past_rename) {
            Ok((file, offsets, len)) => {
                self.file = file;
                self.offsets = offsets;
                self.len = len;
                self.rewritten = true;
            }
            Err(RewriteFail::PastRename(e)) => {
                // Said where the stop is SET, not where it is re-set: a
                // stopped log is rewritten again at the next compacting
                // landing, its stop moving to the newest fence in silence.
                let first = self.stopped.is_none();
                self.stopped = Some(self.min_since);
                self.rewritten = true;
                if first {
                    self.lines.say(
                        Class::Failure,
                        format_args!(
                            "commits.log rewrite failed past its rename: {e}; this file takes no \
                             further line, so the next open re-derives from its fence as bare \
                             entries"
                        ),
                    );
                }
                return Err(RewriteFail::PastRename(e));
            }
            Err(before) => return Err(before),
        }
        Ok(())
    }

    /// Record one committed write at ack time; `Some` — [`Recorded`], the
    /// [`LineOffset`] the line landed at, or that the line is HELD — when
    /// this call recorded a NEW position, `None` when it declined.
    /// Idempotent against replayed acks: a position at or below the
    /// open-time head, or one already recorded this uptime, is an ack for
    /// an OLD commit (idempotency-memo hit, `emit` incumbent) — re-recording
    /// it would invent a time.
    ///
    /// WHILE THE REGION IS PENDING (`pending`'s card; `operations.md` §3.3
    /// step 2, "the walk accumulates in memory and lands by ONE whole
    /// rewrite"): the position enters the resident entries and NOT the file,
    /// which takes no line until the landing writes it at its offset among
    /// the rest, in position order. This uptime answers it in full. THE
    /// COST, stated: a crash before the landing loses the line — the file
    /// is as the open found it — and the next open's walk re-covers the
    /// position BARE, classified from the journal (PUB-6.45), its op and
    /// key null; the attest store's line for it is appended and synced at
    /// once regardless (`feed/attest.rs`, SO-I5 (d)), the store's file
    /// being its own.
    ///
    /// CALLER CONTRACT — call only while holding the daemon's
    /// write-serialization guard, between a commit and its ack; the guard
    /// argument is that contract's cheap half. That is what makes this
    /// file's two invariants true: file order is position order, and
    /// recorded times are monotone non-decreasing in position. The lock the
    /// feed holds around this guards its own state and nothing more, so
    /// calls arriving out of position order would append out of order and
    /// stamp a later position with an earlier time — both silent, both
    /// permanent, and both load-bearing for the feed's paging and
    /// [`CommitsLog::head_time`]. The guard proves the lock is held and
    /// proves nothing about the position order the caller supplies, which
    /// stays [`crate::write_path::WritePath::commit_recorded`]'s — the step
    /// both of the write path's doors run: it runs the execute and this
    /// record under one guard, so the position recorded is the one that
    /// write just committed.
    ///
    /// The clamp against `last_time` below covers the other half of the
    /// monotonicity — a wall clock that steps backwards — and that one IS
    /// this file's own obligation rather than the caller's.
    ///
    /// The offset returned is the one the line landed at, EXCEPT past a
    /// failed append: [`CommitsLog::stopped`] freezes `len`, so every later
    /// offset names a line this file does not hold. Nothing in this build
    /// seeks by an offset (the `offsets` field's card), and the next open
    /// replays `commits.log` from disk and rebuilds them, so
    /// `feed-offsets.log` fails its agreement test and is rewritten whole —
    /// the wrong offsets are latent for the uptime and self-healing after
    /// it.
    // Seven fields of one line beside the guard, each the write path's own
    // reading — bundling them would put a struct between the door and the
    // line it records.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn record(
        &mut self,
        _serial: &SerialGuard<'_>,
        at: u64,
        op: &'static str,
        docs: Vec<String>,
        testimony: String,
        signed: Option<Carrier>,
        terms: Option<OpTerms>,
    ) -> Option<Recorded> {
        if at <= self.open_head || self.entries.contains_key(&at) {
            return None;
        }
        let now = wall_clock_millis();
        let time = now.max(self.last_time);
        self.last_time = time;
        // The one line where the concept meets the wire field it rides in
        // (`CommitMeta::Recorded.key`, wire.md's `key`).
        let meta = CommitMeta::Recorded {
            op: op.to_string(),
            docs,
            time,
            key: Some(testimony),
            signed,
            terms,
        };
        if self.pending.is_some() {
            // The region pending: the entry alone, the file untouched until
            // the landing's one rewrite writes this line at its offset.
            self.entries.insert(at, meta);
            return Some(Recorded::Held);
        }
        let offset = LineOffset(self.len);
        // Testimony must not fail the op: the write is committed and the
        // ack is owed regardless; a lost append answers BARE after restart,
        // which [`CommitsLog::stopped`] is what makes true — the failure
        // stops this file, so the next open's walk starts below the gap
        // instead of above it. The failure is REPORTED through the classed
        // door (`operations.md` §1.1 row 31) — once, since the stop takes
        // every later line — which states why a notice may not panic.
        let line = entry_line(at, &meta);
        if self.stopped.is_none() {
            match self.file.write_all(&line) {
                Ok(()) => self.len += line.len() as u64,
                Err(e) => {
                    self.stopped = Some(at);
                    self.lines.say(
                        Class::Failure,
                        format_args!(
                            "commits.log append failed at position {at}: {e}; this file takes no \
                             further line, so the next open re-derives from {at} as bare entries"
                        ),
                    );
                }
            }
        }
        self.entries.insert(at, meta);
        self.offsets.insert(at, offset);
        Some(Recorded::Appended(offset))
    }

    /// The HEAD POSITION's recorded wall-clock time — `None` when the head's
    /// record is bare (lost, or written before the feature), nothing is
    /// recorded at all, or the head's record lies in the region the walk
    /// has yet to land (no position above it recorded since the open): an
    /// older surviving record is not offered in its place.
    ///
    /// Deliberately not "the newest recorded time anywhere in the feed":
    /// this answers FOR THE HEAD, so an older surviving record is not
    /// offered in its place, any more than a bare position's fields are
    /// invented.
    ///
    /// What it reads is the LAST RECORDED position's time, which IS the
    /// head's because every commit is recorded: every commit this daemon
    /// makes rides [`crate::write_path::WritePath::commit_recorded`], which
    /// records inside the guard its caller holds across the commit. That
    /// premise is this file's RELIANCE, not its check — a `CommitsLog` never
    /// learns the live head — and two states break it.
    ///
    /// Transiently: any in-flight write. `/health` reads this and the log
    /// position independently and under no lock, so its pair may straddle
    /// one commit and report the previous position's time beside the new
    /// position's number. The next call answers the head again.
    ///
    /// Permanently: a panic between M10's commit and this file's append,
    /// which `serve_connection`'s unwind note names. That position stays
    /// unrecorded until the reopen walk covers it as a bare entry, after
    /// which this honestly answers `None`.
    pub fn head_time(&self) -> Option<u64> {
        let (at, meta) = self.entries.iter().next_back()?;
        if self.pending.is_some_and(|(_, head)| *at <= head) {
            return None;
        }
        meta.time()
    }

    /// Whether this log can answer a `/changes` query fenced at `since`:
    /// coverage is complete over `(min_since, head]`, so a `since` at or
    /// above that fence is admissible and one below it reaches into what the
    /// walk could not enumerate.
    ///
    /// The PREDICATE beside [`CommitsLog::floor`]'s datum — the two are one
    /// sentence, and a caller that refuses a query asks for both rather than
    /// comparing against a fence whose distinction from the wire's `floor`
    /// this file spends two doc comments keeping.
    pub fn admits_since(&self, since: u64) -> bool {
        since >= self.min_since
    }

    /// The oldest position still ANSWERABLE — the wire's `floor` (wire.md
    /// §Reading history), which is the first entry ABOVE the fence
    /// [`CommitsLog::admits_since`] tests and not that number itself. The two
    /// are one apart by definition, keeping them apart is this file's job,
    /// and so is the step between them: a caller rendering `floor` asks
    /// rather than deriving it from this type's own state. `None` where
    /// nothing above the fence survives.
    ///
    /// WHILE THE WALK's REGION IS PENDING the region's first position above
    /// the fence — `max(low, min_since) + 1`, the reclaim floor itself where
    /// the floor passed the region's lower edge — is the floor where it lies
    /// below the first entry: the region's boundaries are not yet known,
    /// and a floor named above them would send a reader re-asking from it
    /// past the region, which the landing then serves to nobody.
    pub fn floor(&self) -> Option<u64> {
        let covered = self.entries.range(self.min_since.saturating_add(1)..).next().map(|(k, _)| *k);
        let region = self
            .pending
            .filter(|&(_, head)| head > self.min_since)
            .map(|(low, _)| low.max(self.min_since).saturating_add(1));
        match (covered, region) {
            (Some(c), Some(r)) => Some(c.min(r)),
            (c, r) => c.or(r),
        }
    }

    /// Every entry ABOVE `position`, in position order — what the PUBLISHED
    /// HEAD writer's resume reads (`crate::write_path::head`; the chain's
    /// open items, item 2): the commits landed since the head that named
    /// `position`, and among them the head's own commits, testifying
    /// `"system"`, whose recorded `time` is the head's. Testimony read at a
    /// GATE to decide WHEN, never a fold input (D1): a bare entry answers no
    /// time and no key, and a rewritten one moves a head's timing within the
    /// bounds the triggers already allow. Cloned, once at open — at most the
    /// retained window — so the writer holds no borrow of this file.
    pub fn entries_above(&self, position: u64) -> Vec<(u64, CommitMeta)> {
        self.entries
            .range(position.saturating_add(1)..)
            .map(|(at, meta)| (*at, meta.clone()))
            .collect()
    }

    /// Every enumerable entry above the fence, in position order — READ-ONLY
    /// outside this file, because the invariant the `entries` field's card
    /// states (a `Recorded` entry's document names all parse,
    /// [`demote_malformed_names`] having demoted the rest at open) is this
    /// file's to keep and the feed's to rely on: it classifies by those names
    /// with no second check of its own.
    pub fn entries(&self) -> &BTreeMap<u64, CommitMeta> {
        &self.entries
    }

    /// Each entry's line's byte offset, read-only outside this file for
    /// `entries()`'s reason — the offset array's twin, which the `offsets`
    /// field's card says nothing in this build seeks by.
    pub fn offsets(&self) -> &BTreeMap<u64, LineOffset> {
        &self.offsets
    }

    /// The journal head at open — the fence [`CommitsLog::record`] declines
    /// at or below — read-only outside this file.
    pub fn open_head(&self) -> u64 {
        self.open_head
    }

    /// Whether this open rewrote the file, so every offset moved and the
    /// derived offset array is rewritten with it.
    pub fn rewritten(&self) -> bool {
        self.rewritten
    }
}

/// THE RECLAIM FLOOR — the oldest position the journal can still answer, or
/// `None` when it can still answer genesis (nothing has been reclaimed): the
/// bound the feed's retention follows, at open and after each checkpoint
/// alike. A floor and never a fence: the feed compacts to the fence one
/// below it, `CommitsLog`'s `min_since`.
///
/// Asked by probing position 0 through the same public replay everything
/// else here uses. The probe is free either way: genesis IS the base a
/// position-0 question selects, so a healthy store folds no journal to
/// answer it, and a reclaimed store refuses from the checkpoint listing
/// before touching a segment. Every other refusal — corrupt, I/O,
/// unjournaled — reports no floor, so the feed keeps what it has rather
/// than discarding entries over a fault that may be transient.
pub(super) fn reclaim_floor(engine: &Engine) -> Option<u64> {
    reclaim_floor_of(engine.kernel())
}

/// [`reclaim_floor`] off the kernel alone — the walk thread's probe at its
/// landing, which holds the kernel's handle and no engine.
pub(super) fn reclaim_floor_of(kernel: &Kernel<World>) -> Option<u64> {
    match kernel.world_at(Seq(0)) {
        Err(HistoryError::Reclaimed { floor, .. }) => Some(floor.map(|f| f.0).unwrap_or(0)),
        _ => None,
    }
}

/// THE CUT a feed file's replay made (`operations.md` §1.1 row 9): trust
/// ended at a line that was torn or did not parse, and the file was
/// truncated there. Answered by each replay to its caller — `commits.log`'s
/// own open and `LineFile::open` for the four derived files and the attest
/// store — which words it with the case that is its own: a derived file's
/// cut part is re-derived, `commits.log`'s as bare entries, and the attest
/// store's lies on one side of the reclaim floor. [`CutHead`] renders the
/// head every one of those lines opens with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Cut {
    /// The byte trust ends at — the end of the last whole line that parsed,
    /// where the file was truncated.
    pub valid_end: u64,
    /// The file's length before the cut.
    pub len: u64,
    /// THE LAST TRUSTED POSITION: the coverage the scan reached before the
    /// cut — the highest position the surviving lines reach at or below the
    /// head, an entry's or a fence's — and so the position the cut part is
    /// re-derived from. Every cut line's position lies above it, the files
    /// being position-ordered.
    pub trusted: u64,
}

impl Cut {
    /// The bytes after the trusted end — what was cut.
    fn after(&self) -> u64 {
        self.len.saturating_sub(self.valid_end)
    }
}

/// Row 9's HEAD — `{file}: trust ends at position {c} (byte {n} of {len});
/// the {k} bytes after it are cut` — the words every cut line opens with,
/// each caller adding its own case after a semicolon. A pure value, pinned
/// by `to_string()` in the unit suite.
pub(super) struct CutHead {
    pub name: &'static str,
    pub cut: Cut,
}

impl std::fmt::Display for CutHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: trust ends at position {} (byte {} of {}); the {} bytes after it are cut",
            self.name,
            self.cut.trusted,
            self.cut.valid_end,
            self.cut.len,
            self.cut.after()
        )
    }
}

/// Row 9 for `commits.log`: the head, then this file's own case — the cut
/// part is re-derived as bare entries, by the walk the open runs from the
/// last trusted position (the file's own recovery, which line 31 names for
/// a failed append). Emitted under `Class::Failure` by [`CommitsLog::open`].
pub(super) struct LogCutLine {
    pub cut: Cut,
}

impl std::fmt::Display for LogCutLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; the cut part is re-derived as bare entries",
            CutHead { name: SIDECAR_FILE, cut: self.cut }
        )
    }
}

/// THE WALK's FIRST LINE (`operations.md` §1.1 m15): `commits.log covers to
/// position {c}; walking {b} boundaries to position {h}` — `{c}` the
/// region's lower edge, covered; `{b}` the boundaries the kernel's one scan
/// listed above it at or below `{h}`, the head at open. A pure value,
/// pinned by `to_string()` in the unit suite; emitted under `Class::Open`
/// by [`reconstruct`] at the walk's start, before any boundary is proved.
pub(super) struct WalkOpenLine {
    pub covered: u64,
    pub boundaries: usize,
    pub head: u64,
}

impl std::fmt::Display for WalkOpenLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "commits.log covers to position {}; walking {} boundaries to position {}",
            self.covered, self.boundaries, self.head
        )
    }
}

/// THE WALK's CADENCE LINE (m15): `the walk at position {p} of {h}, {d} in`
/// — `{p}` the boundary last proved, `{h}` the head at open, `{d}` the
/// time since the walk began, in milliseconds as the stream spells a
/// duration. A pure value, pinned by `to_string()`; emitted under
/// `Class::Progress` by [`reconstruct`] every
/// [`FEED_WALK_PROGRESS_BOUNDARIES`] boundaries or
/// [`FEED_WALK_PROGRESS_INTERVAL`], whichever comes first — the walk's
/// tell from a hang.
pub(super) struct WalkProgressLine {
    pub position: u64,
    pub head: u64,
    pub elapsed_ms: u128,
}

impl std::fmt::Display for WalkProgressLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the walk at position {} of {}, {} ms in", self.position, self.head, self.elapsed_ms)
    }
}

/// THE WALK's LANDING LINE (m15): `{b} walked, {k} of them bare, in {d}` —
/// `{b}` the boundaries the walk proved, `{k}` those it could not classify
/// (the world below them unanswerable: served to every class, the module
/// doc's residue), `{d}` from the walk's start to the landing's rewrite,
/// in milliseconds. A pure value, pinned by `to_string()`; emitted under
/// `Class::Landing` by the feed's landing.
pub(super) struct WalkLandingLine {
    pub walked: usize,
    pub bare: usize,
    pub elapsed_ms: u128,
}

impl std::fmt::Display for WalkLandingLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} walked, {} of them bare, in {} ms", self.walked, self.bare, self.elapsed_ms)
    }
}

/// THE LANDING REFUSED before its rename: the file stands as the open found
/// it and takes no further line, so the next open walks again from the
/// region's lower edge — [`CommitsLog::land`] states why the stop is the
/// honest half. A pure value, pinned by `to_string()`; emitted under
/// `Class::Failure`, once per uptime.
pub(super) struct LandingRefusedLine<'a> {
    pub low: u64,
    pub error: &'a io::Error,
}

impl std::fmt::Display for LandingRefusedLine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "commits.log: the walk's landing rewrite failed before its rename: {}; the file \
             stands as it was and takes no further line, so the next open walks again from \
             position {}",
            self.error, self.low
        )
    }
}

/// THE WALK's CONTROLS, shared between the thread that walks and the write
/// path that owns it: the stop (read before each boundary and before the
/// landing — a Daemon dropped mid-walk ends the walk with nothing written,
/// the crash-stop shape), and the `progress:` cadence — the constants'
/// figures, or the ones the test seam moved them to
/// (`crate::Daemon::set_feed_walk_progress_cadence`), read per boundary so
/// a held walk takes a cadence set while it parks.
pub(super) struct WalkControl {
    pub stop: AtomicBool,
    pub progress_boundaries: AtomicU64,
    pub progress_millis: AtomicU64,
}

impl WalkControl {
    /// The controls at the constants' figures, the stop clear.
    pub(super) fn new() -> WalkControl {
        WalkControl {
            stop: AtomicBool::new(false),
            progress_boundaries: AtomicU64::new(FEED_WALK_PROGRESS_BOUNDARIES),
            progress_millis: AtomicU64::new(FEED_WALK_PROGRESS_INTERVAL.as_millis() as u64),
        }
    }

    /// Whether the stop has been asked.
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// The cadence in force: the boundary count and the interval.
    fn cadence(&self) -> (u64, Duration) {
        (
            self.progress_boundaries.load(Ordering::Relaxed).max(1),
            Duration::from_millis(self.progress_millis.load(Ordering::Relaxed)),
        )
    }
}

/// What one walk came to ([`reconstruct`]): the boundaries proved, each
/// with its classification, in position order; the smallest `since` the
/// feed can honor from here on where the journal stopped answering
/// ([`CommitsLog::min_since`]'s number); how many of the proved are bare;
/// and the walk's start, which the landing line's duration is measured
/// from.
pub(super) struct WalkOutcome {
    pub boundaries: Vec<Walked>,
    pub min_since: Option<u64>,
    pub started: Instant,
}

impl WalkOutcome {
    /// The boundaries proved but not classified — the world below them
    /// unanswerable — which the landing line counts as bare.
    pub(super) fn bare(&self) -> usize {
        self.boundaries.iter().filter(|w| w.docs.is_none()).count()
    }
}

/// The line the feed walk's hold writes on the operator stream as it parks
/// — what the dirty-crash harness watches a child's stderr for before it
/// kills. `crate::Daemon::FEED_WALK_HOLD_NOTICE` re-exports it.
#[cfg(any(test, feature = "test-hooks"))]
pub(crate) const FEED_WALK_HOLD_NOTICE: &str =
    "test seam: held before the feed walk's first boundary; kill this process";

/// TEST SEAM: a hold on the feed walk, armed before a daemon opens, so a
/// suite can serve requests against a daemon whose region is pending and
/// release the walk at its own moment — the cell index walk's hold's form.
#[cfg(any(test, feature = "test-hooks"))]
pub(crate) struct FeedWalkHold {
    held: Mutex<bool>,
    released: Condvar,
}

/// The test seam's one hold on the feed walk — process-wide, since the walk
/// starts inside the open, before the daemon exists to be asked.
#[cfg(any(test, feature = "test-hooks"))]
pub(crate) static FEED_WALK_HOLD: FeedWalkHold =
    FeedWalkHold { held: Mutex::new(false), released: Condvar::new() };

#[cfg(any(test, feature = "test-hooks"))]
impl FeedWalkHold {
    /// Arm: every walk started from here on parks before its first
    /// boundary, after its `open:` line, writing [`FEED_WALK_HOLD_NOTICE`].
    pub(crate) fn hold(&self) {
        *self.held.lock() = true;
    }

    /// Release: every parked walk proceeds, and later walks never park.
    pub(crate) fn release(&self) {
        *self.held.lock() = false;
        self.released.notify_all();
    }

    /// The walk's side: park while armed, the notice written as it parks —
    /// in timed waits, so the stop reaches a held walk: a Daemon dropped
    /// while its walk parks here ends the walk, nothing written.
    fn wait(&self, control: &WalkControl) {
        let mut held = self.held.lock();
        if *held {
            skep_util::notice::line(FEED_WALK_HOLD_NOTICE);
        }
        while *held && !control.stopped() {
            self.released.wait_for(&mut held, Duration::from_millis(50));
        }
    }
}

/// TEST SEAM: the feed walk's panic arm (`crate::Daemon::panic_the_feed_walk`)
/// — process-wide, armed before the open or while the walk is held, fired
/// ONCE after the hold and before the first boundary, and disarmed as it
/// fires: the shape the walk thread's death has, which its catch contains.
#[cfg(any(test, feature = "test-hooks"))]
static FEED_WALK_FAULT: AtomicBool = AtomicBool::new(false);

/// Arm the walk's panic seam.
#[cfg(any(test, feature = "test-hooks"))]
pub(crate) fn arm_the_feed_walks_fault() {
    FEED_WALK_FAULT.store(true, Ordering::Release);
}

/// The walk's side of its panic seam: a panic whose payload is a literal,
/// so the binary's hook carries it, located at the caller's site.
#[cfg(any(test, feature = "test-hooks"))]
#[track_caller]
fn fire_the_feed_walks_fault() {
    if FEED_WALK_FAULT.swap(false, Ordering::AcqRel) {
        panic!("the test seam's fault in the feed walk");
    }
}

/// How a feed file's REWRITE failed — on which side of the rename, which is
/// the whole of what the caller acts on. The rename is the one atomic step:
/// before it the old file stands whole and the handle still names it, so
/// nothing is lost and the next compaction tries again; past it the new
/// file is in place and the handle names the REPLACED one, which no open
/// reads, so the file is STOPPED for the uptime ([`CommitsLog::compact_to`],
/// `LineFile::rewrite`). At open either side is fatal, through
/// [`RewriteFail::into_io`] — the bare I/O error, which the open wraps with
/// the file's name; while serving the thread reports and moves on.
#[derive(Debug)]
pub(super) enum RewriteFail {
    /// The temp file's creation, write or sync, or the rename itself: the
    /// old file is whole and still the one the handle names.
    BeforeRename(io::Error),
    /// The reopen of the renamed file: the new file is in place and whole,
    /// and the handle names the one it replaced.
    PastRename(io::Error),
}

impl RewriteFail {
    /// The failure as the open reports it — the I/O error, either side.
    pub(super) fn into_io(self) -> io::Error {
        match self {
            RewriteFail::BeforeRename(e) | RewriteFail::PastRename(e) => e,
        }
    }
}

impl std::fmt::Display for RewriteFail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RewriteFail::BeforeRename(e) => write!(f, "before its rename: {e}"),
            RewriteFail::PastRename(e) => write!(f, "past its rename: {e}"),
        }
    }
}

/// Rewrite `commits.log` as the surviving entries behind one `min_since`
/// record, and hand back the reopened append handle, the offsets every
/// surviving entry now sits at, and the new length.
///
/// Written to a temp file and renamed over the original, which is what
/// makes compaction crash-honest in the same sense the rest of this file
/// is: a reader only ever sees the whole old file or the whole new one.
/// The alternative — truncating in place — has a window in which the file
/// says the feed remembers nothing, and a crash there would cost the
/// surviving metadata for no reason, since it is exactly the metadata the
/// journal can no longer reconstruct. Which side of the rename a failure
/// fell on travels as [`RewriteFail`], since the two leave different files
/// behind.
///
/// The temp is `commits.log.compact`, a fixed name — safe because
/// [`crate::server::Daemon::open`]'s precondition admits one live kernel
/// per data dir. It is not cleaned up: a crash or an I/O failure between
/// the create and the rename leaves it until the next compaction truncates
/// it, which is the price of the rename being the only atomic step.
///
/// `commits.log` opened for reading and appending, created where absent —
/// born `0600` on unix, the mode set at creation and the process umask
/// irrelevant; a file that already stands keeps its mode. The one open the
/// sidecar takes: at the daemon's open, and after a rewrite's rename.
fn open_sidecar(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// A rewrite's temp file, created afresh — born `0600` on unix, the mode
/// set at creation, which the rename carries onto `commits.log`.
fn create_rewrite_temp(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// `fail_past_rename` is the test seam: the reopen refused, so the
/// past-rename arm is reachable without a disk that fails on cue; `false`
/// outside a test build.
fn rewrite(
    dir: &Path,
    entries: &BTreeMap<u64, CommitMeta>,
    min_since: u64,
    fail_past_rename: bool,
) -> Result<(File, BTreeMap<u64, LineOffset>, u64), RewriteFail> {
    let path = dir.join(SIDECAR_FILE);
    let tmp = dir.join(format!("{SIDECAR_FILE}.compact"));
    let mut out = Vec::new();
    let mut offsets = BTreeMap::new();
    out.extend_from_slice(&min_since_line(min_since));
    for (at, meta) in entries {
        offsets.insert(*at, LineOffset(out.len() as u64));
        out.extend_from_slice(&entry_line(*at, meta));
    }
    let renamed = (|| -> io::Result<()> {
        let mut f = create_rewrite_temp(&tmp)?;
        f.write_all(&out)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &path)
    })();
    renamed.map_err(RewriteFail::BeforeRename)?;
    if fail_past_rename {
        return Err(RewriteFail::PastRename(io::Error::other(
            "test seam: the rewritten file's reopen refused",
        )));
    }
    let file = open_sidecar(&path).map_err(RewriteFail::PastRename)?;
    Ok((file, offsets, out.len() as u64))
}

/// Demote every RECORDED position whose document names are MALFORMED — not
/// dotted-decimal addresses this daemon can parse — to a BARE one, before any
/// of them leaves this file.
///
/// A half-parsing name list is a HALF-RECORDED position, and [`CommitMeta`]
/// has no meaning for one: its two states are the whole vocabulary, and
/// [`parse_line`] already ends trust at a line carrying some of
/// `op`/`docs`/`time` and not the others. This is that discipline one level
/// down — testimony this daemon cannot parse is testimony it does not stand
/// behind — and it belongs here for the same reason it is STABLE: it is
/// driven by this file, which is re-read whole at every open, rather than by
/// a derived file whose coverage fence would carry the position past the
/// check on the second open.
///
/// What the demotion buys is the DISCLOSURE, and only that. A name list none
/// of whose names parse classifies the position EMPTY, and an empty class is
/// a `[]`-docs entry, which the feed's mask never masks — so left recorded, a
/// write into a document whose name this build cannot parse is served to
/// every class carrying its op, its wall-clock time, and the FINGERPRINT of
/// the key whose session committed it. Demoted, it discloses its position
/// alone, which is the residue this file already accepts for a position the
/// journal cannot classify (PUB-6.52), and its wire entry is the reserved
/// all-nulls rendering. A partly-parsing list is the same species one step
/// less visible: the mask would be computed over fewer documents than the
/// write touched.
///
/// IN MEMORY ONLY. This file is the sole surviving record of those commits,
/// so a malformed name is never rewritten away over what may be one build's
/// rendering.
///
/// SAID ONCE PER OPEN (`operations.md` §1.1 row 11): the positions demoted
/// are counted and one line names the count and the first of them
/// ([`report_malformed_names`]) — the file is re-read whole at every open
/// and never rewritten over them, so each open says it once.
///
/// UNREACHABLE as built — the names are rendered from validated `Address`es
/// by [`super::feed::Feed::record`] and read back by [`parse_dotted`], which
/// is that rendering's inverse — and the obligation keeping it so is held by
/// nobody: the write path renders, this file stores, the feed's open parses.
fn demote_malformed_names(entries: &mut BTreeMap<u64, CommitMeta>, lines: &Lines) {
    let half_recorded: Vec<u64> = entries
        .iter()
        .filter_map(|(at, meta)| match meta {
            CommitMeta::Recorded { docs, .. } => {
                docs.iter().any(|s| parse_dotted(s).is_none()).then_some(*at)
            }
            CommitMeta::Bare { .. } => None,
        })
        .collect();
    if let Some(&first) = half_recorded.first() {
        report_malformed_names(lines, SIDECAR_FILE, half_recorded.len(), first);
    }
    for at in half_recorded {
        entries.insert(at, CommitMeta::bare());
    }
}

/// THE WALK (`operations.md` §3.3 step 2; §1.1 m15): enumerate the committed
/// boundaries in `(low, head]` in ONE scan of the kernel's markers
/// (`Kernel::boundaries_above`, every boundary above `low` from one base —
/// the attest store's seam, here a LIST), say the `open:` line with their
/// count, and PROVE each one ascending by the kernel's bounded replay — an
/// `Ok` `world_at` proves a boundary — CLASSIFYING each from the journal on
/// the way up: the walk holds the world at the boundary below and diffs the
/// two (`derived_journal`) for the documents that commit touched and the
/// terms its row can answer. Ascending, so the `progress:` line's `{p}`
/// climbs to `{h}`: the lowest boundary's predecessor is `low` itself where
/// `low` is a boundary — genesis, or the last recorded position — and where
/// it is a fence (a previous walk's stopping point) its world refuses and
/// the boundary above it is unclassifiable (`docs: None`); the head's world
/// is `head_world`, the open's own snapshot (no replay), since the live root
/// moves past the head while the board serves.
///
/// Answers the boundaries proved (ascending, each with its classification)
/// and, where the journal stopped answering, the smallest `since` the feed
/// can honor from there on — [`CommitsLog::min_since`]'s number, not the
/// wire's `floor`: the list refused `Reclaimed` naming a floor above `low`
/// (the base below `low` reclaimed before the walk reached it) — asked
/// again AT the floor, whose own boundary the base embodying it answers,
/// unclassifiable, and the fence one below it; a boundary refused
/// `Reclaimed` MID-WALK (a checkpoint landing behind the listener took its
/// base) — the fence one below the floor named, the boundaries below it
/// skipped, those the walk had proved below it dropped by the landing's
/// compaction; any other refusal (corrupt, I/O, a listed boundary the
/// replay will not prove) — the feed reaches down to the boundary above
/// it and no further. `None` where the stop was asked before the walk
/// completed: nothing is landed.
///
/// THE HOLD AND THE FAULT (test seams): the walk parks after its `open:`
/// line and before its first boundary while the hold is armed, and fires
/// its panic arm there, so a suite serves against a pending region, kills
/// a child at the notice, or drives the thread's catch.
pub(super) fn reconstruct(
    kernel: &Kernel<World>,
    head_world: &World,
    low: u64,
    head: u64,
    lines: &Lines,
    control: &WalkControl,
) -> Option<WalkOutcome> {
    let started = Instant::now();
    let (listed, mut min_since) = list_boundaries(kernel, low, head);
    lines.say(Class::Open, WalkOpenLine { covered: low, boundaries: listed.len(), head });
    #[cfg(any(test, feature = "test-hooks"))]
    {
        FEED_WALK_HOLD.wait(control);
        if control.stopped() {
            return None;
        }
        fire_the_feed_walks_fault();
    }
    // The journal's two answers off the two worlds, or — with no world
    // below — unclassifiable, and no term.
    let classify = |at: u64, below: Option<&World>, upper: &World| match below {
        Some(b) => {
            let (docs, journal) = derived_journal(b, upper);
            Walked { at, docs: Some(docs), journal }
        }
        None => Walked { at, docs: None, journal: JournalTerms::default() },
    };
    // The world BELOW the boundary in hand: `low`'s where the journal
    // answers it, none where the list already stopped below the first.
    let mut below: Option<World> =
        if min_since.is_some() { None } else { kernel.world_at(Seq(low)).ok() };
    // Boundaries below this are known unanswerable (a mid-walk reclamation
    // named it), and are passed without a replay each.
    let mut skip_below = 0u64;
    let mut boundaries: Vec<Walked> = Vec::with_capacity(listed.len());
    let mut last_said = (0usize, Instant::now());
    for &at in &listed {
        if control.stopped() {
            return None;
        }
        if at < skip_below {
            continue;
        }
        // The head's world is the snapshot's; every other boundary's one
        // replay, which is its proof.
        let proved: Option<World> = if at == head {
            None
        } else {
            match kernel.world_at(Seq(at)) {
                Ok(w) => Some(w),
                Err(HistoryError::Reclaimed { floor: Some(floor), .. }) if floor.0 > at => {
                    min_since = Some(min_since.map_or(floor.0 - 1, |m| m.max(floor.0 - 1)));
                    skip_below = floor.0;
                    below = None;
                    continue;
                }
                Err(_) => {
                    min_since = Some(min_since.map_or(at, |m| m.max(at)));
                    below = None;
                    continue;
                }
            }
        };
        let upper: &World = proved.as_ref().unwrap_or(head_world);
        boundaries.push(classify(at, below.as_ref(), upper));
        below = proved;
        // THE CADENCE: every so many boundaries, or so long, whichever
        // comes first — the figures read here, so a cadence set while the
        // walk parked at the hold is the one it keeps.
        let (every, interval) = control.cadence();
        if (boundaries.len() - last_said.0) as u64 >= every || last_said.1.elapsed() >= interval {
            lines.say(
                Class::Progress,
                WalkProgressLine { position: at, head, elapsed_ms: started.elapsed().as_millis() },
            );
            last_said = (boundaries.len(), Instant::now());
        }
    }
    Some(WalkOutcome { boundaries, min_since, started })
}

/// The boundaries the walk proves, `(low, head]` ascending, in ONE scan —
/// and where the scan refused below `low`, the fence the feed honors from
/// there: `Reclaimed` naming a floor above `low` is the base below `low`
/// gone, so the list is asked again AT the floor — the floor's own boundary,
/// which the base embodying it answers, leads the list — and the fence is
/// one below it; a refusal naming no floor, or at-rest damage, leaves the
/// head alone to prove, the fence one below it, as the probe-by-probe walk
/// ended at its first refusal. A floor past the head names an empty list:
/// everything the region held is reclaimed.
fn list_boundaries(kernel: &Kernel<World>, low: u64, head: u64) -> (Vec<u64>, Option<u64>) {
    let at_or_below_head = |list: Vec<(Seq, Option<Attestation>)>| -> Vec<u64> {
        list.into_iter().map(|(seq, _)| seq.0).filter(|&at| at > low && at <= head).collect()
    };
    match kernel.boundaries_above(Seq(low)) {
        Ok(list) => (at_or_below_head(list), None),
        Err(HistoryError::Reclaimed { floor: Some(floor), .. }) if floor.0 > low => {
            let mut list = Vec::new();
            if floor.0 <= head {
                list.push(floor.0);
                list.extend(at_or_below_head(kernel.boundaries_above(floor).unwrap_or_default()));
            }
            (list, Some(floor.0 - 1))
        }
        Err(_) => (vec![head], Some(head.saturating_sub(1))),
    }
}

/// Parse whole newline-terminated records; trust ends at the first line
/// that is torn (no `\n`) or does not parse. Returns each record with the
/// byte offset its line starts at, and the byte offset after the last whole
/// one.
fn parse_records(bytes: &[u8]) -> (Vec<(usize, Record)>, usize) {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let Some(nl) = bytes[pos..].iter().position(|&b| b == b'\n') else { break };
        match parse_line(&bytes[pos..pos + nl]) {
            Some(rec) => out.push((pos, rec)),
            None => break,
        }
        pos += nl + 1;
    }
    (out, pos)
}

/// One file line. The file is daemon-private; unknown keys are ignored (a
/// newer daemon's extension), malformed known fields are torn-treatment.
/// The min-since record has two spellings in the field — `min_since` and
/// `floor` — and both read, because an unparseable line ends trust in
/// everything after it.
///
/// The three entry fields are read TOGETHER, because [`CommitMeta`] has only two
/// states: all three present is a recorded position, all three absent (or
/// `null`) is a bare one, and a line carrying some of them is not a line
/// this daemon wrote — so trust ends there exactly as at an unparseable
/// one, and the reopen walk re-covers the position as bare.
///
/// THE ABSENT-VS-NULL DISCIPLINE of the newer fields: `signed` is absent on
/// an unsigned line and one of its two tokens otherwise (any other value is
/// torn); the op's terms are read BY THE LINE'S OP — a `delegate` line's
/// `new_prefix` and `new_id` together (one without the other is torn), a
/// `make_link` line's `link`, a `publish` line's `placed` with `base_extent`
/// beside it, `null` there being the birth shape and not an absence — and
/// absent altogether on a line written before they were recorded, which
/// reads as an op carrying none. A term on a line of another op is an
/// unknown key, ignored. A BARE line's `journal` member is the journal's
/// answer ([`JournalTerms::parse`]): absent on a line written before it was
/// derived, or where the journal answered nothing; an object otherwise, and
/// anything else is torn.
fn parse_line(line: &[u8]) -> Option<Record> {
    let v: Value = serde_json::from_slice(line).ok()?;
    let m = v.as_object()?;
    if let Some(s) = m.get("min_since").or_else(|| m.get("floor")) {
        return Some(Record::MinSince(s.as_u64()?));
    }
    let at = m.get("at")?.as_u64()?;
    // Each field is read THROUGH the same lookup that decides it is
    // present — `serde_json::Map` panics on a missing key, and an
    // indexing read here would rest on a separate presence test agreeing
    // with it about what "present" means. `?` is the torn verdict a
    // half-written line is owed, so the two cannot come apart.
    let field = |k: &str| match m.get(k) {
        None | Some(Value::Null) => None,
        Some(v) => Some(v),
    };
    let meta = match (field("op"), field("docs"), field("time")) {
        (None, None, None) => CommitMeta::Bare {
            journal: match field("journal") {
                None => JournalTerms::default(),
                Some(j) => JournalTerms::parse(j.as_object()?)?,
            },
        },
        (Some(op), Some(docs), Some(time)) => {
            let op = op.as_str()?.to_string();
            let terms = match op.as_str() {
                "delegate" => match (field("new_prefix"), field("new_id")) {
                    (None, None) => None,
                    (Some(p), Some(i)) => Some(OpTerms::Delegate {
                        new_prefix: p.as_str()?.to_string(),
                        new_id: i.as_u64()?,
                    }),
                    _ => return None,
                },
                "make_link" => match field("link") {
                    None => None,
                    Some(l) => Some(OpTerms::MakeLink { link: l.as_str()?.to_string() }),
                },
                "publish" => match field("placed") {
                    None => None,
                    Some(p) => Some(OpTerms::Publish {
                        placed: p.as_str()?.to_string(),
                        base_extent: match field("base_extent") {
                            None => None,
                            Some(e) => Some(e.as_str()?.to_string()),
                        },
                    }),
                },
                _ => None,
            };
            CommitMeta::Recorded {
                op,
                docs: docs
                    .as_array()?
                    .iter()
                    .map(|d| d.as_str().map(str::to_string))
                    .collect::<Option<Vec<String>>>()?,
                time: time.as_u64()?,
                // Absent on a pre-feature line — the reserved null, never
                // invented (AUTH-1.52); present-but-not-a-string is torn.
                key: match field("key") {
                    None => None,
                    Some(k) => Some(k.as_str()?.to_string()),
                },
                // Absent on an unsigned line; a token no carrier spells is
                // torn.
                signed: match field("signed") {
                    None => None,
                    Some(s) => Some(Carrier::of_token(s.as_str()?)?),
                },
                terms,
            }
        }
        _ => return None,
    };
    Some(Record::Entry(at, meta))
}

/// `{"at":N}` for a bare position the journal answered nothing for, and
/// `{"at":N,"journal":{…}}` where it did — the op where named and the terms
/// in the wire's own spelling ([`JournalTerms::members`]);
/// `{"at":N,"docs":[…],"key":"…","op":"…","time":T}` for a recorded one,
/// `key` omitted only where the record carries none (a pre-feature line),
/// `"signed":"marker"|"record"` where the entry carries a signature, and the
/// op's own terms where it has any, spelled as the wire's row spells them
/// ([`OpTerms::members`]). Built through the codec's key-sorting device, so a
/// line is the same bytes whatever backs serde_json's map — which is what
/// lets `GET /changes` answer byte-identically across a restart.
fn entry_line(at: u64, meta: &CommitMeta) -> Vec<u8> {
    let mut pairs = vec![("at", Value::Number(at.into()))];
    match meta {
        CommitMeta::Bare { journal } => {
            if !journal.is_empty() {
                pairs.push(("journal", obj(journal.members())));
            }
        }
        CommitMeta::Recorded { op, docs, time, key, signed, terms } => {
            pairs.push(("op", Value::String(op.clone())));
            pairs.push((
                "docs",
                Value::Array(docs.iter().map(|d| Value::String(d.clone())).collect()),
            ));
            pairs.push(("time", Value::Number((*time).into())));
            if let Some(k) = key {
                pairs.push(("key", Value::String(k.clone())));
            }
            if let Some(carrier) = signed {
                pairs.push(("signed", Value::String(carrier.token().into())));
            }
            if let Some(terms) = terms {
                pairs.extend(terms.members());
            }
        }
    }
    line_bytes(&obj(pairs))
}

/// `{"min_since":N}` — the smallest `since` the feed can honor from here
/// on. The key is deliberately not `floor`, which on the wire names the
/// oldest position still ANSWERABLE — a different number, and one an
/// operator reading this file beside a `410` body would otherwise conflate.
fn min_since_line(min_since: u64) -> Vec<u8> {
    line_bytes(&obj(vec![("min_since", Value::Number(min_since.into()))]))
}

/// THE MALFORMED NAMES, said ONCE PER OPEN with a count (`operations.md`
/// §1.1 row 11) — the notice both halves of the feed's name-parsing share:
/// this file's own [`demote_malformed_names`] and the derived index's read
/// of the same names, each counting the positions it met and saying the
/// count and the first of them through `lines`, the classed door. Nothing
/// per position: the words are [`MalformedNamesLine`]'s.
pub(super) fn report_malformed_names(lines: &Lines, file: &'static str, positions: usize, first: u64) {
    lines.say(Class::Failure, MalformedNamesLine { file, positions, first });
}

/// Row 11's words: `{file}: {n} positions carry malformed document names,
/// the first at position {p}` — one line per file per open. A pure value,
/// pinned by `to_string()` in the unit suite.
pub(super) struct MalformedNamesLine {
    pub file: &'static str,
    pub positions: usize,
    pub first: u64,
}

impl std::fmt::Display for MalformedNamesLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} positions carry malformed document names, the first at position {}",
            self.file, self.positions, self.first
        )
    }
}

/// One newline-terminated file line — the codec's serializer, so a line is
/// the same bytes whatever backs serde_json's map and the "cannot fail"
/// argument is the one written there rather than a second copy of it.
pub(super) fn line_bytes(v: &Value) -> Vec<u8> {
    let mut b = to_bytes(v);
    b.push(b'\n');
    b
}

#[cfg(test)]
impl CommitsLog {
    /// A [`CommitsLog`] whose appends FAIL — a READ-ONLY handle on the file
    /// in `dir` — which is the one condition the stop rule is about and the
    /// one no portable test can produce from [`CommitsLog::open`]'s handle.
    /// The same seam `feed/derived.rs` keeps for the same rule.
    fn over_unwritable(dir: &Path, open_head: u64) -> CommitsLog {
        let path = dir.join(SIDECAR_FILE);
        File::create(&path).expect("create the file to be opened read-only");
        let file = File::open(&path).expect("a read-only handle");
        CommitsLog {
            file,
            dir: dir.to_path_buf(),
            entries: BTreeMap::new(),
            offsets: BTreeMap::new(),
            min_since: 0,
            open_head,
            rewritten: false,
            pending: None,
            last_time: 0,
            len: 0,
            lines: Lines::new(),
            stopped: None,
            fail_next_rewrite_past_rename: false,
        }
    }

    /// A [`CommitsLog`] over a WRITABLE file in `dir` holding `entries`, its
    /// region `(low, head]` PENDING — the state the open leaves a torn file
    /// in — so the landing's one rewrite is judged on the file's bytes
    /// without a journal to walk.
    fn pending_over(dir: &Path, entries: BTreeMap<u64, CommitMeta>, low: u64, head: u64) -> CommitsLog {
        let file = OpenOptions::new()
            .append(true)
            .open(dir.join(SIDECAR_FILE))
            .expect("a writable handle on the file");
        let len = file.metadata().expect("the file's length").len();
        CommitsLog {
            file,
            dir: dir.to_path_buf(),
            entries,
            offsets: BTreeMap::new(),
            min_since: 0,
            open_head: head,
            rewritten: false,
            pending: Some((low, head)),
            last_time: 0,
            len,
            lines: Lines::new(),
            stopped: None,
            fail_next_rewrite_past_rename: false,
        }
    }
}

impl CommitsLog {
    /// THE STOP AS A READ: the position this file's stop was set at
    /// ([`CommitsLog`]'s `stopped` says which position each cause carries),
    /// or `None` while the file takes lines — what the standing line re-says
    /// a stopped file by, once an hour while it stands.
    pub(super) fn stopped_since(&self) -> Option<u64> {
        self.stopped
    }

    /// The test seam behind `crate::Daemon::fail_the_feeds_next_rewrite_past_rename`:
    /// the next compaction's rewrite fails at the reopen of the file it has
    /// just renamed into place — the past-rename arm, and the stop it
    /// carries. Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn fail_next_rewrite_past_rename(&mut self) {
        self.fail_next_rewrite_past_rename = true;
    }
}

#[cfg(test)]
mod tests;
