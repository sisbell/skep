//! The commit-metadata sidecar (wire v6): `commits.log` in the data dir.
//!
//! It holds one JSON line per committed write `(position, op kind, affected
//! docs, unix millis, testimony, signedness, the op's own terms)`, appended
//! by the write path at ack time and replayed on reopen. This is
//! daemon-owned transport metadata, never substrate state (wire.md §The
//! change feed) — exempt from the no-second-persistence-layer rule for the
//! same reason as the kernel's journal-lock file: it persists nothing about
//! the world, since two daemons replaying one journal still converge on
//! byte-identical worlds. The sidecar is the daemon's testimony about its
//! own service, and it feeds `GET /changes` and `/health`'s `head_time`.
//!
//! This file is the feed's authority file: what a position's entry says —
//! its op, its docs, its time, its key, whether and how its entry is signed
//! (`signed`, the daemon's own assertion at commit of why the wire's `key` is
//! absent: the marker slot filled, or a credential or registry record's own
//! `sig` — never on the wire itself), and the op's own terms (a
//! `delegate`'s minted pair, a `make_link`'s minted link address, a
//! `publish`'s placed count and base extent — AUTH-6.36, signed-ops D25) —
//! is recorded here and nowhere else. The feed's four derived sidecars
//! (`feed/derived.rs`: the per-document position index, the offset array,
//! the masked-position bitmap and the per-owner draft streams; PUB-7.19) are
//! projections of this file and the journal, rebuilt from them on loss; the
//! fifth file beside them, the attest store (`feed-attest.log`), mirrors the
//! marker slot's signature per attested position and is not a projection
//! below the reclaim floor (`feed/attest.rs` states its class); `feed.rs`
//! composes the six. The signature itself is never a member of this file:
//! here it would be a rewritable sidecar assertion of the very class the
//! marker exists to be told apart from; this file records only that the
//! marker was filled, which is what lets the feed render a lost store line
//! as `attest: null` (lost) rather than absent (a verdict).
//!
//! **A line written before the signedness and the terms** (no `signed`, no
//! terms) parses: its row renders `key` as recorded and the op's terms
//! absent — dev boards regenerate (no-versioning); `attest` is the store's
//! to answer for such a row, as for every row.
//!
//! Crash honesty is the contract:
//!
//! * A torn tail is truncated at the last whole record on open — trust ends
//!   at the first unparseable line, or at a line that lies below the line
//!   before it (the file is position-ordered, and the reads below the
//!   resident window seek by that order; `feed/window.rs`); the daemon
//!   never wedges on its own testimony. The cut is said on the operator
//!   stream once, with the last trusted position and the bytes ([`Cut`]),
//!   and its case: the cut part is re-derived as bare entries by the walk
//!   below, and past a damaged line the whole lines the cut took are
//!   counted, their keys and times lost unless a copy holds them.
//! * Positions whose record was lost, or that predate the feature, are
//!   reconstructed as bare positions and answer `docs`/`key`/`time` as
//!   `null`. Never an invented value. The op's own terms, and the op where
//!   the journal names one alone, are answered on a bare row — from the
//!   journal, as the position's class is (`classify::derived_journal`): a
//!   `delegate`'s pair, a `make_link`'s link, a `publish`'s count and
//!   extent, so a feed-only mirror's Π is whole across a bare span — save
//!   a `delegate` under a node `register_node` admitted, which the journal's
//!   principal walk does not reach and whose row answers no term. They
//!   ride the bare line under one `journal` member, written by the walk that
//!   derived them so the two reconstructions are paid once; `null` stays
//!   where the journal cannot answer. A write that panicked after the
//!   kernel committed it takes the same bare line, written at the commit by
//!   the write path's door ([`CommitsLog::record_bare`]; `operations.md`
//!   §4 row 34) and classified the same way off the two worlds the door
//!   held, so the next open walks nothing for it.
//! * Reconstruction uses the two public journal-fed surfaces the daemon
//!   already holds — the kernel's one-scan boundary list
//!   (`Kernel::boundaries_above`, every committed boundary above the file's
//!   coverage from one base) and its bounded replay (`Kernel::world_at`):
//!   the list names the boundaries, an `Ok` replay of each proves it, and a
//!   refusal (reclaimed, corrupt, I/O) honestly ends the feed's reach below
//!   the boundary it refused — recorded as the smallest `since` this feed
//!   can honor, under which `/changes` answers the same 410 discipline as
//!   `/op-at`. The kernel's own journal reader stays closed. **The walk runs
//!   behind the listener** (`operations.md` §3.3 step 2; §4 row 16): the
//!   open records the uncovered region `(low, head]` as pending and returns
//!   writing nothing of it; a thread of the write path's walks it while
//!   reads are served and writes admitted — the daemon's open walks it
//!   instead where the OS refuses that thread — and lands it by one whole
//!   rewrite of this file ([`CommitsLog::fold_the_walk`], then
//!   [`CommitsLog::write_the_landing`]), so the walk runs once per uncovered
//!   region, not once per open. While the region is pending, a page of
//!   `/changes` whose rows would have to come from it is refused
//!   retry-class (`feed_rebuilding`), a write's record is kept in memory
//!   alone until the landing writes it (a crash before then re-covers it
//!   bare at the next open), and a kill mid-walk leaves the file unchanged,
//!   the next open walking again from `low`.
//! * A bare position classifies from the journal (PUB-6.45: "a lost sidecar
//!   never unmasks a draft write"): the walk holds the world at each
//!   boundary and the one below it, and the diff of the two — the drafts
//!   minted, the links deposited (their homes, and a retraction's targets'
//!   homes), the drafts whose arrangement moved (`classify::derived_docs`)
//!   — is the set of documents the feed's mask classifies the position by.
//!   The wire entry still answers `docs: null` (lost testimony is never
//!   invented); what the journal supplies is the class, so a draft write
//!   whose record was lost is omitted from a guest's page exactly as a
//!   recorded one is. A boundary whose predecessor world the journal can no
//!   longer answer (the oldest boundary above a reclaimed region) is
//!   unclassifiable and is served to every class: it discloses its position,
//!   which `/events` and `head_time` already disclose board-wide (PUB-6.52's
//!   accepted residue), and of what it wrote nothing but the `attest`
//!   member, where the attest store holds the position's slot.
//!
//! **The file is kept whole from genesis** (wire.md §The change feed,
//! Retention; DOCTRINE: the record of events is kept forever). The journal
//! reclaims old STATES — below its reclaim floor `/op-at` answers `410
//! history_reclaimed` — but a commit's position, time, hand, op, documents
//! and terms are this file's and nothing drops a line of it: no rewrite
//! writes fewer lines than the file held, and the one fence it keeps,
//! `min_since` ([`CommitsLog::min_since`]), marks a hole and never the
//! journal's floor — a region a lost or torn file left that the journal
//! could not re-cover, or a line an earlier build's compaction wrote, under
//! which `/changes` answers the same `410` as `/op-at`. What bounds the
//! daemon's memory is the resident window ([`CommitsLog::resident_from`];
//! `limits::FEED_RESIDENT_WINDOW`): the newest positions' entries stay
//! resident, as every entry once did, and below the window the file itself
//! answers, read by position (`feed/window.rs`), so a page's bytes never
//! depend on which side of the window its positions lie. A rewrite — the
//! walk's landing, or the open's purge of another journal's lines — copies
//! every line the file holds and adds the new ones; one that fails past its
//! rename while serving leaves the append handle naming the replaced file,
//! so it stops this file for the uptime as a failed append does — said once,
//! the next open re-deriving — and never fails an op (P22).
//!
//! The sidecar is appended to under the write path's serialization lock —
//! held by `commits`, which takes that lock and calls the feed's `record` in
//! one operation — so file order is position order and recorded times are
//! monotone non-decreasing in position (wall-clock reads are additionally
//! clamped against the last recorded time). Appends are flushed to the OS
//! but not fsynced — a lost tail answers bare, which is the honest trade for
//! not doubling every write's fsync cost on testimony.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
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
use crate::limits::{
    FEED_RESIDENT_WINDOW, FEED_WALK_PROGRESS_BOUNDARIES, FEED_WALK_PROGRESS_INTERVAL,
};
use crate::serial::SerialGuard;

/// The sidecar's file name inside the data dir.
///
/// It lies beside the kernel's own journal/checkpoint files, which this
/// crate never touches. The feed's reader below the resident window opens
/// it by this name (`feed.rs`).
pub(super) const SIDECAR_FILE: &str = "commits.log";

/// Returns the wall-clock reading a commit's `time` is stamped with.
///
/// It is unix milliseconds, the wire's unit (wire.md §The change feed), `0`
/// for a clock set before the epoch. The write path's one reading of that
/// clock because two readers must agree on it: [`CommitsLog::record`] stamps
/// every commit with it, and the published head writer measures its hour
/// from such a stamp — its resume takes the last head's time off the head's
/// own entry — against its own reading. Two copies of this expression would
/// agree only until one was edited or seamed, and the head's hour would then
/// subtract one clock from another with nothing to say so. The media gate
/// reads the wall clock for itself (`skep_media::gate::wall_clock_ms`,
/// seamed apart for its leases and expiries), and no reading of the one is
/// ever compared with a reading of the other.
pub(super) fn wall_clock_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The carrier of an entry's signature, which the wire never carries.
///
/// It is what the file's `signed` field records: the daemon's own assertion
/// at commit of why the row's `key` is absent (signed-ops D12; AUTH-6.15: "a
/// signed entry has one authority for its hand, its own signature, and the
/// daemon asserts no second beside it"). Two spellings in the file,
/// `"marker"` and `"record"` — the signed-ops record's own tokens, carried by
/// every signed line on disk, so a variant's name never moves them: a token
/// this parser stopped spelling would leave each line carrying it torn at
/// open — and, on every unsigned line, the field's absence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Carrier {
    /// The entry's marker slot is filled.
    ///
    /// It holds the value the plain sequence's check admitted and handed the
    /// kernel, mirrored by the attest store. A row recorded so whose slot the
    /// store cannot answer renders `attest: null`, lost.
    Marker,
    /// The entry's signature is its record's own `sig` member.
    ///
    /// The record is a credential or registry record deposit's (signed-ops
    /// D26) — never this file's record, which holds no signature: at the
    /// atom's `insert` the record carries one, verified at its `make_link`,
    /// a later position, under the set that opens its home (the record
    /// grade: 2a, a registry record's 2b) — or refused there, the atom then
    /// an orphan no link names, the reader's undeterminable here; at the
    /// `make_link` the `sig` verified. Neither row carries `attest`: the
    /// record's `sig` is the deposit's one carrier, covering both positions
    /// (signed-ops D26, D27).
    RecordSig,
}

impl Carrier {
    /// Returns the file's spelling.
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

/// The op's own terms on a row.
///
/// They are what a feed-only mirror needs from the row alone (AUTH-6.36;
/// signed-ops D25 and §5.2), recorded at commit as `docs` is, the daemon's
/// testimony of what it committed. One variant per op kind that carries
/// any, rendered as [`OpTerms::members`] on the wire's row and the file's
/// line alike; every other kind carries none, and its row renders none. A
/// bare row renders what the journal answers ([`JournalTerms`]) and `null`
/// for every member it cannot ([`OpTerms::MEMBER_NAMES`]): lost testimony is
/// never invented, and the journal's answer is no invention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum OpTerms {
    /// `delegate`: the minted account address and the principal id it seated.
    ///
    /// The address is in the board's local form (the `ack_addr` the op
    /// answers) — AUTH-6.36's members by name. `new_id` is a JSON number: it
    /// was held to 2^53 − 1 at the parse, the wire's exactly-representable
    /// range.
    Delegate { new_prefix: String, new_id: u64 },
    /// `make_link`: the minted link's address, the `ack_addr` the op answers.
    ///
    /// For a replacing grant this is the grant record's address; its
    /// `replaces` link sits at the next address, read by adjacency.
    MakeLink { link: String },
    /// `publish`: signed-ops D25's two client terms.
    ///
    /// They are exactly as `doc_metadata` serves them for the minted member —
    /// the count the client placed, and the extent of the base the staged
    /// copy took, `None` in the birth shape (the absence is the birth bit).
    /// Both decimal strings, `Nat`'s wire form.
    Publish { placed: String, base_extent: Option<String> },
}

impl OpTerms {
    /// Every member any op's terms render under.
    ///
    /// It is what a bare row renders `null`, its op (and so which of them it
    /// carried) unknown. Held to the union of [`OpTerms::members`] over the
    /// variants by the sidecar test
    /// `a_bare_row_nulls_exactly_the_members_the_terms_render`.
    const MEMBER_NAMES: [&'static str; 5] =
        ["new_prefix", "new_id", "link", "placed", "base_extent"];

    /// Returns the members these terms render as.
    ///
    /// They render so on the wire's row and in the file's line alike, one
    /// spelling for both, which [`parse_line`] reads back: a `publish`'s
    /// birth extent is `null`, the absence being the birth bit.
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

/// The journal's answer on a bare position (SO-I5 (e)).
///
/// It is the op's own terms as the recorded row would have carried them
/// (save the `link` it names for an `emit` or an `assert_sup`, whose
/// recorded row carries none), and the op where the journal's facts name one
/// op alone — derived by `classify::derived_journal` from two worlds: by the
/// walk that reconstructs the position, from the two it already holds, or by
/// the write path's door, from the two it held, for a write that panicked
/// past its commit — and persisted on the bare line under the `journal`
/// member so the walk is paid once. Not testimony — the daemon witnessed
/// nothing — and never rendered as such: `docs`, `key` and `time` stay
/// `null` beside it. Empty where the journal answers nothing, which renders
/// as a bare row the journal answered nothing for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct JournalTerms {
    /// The op the journal names, where it names one alone.
    ///
    /// That is `delegate`, `publish`, `version`, `nullify`, a replacing
    /// `make_link`; `None` for an op the facts leave ambiguous
    /// (`classify::derived_journal`'s terms say which).
    pub op: Option<String>,
    /// The terms the journal answers.
    ///
    /// They are a seated principal's pair, a minted member's count and
    /// extent, a deposited link.
    pub terms: Option<OpTerms>,
}

impl JournalTerms {
    /// Returns whether nothing was derived.
    ///
    /// Then the row renders as a bare row the journal answered nothing for.
    fn is_empty(&self) -> bool {
        self.op.is_none() && self.terms.is_none()
    }

    /// Returns the `journal` member's object.
    ///
    /// It holds `op` where named, then the terms' members in the wire's own
    /// spelling.
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

    /// Parses a bare line's `journal` object.
    ///
    /// It is the inverse of [`JournalTerms::members`]: `op` an optional
    /// string, the terms by the members present — a `delegate`'s pair
    /// together (one without the other is torn), a `link`, a `placed` with
    /// `base_extent` beside it (`null` the birth shape). `None` is the torn
    /// verdict.
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

/// One committed position's metadata: this file's crash-honesty rule as a type.
///
/// A position is either one the daemon observed committing, carrying all of
/// op/docs/time, or a bare one reconstructed from the journal, carrying none
/// of them. Three independent `Option`s would admit six more combinations,
/// and this file has a meaning for neither the half-recorded position nor
/// the record that remembers when but not what.
#[derive(Clone, Debug)]
pub(super) enum CommitMeta {
    /// Reconstructed, not witnessed: served as explicit `null`s.
    ///
    /// It is never served as an invented value, and stands beside what the
    /// journal answers for it ([`JournalTerms`]: the op's terms, and the op
    /// where named). Its class — which documents the journal shows it
    /// touched — lives in the feed's classification map, not here: this file
    /// records testimony and, of the journal's answer, which is not
    /// testimony, only the op and its terms.
    Bare {
        journal: JournalTerms,
    },
    /// Witnessed by the daemon's own write path as the write commits.
    ///
    /// It is a session write's at its ack, the published head writer's own in
    /// its turn. `key` is the AUTH testimony (AUTH-4.48; wire.md §The change
    /// feed), one of three values: the fingerprint hex of the enrolled key
    /// that established the authoring session, `"bare"` for a bare one, or
    /// `"system"` for the published head writer's own commits, which have no
    /// session (`SYSTEM_TESTIMONY`, `commits/head.rs`) — the value that
    /// writer's resume reads back through this field to tell its own commits
    /// from the ones its count bound counts. `None` only for a line written
    /// before the feature — served as the reserved null (AUTH-1.52's
    /// lost-metadata meaning), never for a line this daemon writes. Recorded
    /// on every line, a signed entry's included: the file is the daemon's
    /// own, and the resume above reads it; what signed-ops D12 keeps off the
    /// wire is decided at [`CommitMeta::entry`] by `signed`, the carrier of
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
    /// Renders one `GET /changes` entry.
    ///
    /// It holds the position, the four fields, and — wire v7.11 — the members
    /// a reader needs to judge and to place the entry from the feed alone. A
    /// bare position renders its testimony as explicit `null`s — `docs`,
    /// `key`, `time` — and the op and its terms as the journal answers them
    /// ([`JournalTerms`]): where the journal names the op, exactly that op's
    /// members, as the recorded row carries them; where it names a deposited
    /// link alone, `link`, the members no link write carries absent as on a
    /// recorded row; where it answers nothing, every term `null` — the
    /// crash-honesty rule of this file, expressed where the rule is stated
    /// rather than at the handler. `reduced` is the record's own docs reduced
    /// to the requester's readable ones (PUB-6.45), which is what a recorded
    /// entry renders — never `Recorded.docs`, which is the whole list and
    /// which rendering here would hand a requester the home of a draft-homed
    /// record they may not read (PUB-6.47 licenses their learning it exists,
    /// never its home). It is ignored for a bare position, whose docs are the
    /// reserved null whatever its class. Deliberately not [`entry_line`]'s
    /// convention, which omits absent fields: the file is daemon-private and
    /// [`parse_line`] reads absent and null alike, so the shorter line costs
    /// nothing there, while a client reading the wire is owed the field it
    /// asked about.
    ///
    /// **The members that are absent rather than null**, and why:
    ///
    /// * `key` (signed-ops D12; AUTH-6.15): present iff the entry carries no
    ///   signature — absent on a row whose `signed` names a carrier (a
    ///   marker-signed row; a credential or registry record deposit's link
    ///   row above the claim, its record's `sig` verified — its atom row is
    ///   admitted unsigned and serves its `key`),
    ///   served as recorded on every other row, a bare row's reserved `null`
    ///   included (lost testimony stays lost; the store's slot is a fact of
    ///   the journal, not testimony this file can restore).
    /// * `attest` (the signed-ops record §7.3 (i)): the marker slot as the
    ///   store holds it, `{"alg", "sig"}`, on any row the store answers;
    ///   `null` — lost — where the line records the marker filled and the
    ///   store cannot answer; absent on every other row: an unsigned entry, a
    ///   credential or registry record deposit's two rows (the deposit's slot
    ///   is empty; its signature is the record's own `sig`), the ceremony's
    ///   rows, the head writer's — and a row whose `docs` the requester's
    ///   class reduces (PUB-6.47's straddles; SO-I5 (e)), its signature a
    ///   function of the home the row withholds, where the feed's page removes
    ///   the member this method renders. Absence on the origin's own feed, on
    ///   a row served whole at the reader's own class, is A6's verdict, so a
    ///   store line is served wherever one is held and never dropped.
    /// * the op's terms ([`OpTerms::members`], the file line's spelling too):
    ///   present on the row of the op that carries them, absent on every
    ///   other op's; on a bare row the journal's answer ([`JournalTerms`]),
    ///   and `null` for every member it does not reach
    ///   ([`OpTerms::MEMBER_NAMES`]).
    ///
    /// `attest` is the store's answer for this position, looked up by the
    /// feed beside the line: the signature is never a member of this file.
    pub(crate) fn entry(&self, at: u64, reduced: Vec<String>, attest: Option<&Attestation>) -> Value {
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

    /// Returns the recorded wall-clock time, or `None` for a bare position.
    ///
    /// It is the reading the open's clamp, [`CommitsLog::head_time`] and the
    /// head writer's resume take; the two renderers match the field itself.
    pub(crate) fn time(&self) -> Option<u64> {
        match self {
            CommitMeta::Bare { .. } => None,
            CommitMeta::Recorded { time, .. } => Some(*time),
        }
    }

    /// Returns a bare position the journal answered nothing for.
    pub(crate) fn bare() -> CommitMeta {
        CommitMeta::Bare { journal: JournalTerms::default() }
    }
}

/// One line's byte offset in `commits.log`.
///
/// A newtype because it travels beside a committed position of the same
/// width — out of [`CommitsLog::record`], through
/// [`super::feed::Feed::record`], into the feed's own indexing — and the two
/// mean opposite things. Transposed, the position index, the bitmap and the
/// owner streams key on a byte offset while `feed-offsets.log` records a
/// position: the first half is loud, since the change feed's pages compare
/// byte for byte, and the second is silent, since nothing in this build
/// seeks by an offset (the card on `CommitsLog`'s `offsets` field says so).
/// The device [`crate::serial::SerialGuard`] already is, applied to data
/// rather than to a guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct LineOffset(pub u64);

/// What [`CommitsLog::record`] did with a new position.
///
/// It appended its line, at the [`LineOffset`] it landed at (past a failed
/// append, an offset that names no line, none being written), or held
/// it in the resident entries alone while the walk's region is pending — the
/// line written, and its offset assigned, by the landing's rewrite
/// ([`CommitsLog::write_the_landing`]). The feed folds a held position into
/// its twins and appends nothing to the four derived files, whose lines the
/// same landing rewrites whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Recorded {
    Appended(LineOffset),
    Held,
}

/// One replayed file record.
///
/// Read by [`parse_line`] off a line of the file: at the open's scan, and
/// by the feed's reader below the resident window (`feed.rs`), which hands
/// each line a cursor reads to the same parser.
#[derive(Debug)]
pub(super) enum Record {
    Entry(u64, CommitMeta),
    /// The smallest `since` this feed can honor.
    ///
    /// See [`CommitsLog::min_since`].
    MinSince(u64),
}

/// One bare position the reconstruction walk covered.
///
/// With it comes the journal's classification of it: the documents the
/// commit touched as the world diff shows them (`Some`, possibly empty), or
/// `None` where the world below the boundary could not be answered —
/// unclassifiable, served to every class (the module doc's residue) — and,
/// off the same two worlds, the journal's terms for its row
/// ([`JournalTerms`]; empty where the world below could not be answered).
#[derive(Debug)]
pub(super) struct Walked {
    pub at: u64,
    pub docs: Option<Vec<Address>>,
    pub journal: JournalTerms,
}

/// The replayed `commits.log`.
///
/// It holds the file handle, the resident window's entries, and the
/// bookkeeping the feed's derived structures key on; the file holds every
/// line, and the feed reads the ones below the window from it.
pub(super) struct CommitsLog {
    file: File,
    /// The data dir the file lives in — what a rewrite re-creates it under.
    dir: PathBuf,
    /// The resident window: every enumerable position at or above
    /// `resident_from`, in order.
    ///
    /// And every one of them is one this file stands behind: `Recorded` means
    /// testimony whose document names all parse — rendered from validated
    /// addresses at the record, read back at the open, where the scan
    /// demoted the rest ([`demoted`]). So a consumer that renders a
    /// `Recorded` entry, or classifies by its names, needs no second check
    /// of its own; the feed's reader below the window demotes each line it
    /// reads the same way.
    ///
    /// Read outside this file through `entries()` and `entries_above()`
    /// alone, as `min_since` is through its two: no file but this one can
    /// add an entry this card does not stand behind. While the walk's region
    /// is pending the window holds, beside the file's newest lines, every
    /// position recorded since the open ([`Recorded::Held`]), which the file
    /// takes at the landing; the eviction never reaches a held position
    /// ([`CommitsLog::evict`]).
    entries: BTreeMap<u64, CommitMeta>,
    /// Each resident entry's line's byte offset in the file.
    ///
    /// It is the offset array's in-memory twin (PUB-7.19) over the window,
    /// learned from the open's scan and advanced by every append; a rewrite
    /// assigns the new lines' offsets and moves none of the old, since it
    /// copies the file's lines verbatim ahead of them. Its one consumer is
    /// `feed-offsets.log` (`feed/derived.rs`), whose lines the feed appends
    /// from it and checks against it over the window at the open; the reads
    /// below the window seek by position, not by offset (`feed/window.rs`).
    ///
    /// Position → [`LineOffset`], which is what keeps the two apart: they
    /// are the same width and mean opposite things, and the map's own key
    /// and value are the pair a transposition swaps.
    offsets: BTreeMap<u64, LineOffset>,
    /// The lowest position the resident window holds.
    ///
    /// Every entry the file holds at or above it is in `entries`; below it
    /// the file alone answers. It is the greater of the fence and the
    /// window's span below the head at the open
    /// (`limits::FEED_RESIDENT_WINDOW` positions, or the test seam's), and
    /// it rises with every record ([`CommitsLog::evict`]) so the window
    /// never holds more than that many positions — save the positions held
    /// in memory alone while the walk's region pends, which no eviction
    /// drops. Read outside this file through [`CommitsLog::resident_from`].
    resident_from: u64,
    /// The window's span in positions.
    ///
    /// It is `limits::FEED_RESIDENT_WINDOW`, or the figure the test seam set
    /// (`set_feed_resident_window`, the test seam), read once at the open.
    window: u64,
    /// The most entries the window has held this uptime.
    ///
    /// It is read for the checkpoint thread's landing line beside the count
    /// now resident, so a window that outgrows its span is told.
    resident_most: usize,
    /// The entries the file holds above the fence, at or below the head.
    ///
    /// They are the lines the open's scan counted and every record since —
    /// the walk's landed boundaries among them — resident or not; what the
    /// open's line reports as `commits.log {n} entries`.
    count: u64,
    /// How many of `count` are bare.
    bare: u64,
    /// The first position the file holds a line for above the fence.
    ///
    /// It is the wire's `floor` on a board whose walk has nothing pending
    /// ([`CommitsLog::floor`]): the oldest position `/changes` answers —
    /// `1` on a board that never compacted and never lost a line. `None`
    /// where no line stands above the fence.
    first_held: Option<u64>,
    /// The smallest admissible `since`: the fence of a hole.
    ///
    /// Coverage is complete over `(min_since, head]` — the region pending
    /// aside, until the walk lands it; at or below it the file holds no
    /// line this build serves: a region a lost or torn file left that the
    /// walk could not re-cover (the journal reclaimed or refused it), or
    /// the fence an earlier build's compaction wrote, which this build
    /// keeps as it found it — never the journal's reclaim floor, which
    /// moves no fence here. Below it `/changes` answers 410. Deliberately
    /// not called a floor — the wire's `floor` is the oldest position still
    /// answerable, whereas this is the highest one that is not. Lines the
    /// file holds at or below the fence — a walk's refusal moved the fence
    /// past them — stay in the file and are served by no route.
    ///
    /// **Invariant.** `min_since <= head` always. A fence above the head is
    /// not a fact about this journal and is discarded at open, exactly as an
    /// entry above it is — the coverage clause above means something only
    /// under that.
    ///
    /// Read from outside this file through [`CommitsLog::admits_since`] and
    /// [`CommitsLog::floor`], the predicate and the datum this fence
    /// answers: the distinction from the wire's `floor` is this file's to
    /// keep, and so is every comparison against it.
    min_since: u64,
    /// The fence line the next landing writes, where the walk moved it.
    ///
    /// It is set by [`CommitsLog::fold_the_walk`] where the walk's own fence
    /// stands above the one in force, and written ahead of the landed lines
    /// by [`CommitsLog::write_the_landing`]'s rewrite, which clears it.
    fence_owed: Option<u64>,
    /// The journal head at open.
    ///
    /// It is the fence between replayed history and this uptime's commits.
    /// An ack carrying a position at or below it (an idempotency-memo
    /// replay, `emit`'s incumbent ack) is never a new commit and is never
    /// re-recorded.
    open_head: u64,
    /// Whether this open's purge rewrote the file, moving every offset.
    ///
    /// It is set where the open found a fence describing another journal
    /// and rewrote the file without it ([`CommitsLog::open`]), and read at
    /// the feed's open alone: every line's offset moved, so the derived
    /// offset array is re-derived from the file. The walk's landing rewrite
    /// moves no offset — it copies the file's lines verbatim ahead of the
    /// new ones — and sets nothing here.
    rewritten: bool,
    /// The reclaim floor this open probed ([`reclaim_floor`]).
    ///
    /// It is `None` where the journal still answered genesis, or refused the
    /// probe other than as reclaimed — the one probe the feed's open pays,
    /// read by the attest store's open for its cut line, which runs before
    /// the listener and the checkpoint thread, so the floor cannot move
    /// between the two. It moves no fence of this file's.
    floor_at_open: Option<u64>,
    /// The region pending: the positions the file did not cover at open.
    ///
    /// It is `(low, head]`, which the walk behind the listener re-covers
    /// ([`reconstruct`]) and the landing writes
    /// ([`CommitsLog::write_the_landing`]); `None` where the file covered the
    /// head, and again once the landing has folded it in. `low` is covered
    /// (the highest surviving entry, or the fence), `head` uncovered, the
    /// last of the region. While it stands: `entries` lacks every position in
    /// it; [`CommitsLog::record`] keeps a new position in memory alone
    /// (`Recorded::Held`); the file takes no line; and the feed refuses a
    /// page whose rows would have to come from it. Read outside this file
    /// through [`CommitsLog::pending_region`].
    pending: Option<(u64, u64)>,
    /// Monotone clamp for recorded wall-clock times.
    last_time: u64,
    /// The file's length — the offset the next appended line lands at.
    len: u64,
    /// The classed door with the daemon's record ([`Lines`]).
    ///
    /// It is what the file's stop is said through, once per uptime: a failed
    /// append's, a rewrite's past its rename, or the walk's landing refused
    /// before its rename.
    lines: Lines,
    /// Set by the first failed append of this uptime, or by a failed rewrite.
    ///
    /// The rewrite is the walk's landing's, failed past its rename — after
    /// which the handle names a file no open reads — or before it
    /// ([`CommitsLog::write_the_landing`]); after any of the three this file
    /// takes no further line.
    ///
    /// **The reopen walk cannot reach an interior loss.** [`CommitsLog::open`]
    /// records `(low, head]` for the walk behind the listener, where `low` is
    /// the highest surviving entry, so a position lost below a later
    /// successful append is re-derived by nothing: absent from `entries`,
    /// hence from every feed source (the published stream and the bitmap are
    /// built from these keys, the index from their classifications, the
    /// streams filtered against them), hence from every page at every class,
    /// permanently, with no error anywhere. Stopping the file keeps `low`
    /// below the loss, so the walk re-covers that position and every one
    /// after it as bare entries — which is what [`CommitsLog::record`]'s
    /// failure path promises, and what the derived layer's own stop rule
    /// (`feed/derived.rs`) buys for the same condition. The resident
    /// `entries` map is written beside every append, whether or not it
    /// lands, so this uptime answers with full testimony; what stops is what
    /// the next open reads. `Some` carries the position the stop was set at —
    /// the position the stop's own line names, an ordering the standing line
    /// re-says the stop by (`operations.md` §1 the rates, `{file} stopped
    /// since position {p}`): the failed append's position, which the next
    /// open re-derives from; the region's lower edge a landing left the file
    /// torn at, which it walks again from; or the last entry a rewrite failed
    /// past its rename wrote, which it re-derives above.
    stopped: Option<u64>,
    /// The test seam that fails the next rewrite past its rename.
    ///
    /// It is behind `skepd::Daemon::fail_the_feeds_next_rewrite_past_rename`:
    /// the next rewrite fails after its rename, at the reopen of the new
    /// file, so the stop that failure carries is reachable without a disk
    /// that fails on cue.
    #[cfg(any(test, feature = "test-hooks"))]
    fail_next_rewrite_past_rename: bool,
}

impl CommitsLog {
    /// Replays the file in one scan and records any uncovered region as pending.
    ///
    /// The scan reads the file a line at a time, holding resident the
    /// window alone (`limits::FEED_RESIDENT_WINDOW` positions below the
    /// head, or the test seam's figure), and counts the rest: how many
    /// entries the file holds above its fence, how many of them are bare,
    /// the first position held and the last. It truncates a torn tail and
    /// drops everything the file says about a journal other than this one
    /// — entries beyond the head, by one truncation, since they lie at the
    /// file's end, and a fence above it, by one rewrite of the file without
    /// it — and any uncovered `(low, head]` region, `low` the last recorded
    /// position or the fence above it, is recorded as pending, to be
    /// reconstructed as bare positions by the walk behind the listener
    /// ([`reconstruct`]) and written by its landing
    /// ([`CommitsLog::write_the_landing`]). Returns the replayed log with
    /// nothing written for the region: no bare line appended, no fence line
    /// written for it.
    ///
    /// **Cost** — the open's own: O(the file) to scan it, the window's
    /// entries held and no more, and the floor probe. The walk is not the
    /// open's (`operations.md` §3.3 step 2; §4 row 16): reconstruction
    /// spends one whole-world `Kernel::world_at` per uncovered boundary — a
    /// checkpoint deserialize plus a journal fold each — plus one world diff
    /// per boundary for its classification and its terms (`derived_docs` and
    /// `derived_terms_over` state that cost), so a dir with no coverage (a
    /// sidecar deleted, arrived corrupt, or written before this feature)
    /// pays that for every boundary the journal still holds; paid inside the
    /// open it would hold the listener unbound for the walk's length, so a
    /// supervisor that killed a slow start would restart the walk from
    /// zero. It is paid on a thread of the write path's instead, the board
    /// serving meanwhile — at the daemon's open after all where the OS
    /// refuses that thread — and lands by one rewrite, so a covered region
    /// is walked once ever rather than once per open. The region is bounded
    /// below by journal reclamation, so the ceiling is the retained window,
    /// which skepd's `server.rs` sets through `CHECKPOINT_EVERY_COMMITS` and
    /// `RETAINED_CHECKPOINTS`: about their product in commits, fewer where
    /// the cadence's byte bound crosses first.
    ///
    /// **Nothing is dropped for the journal's retention.** The file is kept
    /// whole from genesis (the module doc): the reclaim floor is probed
    /// once, for the attest store's cut line alone ([`reclaim_floor`]), and
    /// moves no fence; the fence the file holds is the one it found, a hole
    /// an earlier build or a refused walk left, said once by the feed's open
    /// where one stands. The purge of another journal's lines goes to a
    /// temp file and is renamed over the original, so a crash mid-rewrite
    /// leaves the whole old file or the whole new one — never a half of
    /// either.
    ///
    /// `lines` is the classed door: a torn tail is said through it once
    /// ([`LogCutLine`]) — at the open, before the walk, with the walk's own
    /// fence `low` as the last trusted position — the entries past the head
    /// once with their count and positions ([`ForeignLinesLine`]), the file
    /// cut or rewritten without them, the malformed names once with their
    /// count ([`MalformedNamesLine`]), a file absent on a journal that holds
    /// commits once with the region the walk re-covers
    /// ([`LogBegunAfreshLine`]), and a rewrite's temp file found beside it
    /// (`operations.md` §1.1 m8; [`say_a_compact_twin`]); the log keeps a
    /// clone for its stop and its landing.
    ///
    /// # Errors
    ///
    /// **Disposition**, deliberately the opposite of [`CommitsLog::record`]'s:
    /// every I/O failure here is fatal and reaches the caller as
    /// `DaemonError::Sidecar` — save three reads that refuse nothing: the
    /// look at whether the file stood, the look for a rewrite's temp beside
    /// it, and the floor probe, whose refusal reports no floor. At ack time
    /// the ack is already owed, so lost testimony degrades to bare; at open
    /// nothing is owed yet, and a data dir that cannot take a write the
    /// kernel just performed is an operator condition worth reporting rather
    /// than limping past. Every failure names this file, the kind kept
    /// (`operations.md` §1.1 row 2): one closure wraps each `?` the open takes
    /// on the file, as the blocked list's read wraps its path, so the
    /// daemon's `change-feed sidecar: {e}` reads `commits.log: {e}`.
    pub(super) fn open(dir: &Path, engine: &Engine, lines: &Lines) -> io::Result<CommitsLog> {
        let with_file = |e: io::Error| io::Error::new(e.kind(), format!("{SIDECAR_FILE}: {e}"));
        let path = dir.join(SIDECAR_FILE);
        say_a_compact_twin(lines, dir, SIDECAR_FILE);
        // Absent before the open creates it: begun afresh, said once the
        // region the walk re-covers is known. A look that cannot answer
        // counts as present, so it never says a loss it has not seen.
        let absent = !path.try_exists().unwrap_or(true);
        let mut file = open_sidecar(&path).map_err(with_file)?;
        let head = engine.kernel().current_seq().0;
        let window = resident_window(dir);
        let mut scanned = scan(&mut file, head, window).map_err(with_file)?;
        // The cut's class, judged before the cut: a crash tears the last
        // line, its newline unwritten, and that line is cut and gone; a
        // whole line that does not parse, or lies below the line before it,
        // is damage, and it and every line after it — testimony this file
        // alone holds — are kept beside the file, durably, before the cut.
        let cut_kept = if scanned.damaged {
            file.seek(SeekFrom::Start(scanned.valid_end)).map_err(with_file)?;
            let dropped = (&file).take(scanned.len - scanned.valid_end);
            Some(
                keep_dropped_lines(dir, SIDECAR_FILE, scanned.valid_end, dropped)
                    .map_err(with_file)?,
            )
        } else {
            None
        };
        let cut = if scanned.valid_end < scanned.len {
            // The torn (or corrupt) tail: truncate at the last whole record.
            // Anything the dropped lines described is re-covered as bare
            // positions by the walk below — said once the walk's own fence
            // `low` is known, which is the position trust ends at.
            file.set_len(scanned.valid_end).map_err(with_file)?;
            Some((scanned.valid_end, scanned.len, scanned.whole_after))
        } else {
            None
        };
        // Entries beyond this journal's head describe a different journal —
        // a live copy taken after its journal, an operator's swap, or the
        // testimony of commits a journal tail cut took — and are never
        // served. They lie at the file's end, the file being position-
        // ordered, and leave it by one truncation, kept beside it first; a
        // fence above the head describes that other journal too, and is the
        // half the truncation does not reach: left standing it makes
        // `(min_since, head]` empty, so `changes` refuses every position
        // this journal has — permanently, since nothing re-derives a fence
        // the file already holds — while `/events` announces them and
        // `/op-at` serves them. The file is rewritten without it, every
        // offset moving, and scanned again.
        let mut foreign_kept = None;
        let mut rewritten = false;
        let foreign_lines = scanned.foreign.as_ref().map(|f| f.lines);
        if let Some(foreign) = &scanned.foreign {
            let kept =
                keep_dropped_lines(dir, SIDECAR_FILE, foreign.first, foreign.bytes.as_slice())
                    .map_err(with_file)?;
            foreign_kept = Some(kept);
        }
        if scanned.stale_fence {
            file = purge_the_other_journals(dir, head).map_err(with_file)?;
            rewritten = true;
            scanned = scan(&mut file, head, window).map_err(with_file)?;
        } else if let Some(foreign) = &scanned.foreign {
            file.set_len(foreign.first).map_err(with_file)?;
        }
        let Scanned {
            len,
            window: entries,
            offsets,
            last_entry,
            count,
            bare,
            first_held,
            min_since,
            foreign,
            malformed,
            last_time,
            ..
        } = scanned;
        // The file's length as it stands: cut back to the first line past
        // the head where any stood and no rewrite ran.
        let len = match (&foreign, rewritten) {
            (Some(f), false) => f.first,
            _ => len,
        };
        let low = last_entry.unwrap_or(0).max(min_since);
        if let Some((valid_end, len, whole_after)) = cut {
            // Row 9 for this file: the last trusted position is the walk's
            // own fence, the highest surviving record at or below the head
            // (or the fence record), from which the cut part is re-derived —
            // whatever a torn line named; the whole lines past a damaged one
            // are counted, since their testimony no walk brings back.
            let cut = Cut { valid_end, len, trusted: low, first: None, whole_after };
            lines.say(Class::Failure, LogCutLine { cut, kept: cut_kept });
        }
        // The region, pending: what the file does not cover, `(low, head]`,
        // is the walk thread's to re-cover and its landing's to write — the
        // file takes no line here. `None` where the file covers the head.
        let pending = (head > low).then_some((low, head));
        // The floor, probed once for the attest store's cut line: it moves
        // nothing here.
        let floor_at_open = reclaim_floor(engine);
        // The window's lower edge: the fence's far side, or the span below
        // the head, whichever is higher.
        let resident_from =
            min_since.saturating_add(1).max(head.saturating_sub(window).saturating_add(1));
        let mut log = CommitsLog {
            file,
            dir: dir.to_path_buf(),
            entries,
            offsets,
            resident_from,
            window,
            resident_most: 0,
            count,
            bare,
            first_held,
            min_since,
            fence_owed: None,
            open_head: head,
            rewritten,
            floor_at_open,
            pending,
            last_time,
            len,
            lines: lines.clone(),
            stopped: None,
            #[cfg(any(test, feature = "test-hooks"))]
            fail_next_rewrite_past_rename: false,
        };
        log.entries = log.entries.split_off(&resident_from);
        log.offsets = log.offsets.split_off(&resident_from);
        log.resident_most = log.entries.len();
        if let (Some(foreign), Some(kept)) = (foreign_lines, foreign_kept) {
            // No marker holds this file's testimony, so no journal file is a
            // second copy of it: the kept file alone.
            let line = ForeignLinesLine {
                name: SIDECAR_FILE,
                foreign,
                head,
                what: "testimony",
                kept,
                journal_kept: Vec::new(),
            };
            lines.say(Class::Open, line);
        }
        // A file absent on a journal that holds commits: every retained
        // position comes back bare, its key and time lost — said, so a copy
        // that still holds them is known to be worth restoring. A fresh
        // board has no region, and says nothing.
        if let (true, Some((low, head))) = (absent, log.pending) {
            lines.say(Class::Failure, LogBegunAfreshLine { low, head });
        }
        // The malformed names, said once per open (`operations.md` §1.1 row
        // 11): the scan demoted each such line to a bare entry as it read it
        // — in memory where resident, and the feed's reader below the window
        // demotes the same lines the same way — and the file keeps the line
        // as it was read: this file is the sole surviving record of those
        // commits, and the open never rewrites a name away over what may be
        // one build's rendering.
        if let Some((positions, first)) = malformed {
            let case = MalformedCase::Demoted;
            let line = MalformedNamesLine { file: SIDECAR_FILE, positions, first, case };
            lines.say(Class::Failure, line);
        }
        Ok(log)
    }

    /// Returns the region pending, as a read.
    ///
    /// It is `(low, head]`, the positions the walk behind the listener has
    /// yet to land, or `None` — the `pending` field's card. `low` is covered,
    /// `head` the last of the region.
    pub(super) fn pending_region(&self) -> Option<(u64, u64)> {
        self.pending
    }

    /// Folds the walk into the resident entries and fences them.
    ///
    /// It is the landing's first half, and writes nothing (`operations.md`
    /// §3.3 step 2: "the walk accumulates in memory and lands by one whole
    /// rewrite of `commits.log` under the feed's lock"): the walk's
    /// boundaries enter the resident entries as bare positions carrying the
    /// journal's answer, beside every position recorded in memory while the
    /// region was pending, and the fence moves to the greater of the fence
    /// in force and the walk's own (`walk_min_since`, where the journal
    /// stopped answering), what lies at or below it dropped from the
    /// resident entries — never from the file, which keeps every line it
    /// holds: a line at or below the fence is served by no route from here
    /// on. The region is cleared: the resident entries are complete from
    /// here, and this uptime serves them. Answers the region taken,
    /// `(low, head]`, and the fence, which the feed trims its twins to;
    /// `None` where no region was pending, nothing folded. The file is
    /// [`CommitsLog::write_the_landing`]'s to write, which the feed calls
    /// once the files classified from it are written (`Feed::land` gives the
    /// order); the fence, where it moved, is written there ahead of the
    /// landed lines.
    pub(super) fn fold_the_walk(
        &mut self,
        walked: &[Walked],
        walk_min_since: Option<u64>,
    ) -> Option<((u64, u64), u64)> {
        let region = self.pending.take()?;
        let fence = self.min_since.max(walk_min_since.unwrap_or(0));
        if fence > self.min_since {
            // The walk's own fence stands at or above the region's lower
            // edge, which every line of the file lies at or below: the file's
            // lines are below the hole from here on, and what the file holds
            // above the fence is the positions recorded since the open.
            self.min_since = fence;
            self.fence_owed = Some(fence);
            let keep_from = fence.saturating_add(1);
            self.entries = self.entries.split_off(&keep_from);
            self.offsets = self.offsets.split_off(&keep_from);
            self.first_held = None;
            let held = self.entries.range(self.open_head.saturating_add(1)..);
            let (count, bare) = held.fold((0u64, 0u64), |(c, b), (_, meta)| {
                (c + 1, b + u64::from(matches!(meta, CommitMeta::Bare { .. })))
            });
            self.count = count;
            self.bare = bare;
        }
        for w in walked.iter().filter(|w| w.at > fence) {
            // A position the walk proved; never over one recorded meanwhile,
            // which cannot share it — the region lies at or below the head
            // at open, a record above it.
            if let std::collections::btree_map::Entry::Vacant(slot) = self.entries.entry(w.at) {
                slot.insert(CommitMeta::Bare { journal: w.journal.clone() });
                self.count += 1;
                self.bare += 1;
            }
        }
        if self.first_held.is_none() {
            self.first_held = self.entries.range(fence.saturating_add(1)..).next().map(|(k, _)| *k);
        }
        self.resident_most = self.resident_most.max(self.entries.len());
        Some((region, fence))
    }

    /// Writes the landing: the file rewritten with every line it holds and the landed ones.
    ///
    /// It is the landing's second half, through [`rewrite`]'s path: the
    /// file's lines copied verbatim, the fence line where the walk moved
    /// the fence, then every resident entry above `low` in position order —
    /// the walked boundaries and the positions held since the open — so file
    /// order is position order and every landed line's offset is assigned
    /// here. `low` is the lower edge of the region
    /// [`CommitsLog::fold_the_walk`] took.
    ///
    /// # Errors
    ///
    /// The rewrite's failure ([`RewriteFail`]), each side with its stop.
    /// Before its rename the old file stands whole — torn at `low`, the held
    /// positions unwritten — and this file stops at `low`, said once
    /// ([`LandingRefusedLine`]): a later append would raise the file's
    /// highest entry past the region, which the next open's walk could then
    /// never re-cover (the `stopped` field's card), where a stopped file
    /// keeps `low` where it was and the next open walks again from it. Past
    /// its rename the stop is [`CommitsLog::rewrite_whole`]'s, said there.
    pub(super) fn write_the_landing(&mut self, low: u64) -> Result<(), RewriteFail> {
        match self.rewrite_whole(low.saturating_add(1)) {
            Err(RewriteFail::BeforeRename(e)) => {
                let first = self.stopped.is_none();
                self.stopped = Some(low);
                if first {
                    self.lines.say(Class::Failure, LandingRefusedLine { low, error: &e });
                }
                Err(RewriteFail::BeforeRename(e))
            }
            answered => answered,
        }
    }

    /// Settles the resident window once a landing has written the file.
    ///
    /// Every position is on disk from here, so the window falls back to
    /// its span below the newest position ([`CommitsLog::evict`]), which
    /// the positions held while the region pended had kept it above.
    pub(super) fn settle_the_window(&mut self) {
        let newest = self.entries.keys().next_back().copied().unwrap_or(self.open_head);
        self.evict(newest.saturating_sub(self.window).saturating_add(1));
    }

    /// Rewrites the whole file: its lines copied, then the entries from `from` up.
    ///
    /// They are the file's own lines verbatim — every one it holds, the
    /// fence lines among them — then the fence line the walk owes, where
    /// one does, then the resident entries at or above `from`, each new to
    /// the file ([`rewrite`]). The handle, the new lines' offsets and the
    /// length move with the file; no copied line's offset moves.
    ///
    /// # Errors
    ///
    /// [`RewriteFail::BeforeRename`] where the rewrite failed before its
    /// rename; [`RewriteFail::PastRename`] where it failed past it — the
    /// stop then set at the last entry the new file holds (its fence, where it
    /// holds none), the position the next open's walk starts above, and so
    /// the one the stop's line and the standing line name.
    fn rewrite_whole(&mut self, from: u64) -> Result<(), RewriteFail> {
        #[cfg(any(test, feature = "test-hooks"))]
        let fail_past_rename = std::mem::take(&mut self.fail_next_rewrite_past_rename);
        #[cfg(not(any(test, feature = "test-hooks")))]
        let fail_past_rename = false;
        let new: Vec<(u64, Vec<u8>)> =
            self.entries.range(from..).map(|(at, meta)| (*at, entry_line(*at, meta))).collect();
        match rewrite(&self.dir, self.fence_owed, &new, fail_past_rename) {
            Ok((file, offsets, len)) => {
                self.file = file;
                self.offsets.extend(offsets);
                self.len = len;
                self.fence_owed = None;
            }
            Err(RewriteFail::PastRename(e)) => {
                // Said where the stop is set, not where it is set again: a
                // stopped log is rewritten at the next landing, its stop
                // moving to that rewrite's last entry in silence. The new
                // file is in place, so no fence is owed.
                let first = self.stopped.is_none();
                let last = self.entries.keys().next_back().copied().unwrap_or(self.min_since);
                self.stopped = Some(last);
                self.fence_owed = None;
                if first {
                    self.lines.say(
                        Class::Failure,
                        format_args!(
                            "commits.log rewrite failed past its rename: {}; this file takes no \
                             further line, so the next open re-derives above position {last} as \
                             bare entries; every write until then is held in memory alone, its \
                             key and its time lost at that open — restart soon",
                            IoCause(&e)
                        ),
                    );
                }
                return Err(RewriteFail::PastRename(e));
            }
            Err(before) => return Err(before),
        }
        Ok(())
    }

    /// Moves the window's lower edge up to `target`, dropping what lies below.
    ///
    /// It is every record's tail and the landing's settling: the window
    /// holds its span below the newest position and no more. While the
    /// walk's region pends the edge never passes the lowest position held
    /// in memory alone ([`Recorded::Held`]) — such a line lives nowhere else
    /// until the landing writes it — so the window may outgrow its span by
    /// the writes a long walk admits, which the landing settles. The edge
    /// never recedes.
    fn evict(&mut self, target: u64) {
        let target = match self.pending {
            Some(_) => self
                .entries
                .range(self.open_head.saturating_add(1)..)
                .next()
                .map_or(target, |(held, _)| target.min(*held)),
            None => target,
        };
        if target > self.resident_from {
            self.resident_from = target;
            self.entries = self.entries.split_off(&target);
            self.offsets = self.offsets.split_off(&target);
        }
    }

    /// Records one committed write at ack time.
    ///
    /// It answers `Some` — [`Recorded`]: the [`LineOffset`] the line landed
    /// at, or that the line is held — when this call recorded a new
    /// position, `None` when it declined. Idempotent against replayed acks: a
    /// position at or below the open-time head, or one already recorded this
    /// uptime, is an ack for an old commit (idempotency-memo hit, `emit`
    /// incumbent) — re-recording it would invent a time.
    ///
    /// **While the region is pending** (`pending`'s card; `operations.md`
    /// §3.3 step 2, "the walk accumulates in memory and lands by one whole
    /// rewrite"): the position enters the resident entries and not the file,
    /// which takes no line until the landing writes it at its offset among
    /// the rest, in position order. This uptime answers it in full.
    ///
    /// **The cost**, stated: a crash before the landing loses the line — the
    /// file is as the open found it — and the next open's walk re-covers the
    /// position bare, classified from the journal (PUB-6.45), its key and
    /// time null and its op the journal's where it names one; the attest
    /// store's line for it is appended and synced at once regardless
    /// (`feed/attest.rs`, SO-I5 (d)), the store's file being its own.
    ///
    /// **Caller contract** — call only while holding the daemon's
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
    /// stays [`crate::commits::Commits::commit_recorded`]'s — the step
    /// both of the write path's doors run: it runs the execute and this
    /// record under one guard, so the position recorded is the one that
    /// write just committed.
    ///
    /// The clamp against `last_time` below covers the other half of the
    /// monotonicity — a wall clock that steps backwards — and that one *is*
    /// this file's own obligation rather than the caller's.
    ///
    /// The offset returned is the one the line landed at, except past a
    /// failed append: [`CommitsLog::stopped`] freezes `len`, so every later
    /// offset names a line this file does not hold. No read of this build
    /// seeks by an offset — the reads below the window seek by position
    /// (`feed/window.rs`) — and the next open scans `commits.log` from disk
    /// and learns the offsets afresh, so `feed-offsets.log` fails its
    /// agreement test and is re-derived whole: the wrong offsets are latent
    /// for the uptime and self-healing after it.
    // Six fields of one line beside the guard, each the write path's own
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
        Some(self.admit(at, meta))
    }

    /// Records a bare entry at `at` for a write that committed, then panicked.
    ///
    /// It is recorded at once by the write path's door under the guard it
    /// committed under (`operations.md` §4 row 34) — [`CommitsLog::record`]'s
    /// contract, its idempotency and its disposition — in the form the walk's
    /// landing writes ([`CommitMeta::Bare`]: no op, docs, key or time, the
    /// journal's answer beside the position), so the next open reads the line
    /// as it reads a landed boundary and walks nothing for it. No time is
    /// stamped: the clamp does not move, and [`CommitsLog::head_time`]
    /// answers `None` while this is the head.
    pub(super) fn record_bare(
        &mut self,
        _serial: &SerialGuard<'_>,
        at: u64,
        journal: JournalTerms,
    ) -> Option<Recorded> {
        if at <= self.open_head || self.entries.contains_key(&at) {
            return None;
        }
        Some(self.admit(at, CommitMeta::Bare { journal }))
    }

    /// Admits an entry: the two record paths' one tail.
    ///
    /// The entry goes into the resident window and, the region pending,
    /// nowhere else ([`Recorded::Held`]); otherwise its line is appended at
    /// the offset the file's length names, under the stop's rule. Either way
    /// it is counted, it is the first line held where none was, and the
    /// window's edge moves up behind it ([`CommitsLog::evict`]).
    fn admit(&mut self, at: u64, meta: CommitMeta) -> Recorded {
        self.count += 1;
        self.bare += u64::from(matches!(meta, CommitMeta::Bare { .. }));
        self.first_held.get_or_insert(at);
        if self.pending.is_some() {
            // The region pending: the entry alone, the file untouched until
            // the landing's one rewrite writes this line at its offset.
            self.entries.insert(at, meta);
            self.resident_most = self.resident_most.max(self.entries.len());
            self.evict(at.saturating_sub(self.window).saturating_add(1));
            return Recorded::Held;
        }
        let offset = LineOffset(self.len);
        // Testimony must not fail the op: the write is committed and the
        // ack is owed regardless; a lost append answers bare after restart,
        // which [`CommitsLog::stopped`] is what makes true — the failure
        // stops this file, so the next open's walk starts below the gap
        // instead of above it. The failure is reported through the classed
        // door (`operations.md` §1.1 row 31) — once, since the stop takes
        // every later line — which states why a notice may not panic. The
        // line names what the stop costs until the restart, and the act
        // owed before it, since the restart's open writes this file.
        let line = entry_line(at, &meta);
        if self.stopped.is_none() {
            match self.file.write_all(&line) {
                Ok(()) => self.len += line.len() as u64,
                Err(e) => {
                    self.stopped = Some(at);
                    let cause = IoCause(&e);
                    self.lines.say(
                        Class::Failure,
                        format_args!(
                            "commits.log append failed at position {at}: {cause}; this file \
                             takes no further line, so the next open re-derives from {at} as \
                             bare entries; every write until then is held in memory alone, its \
                             key and its time lost at that open — restart soon{}",
                            cause.before_the_restart()
                        ),
                    );
                }
            }
        }
        self.entries.insert(at, meta);
        self.offsets.insert(at, offset);
        self.resident_most = self.resident_most.max(self.entries.len());
        self.evict(at.saturating_sub(self.window).saturating_add(1));
        Recorded::Appended(offset)
    }

    /// Returns the head position's recorded wall-clock time.
    ///
    /// It is `None` when the head's record is bare (lost, or written before
    /// the feature), nothing is recorded at all, or the head's record lies
    /// in the region the walk has yet to land (no position above it recorded
    /// since the open): an older surviving record is not offered in its
    /// place.
    ///
    /// Deliberately not "the newest recorded time anywhere in the feed":
    /// this answers for the head, so an older surviving record is not
    /// offered in its place, any more than a bare position's fields are
    /// invented.
    ///
    /// What it reads is the last recorded position's time, which is the
    /// head's because every commit is recorded: every commit this daemon
    /// makes rides [`crate::commits::Commits::commit_recorded`], which
    /// records inside the guard its caller holds across the commit. That
    /// premise is this file's reliance, not its check — a `CommitsLog` never
    /// learns the live head — and one state breaks it, transiently: any
    /// in-flight write. `/health` reads this and the log position
    /// independently, no lock held across the two, so its pair may straddle
    /// one commit and report the previous position's time beside the new
    /// position's number. The next call answers the head again.
    ///
    /// A panic between M10's commit and this file's append would break it
    /// permanently; it is caught at the write path's door, which records the
    /// position bare at once ([`CommitsLog::record_bare`]), so this answers
    /// `None` for it honestly from that moment, and the next open reads the
    /// same line.
    pub(crate) fn head_time(&self) -> Option<u64> {
        let (at, meta) = self.entries.iter().next_back()?;
        if self.pending.is_some_and(|(_, head)| *at <= head) {
            return None;
        }
        meta.time()
    }

    /// Returns whether this log can answer a `/changes` query at `since`.
    ///
    /// The query is fenced at `since`; coverage is complete over `(min_since,
    /// head]` — the region pending aside, until the walk lands it — so a
    /// `since` at or above that fence is admissible and one below it reaches
    /// into what the walk could not enumerate.
    ///
    /// The predicate beside [`CommitsLog::floor`]'s datum — the two are one
    /// sentence, and a caller that refuses a query asks for both rather than
    /// comparing against a fence whose distinction from the wire's `floor`
    /// this file spends two doc comments keeping.
    pub(crate) fn admits_since(&self, since: u64) -> bool {
        since >= self.min_since
    }

    /// Returns the oldest position still answerable.
    ///
    /// It is the wire's `floor` (wire.md §Reading history), which is the
    /// first line the file holds above the fence [`CommitsLog::admits_since`]
    /// tests and not that number itself — `1` on a board that never
    /// compacted and never lost a line. The two are one apart by
    /// definition, keeping them apart is this file's job, and so is the step
    /// between them: a caller rendering `floor` asks rather than deriving it
    /// from this type's own state. `None` where nothing above the fence
    /// survives.
    ///
    /// **While the walk's region is pending**, the region's first position
    /// above the fence — `max(low, min_since) + 1` — is the floor where it
    /// lies below the first line held: the region's boundaries are not yet
    /// known, and a floor named above them would send a reader re-asking
    /// from it past the region, which the landing then serves to nobody.
    pub(crate) fn floor(&self) -> Option<u64> {
        let covered = self.first_held.filter(|&first| first > self.min_since);
        let region = self
            .pending
            .filter(|&(_, head)| head > self.min_since)
            .map(|(low, _)| low.max(self.min_since).saturating_add(1));
        match (covered, region) {
            (Some(c), Some(r)) => Some(c.min(r)),
            (c, r) => c.or(r),
        }
    }

    /// Returns the hole the file opened with, where one stands.
    ///
    /// It is the fence and the floor above it ([`CommitsLog::floor`]) where
    /// the fence stands above genesis: the lines at or below it an earlier
    /// build's compaction dropped, or a walk the journal refused could not
    /// re-cover — what the feed's open says once (`OpenHoleLine`). `None` on
    /// a board whose fence is genesis, which holds every line from its first.
    pub(crate) fn hole(&self) -> Option<(u64, Option<u64>)> {
        (self.min_since > 0).then(|| (self.min_since, self.floor()))
    }

    /// Returns every resident entry above `position`, in position order.
    ///
    /// It is the window's half of what the published head writer's resume
    /// reads (`crate::commits::head`; `Feed::entries_above` adds the lines
    /// below the window from the file): the commits landed since the head
    /// that named `position`, and among them the head's own commits,
    /// testifying `"system"`, whose recorded `time` is the head's. Testimony
    /// read at a gate to decide when, never a fold input (D1): a bare entry
    /// answers no time and no key, and a rewritten one moves a head's timing
    /// within the bounds the triggers already allow. Cloned, once at open —
    /// at most the window — so the writer holds no borrow of this file.
    pub(crate) fn entries_above(&self, position: u64) -> Vec<(u64, CommitMeta)> {
        self.entries
            .range(position.saturating_add(1)..)
            .map(|(at, meta)| (*at, meta.clone()))
            .collect()
    }

    /// Returns the resident window's entries, in position order.
    ///
    /// They are every enumerable position at or above
    /// [`CommitsLog::resident_from`] — read-only outside this file, because
    /// the invariant the `entries` field's card states (a `Recorded` entry's
    /// document names all parse, the open's scan having demoted the rest) is
    /// this file's to keep and the feed's to rely on: it classifies by those
    /// names with no second check of its own. The lines below the window the
    /// feed reads from the file ([`parse_line`] and [`demoted`] are its
    /// parser there).
    pub(crate) fn entries(&self) -> &BTreeMap<u64, CommitMeta> {
        &self.entries
    }

    /// Returns the lowest position the resident window holds.
    ///
    /// Every entry the file holds at or above it is resident
    /// ([`CommitsLog::entries`]); the feed reads the rest from the file, and
    /// trims its twins to it as it rises (`resident_from`'s card).
    pub(crate) fn resident_from(&self) -> u64 {
        self.resident_from
    }

    /// Returns how many entries the window holds, and the most it has held.
    ///
    /// The checkpoint thread's landing line carries both beside the window's
    /// span, so a window that outgrows it — the writes a long walk held — is
    /// told from one that holds its span.
    pub(crate) fn resident_figures(&self) -> (usize, usize) {
        (self.entries.len(), self.resident_most)
    }

    /// Returns the fence: the smallest admissible `since`.
    ///
    /// It is [`CommitsLog::min_since`]'s number, for the attest store's open,
    /// which writes back a rebuilt slot for every position above it the
    /// journal lists; a caller refusing a query asks
    /// [`CommitsLog::admits_since`] instead.
    pub(crate) fn fence(&self) -> u64 {
        self.min_since
    }

    /// Returns how many entries the file holds above the fence, and the bare among them.
    ///
    /// They are the open's scan's counts and every record since, resident or
    /// not — the figures the feed's open line carries.
    pub(crate) fn counts(&self) -> (u64, u64) {
        (self.count, self.bare)
    }

    /// Returns the file's length in bytes, as this log last wrote it.
    ///
    /// It is the offset the next appended line lands at — read for the
    /// checkpoint thread's landing line, where the file's growth is the
    /// operator's sizing figure.
    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    /// Returns the journal head at open.
    ///
    /// It is the fence [`CommitsLog::record`] declines at or below —
    /// read-only outside this file.
    pub(crate) fn open_head(&self) -> u64 {
        self.open_head
    }

    /// Returns whether this open's purge rewrote the file.
    ///
    /// Read at the feed's open: then every offset moved and the derived
    /// offset array is re-derived from the file.
    pub(crate) fn rewritten(&self) -> bool {
        self.rewritten
    }

    /// Returns the reclaim floor this open probed.
    ///
    /// It is `None` where the journal still answered genesis, or refused the
    /// probe other than as reclaimed ([`reclaim_floor`]).
    pub(crate) fn floor_at_open(&self) -> Option<u64> {
        self.floor_at_open
    }
}

/// Returns the reclaim floor: the oldest position the journal can still answer.
///
/// It is `None` when the journal can still answer genesis (nothing has been
/// reclaimed). The feed's one probe of it, at the open, for the attest
/// store's cut line — which side of the floor a cut reached — and for
/// nothing else: the floor bounds the journal's STATES, which `/op-at`
/// rebuilds, and moves no fence of the feed's, whose files are kept whole
/// (the module doc).
///
/// Asked by probing position 0 through the same public replay everything
/// else here uses. The probe is free either way: genesis is the base a
/// position-0 question selects, so a healthy store folds no journal to
/// answer it, and a reclaimed store refuses from the checkpoint listing
/// before touching a segment. Every other refusal — corrupt, I/O,
/// unjournaled — reports no floor.
pub(super) fn reclaim_floor(engine: &Engine) -> Option<u64> {
    match engine.kernel().world_at(Seq(0)) {
        Err(HistoryError::Reclaimed { floor, .. }) => Some(floor.map(|f| f.0).unwrap_or(0)),
        _ => None,
    }
}

/// Returns the resident window's span in positions for the board at `dir`.
///
/// It is `limits::FEED_RESIDENT_WINDOW`, or the figure the test seam set
/// for this directory (`set_feed_resident_window`, the test seam) where one stands —
/// read once at each open.
fn resident_window(dir: &Path) -> u64 {
    #[cfg(any(test, feature = "test-hooks"))]
    {
        if let Some(&set) = FEED_RESIDENT_WINDOW_SEAM.lock().get(dir) {
            if set > 0 {
                return set;
            }
        }
    }
    #[cfg(not(any(test, feature = "test-hooks")))]
    let _ = dir;
    FEED_RESIDENT_WINDOW
}

/// The test seam: the resident window's span, keyed by the board's directory.
///
/// Keyed by directory as the registry seed's seams are (`registry.rs`):
/// the window is read inside the open, before any daemon exists to be
/// asked, and one test process opens many boards at once, so a window set
/// for one board touches no other board's feed.
#[cfg(any(test, feature = "test-hooks"))]
static FEED_RESIDENT_WINDOW_SEAM: Mutex<BTreeMap<PathBuf, u64>> = Mutex::new(BTreeMap::new());

/// The test seam: moves the resident window to `positions` for the board at `dir`.
///
/// A suite sets it small before it opens the board, so the pages below the
/// window are reached on a board of a few thousand positions; zero restores
/// the constant. The path is matched as given to the open. Not a stable API.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub fn set_feed_resident_window(dir: &Path, positions: u64) {
    FEED_RESIDENT_WINDOW_SEAM.lock().insert(dir.to_path_buf(), positions);
}

/// The cut a feed file's replay made (`operations.md` §1.1 row 9).
///
/// Trust ended at a line that was torn or did not parse, and the file was
/// truncated there. Answered by each replay to its caller — `commits.log`'s
/// own open and `LineFile::open` for the four derived files and the attest
/// store — which words it with the case that is its own: a derived file's
/// cut part is re-derived, `commits.log`'s as bare entries, and the attest
/// store's lies on one side of the reclaim floor. [`CutHead`] renders the
/// head every one of those lines opens with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Cut {
    /// The byte trust ends at, where the file was truncated.
    ///
    /// It is the end of the last whole line that parsed.
    pub valid_end: u64,
    /// The file's length before the cut.
    pub len: u64,
    /// The last trusted position: the coverage the scan reached before the cut.
    ///
    /// It is the highest position the surviving lines reach at or below the
    /// head, an entry's or a fence's — and so the position the cut part is
    /// re-derived from. Every cut line's position lies above it, the files
    /// being position-ordered.
    pub trusted: u64,
    /// The position the first cut line names, where it can be read.
    ///
    /// It is read where the cut is one torn line at the file's end — the
    /// tear a crash leaves in a line's own append — whose `at` member stands
    /// whole, above `trusted` and at or below the head. `None` otherwise: a
    /// line ended by its newline that does not parse is damage, and its own
    /// digits are no witness. The attest store reads it, its case turning on
    /// which side of the reclaim floor the cut lines lie; `commits.log`'s
    /// own open does not, its cut part re-derived whatever it named.
    pub first: Option<u64>,
    /// The whole entry lines the cut takes with it, at or below the head.
    ///
    /// They are the lines after a damaged one, read before the truncation;
    /// `None` where the cut takes none. The attest store's lost endings and
    /// `commits.log`'s cut line name them: what they held, a copy alone
    /// holds now.
    pub whole_after: Option<EntryLines>,
}

impl Cut {
    /// Returns the bytes after the trusted end: what was cut.
    fn after(&self) -> u64 {
        self.len.saturating_sub(self.valid_end)
    }
}

/// The name of a file an open kept dropped lines in (`operations.md` §3.6).
///
/// It is `{file}.cut-{byte}` beside the file, in the data directory, or
/// `{file}.cut-{byte}.{k}` where that name and the `k − 1` before it
/// already stand — the kernel's own spelling for a journal tail it keeps, so
/// every kept file in the directory is found by one listing. `byte` is where
/// in the file the dropped lines began: the byte trust ended at, for a cut,
/// and the first line above the journal's head, for a purge. Rendered beside
/// the file's name ([`KeptName::of`]); `Copy`, so the line types that carry
/// it stay plain values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct KeptName {
    /// The byte of the file the dropped lines began at.
    pub byte: u64,
    /// The name's suffix: `0` for the first name, `k` for `….{k}`.
    pub k: u64,
}

impl KeptName {
    /// Returns the kept file's name beside `file`.
    pub(super) fn of(self, file: &str) -> String {
        match self.k {
            0 => format!("{file}.cut-{}", self.byte),
            k => format!("{file}.cut-{}.{k}", self.byte),
        }
    }
}

/// Keeps the lines an open drops from `file` beside it, before they go.
///
/// It is the one keep every line file's open takes — `commits.log`'s and
/// the derived files' (`LineFile`, `feed/derived.rs`) — for what it drops in class B
/// (`operations.md` §3.6): a whole line that does not parse and every line
/// after it, which a crash never leaves, and the entry lines above the
/// journal's head, another journal's. A crash's torn last line is cut and
/// gone. The bytes are written whole to the first of [`KeptName`]'s names
/// that stands empty — never over a standing name, whatever it holds, so a
/// crash between the keep and the drop leaves the first kept file beside the
/// next open's — born `0600`, synced, and the directory synced after, so
/// the bytes are durable before the cut or the rewrite that drops them
/// runs. `dropped` is the bytes, read through: a slice of a file read whole,
/// or the file itself from the byte on. Answers the name; the line that
/// says the drop names it ([`LogCutLine`], [`ForeignLinesLine`]).
///
/// # Errors
///
/// The kept file's creation, write or sync, or the directory's sync,
/// failing, each named `{kept}: {act}: {cause}` — fatal at the open, as
/// every failure there is, so no drop runs over a keep that did not.
pub(super) fn keep_dropped_lines(
    dir: &Path,
    file: &str,
    byte: u64,
    mut dropped: impl io::Read,
) -> io::Result<KeptName> {
    let mut kept = KeptName { byte, k: 0 };
    let (mut out, name) = loop {
        let name = kept.of(file);
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(dir.join(&name)) {
            Ok(out) => break (out, name),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => kept.k += 1,
            Err(e) => return Err(io::Error::new(e.kind(), format!("{name}: create: {e}"))),
        }
    };
    let named = |act: &str, e: io::Error| io::Error::new(e.kind(), format!("{name}: {act}: {e}"));
    io::copy(&mut dropped, &mut out).map_err(|e| named("write", e))?;
    out.sync_all().map_err(|e| named("fsync", e))?;
    drop(out);
    #[cfg(unix)]
    File::open(dir).and_then(|d| d.sync_all()).map_err(|e| named("fsync the directory of", e))?;
    Ok(kept)
}

/// Entry lines a feed file's replay dropped, by count and position.
///
/// A replay answers two such runs: the lines past the head this open read,
/// another journal's (`LineFile::open`'s `Replayed`, and `commits.log`'s
/// own open) — a live copy taken after its journal holds them, and after a
/// journal tail cut that took acknowledged commits they are the cut commits'
/// own, kept beside the file ([`keep_dropped_lines`]) and said by the two
/// files whose lines no open re-derives, `commits.log`'s testimony and
/// `feed-attest.log`'s signatures ([`ForeignLinesLine`]); and the whole
/// lines a cut takes with it ([`Cut`]'s `whole_after`), kept the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EntryLines {
    /// How many entry lines were dropped.
    pub lines: usize,
    /// The lowest position they named.
    pub first: u64,
    /// The highest position they named.
    pub last: u64,
}

impl EntryLines {
    /// Returns the report `held` with one more dropped line, at `at`.
    pub(super) fn with(held: Option<EntryLines>, at: u64) -> EntryLines {
        match held {
            None => EntryLines { lines: 1, first: at, last: at },
            Some(f) => {
                EntryLines { lines: f.lines + 1, first: f.first.min(at), last: f.last.max(at) }
            }
        }
    }
}

/// The open's line for the lines past the head it dropped.
///
/// The words: `{file} held {n} lines past the journal's head at position
/// {h} (positions {a}–{b}): dropped and kept in {kept} — a live copy taken
/// after its journal holds them; after a journal tail cut that took
/// acknowledged commits they are the cut commits' {what}`, and, for the
/// attest store where the journal's own open kept its cut tail at this
/// start, `, whose markers the journal's kept file {seg} holds too` — the
/// second copy of the signatures, never of `commits.log`'s testimony, which
/// no marker carries. Never "a copy taken before this open still holds
/// them": the open keeps what it drops. A pure value, pinned by
/// `to_string()` in the unit suite; emitted under `Class::Open` by
/// `commits.log`'s open and the attest store's.
pub(super) struct ForeignLinesLine {
    pub name: &'static str,
    pub foreign: EntryLines,
    pub head: u64,
    /// What the lines carry: `testimony` or `signatures`.
    pub what: &'static str,
    /// The file the dropped lines were kept in, beside this one.
    pub kept: KeptName,
    /// The files the journal's open kept its cut tail in at this start.
    ///
    /// Empty where it kept none this start, and for `commits.log`, whose
    /// lines no marker holds a copy of.
    pub journal_kept: Vec<String>,
}

impl std::fmt::Display for ForeignLinesLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let EntryLines { lines, first, last } = self.foreign;
        write!(
            f,
            "{} held {lines} lines past the journal's head at position {} (positions \
             {first}–{last}): dropped and kept in {} — a live copy taken after its journal \
             holds them; after a journal tail cut that took acknowledged commits they are the \
             cut commits' {}",
            self.name,
            self.head,
            self.kept.of(self.name),
            self.what
        )?;
        match self.journal_kept.as_slice() {
            [] => Ok(()),
            [one] => write!(f, ", whose markers the journal's kept file {one} holds too"),
            [first @ .., last] => write!(
                f,
                ", whose markers the journal's kept files {} and {last} hold too",
                first.join(", ")
            ),
        }
    }
}

/// An I/O failure as the operator stream words its cause.
///
/// A full volume reads `the volume is full ({e})`, the words the
/// checkpoint's line and the blob store's use (`operations.md` §1.1 m1);
/// every other kind reads as the error's own words. Every feed file's
/// failure line renders its cause through this.
pub(super) struct IoCause<'a>(pub &'a io::Error);

impl IoCause<'_> {
    /// Returns whether the cause is a full volume.
    pub(super) fn is_full(&self) -> bool {
        self.0.kind() == io::ErrorKind::StorageFull
    }

    /// Returns the act a stopped file's line ends with, ahead of the restart.
    ///
    /// The restart that re-derives the file writes it first, so where the
    /// cause still stands that open refuses and reads stop with it: on a full
    /// volume the act is room, and for every other cause the volume, its
    /// device and the board user's quota, checked first.
    pub(super) fn before_the_restart(&self) -> &'static str {
        if self.is_full() {
            "; free room before that restart: its open writes this file"
        } else {
            "; check the volume, its device and the board user's quota before that restart: its \
             open writes this file"
        }
    }
}

impl std::fmt::Display for IoCause<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_full() {
            write!(f, "the volume is full ({})", self.0)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// Row 9's head: the words every cut line opens with.
///
/// They are `{file}: trust ends at position {c} (byte {n} of {len}); the
/// {k} bytes after it are cut`, each caller adding its own case after a
/// semicolon. A pure value, pinned by `to_string()` in the unit suite.
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

/// Row 9 for `commits.log`: the head, then this file's own case.
///
/// The cut part is re-derived as bare entries, by the walk behind the
/// listener from the last trusted position (the file's own recovery, which
/// line 31 names for a failed append). Where trust ended at a damaged line
/// and not a torn one — a whole line that does not parse, which no crash
/// leaves — the cut bytes were kept beside the file first
/// ([`keep_dropped_lines`]), and the line names the kept file after the
/// head, `, kept in {kept}`, and goes on with the whole lines the cut took
/// with it: `; the cut took {n} whole lines with it, positions {a}–{b}:
/// their keys and times are LOST to the feed and stand in {kept} alone` —
/// their testimony is held by no file the open reads, and the walk brings
/// each back bare. Emitted under `Class::Failure` by [`CommitsLog::open`].
pub(super) struct LogCutLine {
    pub cut: Cut,
    /// The file the cut bytes were kept in: a damaged line's cut, never a
    /// torn line's.
    pub kept: Option<KeptName>,
}

impl std::fmt::Display for LogCutLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", CutHead { name: SIDECAR_FILE, cut: self.cut })?;
        if let Some(kept) = self.kept {
            write!(f, ", kept in {}", kept.of(SIDECAR_FILE))?;
        }
        f.write_str("; the cut part is re-derived as bare entries")?;
        match (self.cut.whole_after, self.kept) {
            (Some(EntryLines { lines, first, last }), Some(kept)) => write!(
                f,
                "; the cut took {lines} whole lines with it, positions {first}–{last}: their keys \
                 and times are LOST to the feed and stand in {} alone",
                kept.of(SIDECAR_FILE)
            ),
            (Some(EntryLines { lines, first, last }), None) => write!(
                f,
                "; the cut took {lines} whole lines with it, positions {first}–{last}: their keys \
                 and times are LOST unless the board directory's backup is restored"
            ),
            (None, _) => Ok(()),
        }
    }
}

/// `commits.log` absent at an open whose journal holds commits.
///
/// The words: `commits.log was absent at this open and is begun afresh:
/// every position in ({low}, {head}] is walked from the journal as a bare
/// entry, its op recovered where the journal names it — its key and its time
/// are LOST unless the board directory's backup is restored`. The file is
/// the only record of a commit's testimony, so its absence is a loss the
/// walk cannot make good; a fresh board's open walks nothing and says
/// nothing. A pure value, pinned by `to_string()` in the unit suite; emitted
/// under `Class::Failure` by [`CommitsLog::open`].
pub(super) struct LogBegunAfreshLine {
    pub low: u64,
    pub head: u64,
}

impl std::fmt::Display for LogBegunAfreshLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{SIDECAR_FILE} was absent at this open and is begun afresh: every position in ({}, \
             {}] is walked from the journal as a bare entry, its op recovered where the journal \
             names it — its key and its time are LOST unless the board directory's backup is \
             restored",
            self.low, self.head
        )
    }
}

/// A rewrite's temp file found at an open (`operations.md` §1.1 m8).
///
/// The words: `{file}.compact stands ({bytes} bytes): a rewrite cut short
/// before its rename left it, {file} as it stood before that rewrite; its
/// next rewrite overwrites it`. A pure value, pinned by `to_string()` in the
/// unit suite; emitted under `Class::Open` by [`say_a_compact_twin`].
pub(super) struct CompactTwinLine {
    pub name: &'static str,
    pub bytes: u64,
}

impl std::fmt::Display for CompactTwinLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self.name;
        write!(
            f,
            "{name}.compact stands ({} bytes): a rewrite cut short before its rename left it, \
             {name} as it stood before that rewrite; its next rewrite overwrites it",
            self.bytes
        )
    }
}

/// Says `{name}.compact` where one stands in `dir`, once, at an open.
///
/// A rewrite writes the temp whole and renames it over the file, the rename
/// its one atomic step, so a temp left standing is a rewrite cut short — by
/// a crash, or by a failure the stream said at the time — and the file
/// beside it is the whole one before that rewrite. Every open of a feed file
/// asks — `commits.log`'s and `LineFile::open`'s — so the directory holds no
/// file its lines never named. A directory on the name is no rewrite's, and
/// is passed over.
pub(super) fn say_a_compact_twin(lines: &Lines, dir: &Path, name: &'static str) {
    let path = dir.join(format!("{name}.compact"));
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.is_file() {
            lines.say(Class::Open, CompactTwinLine { name, bytes: meta.len() });
        }
    }
}

/// The walk's first line (`operations.md` §1.1 m15).
///
/// The words: `commits.log covers to position {c}; walking {b} boundaries to
/// position {h}` — `{c}` the region's lower edge, covered; `{b}` the
/// boundaries the walk's list holds ([`list_boundaries`]): those the
/// kernel's one scan listed above it at or below `{h}`, the head at open —
/// or, where the journal refused below it, those from the floor up, or the
/// head alone. A pure value, pinned by `to_string()` in the unit suite;
/// emitted under `Class::Open` by the feed's `walk_and_land` at the walk's
/// start, before any boundary is proved and ahead of the hold.
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

/// The walk's cadence line (m15), the walk's tell from a hang.
///
/// The words: `the walk at position {p} of {h}, boundary {i} of {b}, {d} ms
/// in` — `{p}` the boundary last proved, `{h}` the head at open, `{i}` that
/// boundary's place in the walk's list and `{b}` the list's length, the
/// count the `open:` line named — boundaries lie unevenly across positions,
/// so `{i}` is what says how many reconstructions remain — and `{d}` the
/// time since the walk began, in milliseconds as the stream spells a
/// duration. A pure value, pinned by `to_string()`; emitted under
/// `Class::Progress` by [`reconstruct`] as a boundary is walked, once
/// [`FEED_WALK_PROGRESS_BOUNDARIES`] boundaries are walked since the last
/// line or [`FEED_WALK_PROGRESS_INTERVAL`] has passed, whichever comes first
/// — or the figures the test seam set in their place ([`WalkControl`]).
pub(super) struct WalkProgressLine {
    pub position: u64,
    pub head: u64,
    /// The boundary's place in the walk's list, counted from 1.
    pub boundary: usize,
    /// The boundaries the walk's list holds.
    pub boundaries: usize,
    pub elapsed_ms: u128,
}

impl std::fmt::Display for WalkProgressLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the walk at position {} of {}, boundary {} of {}, {} ms in",
            self.position, self.head, self.boundary, self.boundaries, self.elapsed_ms
        )
    }
}

/// The walk's landing line (m15), naming its file and its region.
///
/// The words: `commits.log re-covered positions ({low}, {head}]: {b}
/// boundaries walked, {k} of them unclassifiable and served to every class,
/// in {d} ms; the landing held the change feed's lock {r} ms` — `{b}` the
/// boundaries the walk proved, `{k}` those it could not classify (the world
/// below them unanswerable: served to every class, the module doc's
/// residue), `{d}` from the walk's start to the landing's rewrite and `{r}`
/// the landing's own span under the lock every write's record and every
/// page waits on, in milliseconds. Where the landing's fence stands above
/// the region's lower edge it adds `; the fence stands at position {f}:
/// /changes answers 410 history_reclaimed for every since below it`, and
/// where its rewrite failed before the rename the region is re-covered `in
/// memory alone`. A pure value, pinned by `to_string()`; emitted under
/// `Class::Landing` by the feed's landing.
pub(super) struct WalkLandingLine {
    pub low: u64,
    pub head: u64,
    pub walked: usize,
    pub unclassified: usize,
    pub elapsed_ms: u128,
    pub held_ms: u128,
    /// The landing's fence, where it stands above `low`.
    pub fence: Option<u64>,
    /// Whether the rewrite failed before its rename, the file unwritten.
    pub in_memory_alone: bool,
}

impl std::fmt::Display for WalkLandingLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "commits.log re-covered positions ({}, {}]{}: {} boundaries walked, {} of them \
             unclassifiable and served to every class, in {} ms; the landing held the change \
             feed's lock {} ms",
            self.low,
            self.head,
            if self.in_memory_alone { " in memory alone" } else { "" },
            self.walked,
            self.unclassified,
            self.elapsed_ms,
            self.held_ms
        )?;
        match self.fence {
            Some(fence) => write!(
                f,
                "; the fence stands at position {fence}: /changes answers 410 \
                 history_reclaimed for every since below it"
            ),
            None => Ok(()),
        }
    }
}

/// The walk's refusal by the journal (`operations.md` §3.3 step 2).
///
/// The words: `commits.log's walk: the journal refused position {at}
/// ({account}): once the walk lands the change feed answers 410
/// history_reclaimed for every since below position {m}; the walk goes on,
/// and its landing writes that fence into commits.log, which a segment
/// restored alone does not move — to re-cover the positions, stop the
/// daemon, put back the segment the account names and commits.log from a
/// copy taken before this open, and start again (RUNBOOK §2)`, with `the
/// boundaries above position {at}` in place of `position {at}` where the
/// list was refused. `{account}` is the kernel's own, and `{m}` the fence
/// the refusal moved the walk to as it stands then — the landing's own line
/// names the fence it writes.
/// From the landing on that fence is the file's first line, which every
/// later open reads and none lowers, so the act that re-covers the
/// positions puts back, beside the segment, a `commits.log` that holds no
/// such line. Said once per walk, where the first refusal is met — the
/// list's by the feed's `walk_and_land`, right after the walk's first line;
/// a boundary's by [`reconstruct`]: damage at rest is news while the walk
/// still runs, and a walk of the retained window can run for hours. A pure
/// value, pinned by `to_string()`; emitted under `Class::Failure`.
pub(super) struct WalkRefusedLine<'a> {
    pub refusal: &'a WalkRefusal,
    pub fence: u64,
}

impl std::fmt::Display for WalkRefusedLine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let refused = if self.refusal.list { "the boundaries above position" } else { "position" };
        write!(
            f,
            "commits.log's walk: the journal refused {refused} {} ({}): once the walk lands the \
             change feed answers 410 history_reclaimed for every since below position {}; the \
             walk goes on, and its landing writes that fence into commits.log, which a segment \
             restored alone does not move — to re-cover the positions, stop the daemon, put \
             back the segment the account names and commits.log from a copy taken before this \
             open, and start again (RUNBOOK §2)",
            self.refusal.at, self.refusal.account, self.fence
        )
    }
}

/// The walk's landing, refused before its rename.
///
/// The file stands as the open found it and takes no further line, so the
/// next open walks again from the region's lower edge —
/// [`CommitsLog::write_the_landing`] states why the stop is the honest half
/// — and every write since this open, held in memory alone, comes back at
/// that open as a bare entry. The words: `commits.log: the walk's landing
/// rewrite failed before its rename: {cause}; the file stands as it was and
/// takes no further line, so the next open walks again from position {low};
/// every write since this open is held in memory alone, its key and its time
/// lost at that open — restart soon`, then the act owed before that restart
/// ([`IoCause::before_the_restart`]). A pure value, pinned by `to_string()`;
/// emitted under `Class::Failure`, once per uptime.
pub(super) struct LandingRefusedLine<'a> {
    pub low: u64,
    pub error: &'a io::Error,
}

impl std::fmt::Display for LandingRefusedLine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cause = IoCause(self.error);
        write!(
            f,
            "commits.log: the walk's landing rewrite failed before its rename: {cause}; the file \
             stands as it was and takes no further line, so the next open walks again from \
             position {}; every write since this open is held in memory alone, its key and its \
             time lost at that open — restart soon{}",
            self.low,
            cause.before_the_restart()
        )
    }
}

/// The walk's controls, shared between its thread and the write path.
///
/// The write path owns the walk. The controls are the stop (read before
/// each boundary and before the landing — a Daemon dropped mid-walk ends the
/// walk with nothing written, the crash-stop shape), and the `progress:`
/// cadence — the constants' figures, or the ones the test seam moved them to
/// (`skepd::Daemon::set_feed_walk_progress_cadence`), read per boundary so a
/// held walk takes a cadence set while it parks.
pub(super) struct WalkControl {
    pub stop: AtomicBool,
    pub progress_boundaries: AtomicU64,
    pub progress_millis: AtomicU64,
}

impl WalkControl {
    /// Returns the controls at the constants' figures, the stop clear.
    pub(super) fn new() -> WalkControl {
        WalkControl {
            stop: AtomicBool::new(false),
            progress_boundaries: AtomicU64::new(FEED_WALK_PROGRESS_BOUNDARIES),
            progress_millis: AtomicU64::new(FEED_WALK_PROGRESS_INTERVAL.as_millis() as u64),
        }
    }

    /// Returns whether the stop has been asked.
    pub(super) fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Returns the cadence in force: the step count and the interval.
    ///
    /// The region's walk counts boundaries by it, the set's sort positions.
    pub(super) fn cadence(&self) -> (u64, Duration) {
        (
            self.progress_boundaries.load(Ordering::Relaxed).max(1),
            Duration::from_millis(self.progress_millis.load(Ordering::Relaxed)),
        )
    }
}

/// The cadence a long act's progress lines are said at.
///
/// A line is due every so many steps or so long, whichever comes first —
/// the walk's cadence (m15), over the region's boundaries and over the bare
/// positions `feed-index.log` lost that it sorts, each handing in its
/// figures at every step, so a cadence moved while the act runs is the one
/// it keeps.
pub(super) struct ProgressCadence {
    /// The steps done and the moment, at the last line said.
    said: (usize, Instant),
}

impl ProgressCadence {
    /// Returns a cadence counted from now, no step done.
    pub(super) fn new() -> ProgressCadence {
        ProgressCadence { said: (0, Instant::now()) }
    }

    /// Returns whether a line is due with `done` steps done, marking it said.
    ///
    /// It is due once `every` steps are done since the last line, or
    /// `interval` has passed since it, whichever comes first.
    pub(super) fn due(&mut self, done: usize, every: u64, interval: Duration) -> bool {
        let steps = done.saturating_sub(self.said.0) as u64;
        let due = steps >= every || self.said.1.elapsed() >= interval;
        if due {
            self.said = (done, Instant::now());
        }
        due
    }
}

/// What the walk behind the listener has yet to land, as figures.
///
/// It is the feed's two pending states read together (`operations.md` §3.3
/// step 2; §4 row 16): the region `(low, head]` a lost or torn `commits.log`
/// left uncovered, and the bare positions `feed-index.log` lost — each at or
/// below the log's coverage, a set and no contiguous region — that the walk
/// has yet to classify ([`Unsorted`]). `Copy`, so the lines that name the
/// walk's work, the standing line's clause, a checkpoint's landing line and
/// a page's refusal carry it; the set's positions themselves stay the
/// feed's. Empty where the log covers the head and the index classifies
/// every bare position it holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeedPending {
    /// The region `(low, head]`, `low` covered and `head` the last of it.
    pub region: Option<(u64, u64)>,
    /// The bare positions the index lost that the walk has yet to sort.
    pub unsorted: Option<Unsorted>,
}

impl FeedPending {
    /// Returns whether nothing pends: no region, no unsorted position.
    pub fn is_empty(&self) -> bool {
        self.region.is_none() && self.unsorted.is_none()
    }
}

/// The walk's work as a line names it.
///
/// The words: `positions ({low}, {head}]` for the region, `{n} bare
/// positions the index lost` for the set, and the two joined by `and` where
/// both pend; nothing where nothing does. The feed's open line, the dead
/// walk's lines and the daemon's checkpoint landing line read it.
impl std::fmt::Display for FeedPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.region, self.unsorted) {
            (Some((low, head)), Some(set)) => {
                write!(
                    f,
                    "positions ({low}, {head}] and {} bare positions the index lost",
                    set.count
                )
            }
            (Some((low, head)), None) => write!(f, "positions ({low}, {head}]"),
            (None, Some(set)) => write!(f, "{} bare positions the index lost", set.count),
            (None, None) => Ok(()),
        }
    }
}

/// The bare positions `feed-index.log` lost, counted.
///
/// They are the positions the log holds bare above the index's coverage
/// that no surviving index record classifies, which the walk behind the
/// listener sorts from the journal — a world reconstruction a position and
/// one below each run of them — and lands; a page that would reach one is
/// refused meanwhile. The count, and the lowest and highest of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unsorted {
    /// How many positions wait on the sort.
    pub count: usize,
    /// The lowest of them.
    pub first: u64,
    /// The highest of them.
    pub last: u64,
}

/// What one walk of the region came to ([`reconstruct`]).
///
/// It holds the boundaries proved, each with its classification, in
/// position order; the smallest `since` the feed can honor from here on
/// where the journal stopped answering ([`CommitsLog::min_since`]'s number);
/// and the walk's start, which the landing line's duration is measured
/// from. How many of the proved are unclassified,
/// [`WalkOutcome::unclassified`] counts off them.
pub(super) struct WalkOutcome {
    pub boundaries: Vec<Walked>,
    pub min_since: Option<u64>,
    pub started: Instant,
}

impl WalkOutcome {
    /// Returns how many boundaries were proved but not classified.
    ///
    /// The world below each was unanswerable, so each is served to every
    /// class — what the landing line counts as unclassifiable.
    pub(super) fn unclassified(&self) -> usize {
        self.boundaries.iter().filter(|w| w.docs.is_none()).count()
    }
}

/// A journal refusal that moved the walk's fence, in the kernel's words.
///
/// It is at-rest damage, an I/O failure, or a base that would not load —
/// never the reclamation a checkpoint landing behind the listener makes,
/// which moves the walk's fence in silence ([`reconstruct`]). The walk says
/// its first one where it meets it ([`WalkRefusedLine`]).
pub(super) struct WalkRefusal {
    /// The position refused, or the one above which the list was refused.
    pub at: u64,
    /// Whether the list of boundaries above `at` was refused.
    pub list: bool,
    /// The refusal's `HistoryError`, as its `Display` words it.
    pub account: String,
}

/// The line the feed walk's hold writes on the operator stream as it parks.
///
/// It is what the dirty-crash harness watches a child's stderr for before
/// it kills. `skepd::Daemon::FEED_WALK_HOLD_NOTICE` re-exports it.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub const FEED_WALK_HOLD_NOTICE: &str = "test seam: the feed walk is held; kill this process";

/// The test seam: a hold on the feed walk, armed before a daemon opens.
///
/// A suite can serve requests against a daemon whose region or whose set is
/// pending and release the walk at its own moment — the cell index walk's
/// hold's form — or park the walk after it has sorted so many of the set's
/// positions, the state a kill mid-sort leaves.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub struct FeedWalkHold {
    /// The step the walk parks at: `0` before its first position or
    /// boundary, `k` after the k-th position sorted; `None` released.
    held: Mutex<Option<u64>>,
    released: Condvar,
}

/// The test seam's one hold on the feed walk, process-wide.
///
/// It is process-wide since the walk starts inside the open, before the
/// daemon exists to be asked.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub static FEED_WALK_HOLD: FeedWalkHold =
    FeedWalkHold { held: Mutex::new(None), released: Condvar::new() };

#[cfg(any(test, feature = "test-hooks"))]
impl FeedWalkHold {
    /// Arms the hold for every walk started from here on.
    ///
    /// Each parks before its first position or boundary, after its `open:`
    /// lines, writing [`FEED_WALK_HOLD_NOTICE`].
    #[doc(hidden)]
    pub fn hold(&self) {
        *self.held.lock() = Some(0);
    }

    /// Arms the hold after the k-th position of the set is sorted.
    ///
    /// Every walk started from here on parks once it has sorted and landed
    /// `k` of the bare positions the index lost — writing
    /// [`FEED_WALK_HOLD_NOTICE`] — and before the next; a walk whose set
    /// holds no more than `k` never parks, landing everything. The daemon
    /// dropped while it parks leaves the files a kill after `k` positions
    /// leaves.
    #[doc(hidden)]
    pub fn hold_after_sorting(&self, k: u64) {
        *self.held.lock() = Some(k);
    }

    /// Releases the hold.
    ///
    /// Every parked walk proceeds, and later walks never park.
    #[doc(hidden)]
    pub fn release(&self) {
        *self.held.lock() = None;
        self.released.notify_all();
    }

    /// Parks the walk at `step` while the hold is armed for it.
    ///
    /// It is the walk's side, in timed waits, so the stop reaches a held
    /// walk: a Daemon dropped while its walk parks here ends the walk,
    /// nothing further written. The notice is written as it parks. The
    /// feed's `walk_and_land` calls it at step `0` ahead of the first
    /// position or boundary, and after each position of the set it lands.
    pub(super) fn wait_at(&self, step: u64, control: &WalkControl) {
        let mut held = self.held.lock();
        if *held == Some(step) {
            skep_util::notice::emit(Class::Failure, FEED_WALK_HOLD_NOTICE);
        }
        while *held == Some(step) && !control.stopped() {
            self.released.wait_for(&mut held, Duration::from_millis(50));
        }
    }
}

/// The test seam: the feed walk's panic arm.
///
/// It is behind `skepd::Daemon::panic_the_feed_walk` — process-wide, armed
/// before the open or while the walk is held, fired once after the hold and
/// before the first position or boundary, and disarmed as it fires: the
/// shape the walk thread's death has, which its catch contains.
#[cfg(any(test, feature = "test-hooks"))]
static FEED_WALK_FAULT: AtomicBool = AtomicBool::new(false);

/// Arms the walk's panic seam.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub fn arm_the_feed_walks_fault() {
    FEED_WALK_FAULT.store(true, Ordering::Release);
}

/// Fires the walk's side of its panic seam, where armed.
///
/// The feed's `walk_and_land` fires it after the hold and before the first
/// position or boundary.
///
/// # Panics
///
/// Panics where the seam is armed: a panic whose payload is a literal, so
/// the binary's hook carries it, located at the caller's site.
#[cfg(any(test, feature = "test-hooks"))]
#[track_caller]
pub(super) fn fire_the_feed_walks_fault() {
    if FEED_WALK_FAULT.swap(false, Ordering::AcqRel) {
        panic!("the test seam's fault in the feed walk");
    }
}

/// How a feed file's rewrite failed: on which side of the rename.
///
/// That is the whole of what the caller acts on. The rename is the one
/// atomic step: before it the old file stands whole and the handle still
/// names it, so nothing is lost — the walk's landing stops the file at the
/// region's lower edge there ([`CommitsLog::write_the_landing`]); past it
/// the new file is in place and the handle names the replaced one, which no
/// open reads, so the file is stopped for the uptime
/// ([`CommitsLog::rewrite_whole`], `LineFile::rewrite`). At open either side
/// is fatal, through [`RewriteFail::into_io`] — the bare I/O error, which
/// the open wraps with the file's name; while serving the walk's landing
/// reports and moves on.
#[derive(Debug)]
pub(super) enum RewriteFail {
    /// The temp file's creation, write or sync failed, or the rename itself.
    ///
    /// The old file is whole and still the one the handle names.
    BeforeRename(io::Error),
    /// The reopen of the renamed file failed.
    ///
    /// The new file is in place and whole, and the handle names the one it
    /// replaced.
    PastRename(io::Error),
}

impl RewriteFail {
    /// Returns the failure as the open reports it: the I/O error, either side.
    pub(super) fn into_io(self) -> io::Error {
        match self {
            RewriteFail::BeforeRename(e) | RewriteFail::PastRename(e) => e,
        }
    }
}

impl std::fmt::Display for RewriteFail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RewriteFail::BeforeRename(e) => write!(f, "before its rename: {}", IoCause(e)),
            RewriteFail::PastRename(e) => write!(f, "past its rename: {}", IoCause(e)),
        }
    }
}

/// Opens `commits.log` for reading and appending, created where absent.
///
/// It is born `0600` on unix, the mode set at creation, which the process
/// umask can narrow and never widen; a file that already stands keeps its
/// mode. The one open the sidecar takes: at the daemon's open, and after a
/// rewrite's rename.
///
/// # Errors
///
/// The OS's error where the file can be neither opened nor created.
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

/// Creates a rewrite's temp file afresh, born `0600` on unix.
///
/// The mode is set at creation, and the rename carries it onto
/// `commits.log`.
///
/// # Errors
///
/// The OS's error where the file can be neither created nor truncated.
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

/// What a rewrite hands back ([`rewrite`]).
///
/// It is the reopened append handle, the offset each new line now sits at,
/// and the file's new length.
type Rewritten = (File, Vec<(u64, LineOffset)>, u64);

/// Rewrites `commits.log` as every line it holds, then a fence and the new lines.
///
/// The file's own lines are copied verbatim — nothing it holds is dropped,
/// so no copied line's offset moves — then the `min_since` line where the
/// landing owes one, then each of `new` in the order given, every one a
/// line the file did not hold. It hands back the reopened append handle,
/// the offset each new line now sits at, and the new length.
///
/// Written to a temp file and renamed over the original, which is what
/// makes the landing crash-honest in the same sense the rest of this file
/// is: a reader only ever sees the whole old file or the whole new one,
/// and a kill between the two leaves the region to a walk behind the
/// listener again.
///
/// The temp is `commits.log.compact`, a fixed name — safe because
/// `skepd::Daemon::open`'s precondition admits one live kernel per data
/// dir. It is not cleaned up: a crash or an I/O failure between the create
/// and the rename leaves it until the next rewrite truncates it, which is
/// the price of the rename being the only atomic step.
///
/// `fail_past_rename` is the test seam: the reopen refused, so the
/// past-rename arm is reachable without a disk that fails on cue; `false`
/// outside a test or `test-hooks` build.
///
/// # Errors
///
/// Which side of the rename a failure fell on travels as [`RewriteFail`],
/// since the two leave different files behind:
/// [`RewriteFail::BeforeRename`] where the temp file's creation, the copy,
/// a write or the sync, or the rename itself failed;
/// [`RewriteFail::PastRename`] where the renamed file's reopen failed, or
/// `fail_past_rename` refused it.
fn rewrite(
    dir: &Path,
    fence: Option<u64>,
    new: &[(u64, Vec<u8>)],
    fail_past_rename: bool,
) -> Result<Rewritten, RewriteFail> {
    let path = dir.join(SIDECAR_FILE);
    let tmp = dir.join(format!("{SIDECAR_FILE}.compact"));
    let mut offsets = Vec::with_capacity(new.len());
    let renamed = (|| -> io::Result<u64> {
        let mut out = create_rewrite_temp(&tmp)?;
        let mut len = io::copy(&mut File::open(&path)?, &mut out)?;
        if let Some(fence) = fence {
            let line = min_since_line(fence);
            out.write_all(&line)?;
            len += line.len() as u64;
        }
        for (at, line) in new {
            offsets.push((*at, LineOffset(len)));
            out.write_all(line)?;
            len += line.len() as u64;
        }
        out.sync_all()?;
        drop(out);
        std::fs::rename(&tmp, &path)?;
        Ok(len)
    })();
    let len = renamed.map_err(RewriteFail::BeforeRename)?;
    if fail_past_rename {
        return Err(RewriteFail::PastRename(io::Error::other(
            "test seam: the rewritten file's reopen refused",
        )));
    }
    let file = open_sidecar(&path).map_err(RewriteFail::PastRename)?;
    Ok((file, offsets, len))
}

/// Rewrites `commits.log` without the lines of another journal.
///
/// It is the open's purge where a fence above the head stood
/// ([`CommitsLog::open`]): every entry line at or below `head` and every
/// fence at or below it copied verbatim, in file order, the rest left out
/// — through `commits.log.compact` renamed over the original. The file is
/// already cut at its trusted end, so every line read here is whole; the
/// entry lines above the head were kept beside the file before this runs.
/// Answers the reopened append handle; every offset moved.
///
/// # Errors
///
/// The OS refused the temp file's creation, a read, a write, the sync, the
/// rename or the reopen.
fn purge_the_other_journals(dir: &Path, head: u64) -> io::Result<File> {
    let path = dir.join(SIDECAR_FILE);
    let tmp = dir.join(format!("{SIDECAR_FILE}.compact"));
    let mut out = io::BufWriter::new(create_rewrite_temp(&tmp)?);
    let mut reader = BufReader::new(File::open(&path)?);
    let mut line = Vec::new();
    while reader.read_until(b'\n', &mut line)? > 0 {
        let kept = match line.strip_suffix(b"\n").and_then(parse_line) {
            Some(Record::Entry(at, _)) => at <= head,
            Some(Record::MinSince(n)) => n <= head,
            None => false,
        };
        if kept {
            out.write_all(&line)?;
        }
        line.clear();
    }
    let f = out.into_inner().map_err(io::IntoInnerError::into_error)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, &path)?;
    open_sidecar(&path)
}

/// What one scan of `commits.log` read ([`scan`]).
struct Scanned {
    /// The byte trust ends at.
    valid_end: u64,
    /// The file's length.
    len: u64,
    /// Whether trust ended at a whole line — damage — rather than a torn one.
    damaged: bool,
    /// The whole entry lines at or below the head past a damaged one.
    whole_after: Option<EntryLines>,
    /// The window's entries: the newest positions at or below the head,
    /// above the fence, no more than the window's span.
    window: BTreeMap<u64, CommitMeta>,
    /// The window's entries' offsets.
    offsets: BTreeMap<u64, LineOffset>,
    /// The highest entry at or below the head above the fence.
    last_entry: Option<u64>,
    /// The entries at or below the head above the fence.
    count: u64,
    /// How many of them are bare.
    bare: u64,
    /// The first entry above the fence.
    first_held: Option<u64>,
    /// The greatest fence at or below the head.
    min_since: u64,
    /// Whether the file is rewritten without another journal's lines.
    ///
    /// It is where a fence above the head stood, or a line of this journal
    /// stood past another journal's — neither leaves by the truncation that
    /// drops the lines at the file's end.
    stale_fence: bool,
    /// The entry lines above the head, where any stood.
    foreign: Option<Foreign>,
    /// The entries with malformed names: how many, and the first.
    malformed: Option<(usize, u64)>,
    /// The greatest recorded time.
    last_time: u64,
}

/// The entry lines above the head one scan met.
struct Foreign {
    /// The byte the first of them begins at.
    first: u64,
    /// Their bytes, whole, for the keep.
    bytes: Vec<u8>,
    /// Their count and positions.
    lines: EntryLines,
}

/// Scans the file whole, a line at a time, keeping the window.
///
/// It is the open's one pass ([`CommitsLog::open`]): trust ends at the
/// first line that is torn, does not parse, or lies below the line of this
/// journal before it — an entry at or below the last entry, or a fence
/// below the last position — the file being position-ordered
/// (`feed/window.rs`). An entry above `head` is another journal's whatever
/// its order, counted and kept for the keep and held in no count; a fence
/// above the head, or a line of this journal past another journal's, calls
/// for the rewrite that drops the other's lines. A fence at or below
/// the head makes every entry before it dead to this build — a fence
/// stands at or above every line before it — so the counts, the window and
/// the first line held start afresh past it. Each entry with a malformed
/// name is demoted as it is read ([`demoted`]) and counted. The window is
/// trimmed as the scan climbs, so it holds the window's span and no more
/// at any moment.
///
/// # Errors
///
/// The OS refused a read or a seek.
fn scan(file: &mut File, head: u64, window: u64) -> io::Result<Scanned> {
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::with_capacity(64 * 1024, &*file);
    let mut s = Scanned {
        valid_end: 0,
        len,
        damaged: false,
        whole_after: None,
        window: BTreeMap::new(),
        offsets: BTreeMap::new(),
        last_entry: None,
        count: 0,
        bare: 0,
        first_held: None,
        min_since: 0,
        stale_fence: false,
        foreign: None,
        malformed: None,
        last_time: 0,
    };
    let mut offset = 0u64;
    let mut last_position: Option<u64> = None;
    let mut keep_from = 0u64;
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 || !line.ends_with(b"\n") {
            break;
        }
        let Some(record) = parse_line(&line[..line.len() - 1]) else {
            s.damaged = true;
            break;
        };
        // The order, judged over this journal's lines alone: a line past
        // the head is another journal's whatever its order, dropped below.
        let (position, backwards) = match (&record, last_position) {
            (Record::Entry(at, _), last) if *at <= head => (*at, last.is_some_and(|l| *at <= l)),
            (Record::MinSince(n), last) if *n <= head => (*n, last.is_some_and(|l| *n < l)),
            _ => (u64::MAX, false),
        };
        if backwards {
            s.damaged = true;
            break;
        }
        match record {
            Record::MinSince(n) if n > head => s.stale_fence = true,
            Record::MinSince(n) => {
                s.min_since = s.min_since.max(n);
                s.window.clear();
                s.offsets.clear();
                s.last_entry = None;
                s.count = 0;
                s.bare = 0;
                s.first_held = None;
            }
            Record::Entry(at, _) if at > head => {
                let foreign = s.foreign.get_or_insert_with(|| Foreign {
                    first: offset,
                    bytes: Vec::new(),
                    lines: EntryLines { lines: 0, first: at, last: at },
                });
                foreign.bytes.extend_from_slice(&line);
                foreign.lines = EntryLines::with(Some(foreign.lines), at);
            }
            Record::Entry(at, meta) => {
                // This journal's line after another journal's: the file is
                // rewritten without the other's, and scanned again.
                if s.foreign.is_some() {
                    s.stale_fence = true;
                    continue;
                }
                let (meta, malformed) = demoted(meta);
                if malformed {
                    let (count, first) = s.malformed.unwrap_or((0, at));
                    s.malformed = Some((count + 1, first.min(at)));
                }
                s.count += 1;
                s.bare += u64::from(matches!(meta, CommitMeta::Bare { .. }));
                s.first_held.get_or_insert(at);
                s.last_entry = Some(at);
                if let Some(time) = meta.time() {
                    s.last_time = s.last_time.max(time);
                }
                s.window.insert(at, meta);
                s.offsets.insert(at, LineOffset(offset));
                let edge = at.saturating_sub(window).saturating_add(1);
                if edge > keep_from {
                    keep_from = edge;
                    while s.window.first_key_value().is_some_and(|(k, _)| *k < keep_from) {
                        s.window.pop_first();
                        s.offsets.pop_first();
                    }
                }
            }
        }
        if position != u64::MAX {
            last_position = Some(position);
        }
        offset += read as u64;
    }
    s.valid_end = offset;
    if s.damaged {
        // The whole entry lines past the damaged one, at or below the head:
        // the testimony the cut takes, which no walk brings back.
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if let Some(Record::Entry(at, _)) = line.strip_suffix(b"\n").and_then(parse_line) {
                if at <= head {
                    s.whole_after = Some(EntryLines::with(s.whole_after, at));
                }
            }
        }
    }
    Ok(s)
}

/// Returns the first position `commits.log` in `dir` holds a line for above its fence.
///
/// It is the feed's coverage as the operator's inventory reports it
/// (`journal.feed_from`): one scan of the file's lines, the first entry
/// above the greatest fence line — `None` where the file is absent, holds
/// no entry, or holds none above its fence. Trust ends where the open's
/// scan ends it, at a torn or unparseable line, and what stands before it
/// answers; nothing is cut or written.
///
/// # Errors
///
/// The OS refused the open or a read, an absent file aside.
pub(crate) fn first_held_in(dir: &Path) -> io::Result<Option<u64>> {
    let file = match File::open(dir.join(SIDECAR_FILE)) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut fence = 0u64;
    let mut first: Option<u64> = None;
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 || !line.ends_with(b"\n") {
            break;
        }
        match parse_line(&line[..line.len() - 1]) {
            Some(Record::MinSince(n)) => {
                fence = fence.max(n);
                if first.is_some_and(|f| f <= fence) {
                    first = None;
                }
            }
            Some(Record::Entry(at, _)) => {
                if at > fence {
                    first.get_or_insert(at);
                }
            }
            None => break,
        }
    }
    Ok(first)
}

/// Demotes an entry whose document names are malformed to a bare one.
///
/// A malformed name is not a dotted-decimal address this daemon can parse;
/// the entry answers bare, and the second answer says whether it was
/// demoted. The open's scan runs it on every line it reads, counting the
/// demoted for one line said once per open (`operations.md` §1.1 row 11),
/// and the feed's reader below the window runs it on each line it reads,
/// so a position answers the same bare entry whichever side of the window
/// it lies on; the file keeps the line as written, this file being the sole
/// surviving record of the commit, so the open never rewrites a name away
/// over what may be one build's rendering.
///
/// A half-parsing name list is a half-recorded position, and [`CommitMeta`]
/// has no meaning for one: its two states are the whole vocabulary, and
/// [`parse_line`] already ends trust at a line carrying some of
/// `op`/`docs`/`time` and not the others. This is that discipline one level
/// down — testimony this daemon cannot parse is testimony it does not stand
/// behind. What the demotion buys is the disclosure, and only that. A name
/// list none of whose names parse classifies the position empty, and an
/// empty class is a `[]`-docs entry, which the feed's mask never masks — so
/// left recorded, a write into a document whose name this build cannot
/// parse is served to every class carrying its op, its wall-clock time, and
/// the fingerprint of the key whose session committed it. Demoted, it
/// discloses its position, which is the residue this file already accepts
/// for a position the journal cannot classify (PUB-6.52), and nothing more
/// but the `attest` member where the attest store holds the position's
/// slot; its wire entry is the reserved all-nulls rendering, that member
/// aside. A partly-parsing list is the same species one step less visible:
/// the mask would be computed over fewer documents than the write touched.
///
/// **Unreachable as built** — the names are rendered from validated
/// `Address`es by [`super::feed::Feed::record`] and read back by
/// [`parse_dotted`], which is that rendering's inverse — and the obligation
/// keeping it so is held by nobody: the write path renders, this file
/// stores, the feed's open parses.
pub(super) fn demoted(meta: CommitMeta) -> (CommitMeta, bool) {
    match &meta {
        CommitMeta::Recorded { docs, .. } if docs.iter().any(|s| parse_dotted(s).is_none()) => {
            (CommitMeta::bare(), true)
        }
        _ => (meta, false),
    }
}

/// What the kernel's one scan listed for the walk ([`list_boundaries`]).
///
/// It is the region `(low, head]` it was made for; the boundaries to prove,
/// ascending; the smallest `since` the feed honors from here on where the
/// scan refused below `low` ([`CommitsLog::min_since`]'s number); and the
/// refusal itself where the list was refused, which the caller says where
/// it meets it ([`WalkRefusedLine`]), ahead of the first boundary.
pub(super) struct Listing {
    /// The region's lower edge, covered.
    pub low: u64,
    /// The region's last position, the head at open.
    pub head: u64,
    pub boundaries: Vec<u64>,
    pub min_since: Option<u64>,
    pub refusal: Option<WalkRefusal>,
}

/// Walks `(low, head]`, listed (`operations.md` §3.3 step 2; §1.1 m15).
///
/// `listing` is the kernel's one scan ([`list_boundaries`]), which the
/// caller took to say the walk's `open:` line with the count and the list's
/// refusal where it met one — the feed's `walk_and_land`, which holds the
/// walk and sorts the bare positions the index lost ahead of this. It proves
/// each boundary ascending by the kernel's bounded replay — an `Ok`
/// `world_at` proves a boundary — classifying each from the journal on the
/// way up: the walk holds the world at the boundary below and diffs the two
/// (`derived_journal`) for the documents that commit touched and the terms
/// its row can answer. Ascending, so the `progress:` line's `{p}` climbs to
/// `{h}`: the lowest boundary's predecessor is `low` itself where `low` is a
/// boundary — genesis, or the last recorded position — and where it is a
/// fence (a previous walk's stopping point, or one an earlier build's
/// compaction wrote) its world refuses and the boundary above it is
/// unclassifiable (`docs: None`); the head's world is `head_world`, the
/// open's own snapshot (no replay), since the live root moves past the head
/// while the board serves. `started` is the walk thread's start, which the
/// `progress:` lines' and the landing line's durations are measured from.
///
/// Answers the boundaries proved (ascending, each with its classification)
/// and, where the journal stopped answering, the smallest `since` the feed
/// can honor from there on — [`CommitsLog::min_since`]'s number, not the
/// wire's `floor`: the list refused `Reclaimed` naming a floor above `low`
/// (the base below `low` reclaimed before the walk reached it) — asked
/// again at the floor, whose own boundary the base embodying it answers,
/// unclassifiable, and the fence one below it; a boundary refused
/// `Reclaimed` mid-walk (a checkpoint landing behind the listener took its
/// base) — the fence one below the floor named, the boundaries below it
/// skipped, those the walk had proved below it left out by the landing's
/// fold; any other refusal (corrupt, I/O, a listed boundary the
/// replay will not prove) — the feed reaches down to the boundary above
/// it and no further, the first such refusal said where it is met, in the
/// kernel's words, with the fence as it then stands ([`WalkRefusedLine`]),
/// where the list's own was not. `None` where the stop was asked before the
/// walk completed: nothing is landed.
pub(super) fn reconstruct(
    kernel: &Kernel<World>,
    head_world: &World,
    listing: Listing,
    started: Instant,
    lines: &Lines,
    control: &WalkControl,
) -> Option<WalkOutcome> {
    let Listing { low, head, boundaries: listed, mut min_since, refusal: list_refusal } = listing;
    // The journal's first refusal, said where it is met: the list's, by the
    // caller; else the first boundary's that moves the fence, below, a
    // mid-walk reclamation aside.
    let mut refusal_said = list_refusal.is_some();
    // The journal's two answers off the two worlds, or — with no world
    // below — unclassifiable, and no term.
    let classify = |at: u64, below: Option<&World>, upper: &World| match below {
        Some(b) => {
            let (docs, journal) = derived_journal(b, upper);
            Walked { at, docs: Some(docs), journal }
        }
        None => Walked { at, docs: None, journal: JournalTerms::default() },
    };
    // The world below the boundary in hand: `low`'s where the journal
    // answers it, none where the list already stopped below the first.
    let mut below: Option<World> =
        if min_since.is_some() { None } else { kernel.world_at(Seq(low)).ok() };
    // Boundaries below this are known unanswerable (a mid-walk reclamation
    // named it), and are passed without a replay each.
    let mut skip_below = 0u64;
    let mut boundaries: Vec<Walked> = Vec::with_capacity(listed.len());
    let mut cadence = ProgressCadence::new();
    for (i, &at) in listed.iter().enumerate() {
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
                Err(e) => {
                    let fence = min_since.map_or(at, |m| m.max(at));
                    min_since = Some(fence);
                    if !refusal_said {
                        refusal_said = true;
                        let refusal = WalkRefusal { at, list: false, account: e.to_string() };
                        lines.say(Class::Failure, WalkRefusedLine { refusal: &refusal, fence });
                    }
                    below = None;
                    continue;
                }
            }
        };
        let upper: &World = proved.as_ref().unwrap_or(head_world);
        boundaries.push(classify(at, below.as_ref(), upper));
        below = proved;
        // The cadence: every so many boundaries, or so long, whichever
        // comes first — the figures read here, so a cadence set while the
        // walk parked at the hold is the one it keeps.
        let (every, interval) = control.cadence();
        if cadence.due(boundaries.len(), every, interval) {
            let progress = WalkProgressLine {
                position: at,
                head,
                boundary: i + 1,
                boundaries: listed.len(),
                elapsed_ms: started.elapsed().as_millis(),
            };
            lines.say(Class::Progress, progress);
        }
    }
    Some(WalkOutcome { boundaries, min_since, started })
}

/// Lists the boundaries the walk proves, `(low, head]` ascending.
///
/// They are read in one scan of the kernel's markers
/// (`Kernel::boundaries_above`, every boundary above `low` from one base —
/// the attest store's seam, here a list). Where the scan refused below
/// `low`, it answers the fence the feed honors from there too: `Reclaimed`
/// naming a floor above `low` is the base below `low` gone, so the list is
/// asked again at the floor, a second scan — the floor's own boundary, which
/// the base embodying it answers, leads the list — and the fence is one
/// below it; a refusal naming no floor, at-rest damage, or the list at the
/// floor refused in turn leaves the head alone to prove, the fence one below
/// it, and that refusal is answered beside them ([`WalkRefusal`]). A floor
/// past the head names an empty list: everything the region held is
/// reclaimed. The feed's `walk_and_land` takes it ahead of the walk's
/// `open:` line, whose count is the list's, and hands it to
/// [`reconstruct`].
pub(super) fn list_boundaries(kernel: &Kernel<World>, low: u64, head: u64) -> Listing {
    let at_or_below_head = |list: Vec<(Seq, Option<Attestation>)>| -> Vec<u64> {
        list.into_iter().map(|(seq, _)| seq.0).filter(|&at| at > low && at <= head).collect()
    };
    let listing = |boundaries: Vec<u64>, min_since: Option<u64>, refusal: Option<WalkRefusal>| {
        Listing { low, head, boundaries, min_since, refusal }
    };
    let refused = |at: u64, e: HistoryError| {
        let refusal = WalkRefusal { at, list: true, account: e.to_string() };
        listing(vec![head], Some(head.saturating_sub(1)), Some(refusal))
    };
    match kernel.boundaries_above(Seq(low)) {
        Ok(list) => listing(at_or_below_head(list), None, None),
        Err(HistoryError::Reclaimed { floor: Some(floor), .. }) if floor.0 > low => {
            if floor.0 > head {
                return listing(Vec::new(), Some(floor.0 - 1), None);
            }
            match kernel.boundaries_above(floor) {
                Ok(above) => {
                    let mut list = vec![floor.0];
                    list.extend(at_or_below_head(above));
                    listing(list, Some(floor.0 - 1), None)
                }
                Err(e) => refused(floor.0, e),
            }
        }
        Err(e) => refused(low, e),
    }
}

/// Parses whole newline-terminated records: the unit suite's reading of a file.
///
/// Trust ends at the first line that is torn (no `\n`) or does not parse —
/// the order check is the open's scan's alone ([`scan`]). Returns each
/// record with the byte offset its line starts at, and the byte offset after
/// the last whole one.
#[cfg(test)]
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

/// Parses one file line.
///
/// The file is daemon-private; unknown keys are ignored (a newer daemon's
/// extension), malformed known fields are torn-treatment. The min-since
/// record has two spellings in the field — `min_since` and `floor` — and
/// both read, because an unparseable line ends trust in everything after
/// it. The one parser of the file: the open's scan reads every line through
/// it, and the feed's reader below the window reads each line a cursor
/// hands it through it, demoting the entry after ([`demoted`]).
///
/// The three entry fields are read together, because [`CommitMeta`] has only
/// two states: all three present is a recorded position, all three absent
/// (or `null`) is a bare one, and a line carrying some of them is not a line
/// this daemon wrote — so trust ends there exactly as at an unparseable
/// one, and the reopen walk re-covers the position as bare.
///
/// **The absent-vs-null discipline** of the fields beside those three:
/// `signed` is absent on an unsigned line and one of its two tokens
/// otherwise (any other value is torn); the op's terms are read by the
/// line's op — a `delegate` line's `new_prefix` and `new_id` together (one
/// without the other is torn), a `make_link` line's `link`, a `publish`
/// line's `placed` with `base_extent` beside it, `null` there being the
/// birth shape and not an absence — and absent altogether on a line written
/// before they were recorded, which reads as an op carrying none. A term on
/// a line of another op is an unknown key, ignored. A bare line's `journal`
/// member is the journal's answer ([`JournalTerms::parse`]): absent on a
/// line written before it was derived, or where the journal answered
/// nothing; an object otherwise, and anything else is torn.
pub(super) fn parse_line(line: &[u8]) -> Option<Record> {
    let v: Value = serde_json::from_slice(line).ok()?;
    let m = v.as_object()?;
    if let Some(s) = m.get("min_since").or_else(|| m.get("floor")) {
        return Some(Record::MinSince(s.as_u64()?));
    }
    let at = m.get("at")?.as_u64()?;
    // Each field is read through the same lookup that decides it is
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

/// Renders one entry's file line.
///
/// It is `{"at":N}` for a bare position the journal answered nothing for,
/// and `{"at":N,"journal":{…}}` where it did — the op where named and the
/// terms in the wire's own spelling ([`JournalTerms::members`]);
/// `{"at":N,"docs":[…],"key":"…","op":"…","time":T}` for a recorded one,
/// `key` omitted only where the record carries none (a pre-feature line),
/// `"signed":"marker"|"record"` where the entry carries a signature, and the
/// op's own terms where it has any, spelled as the wire's row spells them
/// ([`OpTerms::members`]). Built through the codec's key-sorting device, so
/// a line is the same bytes whatever backs serde_json's map — which is what
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

/// Renders the fence line, `{"min_since":N}`.
///
/// It is the smallest `since` the feed can honor from here on. The key is
/// deliberately not `floor`, which on the wire names the oldest position
/// still answerable — a different number, and one an operator reading this
/// file beside a `410` body would otherwise conflate.
fn min_since_line(min_since: u64) -> Vec<u8> {
    line_bytes(&obj(vec![("min_since", Value::Number(min_since.into()))]))
}

/// Row 11's line: a file's malformed document names, said once per open.
///
/// The words: `{file}: {n} positions carry malformed document names, the
/// first at position {p}`, then what still serves, the line's case
/// ([`MalformedCase`]). The names are said once per open with a count
/// (`operations.md` §1.1 row 11), by both halves of the feed's
/// name-parsing: this file's own [`demoted`] and the derived
/// index's read of the same names, each counting the positions it met and
/// saying the count, the first of them and its case through `lines`, the
/// classed door, under `Class::Failure`. Nothing per position. A pure
/// value, pinned by `to_string()` in the unit suite.
pub(super) struct MalformedNamesLine {
    pub file: &'static str,
    pub positions: usize,
    pub first: u64,
    pub case: MalformedCase,
}

/// What a file's malformed names leave serving, the line's last clause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MalformedCase {
    /// `commits.log`'s own: each position is demoted to a bare entry.
    ///
    /// The clause: `; those positions serve as bare entries`.
    Demoted,
    /// The index file's: a recorded position answers from the log's record.
    ///
    /// A bare one has no testimony to answer from, so it stays unclassified
    /// and the per-entry mask withholds it from no class. The clause: `; {r}
    /// of them answer from commits.log's testimony, and {b} bare ones stay
    /// unclassified, each shown to any class that reaches it`.
    Index {
        /// How many of the positions are bare.
        bare: usize,
    },
}

impl std::fmt::Display for MalformedNamesLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} positions carry malformed document names, the first at position {}",
            self.file, self.positions, self.first
        )?;
        match self.case {
            MalformedCase::Demoted => f.write_str("; those positions serve as bare entries"),
            MalformedCase::Index { bare } => write!(
                f,
                "; {} of them answer from commits.log's testimony, and {bare} bare ones stay \
                 unclassified, each shown to any class that reaches it",
                self.positions.saturating_sub(bare)
            ),
        }
    }
}

/// Returns one newline-terminated file line, through the codec's serializer.
///
/// So a line is the same bytes whatever backs serde_json's map, and the
/// "cannot fail" argument is the one written there rather than a second
/// copy of it.
pub(super) fn line_bytes(v: &Value) -> Vec<u8> {
    let mut b = to_bytes(v);
    b.push(b'\n');
    b
}

#[cfg(test)]
impl CommitsLog {
    /// Returns a [`CommitsLog`] whose appends fail, over a read-only handle.
    ///
    /// The handle is on the file in `dir` — which is the one condition the
    /// stop rule is about and the one no portable test can produce from
    /// [`CommitsLog::open`]'s handle. The same seam `feed/derived.rs` keeps
    /// for the same rule.
    ///
    /// # Panics
    ///
    /// Panics where the file in `dir` cannot be created, or opened read-only.
    fn over_unwritable(dir: &Path, open_head: u64) -> CommitsLog {
        let path = dir.join(SIDECAR_FILE);
        File::create(&path).expect("create the file to be opened read-only");
        let file = File::open(&path).expect("a read-only handle");
        CommitsLog {
            file,
            dir: dir.to_path_buf(),
            entries: BTreeMap::new(),
            offsets: BTreeMap::new(),
            resident_from: 0,
            window: FEED_RESIDENT_WINDOW,
            resident_most: 0,
            count: 0,
            bare: 0,
            first_held: None,
            min_since: 0,
            fence_owed: None,
            open_head,
            rewritten: false,
            floor_at_open: None,
            pending: None,
            last_time: 0,
            len: 0,
            lines: Lines::new(),
            stopped: None,
            fail_next_rewrite_past_rename: false,
        }
    }

    /// Returns a [`CommitsLog`] over a writable file, its region pending.
    ///
    /// The file is in `dir`, the log holding `entries` and its region
    /// `(low, head]` pending — the state the open leaves a torn file in — so
    /// the landing's one rewrite is judged on the file's bytes without a
    /// journal to walk.
    ///
    /// # Panics
    ///
    /// Panics where the file in `dir` cannot be opened for appending, or its
    /// length read.
    fn pending_over(dir: &Path, entries: BTreeMap<u64, CommitMeta>, low: u64, head: u64) -> CommitsLog {
        let file = OpenOptions::new()
            .append(true)
            .open(dir.join(SIDECAR_FILE))
            .expect("a writable handle on the file");
        let len = file.metadata().expect("the file's length").len();
        let count = entries.len() as u64;
        let bare = entries.values().filter(|m| matches!(m, CommitMeta::Bare { .. })).count() as u64;
        let first_held = entries.keys().next().copied();
        CommitsLog {
            file,
            dir: dir.to_path_buf(),
            entries,
            offsets: BTreeMap::new(),
            resident_from: 0,
            window: FEED_RESIDENT_WINDOW,
            resident_most: 0,
            count,
            bare,
            first_held,
            min_since: 0,
            fence_owed: None,
            open_head: head,
            rewritten: false,
            floor_at_open: None,
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
    /// Returns the stop as a read: the position this file's stop was set at.
    ///
    /// It is `None` while the file takes lines ([`CommitsLog`]'s `stopped`
    /// says which position each cause carries) — what the standing line
    /// re-says a stopped file by, once an hour while it stands.
    pub(super) fn stopped_since(&self) -> Option<u64> {
        self.stopped
    }

    /// The test seam that fails the next rewrite past its rename.
    ///
    /// It is behind `skepd::Daemon::fail_the_feeds_next_rewrite_past_rename`:
    /// the next rewrite fails at the reopen of the file it has just renamed
    /// into place — the past-rename arm, and the stop it carries. Not a
    /// stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn fail_next_rewrite_past_rename(&mut self) {
        self.fail_next_rewrite_past_rename = true;
    }
}

#[cfg(test)]
mod tests;
