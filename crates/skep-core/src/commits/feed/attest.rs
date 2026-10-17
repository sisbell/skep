//! THE ATTEST STORE (signed ops; the design record §7.3 (i); BW-01,
//! owner-ruled 2026-09-29) — `feed-attest.log`: the marker slot's signature
//! per attested position, which `GET /changes` serves as the row's `attest`
//! member (`CommitMeta::entry`). It rides [`LineFile`]'s line discipline
//! under a class of its own:
//!
//! One line per ATTESTED position — `alg` the marker's `sig_alg` TAG (the
//! wire's token is rendered at serve), `sig` the blob as lowercase hex,
//! byte-equal to what the request presented — appended AT COMMIT from the
//! value the plain sequence admitted and handed the kernel, under the write
//! path's serialization lock in the same `record` that appends `commits.log`;
//! REBUILT on loss or a short tail from the kernel's markers in ONE scan —
//! `Kernel::boundaries_above` the file's fence, every committed boundary
//! above it with its slot, from one base (the operations design §3.3 step
//! 2) — for every served position the journal still answers, ABOVE THE
//! RECLAIM FLOOR alone — a position the journal refuses `Reclaimed` is
//! neither rebuilt nor dropped, and its row renders `attest: null` (LOST),
//! and the list is asked again at the floor the refusal names, for the
//! positions above it ([`rebuilt_tail`]). Below the floor the checkpoint
//! body holds no marker, so a line here is an entry signature's ONLY copy at
//! the origin: there the store is PRIMARY state and not a projection — NEVER
//! COMPACTED to the journal's retention (where `commits.log` and the four
//! derived sidecars drop their entries below the floor at open, this file
//! KEEPS them), neither prunable nor rebuildable, backed up by location with
//! the board directory as `blobs/` is, its loss served as `null`. The
//! coverage fence, the foreign-line purge and the stop on a failed append
//! apply as in the four, and so does the TRUNCATION, which does not stop at
//! the floor: trust ends at the first line that is torn or does not parse
//! ([`LineFile::open`]), and every line after it is cut — below the floor
//! too, where each was an entry signature's only copy. A crash tears the
//! file's newest lines, at the head's end, which the journal still answers and
//! the open rebuilds; a cut that reaches below the floor is damage to the
//! file. The open names every cut on the operator stream with the last
//! trusted position, the reclaim floor at this open and THE SIDE the cut
//! reached ([`AttestCutLine`]) — REBUILT where every cut line lies above the
//! floor, which is `coverage + 1 ≥ floor` since the file is position-ordered
//! and the rebuild covers `(coverage, head]`; LOST between the last trusted
//! position and the floor otherwise — so the board directory's backup is
//! restored on a LOST cut alone. At HEAD no read serves a below-floor slot
//! (`/changes` answers `410 history_reclaimed` below the feed's floor): the
//! lines below it are kept for a read that does not yet exist, the class
//! being the design record's and not this build's to narrow.
//!
//! DURABLE BEFORE THE NEXT COMMIT, AND A FAILED LINE HALTS WRITES (SO-I5 (d):
//! no signature the board keeps is lost by a crash, a power loss or a failed
//! write). The checkpoint that reclaims a position's journal segment is
//! TRIGGERED by a LATER commit than the position's own and runs on the
//! daemon's checkpoint thread — the kernel's cadence crosses within a
//! commit and sets the flag that thread services, the thread notified after
//! that commit's record step, and the backstop running inline within the
//! later commit itself — and it reclaims only below the oldest checkpoint
//! the kernel retains, which is strictly below the root it embodies; and
//! every commit opens after the previous write's record step, under the
//! write path's serialization lock. So [`AttestStore::record`]
//! SYNCS the line before it returns ([`LineFile::append_synced`]), and the
//! line is on disk before any commit that could take the journal's copy away
//! can begin; the open syncs what it rebuilt before the first commit, for the
//! same reason. The four derived files are not synced: what they lose, the
//! next open re-derives. A write or a sync that FAILS stops this file as a
//! failed append stops theirs, and — the file being primary where theirs are
//! projections — it HALTS the write path: the record answers
//! [`super::AttestStoreFailed`], and the daemon refuses every later write until a
//! restart, since any commit could trigger the checkpoint that deletes the
//! journal copy the lost line depends on. The restart's open rebuilds the
//! line from the journal, which the halt kept.
//!
//! What keeps the class is this card's privacy: [`AttestStore`]'s file is its
//! own, and nothing rewrites it but [`LineFile::open`]'s purge of the lines
//! above the head — another journal's — which copies every line of this
//! journal verbatim, so no other card can compact it.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{Map, Value};
use skep_engine::Engine;
use skep_kernel::{Attestation, HistoryError, Seq};
use skep_util::json::hex_string;
use skep_util::notice::Class;

use super::derived::LineFile;
use super::super::sidecar::{CommitsLog, Cut, CutHead, ForeignLinesLine, IoCause};
use super::super::Lines;
use super::AttestStoreFailed;
use crate::codec::parse_lower_hex_bytes;

// The file is named BESIDE the fields its records carry, and both beside the
// line's one writer ([`attest_fields`]) and its one reader
// ([`attest_of_record`]): a write site that spelled a field apart from the
// read site would write lines that replay as no slot.

/// The store's file.
const ATTEST_FILE: &str = "feed-attest.log";
/// Its records' first field: the marker's `sig_alg` tag, a number.
const ATTEST_ALG: &str = "alg";
/// Its records' second field: the signature blob, lowercase hex.
const ATTEST_SIG: &str = "sig";

/// THE ATTEST STORE: its file, and the slots of the positions `commits.log`
/// serves — resident at one blob (~3.4 KB under tag 1) per attested position
/// it serves: the retained window at open, then every attested commit this
/// uptime records — nothing prunes it before the next open. The FILE holds
/// more: every line ever appended, the positions the log compacted away
/// included, where the store is primary state.
pub(super) struct AttestStore {
    /// `feed-attest.log`: appended, replayed and fenced, and never compacted.
    file: LineFile,
    /// Position → the marker slot, for the served positions — behind an
    /// `Arc`, so a page rendered after the feed's lock is released
    /// ([`super::Feed::page`]) clones a pointer, never a signature.
    served: BTreeMap<u64, Arc<Attestation>>,
    /// The classed door with the daemon's record ([`Lines`]), a clone held
    /// from the open as the line files hold theirs: what the halt's line
    /// (`operations.md` §1.1 row 33) is said through, once.
    lines: Lines,
}

impl AttestStore {
    /// Open the store beside the replayed `log`: replay every line at or
    /// below the head, a line at a time, holding resident the SERVED window
    /// alone — the lines below the log's fence are read past and stay in the
    /// FILE, untouched — then rebuild the missing tail from the journal's
    /// markers in ONE scan, then fence at the head and SYNC, so every line
    /// the open rebuilt is on disk before the first commit can begin (SO-I5
    /// (d)).
    ///
    /// A line this daemon cannot read (a tag of no signature, a blob of none,
    /// hex it did not write) is counted and not held — said ONCE PER OPEN
    /// with the count and the first position (`operations.md` §1.1 row 10),
    /// the file never compacted and the line never rewritten, so each open
    /// meets it again: the row then renders `attest: null` where its line
    /// records the marker filled, never an invented slot. A CUT the replay
    /// made is said once the rebuild has run, with the floor and the side it
    /// reached ([`AttestCutLine`]), the floor the log's open probed
    /// (`CommitsLog::floor_at_open`, the feed's one probe) — the same
    /// refusal the rebuild below meets where its fence's base is gone, both
    /// the kernel's one base selection naming the oldest retained
    /// checkpoint. Every
    /// failure of the open names this file, the kind kept (row 2): the
    /// replay's through `LineFile::open`, the rebuilt lines' appends, the
    /// fence, the sync and the size through one closure here. The tail is
    /// every committed boundary above the file's coverage whose slot is
    /// filled, listed by `Kernel::boundaries_above` in one scan from one base
    /// ([`rebuilt_tail`]: the floor arm, and what a refusal leaves), kept
    /// where the log serves the position — the marker-mirroring rebuild,
    /// above the floor alone. An empty slot contributes nothing; a refusal
    /// rebuilds nothing and drops nothing, and the fence still closes over
    /// it: the journal will not answer it on a later open either, and the
    /// row's own line says LOST — so the refusal is said once, in the
    /// kernel's words ([`RebuildRefusedLine`]).
    ///
    /// THE OPEN'S OTHER LINES: the entry lines past the head the replay
    /// purged, signatures a copy taken before this open still holds
    /// ([`ForeignLinesLine`]); a file ABSENT at this open on a journal that
    /// has reclaimed, every signature it kept at or below the floor gone
    /// ([`BegunAfreshLine`]); and, last, what the store holds — its size,
    /// never compacted, and what the rebuild wrote back ([`AttestOpenLine`]).
    ///
    /// COST: O(the file) to READ it, a line at a time — holding one line and
    /// the served window, never the file, which keeps a line for every
    /// attested commit the board ever made — and, for the tail, ONE
    /// `Kernel::boundaries_above`: the base at or below the fence LOADED and
    /// seeded — a whole checkpoint file read and deserialized, dropped
    /// unfolded — then ONE scan from that base to the journal's end, the
    /// retained window at most, one entry kept per committed transaction
    /// above the base and a signature per attested one; a second such read
    /// where the fence's base is gone (the floor arm). Where nothing is
    /// uncovered — the fence at the head, the last commit attested or the
    /// board reopened twice — no base is loaded and no segment read. What it
    /// does not pay is a base and a scan PER uncovered position: a whole
    /// checkpoint decoded per commit made since the last open, which the
    /// fence's own motion — at an attested commit and at this open's end,
    /// never at an unattested commit — made every reopen of a board that
    /// took only unattested writes pay, a restart measured in minutes to
    /// hours at a large world. Never a compaction: the store keeps what the
    /// log drops.
    pub(super) fn open(
        dir: &Path,
        engine: &Engine,
        log: &CommitsLog,
        lines: &Lines,
    ) -> io::Result<AttestStore> {
        let started = Instant::now();
        let with_file = |e: io::Error| io::Error::new(e.kind(), format!("{ATTEST_FILE}: {e}"));
        let head = log.open_head();
        // Served: a position the log holds, or one in the region the walk
        // behind the listener has yet to land — the log's `(low, head]`,
        // whose rows this store's slots ride once the landing writes them;
        // the rebuild's positions are the kernel's markers' either way.
        let served_only = |at: u64| {
            log.entries().contains_key(&at)
                || log.pending_region().is_some_and(|(low, head)| at > low && at <= head)
        };
        // Absent before the replay creates it: begun afresh. A look that
        // cannot answer counts as present, so it never says a loss it has
        // not seen.
        let absent = !dir.join(ATTEST_FILE).try_exists().unwrap_or(true);
        let (mut file, entries, replayed) =
            LineFile::open(dir, ATTEST_FILE, head, served_only, lines)?;
        if let Some(foreign) = replayed.foreign {
            lines.say(
                Class::Open,
                ForeignLinesLine { name: ATTEST_FILE, foreign, head, what: "signatures" },
            );
        }
        let mut served = BTreeMap::new();
        let mut unreadable: Option<(usize, u64)> = None;
        for (at, m) in &entries {
            match attest_of_record(m) {
                Some(slot) => {
                    served.insert(*at, Arc::new(slot));
                }
                None => {
                    let (count, first) = unreadable.unwrap_or((0, *at));
                    unreadable = Some((count + 1, first.min(*at)));
                }
            }
        }
        if let Some((count, first)) = unreadable {
            lines.say(Class::Failure, UnreadableSlotsLine { count, first });
        }
        let coverage = file.coverage();
        let (tail, refused) = rebuilt_tail(engine, coverage);
        let mut rebuilt = Rebuilt::default();
        for (at, slot) in tail {
            if served_only(at) {
                file.append(at, attest_fields(&slot)).map_err(with_file)?;
                served.insert(at, Arc::new(slot));
                rebuilt.note(at);
            }
        }
        file.fence(head).map_err(with_file)?;
        file.sync().map_err(with_file)?;
        if let Some(account) = &refused {
            lines.say(Class::Failure, RebuildRefusedLine { coverage, head, account });
        }
        // The floor the log's open probed: `None` is a journal that still
        // answers genesis, so every cut line is rebuilt and an absent file
        // lost nothing — the floor is genesis, position 0.
        let floor = log.floor_at_open();
        if let Some(cut) = replayed.cut {
            let rebuilt = refused.is_none();
            lines.say(Class::Failure, AttestCutLine { cut, floor: floor.unwrap_or(0), rebuilt });
        }
        if let (true, Some(floor)) = (absent, floor) {
            lines.say(Class::Failure, BegunAfreshLine { floor, rebuilt: rebuilt.lines });
        }
        let bytes = file.len().map_err(with_file)?;
        let elapsed_ms = started.elapsed().as_millis();
        lines.say(Class::Open, AttestOpenLine { bytes, rebuilt, elapsed_ms });
        Ok(AttestStore { file, served, lines: lines.clone() })
    }

    /// Returns the store's file size in bytes, as its handle reads it.
    ///
    /// The file is never compacted, so this grows by one line (~6.9 KB under
    /// tag 1) per attested commit for the life of the board.
    ///
    /// # Errors
    ///
    /// The handle's metadata could not be read.
    pub(super) fn bytes(&self) -> io::Result<u64> {
        self.file.len()
    }

    /// Mirror one admitted marker slot at RECORD time — the attestation the
    /// plain sequence's check admitted and handed the kernel — into the file,
    /// SYNCED before this returns, and into the served window (SO-I5 (d)).
    /// A failed write or sync stops the file for the uptime, is said ONCE
    /// through the classed door (`operations.md` §1.1 row 33) — this file,
    /// the position, the cause ([`IoCause`]), what still serves and the act,
    /// on a full volume room before the restart — and is answered
    /// [`AttestStoreFailed`], on which the write path halts, so no later
    /// commit runs to say it twice. This uptime still serves the slot, and
    /// the restart's open rebuilds the line from the journal.
    pub(super) fn record(&mut self, at: u64, slot: Attestation) -> Result<(), AttestStoreFailed> {
        let durable = self.file.append_synced(at, attest_fields(&slot));
        self.served.insert(at, Arc::new(slot));
        durable.map_err(|e| {
            self.lines.say(Class::Failure, NotDurableLine { at, error: &e });
            AttestStoreFailed
        })
    }

    /// The test seam behind `skepd::Daemon::attest_store_synced_through`:
    /// the coverage the file's last successful sync made durable. Not a
    /// stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn synced_through(&self) -> u64 {
        self.file.synced()
    }

    /// The test seam behind `skepd::Daemon::fail_the_attest_stores_next_write`:
    /// the file's next write fails at the OS ([`LineFile::make_unwritable`]).
    /// A seam whose act failed PANICS here. Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn fail_next_write(&mut self) {
        self.file.make_unwritable().expect("the test seam's read-only handle");
    }

    /// The slot the store holds for a served position — `None` where it holds
    /// none, which `CommitMeta::entry` renders `null` where the position's
    /// line records the marker filled (LOST) and absent otherwise. A pointer,
    /// cloned: the page that asks renders it after the feed's lock is gone.
    pub(super) fn slot(&self, at: u64) -> Option<Arc<Attestation>> {
        self.served.get(&at).cloned()
    }
}

/// Row 33's words (`operations.md` §1.1 row 33; SO-I5 (d)): the line the
/// store could not make durable, and what the halt it answers costs.
///
/// The words: `feed-attest.log: position {at}'s line is not durable
/// ({cause}); every later write is refused until a restart, whose open
/// rebuilds the line from the journal`, `{cause}` as [`IoCause`] words it.
/// On a full volume it adds `; free room on the volume first: the restart's
/// open writes the line back and syncs it, and on a full volume it refuses
/// and reads stop with it` — a restart before room stands would take down a
/// board that still serves reads. A pure value, pinned by `to_string()` in
/// the unit suite; emitted under `Class::Failure` by [`AttestStore::record`].
struct NotDurableLine<'a> {
    at: u64,
    error: &'a io::Error,
}

impl std::fmt::Display for NotDurableLine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cause = IoCause(self.error);
        write!(
            f,
            "{ATTEST_FILE}: position {}'s line is not durable ({cause}); every later write is \
             refused until a restart, whose open rebuilds the line from the journal",
            self.at
        )?;
        if cause.is_full() {
            f.write_str(
                "; free room on the volume first: the restart's open writes the line back and \
                 syncs it, and on a full volume it refuses and reads stop with it",
            )?;
        }
        Ok(())
    }
}

/// Row 9 for the attest store (`operations.md` §1.1 row 9; §3.6 step 3; §4
/// row 17): the head every cut line opens with, then THE SIDE.
///
/// `coverage ≥ floor` is REBUILT where the rebuild answered: the file is
/// position-ordered, so every cut line's position is above the last trusted
/// one, and the rebuild covers `(coverage, head]` above the floor — the
/// floor's own slot no retained base answers ([`rebuilt_tail`]). Otherwise
/// the lines between the last trusted position and the floor were entry
/// signatures' only copies, LOST unless the board directory's backup is
/// restored; and where the journal refused the rebuild, the cut lines above
/// the floor are lost with them ([`RebuildRefusedLine`] names the account).
/// `floor` is the reclaim floor at this open — genesis, 0, where nothing is
/// reclaimed. Said once the rebuild has run. A pure value, pinned by
/// `to_string()` in the unit suite; emitted under `Class::Failure` by
/// [`AttestStore::open`].
struct AttestCutLine {
    cut: Cut,
    floor: u64,
    /// Whether the journal answered the rebuild.
    rebuilt: bool,
}

impl AttestCutLine {
    /// Returns whether every cut line lies above the reclaim floor.
    fn above_the_floor(&self) -> bool {
        self.cut.trusted >= self.floor
    }
}

impl std::fmt::Display for AttestCutLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let head = CutHead { name: ATTEST_FILE, cut: self.cut };
        match (self.above_the_floor(), self.rebuilt) {
            (true, true) => write!(
                f,
                "{head}; every cut line lies above the reclaim floor at position {} and is \
                 rebuilt from the journal",
                self.floor
            ),
            (true, false) => write!(
                f,
                "{head}; every cut line lies above the reclaim floor at position {}, but the \
                 journal refused their rebuild: they are LOST unless the board directory's \
                 backup is restored",
                self.floor
            ),
            (false, _) => write!(
                f,
                "{head}; the lines between position {} and the reclaim floor at position {} are \
                 LOST unless the board directory's backup is restored",
                self.cut.trusted, self.floor
            ),
        }
    }
}

/// Row 10's words (`operations.md` §1.1 row 10): `feed-attest.log: {n} slots
/// this daemon cannot read, the first at position {p}; their rows serve
/// attest: null, the lines kept as written` — one line per open.
///
/// A pure value, pinned by `to_string()` in the unit suite; emitted under
/// `Class::Failure` by [`AttestStore::open`].
struct UnreadableSlotsLine {
    count: usize,
    first: u64,
}

impl std::fmt::Display for UnreadableSlotsLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{ATTEST_FILE}: {} slots this daemon cannot read, the first at position {}; their \
             rows serve attest: null, the lines kept as written",
            self.count, self.first
        )
    }
}

/// The journal's refusal of the rebuild, said once at the open.
///
/// The words: `feed-attest.log: the journal refused the rebuild above
/// position {c} ({account}): any attested commit in ({c}, {h}] serves
/// attest: null, its line LOST at this store and not retried — restore this
/// file and the segment the account names from a copy taken before this open
/// (RUNBOOK §2)`. Not retried because the open fences the file at the head
/// over it. A pure value, pinned by `to_string()` in the unit suite; emitted
/// under `Class::Failure` by [`AttestStore::open`].
struct RebuildRefusedLine<'a> {
    coverage: u64,
    head: u64,
    account: &'a str,
}

impl std::fmt::Display for RebuildRefusedLine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (c, h) = (self.coverage, self.head);
        write!(
            f,
            "{ATTEST_FILE}: the journal refused the rebuild above position {c} ({}): any \
             attested commit in ({c}, {h}] serves attest: null, its line LOST at this store and \
             not retried — restore this file and the segment the account names from a copy \
             taken before this open (RUNBOOK §2)",
            self.account
        )
    }
}

/// A store absent at this open on a journal that has reclaimed.
///
/// The words: `feed-attest.log was absent at this open and is begun afresh:
/// the attested commits above the reclaim floor at position {f} are rebuilt
/// from the journal ({n} lines); every signature this board kept at or below
/// position {f} is LOST unless the board directory's backup is restored`.
/// Below the floor the store is the only copy, so an absent file is a loss
/// the open cannot make good. A pure value, pinned by `to_string()` in the
/// unit suite; emitted under `Class::Failure` by [`AttestStore::open`].
struct BegunAfreshLine {
    floor: u64,
    rebuilt: usize,
}

impl std::fmt::Display for BegunAfreshLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let floor = self.floor;
        write!(
            f,
            "{ATTEST_FILE} was absent at this open and is begun afresh: the attested commits \
             above the reclaim floor at position {floor} are rebuilt from the journal ({} \
             lines); every signature this board kept at or below position {floor} is LOST \
             unless the board directory's backup is restored",
            self.rebuilt
        )
    }
}

/// The lines the open's rebuild wrote back: how many, and their positions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Rebuilt {
    lines: usize,
    /// The first and the last position rebuilt, where any was.
    span: Option<(u64, u64)>,
}

impl Rebuilt {
    /// Notes one more line rebuilt, at `at`, the rebuild being ascending.
    fn note(&mut self, at: u64) {
        self.lines += 1;
        self.span = Some(self.span.map_or((at, at), |(first, _)| (first, at)));
    }
}

/// The open's report of the store: its size and what the rebuild wrote.
///
/// The words: `feed-attest.log: {bytes} bytes, never compacted; {n} lines
/// rebuilt from the journal's markers (positions {a}–{b}), in {d} ms`, the
/// positions where any line was rebuilt — so the restart row 33 asks for
/// says that it wrote the lost line back. A pure value, pinned by
/// `to_string()` in the unit suite; emitted under `Class::Open` by
/// [`AttestStore::open`], once per open.
struct AttestOpenLine {
    bytes: u64,
    rebuilt: Rebuilt,
    elapsed_ms: u128,
}

impl std::fmt::Display for AttestOpenLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{ATTEST_FILE}: {} bytes, never compacted; {} lines rebuilt from the journal's markers",
            self.bytes, self.rebuilt.lines
        )?;
        if let Some((first, last)) = self.rebuilt.span {
            write!(f, " (positions {first}–{last})")?;
        }
        write!(f, ", in {} ms", self.elapsed_ms)
    }
}

/// THE TAIL REBUILT (the operations design §3.3 step 2): every committed
/// boundary above `coverage` — the file's fence — whose marker slot is
/// filled, in `Seq` order, read in ONE scan: `Kernel::boundaries_above` the
/// fence, from one base at or below it to the journal's end, where a read
/// per position loaded a base per position. Empty slots contribute nothing.
/// A fence at the head asks nothing of the journal: nothing lies above it to
/// rebuild, so no read is made and no refusal can be met — a kernel that
/// keeps no journal refuses every history read, an empty range included.
///
/// THE FLOOR: where the fence's base is gone — the read refuses `Reclaimed`
/// naming a `floor`, the oldest retained checkpoint, above the fence — the
/// list is asked again AT the floor, where the read answers from the base
/// embodying it (its base may sit at its position, where `attestation_at`'s
/// must sit below), and every position in `(coverage, floor]` stays as it
/// was: neither rebuilt nor dropped, its row LOST. A floor at or below the
/// fence names a base that refused to load, which asking again would meet
/// again; asked once. Every other refusal — a `Reclaimed` naming no floor,
/// at-rest damage, I/O — rebuilds nothing, as the per-position read's
/// refusal did: the fence still closes over the tail, the journal will not
/// answer it at a later open either, and each row's own line says LOST —
/// the refusal answered beside the list, in the kernel's words, for the
/// open to say. No retry: the feed opens before the listener and the
/// checkpoint thread, so nothing appends or reclaims under this read and
/// its two transient refusals cannot occur here.
fn rebuilt_tail(engine: &Engine, coverage: u64) -> (Vec<(u64, Attestation)>, Option<String>) {
    let kernel = engine.kernel();
    if coverage >= kernel.current_seq().0 {
        return (Vec::new(), None);
    }
    let listed = match kernel.boundaries_above(Seq(coverage)) {
        Err(HistoryError::Reclaimed { floor: Some(floor), .. }) if floor.0 > coverage => {
            kernel.boundaries_above(floor)
        }
        answered => answered,
    };
    match listed {
        Ok(list) => {
            let slots = list.into_iter().filter_map(|(seq, slot)| slot.map(|slot| (seq.0, slot)));
            (slots.collect(), None)
        }
        Err(e) => (Vec::new(), Some(e.to_string())),
    }
}

/// One attest-store record's two fields for the marker slot `a`: the tag as
/// a number, the blob as lowercase hex — the spelling [`attest_of_record`]
/// reads back, and the one the codec's `j_attest` renders on the wire from
/// the same value (the token for the tag there).
fn attest_fields(a: &Attestation) -> Vec<(&'static str, Value)> {
    vec![
        (ATTEST_ALG, Value::Number(u64::from(a.sig_alg()).into())),
        (ATTEST_SIG, Value::String(hex_string(a.sig()))),
    ]
}

/// The marker slot one replayed attest-store record holds — [`attest_fields`]'s
/// inverse — or `None` where its spelling is not [`attest_fields`]'s: a tag
/// past a byte or of no signature (`0`), a blob of no bytes, hex not in
/// `hex_string`'s own lowercase. It admits EVERY slot `Attestation::new`
/// admits — a tag no `SIG_ALGS` row names included, as a slot rebuilt from a
/// marker another build wrote may carry one — so a consumer asks the slot's
/// row of the table and owns the answer for a tag with none, as the codec's
/// `j_attest` does.
fn attest_of_record(m: &Map<String, Value>) -> Option<Attestation> {
    let tag = u8::try_from(m.get(ATTEST_ALG)?.as_u64()?).ok()?;
    let sig = parse_lower_hex_bytes(m.get(ATTEST_SIG)?.as_str()?)?;
    Attestation::new(tag, sig).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A slot the store records is served at once and replays from its line
    /// as the same slot — [`attest_fields`] and [`attest_of_record`] one
    /// spelling in both directions — and a line [`attest_fields`] could not
    /// have spelled replays as no slot: an uppercase blob, a tag of no
    /// signature, a tag past a byte, an empty blob. A tag no `SIG_ALGS` row
    /// names is a slot all the same: the table is its consumer's to ask.
    #[test]
    fn a_recorded_slot_is_served_and_replays_from_its_line_as_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lines = Lines::new();
        let slot = Attestation::new(1, vec![0xab, 0x01]).expect("tag 1 and a non-empty blob");
        {
            let (file, entries, replayed) =
                LineFile::open(dir.path(), ATTEST_FILE, 9, |_| true, &lines)
                    .expect("a fresh store opens");
            assert!(entries.is_empty() && replayed.cut.is_none() && replayed.foreign.is_none());
            let mut store = AttestStore { file, served: BTreeMap::new(), lines: lines.clone() };
            store.record(5, slot.clone()).expect("a writable store takes the line");
            assert_eq!(store.synced_through(), 5, "and syncs it before answering");
            assert_eq!(store.slot(5).as_deref(), Some(&slot), "served at once");
            assert_eq!(store.slot(4).as_deref(), None, "and only where recorded");
            assert!(lines.said().lock().is_empty(), "a line that landed says nothing");
        }
        let (_file, entries, _) =
            LineFile::open(dir.path(), ATTEST_FILE, 9, |_| true, &lines).expect("reopen");
        let replayed: Vec<(u64, Option<Attestation>)> =
            entries.iter().map(|(at, m)| (*at, attest_of_record(m))).collect();
        assert_eq!(replayed, [(5, Some(slot))], "the line replays as the slot it mirrors");

        let record = |alg: Value, sig: &str| {
            let mut m = Map::new();
            m.insert(ATTEST_ALG.to_string(), alg);
            m.insert(ATTEST_SIG.to_string(), Value::String(sig.to_string()));
            m
        };
        for (alg, sig, why) in [
            (Value::from(1u64), "AB01", "hex not in the store's own lowercase"),
            (Value::from(0u64), "ab01", "the empty slot's tag signs nothing"),
            (Value::from(256u64), "ab01", "a tag past a byte"),
            (Value::from(1u64), "", "a blob of no bytes"),
        ] {
            assert_eq!(attest_of_record(&record(alg, sig)), None, "{why}");
        }
        assert_eq!(
            attest_of_record(&record(Value::from(200u64), "ab01")),
            Attestation::new(200, vec![0xab, 0x01]).ok(),
            "a tag no row names replays as the slot it spells"
        );
    }

    /// ROW 33 ON THE DOOR (`operations.md` §1.1 row 33; SO-I5 (d)): a line
    /// the store cannot make durable — its handle read-only, the seam
    /// `fail_next_write` — is answered [`AttestStoreFailed`] and said
    /// through the classed door under `failure:`, in the ruled words: the
    /// file, the position, the cause, what still serves and the act. The
    /// slot is served this uptime all the same. ONCE by the halt above: the
    /// write path refuses every later commit on the answer, so no later
    /// `record` runs — the file's own refusal of a later line is the halt's
    /// premise, not this card's rate.
    #[test]
    fn a_line_the_store_cannot_make_durable_is_said_through_the_door_and_answered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lines = Lines::new();
        let (file, _, _) = LineFile::open(dir.path(), ATTEST_FILE, 9, |_| true, &lines)
            .expect("a fresh store opens");
        let mut store = AttestStore { file, served: BTreeMap::new(), lines: lines.clone() };
        store.fail_next_write();
        let slot = Attestation::new(1, vec![0xab, 0x01]).expect("a slot");
        assert!(store.record(5, slot.clone()).is_err(), "answered, so the write path halts");
        assert_eq!(store.slot(5).as_deref(), Some(&slot), "served this uptime all the same");
        let said = lines.said().lock().clone();
        assert_eq!(said.len(), 1, "one line for the failure:\n{}", said.join("\n"));
        assert!(
            said[0].starts_with("failure: feed-attest.log: position 5's line is not durable ("),
            "the class word, the file and the position: {}",
            said[0]
        );
        assert!(
            said[0].ends_with(
                "); every later write is refused until a restart, whose open rebuilds the line \
                 from the journal"
            ),
            "what still serves and the act: {}",
            said[0]
        );
    }

    /// Row 9's attest words, all three sides, and row 10's: the cut is
    /// REBUILT exactly where `coverage ≥ floor` and the journal answered —
    /// the last trusted position at the floor included, the floor's own slot
    /// below every cut line — and LOST below, a last trusted position one
    /// below the floor included, since no retained base answers the floor's
    /// own slot; LOST above too where the journal refused the rebuild. A
    /// journal still answering genesis is the floor at 0, every cut rebuilt.
    #[test]
    fn the_attest_cut_names_the_floor_and_its_side_and_the_unreadable_slots_their_count() {
        let cut = Cut { valid_end: 1_400, len: 2_000, trusted: 40 };
        let head = "feed-attest.log: trust ends at position 40 (byte 1400 of 2000); the 600 bytes \
                    after it are cut";
        let line = |floor, rebuilt| AttestCutLine { cut, floor, rebuilt }.to_string();
        let rebuilt = |floor| {
            format!(
                "{head}; every cut line lies above the reclaim floor at position {floor} and is \
                 rebuilt from the journal"
            )
        };
        let lost = |floor| {
            format!(
                "{head}; the lines between position 40 and the reclaim floor at position {floor} \
                 are LOST unless the board directory's backup is restored"
            )
        };
        assert_eq!(line(40, true), rebuilt(40), "coverage = floor: rebuilt");
        assert_eq!(line(0, true), rebuilt(0), "nothing reclaimed: the floor is genesis");
        assert_eq!(line(41, true), lost(41), "coverage + 1 = floor: the floor's slot is lost");
        assert_eq!(line(42, true), lost(42), "coverage + 1 < floor: lost");
        assert_eq!(
            line(40, false),
            format!(
                "{head}; every cut line lies above the reclaim floor at position 40, but the \
                 journal refused their rebuild: they are LOST unless the board directory's \
                 backup is restored"
            ),
            "above the floor, the rebuild refused: lost"
        );
        assert_eq!(
            UnreadableSlotsLine { count: 3, first: 17 }.to_string(),
            "feed-attest.log: 3 slots this daemon cannot read, the first at position 17; their \
             rows serve attest: null, the lines kept as written"
        );
    }

    /// The open's other lines and row 33's two endings, at fixed inputs: the
    /// refused rebuild with the account and the region; the absent store
    /// with the floor and the count; the store's size with the positions
    /// rebuilt, and with none; and the line not made durable, the act a full
    /// volume adds after it and no other cause does.
    #[test]
    fn the_open_and_the_halt_say_what_the_store_holds_and_what_is_lost() {
        assert_eq!(
            RebuildRefusedLine { coverage: 12, head: 30, account: "journal corrupt at rest" }
                .to_string(),
            "feed-attest.log: the journal refused the rebuild above position 12 (journal corrupt \
             at rest): any attested commit in (12, 30] serves attest: null, its line LOST at this \
             store and not retried — restore this file and the segment the account names from a \
             copy taken before this open (RUNBOOK §2)"
        );
        assert_eq!(
            BegunAfreshLine { floor: 2049, rebuilt: 3 }.to_string(),
            "feed-attest.log was absent at this open and is begun afresh: the attested commits \
             above the reclaim floor at position 2049 are rebuilt from the journal (3 lines); \
             every signature this board kept at or below position 2049 is LOST unless the board \
             directory's backup is restored"
        );
        let mut rebuilt = Rebuilt::default();
        let open = |rebuilt| AttestOpenLine { bytes: 20_700, rebuilt, elapsed_ms: 4 }.to_string();
        assert_eq!(
            open(rebuilt),
            "feed-attest.log: 20700 bytes, never compacted; 0 lines rebuilt from the journal's \
             markers, in 4 ms"
        );
        for at in [7, 9, 12] {
            rebuilt.note(at);
        }
        assert_eq!(
            open(rebuilt),
            "feed-attest.log: 20700 bytes, never compacted; 3 lines rebuilt from the journal's \
             markers (positions 7–12), in 4 ms"
        );
        let durable =
            |kind| NotDurableLine { at: 5, error: &io::Error::new(kind, "no room") }.to_string();
        let halt = "feed-attest.log: position 5's line is not durable";
        let rest = "every later write is refused until a restart, whose open rebuilds the line \
                    from the journal";
        assert_eq!(durable(io::ErrorKind::Other), format!("{halt} (no room); {rest}"));
        assert_eq!(
            durable(io::ErrorKind::StorageFull),
            format!(
                "{halt} (the volume is full (no room)); {rest}; free room on the volume first: \
                 the restart's open writes the line back and syncs it, and on a full volume it \
                 refuses and reads stop with it"
            )
        );
    }
}
