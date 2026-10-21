//! The attest store: the marker slot's signature per attested position.
//!
//! It is `feed-attest.log` (signed ops; the design record §7.3 (i)), which
//! `GET /changes` serves as the row's `attest` member (`CommitMeta::entry`).
//! It rides [`LineFile`]'s line discipline under a class of its own:
//!
//! One line per *attested* position — `alg` the marker's `sig_alg` tag (the
//! wire's token is rendered at serve), `sig` the blob as lowercase hex,
//! byte-equal to what the request presented — appended at commit from the
//! value the plain sequence admitted and handed the kernel, under the write
//! path's serialization lock in the same `record` that appends `commits.log`;
//! rebuilt on loss or a short tail from the kernel's markers in one scan —
//! `Kernel::boundaries_above` the file's fence, every committed boundary
//! above it with its slot, from one base (the operations design §3.3 step
//! 2) — for every served position the journal still answers, above the
//! reclaim floor alone — a position the journal refuses `Reclaimed` is
//! neither rebuilt nor dropped, and its row renders `attest: null` (lost)
//! where its line records the marker filled, and the list is asked again at
//! the floor the refusal names, for the positions above it
//! ([`rebuilt_tail`]). Below the floor the checkpoint body holds no marker,
//! so a line here is an entry signature's *only* copy at the origin: there
//! the store is primary state and not a projection — never compacted to the
//! journal's retention (where `commits.log` and the four derived sidecars
//! drop their entries below the floor at open, this file *keeps* them),
//! neither prunable nor rebuildable, backed up by location with the board
//! directory as `blobs/` is, its loss served as `null`. The coverage fence,
//! the foreign-line purge and the stop on a failed append apply as in the
//! four, and so does the truncation, which does not stop at the floor:
//! trust ends at the first line that is torn or does not parse
//! ([`LineFile::open`]), and every line after it is cut — below the floor
//! too, where each was an entry signature's only copy. A crash tears the
//! file's newest lines, at the head's end, which the journal still answers
//! and the open rebuilds; a cut that reaches below the floor is damage to
//! the file. The open names every cut on the operator stream with the last
//! trusted position, the reclaim floor at this open and *the side* the cut
//! reached ([`AttestCutLine`]) — rebuilt where every cut line lies above the
//! floor and the journal answered the rebuild; otherwise lost, between the
//! edge they lie above and the floor, or above the floor where the journal
//! refused the rebuild. The edge is the greatest of what the open can
//! witness: the last trusted position, the file being position-ordered; the
//! position before the one a torn line at the file's end names, where its
//! `at` stands whole; and the board term's, at or below which no write is
//! attested ([`Attested`]). So a crash's tear reads as rebuilt wherever a
//! witness names its side, and the board directory's backup is restored on
//! a lost cut alone. No read serves a below-floor slot (`/changes` answers
//! `410 history_reclaimed` below the feed's floor): the lines below it are
//! kept for a read no route of this build serves, the class being the design
//! record's and not this build's to narrow.
//!
//! **Durable before the next commit, and a failed line halts writes**
//! (SO-I5 (d): no signature the board keeps is lost by a crash, a power loss or
//! a failed write). The checkpoint that reclaims a position's journal segment
//! is triggered by a later commit than the position's own and runs on the
//! daemon's checkpoint thread — the kernel's cadence crosses within a commit
//! and sets the flag that thread services, the thread notified after that
//! commit's record step, and the backstop running inline within the later
//! commit itself — and it reclaims only below the oldest checkpoint the kernel
//! retains, which is strictly below the root it embodies; and every commit
//! opens after the previous write's record step, under the write path's
//! serialization lock. So the record step syncs the line before it returns —
//! [`AttestStore::record`] appends it under the feed's lock, owing its sync
//! ([`LineFile::append_owing_sync`]), and the feed makes it durable through the
//! file's own [`SyncHandle`] once that lock is released, under the
//! serialization guard the record step holds (`Feed::record`), so no page or
//! `/health` probe waits on the fsync — and the line is on disk before any
//! commit that could take the journal's copy away can begin; the open syncs
//! what it rebuilt before the first commit, for the same reason. The four
//! derived files' appends are not synced: what they lose, the next open
//! re-derives. A write or a sync that fails stops this file as a failed
//! append stops theirs, and — the file being primary where theirs are
//! projections — it halts the write path: the record answers
//! [`super::AttestStoreFailed`], and the daemon refuses every later write
//! until a restart, since any commit could trigger the checkpoint that
//! deletes the journal copy the lost line depends on. The restart's open
//! rebuilds the line from the journal, which the halt kept.
//!
//! What keeps the class is this card's privacy: [`AttestStore`]'s file is its
//! own, and nothing rewrites it but [`LineFile::open`]'s purge of the lines
//! above the head — another journal's — which copies every entry line of
//! this journal verbatim, so no other card can compact it.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{Map, Value};
use skep_engine::{Engine, World};
use skep_identity::HasIdentity;
use skep_kernel::{Attestation, HistoryError, Seq};
use skep_util::json::hex_string;
use skep_util::notice::Class;

use super::super::board_term;
use super::super::sidecar::{
    CommitsLog, Cut, CutHead, EntryLines, ForeignLinesLine, IoCause, KeptName,
};
use super::super::Lines;
use super::derived::{LineFile, OwedSync, SyncHandle};
use super::{AttestStoreFailed, AttestStoreFigures};
use crate::codec::parse_lower_hex_bytes;

// The file is named beside the fields its records carry, and both beside the
// line's one writer ([`attest_fields`]) and its one reader
// ([`attest_of_record`]): a write site that spelled a field apart from the
// read site would write lines that replay as no slot.

/// The store's file.
const ATTEST_FILE: &str = "feed-attest.log";
/// Its records' first field: the marker's `sig_alg` tag, a number.
const ATTEST_ALG: &str = "alg";
/// Its records' second field: the signature blob, lowercase hex.
const ATTEST_SIG: &str = "sig";

/// The attest store: its file, and the slots of the positions the feed serves.
///
/// The slots are resident at one blob (~3.4 KB under tag 1) per attested
/// position `commits.log` serves, the window above the reclaim floor, trimmed
/// with the log at every compaction ([`AttestStore::drop_at_or_below`]), so the
/// journal's retained window bounds them. The file holds more: every line
/// appended that no cut or purge has taken, the positions the log compacted
/// away included, where the store is primary state.
pub(super) struct AttestStore {
    /// `feed-attest.log`: appended, replayed and fenced, and never compacted.
    file: LineFile,
    /// Position → the marker slot, for the served positions.
    ///
    /// Each slot sits behind an `Arc`, so a page rendered after the feed's
    /// lock is released ([`super::Feed::page`]) clones a pointer, never a
    /// signature.
    served: BTreeMap<u64, Arc<Attestation>>,
    /// The classed door with the daemon's record ([`Lines`]).
    ///
    /// It is a clone held from the open as the line files hold theirs: what
    /// the halt's line (`operations.md` §1.1 row 33) is said through, once.
    lines: Lines,
}

impl AttestStore {
    /// Opens the store beside the replayed `log`, and its file's sync handle.
    ///
    /// It replays every line at or below the head, a line at a time, holding
    /// resident the served window alone — the lines below the log's fence are
    /// read past and stay in the file, untouched — then rebuilds the missing
    /// tail from the journal's markers in one scan, then fences at the head and
    /// syncs, so every line the open rebuilt is on disk before the first commit
    /// can begin (SO-I5 (d)). Beside the store it answers the file's
    /// [`SyncHandle`], duplicated once the replay is done: what the record step
    /// makes each line durable through, off the feed's lock.
    ///
    /// A served position's line this daemon cannot read (a tag of no
    /// signature, a blob of none, hex it did not write) is counted and not
    /// held — said once per open with the count and the first position
    /// (`operations.md` §1.1 row 10), the file never compacted and the line
    /// never rewritten, so each open meets it again: the row then renders
    /// `attest: null` where its line records the marker filled, never an
    /// invented slot. A cut the replay made is said once the rebuild has run,
    /// with the floor and the side it reached ([`AttestCutLine`]), the floor
    /// the log's open probed (`CommitsLog::floor_at_open`, the open's one
    /// probe) — the same refusal the rebuild below meets where its fence's
    /// base is gone, both the kernel's one base selection naming the oldest
    /// retained checkpoint — and the edge of the board's attested positions
    /// read off the head beside it ([`Attested`]). The tail is every committed
    /// boundary above the file's coverage whose slot is filled, listed by
    /// `Kernel::boundaries_above` in one scan from one base ([`rebuilt_tail`]:
    /// the floor arm, and what a refusal leaves), kept where the log serves
    /// the position — the marker-mirroring rebuild, above the floor alone. An
    /// empty slot contributes nothing; a refusal rebuilds nothing and drops
    /// nothing, and the fence still closes over it: the journal will not
    /// answer it on a later open either, and the row's own line says its slot
    /// is lost — so the refusal is said once, in the kernel's words
    /// ([`RebuildRefusedLine`]).
    ///
    /// **The open's other lines.** It says the entry lines past the head the
    /// replay purged, signatures a copy taken before this open still holds
    /// ([`ForeignLinesLine`]); a file absent at this open where an attested
    /// position can lie at or below the reclaim floor, every signature it kept
    /// there gone ([`BegunAfreshLine`]); and, last, what the store holds — its
    /// size, never compacted, the slots resident — and what the rebuild wrote
    /// back ([`AttestOpenLine`]).
    ///
    /// **Cost.** O(the file) to read it, a line at a time — holding one line
    /// and the served window, never the file, which keeps a line for every
    /// attested commit the board ever made — and, for the tail, one
    /// `Kernel::boundaries_above`: the base at or below the fence loaded and
    /// seeded — a whole checkpoint file read and deserialized, dropped unfolded
    /// — then one scan from that base to the journal's end, the retained window
    /// at most, one entry kept per committed transaction above the base and a
    /// signature per attested one; a second such read where the fence's base is
    /// gone (the floor arm). Where nothing is uncovered — the fence at the
    /// head, the last commit attested or the board reopened twice — no base is
    /// loaded and no segment read. What it does not pay is a base and a scan
    /// per uncovered position: a whole checkpoint decoded per commit made since
    /// the last open, which — the fence moving at an attested commit and at
    /// this open's end, never at an unattested commit — every reopen of a board
    /// that took only unattested writes would pay, a restart measured in
    /// minutes to hours at a large world. Never a compaction: the store keeps
    /// what the log drops.
    ///
    /// # Errors
    ///
    /// Every failure names this file, the kind kept (`operations.md` §1.1 row
    /// 2): the replay's through `LineFile::open`; the rebuilt lines' appends,
    /// the fence, the sync, the size and the handle's duplication through one
    /// closure here.
    pub(super) fn open(
        dir: &Path,
        engine: &Engine,
        log: &CommitsLog,
        lines: &Lines,
    ) -> io::Result<(AttestStore, SyncHandle)> {
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
        if let (Some(foreign), Some(kept)) = (replayed.foreign, replayed.foreign_kept) {
            // The second copy: a line here is a marker's slot mirrored, so
            // after a journal tail cut the cut commits' markers hold these
            // signatures too — in the files the journal's open kept at this
            // start, where it kept any.
            let journal_kept = engine
                .recovery()
                .map(|recovery| recovery.tail_cut_kept.clone())
                .unwrap_or_default();
            let line = ForeignLinesLine {
                name: ATTEST_FILE,
                foreign,
                head,
                what: "signatures",
                kept,
                journal_kept,
            };
            lines.say(Class::Open, line);
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
        // answers genesis, so every cut line lies above the floor, rebuilt
        // where the journal answered the rebuild, and an absent file lost
        // nothing — the floor is genesis, position 0. Beside it, where an
        // attested position can lie at all, read off the head.
        let floor = log.floor_at_open();
        let attested = Attested::of(engine.kernel().snapshot().world());
        if let Some(cut) = replayed.cut {
            let rebuilt = refused.is_none();
            let floor = floor.unwrap_or(0);
            let kept = replayed.kept;
            lines.say(Class::Failure, AttestCutLine { cut, floor, attested, rebuilt, kept });
        }
        if let (true, Some(floor)) = (absent, floor) {
            if let Some(above) = attested.edge().filter(|&edge| edge < floor) {
                let rebuilt = rebuilt.lines;
                lines.say(Class::Failure, BegunAfreshLine { above, floor, rebuilt });
            }
        }
        let bytes = file.len().map_err(with_file)?;
        let sync = file.sync_handle().map_err(with_file)?;
        let elapsed_ms = started.elapsed().as_millis();
        let slots = served.len();
        lines.say(Class::Open, AttestOpenLine { bytes, slots, rebuilt, elapsed_ms });
        Ok((AttestStore { file, served, lines: lines.clone() }, sync))
    }

    /// Returns what the store holds: its file's size and the slots resident.
    ///
    /// The file is never compacted, so it grows by one line (~6.9 KB under
    /// tag 1) per attested commit for the life of the board; the slots
    /// resident are one blob (~3.4 KB) per attested position the feed serves,
    /// trimmed at every compaction ([`AttestStore::drop_at_or_below`]). The
    /// size is `None` where the handle's metadata could not be read.
    pub(super) fn figures(&self) -> AttestStoreFigures {
        AttestStoreFigures { bytes: self.file.len().ok(), slots: self.served.len() }
    }

    /// Drops the served slots at or below `fence`.
    ///
    /// The positions are the ones the feed's compaction has just dropped from
    /// its twins (`Inner::drop_at_or_below`), at or below the fence one under
    /// the reclaim floor, where `/changes` answers `410 history_reclaimed` and
    /// no page renders a slot. The file keeps every line: below the floor it
    /// is primary state, and nothing here touches it.
    pub(super) fn drop_at_or_below(&mut self, fence: u64) {
        self.served = self.served.split_off(&fence.saturating_add(1));
    }

    /// Mirrors one admitted marker slot into the file and the served window.
    ///
    /// The slot is the attestation the plain sequence's check admitted and
    /// handed the kernel, mirrored at record time (SO-I5 (d)): into the file,
    /// its sync owed ([`OwedSync`]: the record step makes it through the file's
    /// [`SyncHandle`] before it returns, off the feed's lock), and into the
    /// served window. This uptime serves the slot whatever the file answers,
    /// and where the line is lost the restart's open rebuilds it from the
    /// journal.
    ///
    /// # Errors
    ///
    /// [`AttestStoreFailed`] where the line could not be written: the file
    /// stops for the uptime and row 33 is said once through the classed door
    /// (`operations.md` §1.1 row 33) — this file, the position, the cause
    /// ([`IoCause`]), what still serves and the act, the cause cleared before
    /// the restart — and the write path halts on the answer, so no later commit
    /// runs to say it twice. A failed sync is said and answered alike
    /// ([`AttestStore::sync_failed`]).
    pub(super) fn record(
        &mut self,
        at: u64,
        slot: Attestation,
    ) -> Result<OwedSync, AttestStoreFailed> {
        let appended = self.file.append_owing_sync(at, attest_fields(&slot));
        self.served.insert(at, Arc::new(slot));
        appended.map_err(|e| {
            self.lines.say(Class::Failure, NotDurableLine { at, error: &e });
            AttestStoreFailed
        })
    }

    /// Stops the file where `owed`'s sync failed, and says row 33 once.
    ///
    /// It is [`AttestStore::record`]'s failure, met after the record step
    /// released the feed's lock: the line, the halt it answers and the act,
    /// as a failed write says them ([`NotDurableLine`]).
    pub(super) fn sync_failed(&mut self, owed: OwedSync, error: &io::Error) {
        let at = owed.at;
        self.file.stop_after_a_failed_sync(owed);
        self.lines.say(Class::Failure, NotDurableLine { at, error });
    }

    /// Settles `owed`, its sync made: the test seam's mark moves to it.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn settle(&mut self, owed: OwedSync) {
        self.file.settle(owed);
    }

    /// The test seam behind `skepd::Daemon::attest_store_synced_through`.
    ///
    /// It answers the coverage the file's last successful sync made durable.
    /// Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn synced_through(&self) -> u64 {
        self.file.synced()
    }

    /// The test seam behind `skepd::Daemon::fail_the_attest_stores_next_write`.
    ///
    /// The file's next write fails at the OS ([`LineFile::make_unwritable`]).
    /// Not a stable API.
    ///
    /// # Panics
    ///
    /// A seam whose act failed panics here: the read-only handle on the file
    /// could not be opened.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn fail_next_write(&mut self) {
        self.file.make_unwritable().expect("the test seam's read-only handle");
    }

    /// Returns the slot the store holds for a served position.
    ///
    /// It is `None` where the store holds none, which `CommitMeta::entry`
    /// renders `null` where the position's line records the marker filled
    /// (lost) and absent otherwise. A pointer, cloned: the page that asks
    /// renders it after the feed's lock is gone.
    pub(super) fn slot(&self, at: u64) -> Option<Arc<Attestation>> {
        self.served.get(&at).cloned()
    }
}

/// Row 33's words: the line the store could not make durable, and its cost.
///
/// It is `operations.md` §1.1 row 33's line (SO-I5 (d)): the line and what
/// the halt it answers costs. The words: `feed-attest.log: position {at}'s
/// line is not durable ({cause}); every later write is refused until a
/// restart, whose open rebuilds the line from the journal`, `{cause}` as
/// [`IoCause`] words it.
/// On a full volume it adds `; free room on the volume first: the restart's
/// open writes the line back and syncs it, and on a full volume it refuses
/// and reads stop with it`, and for every other cause `; check the volume,
/// its device and the board user's quota first: the restart's open writes
/// the line back and syncs it, and where its cause stands it refuses and
/// reads stop with it` — a restart before the cause clears would take down a
/// board that still serves reads. A pure value, pinned by `to_string()` in
/// the unit suite; emitted under `Class::Failure` by [`AttestStore::record`]
/// and [`AttestStore::sync_failed`].
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
        f.write_str(if cause.is_full() {
            "; free room on the volume first: the restart's open writes the line back and syncs \
             it, and on a full volume it refuses and reads stop with it"
        } else {
            "; check the volume, its device and the board user's quota first: the restart's open \
             writes the line back and syncs it, and where its cause stands it refuses and reads \
             stop with it"
        })
    }
}

/// Where this board's attested positions can lie, as the head shows it.
///
/// A marker slot is filled by an attested write alone, which the write-path
/// check admits on a claimed board over the board term — `H.1`'s pair, read
/// before the member is asked for (signed-ops D13; `attestation_check`'s
/// step 4) — so an unclaimed board holds no attested position, and a claimed
/// one none at or below the position its board term names. The cut line and
/// the absent store's line measure a loss against it: a line this file kept
/// at or below that edge is no signature this journal made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attested {
    /// An unclaimed board: no write is attested.
    Nowhere,
    /// Every attested position lies above this one.
    ///
    /// It is the board term's position, or 0 where the head reads no `H.1`
    /// on a claimed board.
    Above(u64),
}

impl Attested {
    /// Returns where `world`'s attested positions can lie.
    fn of(world: &World) -> Attested {
        if world.identity().claimant().is_none() {
            return Attested::Nowhere;
        }
        Attested::Above(board_term(world).map_or(0, |term| term.log_position))
    }

    /// Returns the position every attested one lies above, `None` for none.
    fn edge(self) -> Option<u64> {
        match self {
            Attested::Nowhere => None,
            Attested::Above(edge) => Some(edge),
        }
    }
}

/// Row 9 for the attest store: the cut line's head, then the side it reached.
///
/// It is `operations.md` §1.1 row 9's line (§3.6 step 3; §4 row 17).
///
/// **The edge.** Every cut line lies above an edge, the greatest of three
/// witnesses: the last trusted position, the file being position-ordered;
/// the position before the one a torn line at the file's end names, where
/// its `at` stands whole ([`Cut`]'s `first`); and the edge of the board's
/// attested positions ([`Attested`]), no line of this journal lying at or
/// below it.
///
/// **The side.** An edge at or above the floor reads rebuilt where the
/// rebuild answered: the rebuild covers `(coverage, head]` above the floor,
/// the floor's own slot no retained base answers ([`rebuilt_tail`]). A crash
/// tears a line above the floor, the store's durable-before-the-next-commit
/// premise, so its cut reads as rebuilt wherever a witness names its side.
/// Otherwise the lines between the edge and the floor may be entry
/// signatures' only copies, LOST to the feed — standing in the file the open
/// kept the cut bytes in, where the cut was a damaged line's
/// (`, kept in {kept}` after the head, and the lost arm's `unless restored
/// from {kept} or the board directory's backup`), and otherwise lost unless
/// the board directory's backup is restored; and where the journal refused
/// the rebuild, the cut lines above the floor are lost with them
/// ([`RebuildRefusedLine`] names the account). Each lost arm adds the whole
/// lines the cut took with it, where it took any: `; the cut took {m} whole
/// lines with it, positions {a}–{b}`.
///
/// `floor` is the reclaim floor at this open — genesis, 0, where nothing is
/// reclaimed. Said once the rebuild has run. A pure value, pinned by
/// `to_string()` in the unit suite; emitted under `Class::Failure` by
/// [`AttestStore::open`].
struct AttestCutLine {
    cut: Cut,
    floor: u64,
    attested: Attested,
    /// Whether the journal answered the rebuild.
    rebuilt: bool,
    /// The file the cut bytes were kept in: a damaged line's cut, never a
    /// torn line's.
    kept: Option<KeptName>,
}

impl AttestCutLine {
    /// Returns the position every cut line lies above.
    fn edge(&self) -> u64 {
        let torn = self.cut.first.map_or(0, |at| at.saturating_sub(1));
        let attested = self.attested.edge().unwrap_or(u64::MAX);
        self.cut.trusted.max(torn).max(attested)
    }

    /// Returns whether every cut line lies above the reclaim floor.
    fn above_the_floor(&self) -> bool {
        self.edge() >= self.floor
    }

    /// Writes the whole lines the cut took with it, where it took any.
    ///
    /// # Errors
    ///
    /// The formatter's error, where its write fails.
    fn whole_after(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.cut.whole_after {
            Some(EntryLines { lines, first, last }) => {
                write!(f, "; the cut took {lines} whole lines with it, positions {first}–{last}")
            }
            None => Ok(()),
        }
    }
}

impl std::fmt::Display for AttestCutLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", CutHead { name: ATTEST_FILE, cut: self.cut })?;
        if let Some(kept) = self.kept {
            write!(f, ", kept in {}", kept.of(ATTEST_FILE))?;
        }
        let unless = match self.kept {
            Some(kept) => {
                format!(
                    "unless restored from {} or the board directory's backup",
                    kept.of(ATTEST_FILE)
                )
            }
            None => "unless the board directory's backup is restored".to_string(),
        };
        match (self.above_the_floor(), self.rebuilt) {
            (true, true) => write!(
                f,
                "; every cut line lies above the reclaim floor at position {} and is rebuilt \
                 from the journal",
                self.floor
            ),
            (true, false) => {
                write!(
                    f,
                    "; every cut line lies above the reclaim floor at position {}, but the \
                     journal refused their rebuild: they are LOST {unless}",
                    self.floor
                )?;
                self.whole_after(f)
            }
            (false, _) => {
                write!(
                    f,
                    "; the lines between position {} and the reclaim floor at position {} are \
                     LOST {unless}",
                    self.edge(),
                    self.floor
                )?;
                self.whole_after(f)
            }
        }
    }
}

/// Row 10's words: the slots this daemon cannot read, one line per open.
///
/// It is `operations.md` §1.1 row 10's line: `feed-attest.log: {n} slots
/// this daemon cannot read, the first at position {p}; their rows serve
/// attest: null, the lines kept as written`.
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

/// A store absent at this open where it can have kept a signature alone.
///
/// The words: `feed-attest.log was absent at this open and is begun afresh:
/// the attested commits above the reclaim floor at position {f} are rebuilt
/// from the journal ({n} lines); every signature this board kept between
/// position {p} and position {f} is LOST unless the board directory's backup
/// is restored`. Below the floor the store is the only copy, so an absent
/// file is a loss the open cannot make good — said where an attested
/// position can lie at or below the floor, above `{p}`, the edge of the
/// board's attested positions ([`Attested`]); an unclaimed board, or one
/// whose board term stands at or above the floor, lost none. A pure value,
/// pinned by `to_string()` in the unit suite; emitted under
/// `Class::Failure` by [`AttestStore::open`].
struct BegunAfreshLine {
    /// The edge every attested position lies above.
    above: u64,
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
             lines); every signature this board kept between position {} and position {floor} \
             is LOST unless the board directory's backup is restored",
            self.rebuilt, self.above
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

/// The open's report of the store: what it holds and what the rebuild wrote.
///
/// The words: `feed-attest.log: {bytes} bytes, never compacted, {s} slots
/// resident; {n} lines rebuilt from the journal's markers (positions
/// {a}–{b}), in {d} ms` — the slots the served window holds resident, one
/// per attested position above the reclaim floor, and the positions where
/// any line was rebuilt, so the restart row 33 asks for says that it wrote
/// the lost line back. A pure value, pinned by `to_string()` in the unit
/// suite; emitted under `Class::Open` by [`AttestStore::open`], once per
/// open.
struct AttestOpenLine {
    bytes: u64,
    slots: usize,
    rebuilt: Rebuilt,
    elapsed_ms: u128,
}

impl std::fmt::Display for AttestOpenLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{ATTEST_FILE}: {} bytes, never compacted, {} slots resident; {} lines rebuilt from \
             the journal's markers",
            self.bytes, self.slots, self.rebuilt.lines
        )?;
        if let Some((first, last)) = self.rebuilt.span {
            write!(f, " (positions {first}–{last})")?;
        }
        write!(f, ", in {} ms", self.elapsed_ms)
    }
}

/// Returns the tail rebuilt (the operations design §3.3 step 2).
///
/// It is every committed boundary above `coverage` — the file's fence —
/// whose marker slot is filled, in `Seq` order, read in one scan:
/// `Kernel::boundaries_above` the fence, from one base at or below it to the
/// journal's end, where a read per position would load a base per position.
/// Empty slots contribute nothing. A fence at the head asks nothing of the
/// journal: nothing lies above it to rebuild, so no read is made and no
/// refusal can be met — a kernel that keeps no journal refuses every history
/// read, an empty range included.
///
/// **The floor.** Where the fence's base is gone — the read refuses
/// `Reclaimed` naming a `floor`, the oldest retained checkpoint, above the
/// fence — the list is asked again *at* the floor, where the read answers
/// from the base embodying it (its base may sit at its position, where
/// `attestation_at`'s must sit below), and every position in
/// `(coverage, floor]` stays as it was: neither rebuilt nor dropped, its row
/// lost. A floor at or below the fence names a base that refused to load,
/// which asking again would meet again; asked once. Every other refusal — a
/// `Reclaimed` naming no floor, at-rest damage, I/O — rebuilds nothing: the
/// fence still closes over the tail, the journal will not answer it at a
/// later open either, and each row's own line says lost — the refusal
/// answered beside the list, in the kernel's words, for the open to say. No
/// retry: the feed opens before the listener and the checkpoint thread, so
/// nothing appends or reclaims under this read and its two transient
/// refusals cannot occur here.
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

/// Returns one attest-store record's two fields for the marker slot `a`.
///
/// They are the tag as a number and the blob as lowercase hex — the spelling
/// [`attest_of_record`] reads back, and the one the codec's `j_attest`
/// renders on the wire from the same value (the token for the tag there).
fn attest_fields(a: &Attestation) -> Vec<(&'static str, Value)> {
    vec![
        (ATTEST_ALG, Value::Number(u64::from(a.sig_alg()).into())),
        (ATTEST_SIG, Value::String(hex_string(a.sig()))),
    ]
}

/// Returns the marker slot one replayed attest-store record holds, or `None`.
///
/// It is [`attest_fields`]'s inverse, `None` where the record's spelling is
/// not [`attest_fields`]'s: a tag past a byte or of no signature (`0`), a
/// blob of no bytes, hex not in `hex_string`'s own lowercase. It admits
/// *every* slot `Attestation::new` admits — a tag no `SIG_ALGS` row names
/// included, as a slot rebuilt from a marker another build wrote may carry
/// one — so a consumer asks the slot's row of the table and owns the answer
/// for a tag with none, as the codec's `j_attest` does.
fn attest_of_record(m: &Map<String, Value>) -> Option<Attestation> {
    let tag = u8::try_from(m.get(ATTEST_ALG)?.as_u64()?).ok()?;
    let sig = parse_lower_hex_bytes(m.get(ATTEST_SIG)?.as_str()?)?;
    Attestation::new(tag, sig).ok()
}

#[cfg(test)]
mod tests;
