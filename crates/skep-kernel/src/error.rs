//! Error types of the public surface (§Public interface).

use std::fmt;
use std::io;

use crate::checkpoint::refused_at_decode;
use crate::Seq;

/// The one remedy a board written under another format has (PUB-1.2).
///
/// Dev boards regenerate; no migration path, no dual-stamp reading. Rendered
/// by [`OpenError::ForeignFormat`] for the journal and by the checkpoint's own
/// load refusal for a checkpoint, so the daemon prints the same sentence
/// whichever file names the foreign stamp.
pub(crate) const NO_MIGRATION_REMEDY: &str = "there is no migration path — every board is a \
    development artifact: delete the data directory and start over";

/// Renders a four-byte format stamp as an operator reads it.
///
/// Printable ASCII is itself (`SKJ2`) save a quote or a backslash, which
/// takes a backslash before it, and anything else is escaped (`\xff`), so a
/// message naming a stamp never emits a control byte.
pub(crate) fn stamp_text(stamp: &[u8; 4]) -> String {
    stamp.escape_ascii().to_string()
}

/// The account a refusal carries where it has one.
///
/// It is a serializer's own error, an I/O failure, a reservation the process
/// could not make, or an account of this crate's, a sentence or a typed
/// refusal — boxed so it travels as a `source` and crosses threads. The
/// crate's one spelling of that type; the public variants below write it out
/// in full, so a caller reading them sees what each holds.
pub(crate) type Cause = Box<dyn std::error::Error + Send + Sync + 'static>;

/// An I/O failure at the journal directory or one of its files.
///
/// As an operator reads it: `{file}: {act}: {the OS's words}` — a file by
/// its name in the journal directory (`seg-5.wal`, `checkpoint.tmp`,
/// `kernel.lock`), the directory itself by [`JOURNAL_DIR`], the act that
/// failed, and the OS's own account last: the convention every other writer
/// of the daemon's data directory keeps (`operations.md` §1.1 row 2), so a
/// line says which file under which act, where a bare `Input/output error`
/// says neither. No path is in it: the account can reach a client whole, as
/// a refused write's `durability` detail, and where the directory lives is
/// the embedder's to say, once (PATTERNS SP-13, SP-15). Made only by
/// [`at_file`], which carries it as the payload of an `io::Error` of the same
/// kind as the failure it names, so a caller that answers by kind — the lock
/// race by `WouldBlock`, the full volume by `StorageFull` — answers as it
/// would to the bare error; and the OS's error itself is this one's
/// `source`, so a reporter walking the chain reaches it, its OS code with it.
#[derive(Debug)]
pub(crate) struct FileFailure {
    file: String,
    act: String,
    error: io::Error,
}

impl fmt::Display for FileFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}: {}", self.file, self.act, self.error)
    }
}

impl std::error::Error for FileFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// The journal directory's name in the account of each of its own acts.
///
/// The acts are its creation and its path's resolution at the open, its
/// listing and its sync. It is never the directory's path: an account can
/// reach a client whole, and the embedder says once where the directory
/// lives — the daemon's `open: data-dir` line (PATTERNS SP-13, SP-15).
pub(crate) const JOURNAL_DIR: &str = "the journal directory";

/// Returns the `map_err` that names `file` and `act` on an I/O failure.
///
/// It is the one door to a [`FileFailure`], applied once, at the file
/// operation that failed, and rendered only where one does: the failure
/// keeps its kind, and gains the file and the act ahead of the OS's words.
/// `file` is a name — a file's in the journal directory, or [`JOURNAL_DIR`]
/// — taken as text, so a `Path` and its `display()` are refused at compile
/// time; `tests/it/tidy.rs` holds every call to a name rather than a path
/// made into text.
pub(crate) fn at_file(
    file: impl AsRef<str>,
    act: impl fmt::Display,
) -> impl FnOnce(io::Error) -> io::Error {
    move |error| {
        let kind = error.kind();
        let file = file.as_ref().to_owned();
        io::Error::new(kind, FileFailure { file, act: act.to_string(), error })
    }
}

/// Why [`crate::WorldState::rebuild_derived`] could not seed a base.
///
/// M2's own vocabulary, and slice-agnostic (the AUTH spec's M2 seam delta,
/// AUTH-2.85): the method is this crate's trait's, so its refusal is nameable
/// here and names no subsystem's concept — `Unresolved { slice }` and never a
/// per-subsystem variant. Only the account branches on it: `open` and the
/// history reads treat an `Err` base exactly as one that does not load — not
/// a start point, passed over for the next-older retained checkpoint, then
/// genesis while the journal reaches it — and a base passed over carries the
/// refusal's fact alone ([`crate::SkippedBase`]'s `why`), so the sentence
/// below reaches an operator only through the exhausted chain, as
/// [`OpenError::BadCheckpoint`]'s or [`HistoryError::Reclaimed`]'s `cause`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RebuildError {
    /// A derived slice the base carries no input to seed from.
    ///
    /// The checkpoint was written without it, and the authoritative state it
    /// does carry holds records whose fold the slice could only reproduce by
    /// a replay in commit order — an order no checkpoint holds. The base is
    /// not a start point, and the remedy is the one the sentence names: a
    /// base that carries the slice, or a journal that reaches one.
    Unresolved {
        /// The slice's name, for the line an operator reads.
        slice: &'static str,
    },
}

impl RebuildError {
    /// Returns the refusal's fact, without its remedy.
    ///
    /// The fact is the slice and that the base is not a start point; the
    /// remedy is the one [`fmt::Display`] ends on, and it is the exhausted
    /// chain's: it is what [`OpenError::BadCheckpoint`]'s cause says when no
    /// base stands in (AUTH-2.88). A base the chain passed over while an older
    /// one stood in owes no restore, so a skipped base carries the fact alone
    /// ([`crate::SkippedBase`]'s `why`, AUTH-2.86).
    pub(crate) fn fact(&self) -> String {
        match self {
            RebuildError::Unresolved { slice } => format!(
                "the `{slice}` slice could not be resolved from this checkpoint, so it is not a \
                 start point"
            ),
        }
    }
}

impl fmt::Display for RebuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: restore a checkpoint that carries the slice, or a journal that reaches one, \
             from backup",
            self.fact()
        )
    }
}

impl std::error::Error for RebuildError {}

/// Failure of [`crate::Kernel::open`] (§6/§7).
#[derive(Debug)]
pub enum OpenError {
    /// The journal was written under another format.
    ///
    /// Its first scanned segment opens with a well-formed sync word that is
    /// not this build's (`SKJ3` under a build writing `SKJ4`), and the frame
    /// after it does not carry this build's either, or is not there to read.
    /// A format stamps every frame, where damage changes one word: a
    /// foreign-shaped first word whose successor carries this build's stamp
    /// is one damaged sync word, which [`OpenError::Corruption`] names with a
    /// remedy that keeps the journal. Refused by name, before the scan —
    /// which would otherwise read the whole segment as one corrupt run
    /// reaching end-of-file, classify it as the un-acked tail, truncate the
    /// segment to nothing and serve an empty world — and before any write to
    /// a segment or a checkpoint, which stand exactly as they were found: the
    /// open takes its lock and removes a stray `checkpoint.tmp` before it
    /// probes. Operator-intervention condition — not auto-retried; the remedy
    /// is `NO_MIGRATION_REMEDY`'s: no build reads two formats.
    ///
    /// A checkpoint under another format is refused the same way but on its
    /// own channel: it is one base among a fallback chain, so it is skipped
    /// with its account, and reaches an operator through
    /// [`OpenError::BadCheckpoint`]'s cause when the chain is exhausted —
    /// naming the stamp found, the stamp expected and the same remedy.
    ForeignFormat {
        /// The sync word the segment opens with.
        found: [u8; 4],
        /// The sync word this build writes and reads.
        expected: [u8; 4],
        /// The segment's name in the journal directory.
        ///
        /// It is the first one the scan would read, `seg-{n}.wal` — the file
        /// the refusal names.
        segment: String,
    },
    /// The configuration is not one this kernel offers.
    ///
    /// The payload names the rule broken. Not an environmental failure: no
    /// retry and no operator action on the journal changes it, only a
    /// corrected configuration does.
    InvalidConfig(&'static str),
    /// I/O failure during open/recovery.
    ///
    /// It includes a recovery tail-truncation that fails to complete durably
    /// (§7; `open()` then fails, the step is idempotent and the next `open()`
    /// retries it) and a failed acquisition of the journal-path exclusion lock
    /// (a second live kernel on this journal; Lifecycle). A checkpoint that
    /// cannot be read is no `Io`: recovery passes it over as a refused base,
    /// and where the fallback chain is exhausted, a newest base that could not
    /// be read is [`OpenError::BadCheckpoint`]'s `cause`, carrying the read's
    /// own failure.
    ///
    /// The error names its file and its act ahead of the OS's words —
    /// `seg-5.wal: read: Input/output error (os error 5)`, and
    /// `the journal directory: list: …` where the directory's own act failed,
    /// never its path — and keeps the OS error's kind, so a caller that
    /// answers by kind answers as it would to the bare error. The held lock
    /// is `WouldBlock`, worded as the act that clears it: `kernel.lock: lock:
    /// another process holds it — a second kernel open over this journal
    /// directory, a daemon or a tool; stop it, or open another directory:
    /// {the OS's words}`.
    Io(io::Error),
    /// No retained checkpoint loads and seeds, and genesis cannot stand in.
    ///
    /// Genesis cannot stand in where its covering journal is reclaimed, or
    /// where its own seed refuses. Recovery internally falls back newest →
    /// next-older retained checkpoint → genesis-while-reachable (§6/§7) — a
    /// base that decodes but whose [`WorldState::rebuild_derived`] answers
    /// [`RebuildError`] is passed over exactly as one that does not decode
    /// (the seam delta, AUTH-2.85) — and this is returned only when that
    /// whole chain is exhausted; what the chain did on the way is
    /// [`crate::Recovery`]'s to report when it is not. Operator-intervention
    /// condition — not auto-retried.
    ///
    /// [`WorldState::rebuild_derived`]: crate::WorldState::rebuild_derived
    BadCheckpoint {
        /// Why the newest base recovery could have used refused.
        ///
        /// It is the whole of what names the remedy, since nothing else about
        /// an exhausted chain distinguishes one condition from another. A body
        /// that will not decode under this build's own stamp, its checksum and
        /// hash intact, is a body another layout wrote under the same stamp —
        /// a development board written before a layout change made under that
        /// stamp, or a binary on the wrong side of a `W` format change — and
        /// the line appends `NO_MIGRATION_REMEDY` after the serializer's
        /// words: the one act that serves both, where "roll the binary" or
        /// "restore the media" would each teach another condition's act (the
        /// predicate is `checkpoint::refused_at_decode`, by the kind the
        /// refusal travels as; it never fires where the newest base refused
        /// for damage). A failed header checksum or hash, or a truncated file,
        /// is damage: restore the media. A foreign format stamp is a
        /// checkpoint written under another format, and its account names the
        /// stamp found, the stamp expected and the remedy
        /// (`NO_MIGRATION_REMEDY`), as [`OpenError::ForeignFormat`] does for
        /// the journal. A base that decoded but could not seed a derived slice
        /// carries [`RebuildError`]'s sentence, which names its own remedy — a
        /// base that carries the slice, or a journal that reaches one
        /// (AUTH-2.88). A base that could not be read at all carries the
        /// read's own I/O failure, which names the file and its own remedy —
        /// `checkpoint.{n}: read: Permission denied (os error 13)`, a
        /// permission, a device — rather than any of the shapes above.
        /// Whichever it is, a checkpoint's account opens on the base's file,
        /// `checkpoint.{n}: …` — the read's own failure named so where it
        /// failed, every other refusal wrapped in the name and travelling
        /// beneath it as its `source` — so the line names the one base an
        /// operator acts on; where no checkpoint was tried and genesis's own
        /// seed refused, the account is that [`RebuildError`]'s sentence,
        /// named on no file. `None` when no candidate was tried at all — the
        /// journal retains no checkpoint, and only its unreachable genesis was
        /// ever available.
        cause: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    /// Durable committed data the recovered state needs is damaged.
    ///
    /// It cannot be read, or is not the history it claims to be. These
    /// conditions reach here, in the order they speak (where the group as a
    /// whole sits among `open`'s other refusals is [`crate::Kernel::open`]'s
    /// refusal precedence):
    ///
    /// 1. a damaged sync word opening the first scanned segment — a word
    ///    shaped like another format's stamp on a frame whose successor
    ///    carries this build's, which the frame CRC does not cover — refused
    ///    by the same probe as [`OpenError::ForeignFormat`] and ahead of the
    ///    scan, since that variant's remedy would discard a journal this build
    ///    wrote; refused even where that frame lies at or below the base,
    ///    which the probe cannot tell, reading no `Seq`;
    /// 2. a segment that could not be enumerated in bounded work or read in
    ///    bounded memory — a file longer than any segment this journal's
    ///    writer produces — so nothing derived from it would be more than a
    ///    prefix;
    /// 3. a corrupt run inside the genuinely-replayed range `(S_load, W]`: a
    ///    span of frames that fail their CRC or do not decode, with an intact
    ///    frame after it (a run reaching EOF is the un-acked / torn tail, not
    ///    this);
    /// 4. the base mismatch: the committed marker closing the base's seq
    ///    carries a chain that is not the checkpoint header's `chain_head` —
    ///    two stored values disagree, and nothing is recomputed;
    /// 5. the edited transaction: a transaction intact frame by frame that no
    ///    intact marker closes — its own marker refusing it, or its next
    ///    intact frame being another transaction's marker: a rewritten
    ///    `records_checksum`, `last_seq` or `txn`, a shape no writer of this
    ///    format leaves;
    /// 6. a chain break: a committed transaction above the base whose marker
    ///    carries a chain value that is not the recomputation over its
    ///    predecessor's and its own bytes (its records, its marker's pre-chain
    ///    fields, its salt and its slot's digest) — rewritten consistently
    ///    with its frame CRCs, or following a transaction that is not the one
    ///    before it;
    /// 7. a committed head that leaves no coordinate for a successor, which
    ///    no sequencer here could have written;
    /// 8. the fold's own verdict: a committed record that does not decode as
    ///    `W::Record`, or a `Seq` the committed set presents twice;
    /// 9. a damaged journal tail ([`DamagedTail`]): the bytes after the last
    ///    committed marker are not what one interrupted append leaves — an
    ///    intact commit marker committing nothing, a CRC-intact frame that
    ///    does not decode, or no intact frame over more bytes than one
    ///    append can leave — so the write they held may have been
    ///    acknowledged, and the open cuts them only where its configuration
    ///    accepts the cut by name ([`crate::Durability::Fsync`]'s
    ///    `cut_damaged_tail`); the cause names the frame, the position the
    ///    tail claims where one is read, and the two acts.
    ///
    /// Halt, never drop — nothing is folded, nothing is installed, and
    /// nothing is truncated. Operator-intervention condition — not
    /// auto-retried (§7).
    Corruption {
        /// The coordinate naming the damage, which differs by condition.
        ///
        /// For a damaged sync word, the base's own coordinate, where the scan
        /// would have begun — the probe reads a frame header and no `Seq`; for
        /// an unenumerable or oversized segment, the base's own coordinate,
        /// where the scan began, since the damage lies somewhere in the
        /// segments it reads — above the base, or below it in a segment
        /// straddling it — and the scan could not get past the damage to say
        /// which coordinates it holds (the account names the file instead);
        /// for a corrupt run, the next intact frame's coordinate — the run's
        /// own seqs are unreadable, so this bounds the damage rather than
        /// locating it, and the account locates it by file and byte; for the
        /// base mismatch, the base's seq; for the edited transaction, the last
        /// seq of its own records — not its marker's, which in one shape is
        /// the rewritten field; for a chain break, the `last_seq` of the first
        /// transaction whose chain did not verify; for an exhausted order, the
        /// committed head itself; for an undecodable or repeated record, that
        /// record's own `Seq`; for a damaged tail, the position an intact
        /// marker in it claims, else the first position above the committed
        /// head, the lowest the tail's frames could hold.
        at: Seq,
        /// The account of what could not be read, where there is one.
        ///
        /// It names the file wherever it places the damage in one: a damaged
        /// sync word's names the segment, the word found and a remedy that
        /// keeps the journal — restore that segment — where
        /// [`OpenError::ForeignFormat`]'s would discard it; an unenumerable or
        /// oversized segment's names the segment and the bound it broke; a
        /// corrupt run's names the segments its bytes lie in, the bytes it
        /// spans, and the act that clears it — a run wholly in closed
        /// segments, whose bytes never change once the next segment begins,
        /// is cleared by restoring those files alone from a copy that holds
        /// the segment after them, where a run in the active segment rewinds
        /// the journal to the copy restored; the base mismatch names the
        /// checkpoint file, and it, the edited transaction and a chain break
        /// each say which chain link failed and how, the last two by position
        /// alone, naming no file; and a committed record that does not decode
        /// carries the serializer's own refusal, which is what separates a
        /// writer/reader skew — a binary rolled back over a record format —
        /// from bit-rot, two conditions this variant otherwise reports alike
        /// and an operator must not treat alike; and a damaged tail's is
        /// [`DamagedTail`], a typed value a caller above may read back
        /// through `source`, naming the frame, the segment and the two acts.
        /// `None` for the rest: an exhausted order is arithmetic, and a `Seq`
        /// the committed set presents twice is a malformed journal rather
        /// than an unreadable one.
        cause: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
}

/// A journal tail that is not a crash's, refused at the open (§7).
///
/// It is [`OpenError::Corruption`]'s ninth cause. The bytes after the last
/// committed marker are, after a crash, one interrupted append's: the
/// record frames of one transaction and at most one short or CRC-failing
/// frame, never longer than a transaction at the budget and its signature
/// slot at the cap ([`crate::MAX_CRASH_TAIL_BYTES`]); every write they held
/// was unacknowledged, and the open cuts them. A tail of any other shape —
/// [`DamagedTailTell`] names the three the scan tells — is damage: decay in
/// the last acknowledged transaction, a rewrite of it, or bytes no writer
/// of this journal left, and the write it holds may have been acknowledged.
/// The open leaves the journal as it found it and refuses, and the operator
/// chooses: restore the segment from a copy, or open once accepting the cut
/// ([`crate::Durability::Fsync`]'s `cut_damaged_tail`), which keeps every
/// byte of the tail beside the journal before it cuts one
/// ([`crate::Recovery`]'s `tail_cut_kept`) and hands out no position the
/// tail claimed ([`crate::Kernel::order_floor`]).
///
/// Every field is public and the struct is plain: a caller above renders its
/// own line from the facts, as the daemon renders its refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DamagedTail {
    /// The segment the tail begins in, by its name in the journal directory.
    ///
    /// It is the segment holding the last committed marker where a byte of
    /// it lies past that marker, else the first wholly-later segment that
    /// holds a byte — the file the keep would name, `{segment}.cut-{byte}`.
    pub segment: String,
    /// The byte of that segment the tail begins at.
    pub byte: u64,
    /// The committed head: the position every write at or below stands at.
    pub head: Seq,
    /// The tail's length in bytes, over every segment it reaches.
    pub bytes: u64,
    /// The intact frames of no writer's among them.
    ///
    /// They are commit markers committing nothing and CRC-intact frames that
    /// do not decode — what [`crate::Recovery`]'s `tail_cut_intact` counts
    /// once the cut is accepted; `0` where the tail's tell is its length.
    pub intact: u64,
    /// The greatest position an intact marker in the tail claims.
    ///
    /// It is the position the lost acknowledgement named, where a marker
    /// stands to read it from; `None` otherwise.
    pub claimed: Option<Seq>,
    /// The tell that makes the tail damage rather than a crash's.
    pub tell: DamagedTailTell,
}

/// What tells a damaged journal tail from a crash's ([`DamagedTail`]).
///
/// The first of the three the scan meets names the tail; a tail may show
/// several. `#[non_exhaustive]`: a fourth tell is an addition, and a caller
/// rendering these keeps a wildcard arm.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DamagedTailTell {
    /// An intact commit marker commits nothing.
    ///
    /// Its records fail their check, or stand out of order: rot in the
    /// records of the transaction the board acknowledged at `position`, or a
    /// rewrite of them, which a crash leaves only where the disk wrote an
    /// append's pages out of order.
    MarkerCommitsNothing {
        /// The marker's segment, by name.
        segment: String,
        /// The byte of that segment the marker's frame begins at.
        byte: u64,
        /// The position the marker claims: its `last_seq`.
        position: Seq,
    },
    /// A frame passes its CRC and does not decode.
    ///
    /// Under one stamp no writer of this format writes one and no torn write
    /// leaves one: a rewrite with its CRC re-fixed, or a frame of a layout
    /// this build does not read.
    FrameDoesNotDecode {
        /// The frame's segment, by name.
        segment: String,
        /// The byte of that segment the frame begins at.
        byte: u64,
    },
    /// No intact frame stands in the tail and it is longer than one append.
    ///
    /// One interrupted append leaves at most `bound` bytes
    /// ([`crate::MAX_CRASH_TAIL_BYTES`]); a longer run of bytes no frame
    /// anchors is decay over the journal's trailing bytes, or bytes no writer
    /// of this journal left.
    LongerThanOneAppend {
        /// The most bytes one interrupted append leaves.
        bound: u64,
    },
}

impl fmt::Display for DamagedTailTell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DamagedTailTell::MarkerCommitsNothing { segment, byte, position } => write!(
                f,
                "the intact commit marker at byte {byte} of {segment} commits nothing — the \
                 records it closes fail their check — and claims position {position}, the \
                 position the write it closed was acknowledged at: rot in that write's records, \
                 or a rewrite of them"
            ),
            DamagedTailTell::FrameDoesNotDecode { segment, byte } => write!(
                f,
                "the frame at byte {byte} of {segment} passes its CRC and does not decode, which \
                 no torn write leaves: a rewrite, or a frame this build does not read"
            ),
            DamagedTailTell::LongerThanOneAppend { bound } => write!(
                f,
                "no intact frame stands among them and they are longer than one interrupted \
                 append leaves ({bound} bytes: a transaction at the budget and its signature \
                 slot at the cap): decay over the journal's trailing bytes, or bytes no writer \
                 of this journal left"
            ),
        }
    }
}

impl fmt::Display for DamagedTail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "damaged journal tail: the {bytes} bytes after the last committed marker at position \
             {head}, from byte {byte} of {segment}, are not a crash's — {tell}; nothing was cut. \
             Two acts: restore {segment} from a copy, or open once accepting the cut, which \
             first keeps every one of the {bytes} bytes beside the journal as {segment}.cut-{byte} \
             and then cuts them, handing out no position the tail claims",
            bytes = self.bytes,
            head = self.head,
            byte = self.byte,
            segment = self.segment,
            tell = self.tell,
        )
    }
}

impl std::error::Error for DamagedTail {}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::InvalidConfig(msg) => write!(f, "invalid kernel configuration: {msg}"),
            OpenError::ForeignFormat { found, expected, segment } => write!(
                f,
                "journal is not this build's format: {segment} opens with the stamp `{}`, this \
                 build reads and writes `{}` only; {NO_MIGRATION_REMEDY}",
                stamp_text(found),
                stamp_text(expected)
            ),
            OpenError::Io(e) => write!(f, "journal open/recovery I/O failure: {e}"),
            OpenError::BadCheckpoint { cause: None } => {
                write!(f, "no retained checkpoint loads and genesis is unreachable")
            }
            // The no-migration remedy after the serializer's words, where the
            // newest base refused at decode under this build's own stamp (the
            // variant's doc); every other account is said as it stands, a
            // foreign stamp's and a seed refusal's ending on their own remedy.
            OpenError::BadCheckpoint { cause: Some(e) } if refused_at_decode(&**e) => write!(
                f,
                "no retained checkpoint loads and genesis is unreachable; the newest \
                 refused: {e}; {NO_MIGRATION_REMEDY}"
            ),
            OpenError::BadCheckpoint { cause: Some(e) } => write!(
                f,
                "no retained checkpoint loads and genesis is unreachable; the newest \
                 refused: {e}"
            ),
            // The coordinate spelled as the operator's stream spells every
            // one, `position N`, so a line naming the damage joins every other
            // line about that position.
            OpenError::Corruption { at, cause: None } => write!(
                f,
                "durable committed data cannot be read; position {at} names the damage"
            ),
            OpenError::Corruption { at, cause: Some(e) } => write!(
                f,
                "durable committed data cannot be read; position {at} names the damage: {e}"
            ),
        }
    }
}

impl std::error::Error for OpenError {
    /// Returns the variant's cause.
    ///
    /// Spelled out variant by variant, so a condition added here has to say
    /// whether it carries a cause: a wildcard would compile and silently drop
    /// the next variant's out of every chain a caller walks.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OpenError::Io(e) => Some(e),
            OpenError::Corruption { cause, .. } | OpenError::BadCheckpoint { cause } => {
                cause.as_deref().map(|e| e as _)
            }
            // A foreign stamp is the whole of its own account: the two words
            // and the remedy are in the sentence, and nothing underlies them.
            OpenError::InvalidConfig(_) | OpenError::ForeignFormat { .. } => None,
        }
    }
}

impl From<io::Error> for OpenError {
    fn from(e: io::Error) -> Self {
        OpenError::Io(e)
    }
}

/// Which step of [`crate::Kernel::checkpoint`] after the rename failed.
///
/// The rename is the one that publishes a base; this is
/// [`CheckpointError::Landed`]'s member. Three steps follow the rename, in
/// this order, each over a base already on disk: the directory's fsync,
/// which makes the rename durable; retention, which removes the excess
/// bases; and the journal's reclamation below the oldest kept base. Each
/// arm's card says what the failure left undone, which is the one thing that
/// differs between them: the base itself stands whichever failed, save where
/// something other than this kernel removed it before retention listed it,
/// which retention answers as its own failure.
/// Deliberately not `#[non_exhaustive]`: a fourth step after the rename would
/// be a change to that order, which a caller naming these three in its own
/// words should meet as a build break rather than fall into a wildcard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LandedStep {
    /// The directory's fsync after the rename.
    ///
    /// Whether the base's directory entry is durable is what the step would
    /// have settled, and retention and reclamation did not run — an extra
    /// base may stand, and the journal is unreclaimed.
    DirectorySync,
    /// Retention (`retain_checkpoints`).
    ///
    /// A base it would have removed stands, an extra base and no harm, and
    /// reclamation did not run — save where the base this call wrote was gone
    /// before retention listed it: retention then ran whole and kept no base.
    Retention,
    /// The journal's reclamation below the oldest kept base.
    ///
    /// The step [`crate::Reclaim::BelowOldestRetained`] takes and
    /// [`crate::Reclaim::Never`] does not. An unreclaimed segment is space,
    /// and nothing else is left undone.
    Reclamation,
}

impl fmt::Display for LandedStep {
    /// Writes the step in the kernel's own words.
    ///
    /// The daemon above renders its line's words from the arm, never from
    /// this text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LandedStep::DirectorySync => "the directory fsync after the rename",
            LandedStep::Retention => "checkpoint retention",
            LandedStep::Reclamation => "journal reclamation",
        })
    }
}

/// Failure of [`crate::Kernel::checkpoint`] (§6).
///
/// A failed checkpoint never poisons the kernel and never disturbs the write
/// path; each variant states what it left behind, since that is what decides
/// the caller's next move.
#[derive(Debug)]
pub enum CheckpointError {
    /// I/O failure persisting the checkpoint, up to and including its rename.
    ///
    /// No base landed, and no `checkpoint.tmp` survives save one whose
    /// removal failed — the write removes its own before this is answered,
    /// best-effort, a failed removal named in the account. So the call is
    /// safe to retry, and a retry re-does the whole sequence from a fresh
    /// root. A failure after the rename is [`CheckpointError::Landed`], which
    /// names the step. The error names its file and its act ahead of the OS's
    /// words — `checkpoint.tmp: fsync: No space left on device (os error 28)`
    /// — and keeps the OS error's kind, as [`OpenError::Io`]'s does.
    Io(io::Error),
    /// A base landed, its publishing rename run, and a step after it failed.
    ///
    /// `step` names which of the three, `cause` carries the I/O failure. The
    /// base stands on disk whatever the step, save where something other than
    /// this kernel removed it before retention listed it: the next open loads
    /// it, and [`crate::Kernel::newest_checkpoint`] names it. What is left
    /// undone is the step's card ([`LandedStep`]), benign in each case — an
    /// extra base, an unreclaimed segment — so the call is safe to retry, and
    /// a retry re-does the whole sequence from a fresh root, as after
    /// [`CheckpointError::Io`].
    Landed {
        /// The step after the rename that failed.
        step: LandedStep,
        /// The step's own I/O failure.
        cause: io::Error,
    },
    /// The world failed to serialize.
    ///
    /// Carries the serializer's own account of which part of the world it
    /// could not encode — the only thing that identifies the failure, since
    /// M2 never inspects `W`. Nothing was written, not even a temp file: the
    /// encode precedes the temp file's creation. Retrying repeats the refusal
    /// until `W` itself encodes.
    Serialize(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// A prior unrecoverable failure has halted the kernel (§1/§3).
    ///
    /// It is any [`TxnError::Poisoned`] lists, a `Seq` order with no room left
    /// among them. No checkpoint was attempted, nothing was written, and none
    /// will be until the kernel is reopened. Which failure halted it is
    /// [`crate::Kernel::poison_cause`]'s to say.
    Poisoned,
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckpointError::Io(e) => write!(f, "checkpoint I/O failure: {e}"),
            CheckpointError::Landed { step, cause } => {
                write!(f, "checkpoint landed, then {step} failed: {cause}")
            }
            CheckpointError::Serialize(e) => {
                write!(f, "checkpoint world serialization failed: {e}")
            }
            CheckpointError::Poisoned => write!(f, "kernel is poisoned; no checkpoint taken"),
        }
    }
}

impl std::error::Error for CheckpointError {
    /// Returns the variant's cause.
    ///
    /// Spelled out variant by variant, for the reason [`OpenError`]'s is.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CheckpointError::Io(e) | CheckpointError::Landed { cause: e, .. } => Some(e),
            CheckpointError::Serialize(e) => Some(&**e),
            CheckpointError::Poisoned => None,
        }
    }
}

impl From<io::Error> for CheckpointError {
    fn from(e: io::Error) -> Self {
        CheckpointError::Io(e)
    }
}

/// Failure of the history reads.
///
/// The reads are [`crate::Kernel::world_at`], [`crate::Kernel::chain_at`]
/// and [`crate::Kernel::attestation_at`] at a boundary, and
/// [`crate::Kernel::boundaries_above`] over the range above a position —
/// each derived read-only from the journal directory. None of these poisons
/// the kernel or perturbs the live write path; every variant is an honest
/// "this boundary, or this range, cannot be answered" (or a corruption find
/// — at rest, save the one transient [`HistoryError::Corruption`] names).
#[derive(Debug)]
pub enum HistoryError {
    /// `at` is above the installed head at the time of the call.
    ///
    /// The installed head is the installed root's seq
    /// ([`crate::Kernel::current_seq`]), which is the greatest boundary this
    /// kernel answers, and the head [`crate::Kernel::boundaries_above`]
    /// bounds its list at. Not §7's committed head: a kernel poisoned after a
    /// barrier but before its install holds a durable committed boundary
    /// above this one, and refuses it.
    BeyondHead {
        /// The installed head observed by this call.
        head: Seq,
    },
    /// `at` is not a committed transaction boundary the journal closes.
    ///
    /// It names an interior `Seq` of a multi-record commit (never externally
    /// observable — §2/§3), a burned `Seq` under `TolerateGap`, or a
    /// committed boundary whose marker, the last in the journal, has rotted at
    /// rest, which the scan reads as the torn tail. Boundaries are the `Seq`
    /// values `transact` returns; nothing else is one. Never
    /// [`crate::Kernel::boundaries_above`]'s, which takes a position and
    /// judges no boundary: a coordinate this variant refuses is one that read
    /// simply lists nothing at.
    NotABoundary {
        /// The greatest committed boundary at or below the requested value.
        ///
        /// It is never below the base this call selected — a segment
        /// straddling that base contributes boundaries below it with no base
        /// left to fold from (0 = genesis). [`crate::Kernel::world_at`] and
        /// [`crate::Kernel::chain_at`] answer it — the base's own seq from the
        /// base itself — so it is the value they may safely be re-asked with;
        /// a boundary lower still may be answerable in its own right, from the
        /// older base a lower `at` would select.
        /// [`crate::Kernel::attestation_at`], whose base sits strictly below
        /// its boundary, answers it too — save where it is that base's own seq
        /// and the base a checkpoint: re-asked there, it answers only while an
        /// older base remains derivable, and refuses
        /// [`HistoryError::Reclaimed`] once none does.
        nearest: Seq,
    },
    /// No base at or below `at` remains derivable.
    ///
    /// Strictly below `at`, for [`crate::Kernel::attestation_at`], whose base
    /// must sit below its boundary; at or below the position, for
    /// [`crate::Kernel::boundaries_above`], whose base may sit *at* it: no
    /// retained checkpoint there loads and seeds (a base whose
    /// [`crate::WorldState::rebuild_derived`] refuses is passed over as one
    /// that does not load, AUTH-2.85), and the journal below the oldest
    /// retained checkpoint has been reclaimed — by a landing under
    /// [`crate::Reclaim::BelowOldestRetained`], this open's or an earlier
    /// one's (§6) — so genesis is unreachable — or genesis's own seed
    /// refuses. Where the journal still reaches genesis, as it does at every
    /// landing under [`crate::Reclaim::Never`], a boundary below the oldest
    /// retained checkpoint is answered by the fold from genesis and never
    /// refused this way. `floor` names the oldest boundary a base could
    /// still be derived at, when a checkpoint exists to derive it from.
    Reclaimed {
        /// The oldest retained checkpoint's seq.
        ///
        /// It is the oldest boundary a base could still be derived at, or
        /// `None` when no checkpoint exists. That checkpoint is the oldest
        /// candidate, not a guarantee: one that refuses to load refuses this
        /// way again, which is what `cause` distinguishes.
        /// [`crate::Kernel::attestation_at`] answers only strictly above it:
        /// asked at `floor` itself, it refuses this way again, `floor` naming
        /// the very boundary it was asked. [`crate::Kernel::boundaries_above`]
        /// answers *at* it, the list above the floor from the base embodying
        /// it, as `world_at` and `chain_at` answer there.
        floor: Option<Seq>,
        /// Why the newest base this call could have used refused.
        ///
        /// It is there when one was tried at all. `Some` is a retained base
        /// that is itself unusable, its account opening on that base's file,
        /// `checkpoint.{n}: …`, as [`OpenError::BadCheckpoint`]'s does;
        /// re-asking at `floor` refuses again, and a caller honouring the
        /// `floor` alone retries forever.
        /// Where no retained base was tried, `Some` is genesis's own refused
        /// seed instead ([`RebuildError`]'s sentence), and re-asking at
        /// `floor` tries the oldest as under `None`. `None` means no candidate
        /// was tried — every retained base lies above the boundary (at or
        /// above it, for [`crate::Kernel::attestation_at`]), or none is
        /// retained: re-asking [`crate::Kernel::world_at`] or
        /// [`crate::Kernel::chain_at`] at `floor` tries the oldest, and either
        /// answers or refuses again, now with the cause that ends the retry. A
        /// `Reclaimed` whose `floor` is the boundary asked carries `None` and
        /// leaves nothing to re-ask: it is [`crate::Kernel::attestation_at`]'s
        /// answer at the oldest retained checkpoint's own seq, whose slot no
        /// remaining base reaches.
        cause: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    /// The kernel runs under [`crate::Durability::InMemory`].
    ///
    /// There is no journal to derive history from.
    Unjournaled,
    /// I/O failure listing the journal directory or reading a journal segment.
    ///
    /// May be transient (a concurrent checkpoint's segment reclamation can
    /// remove a file between listing and reading); a retry re-selects a base.
    /// A checkpoint that cannot be read is no `Io`: it is a refused base,
    /// passed over for the next-older one as recovery passes it, and where
    /// nothing below it stands in, a newest base that could not be read is
    /// [`HistoryError::Reclaimed`]'s `cause`, carrying the read's own
    /// failure. The error names its file and its act ahead of the OS's words,
    /// and keeps the OS error's kind, as [`OpenError::Io`]'s does.
    Io(io::Error),
    /// Corrupt data in the scanned region.
    ///
    /// The same conditions, the same coordinate and the same account, that
    /// [`OpenError::Corruption`] carries, with the same halt-never-drop
    /// verdict (§7). Two routes are not available here: the exhausted `Seq`
    /// order, which only the open's check of the head it commits from
    /// reaches, and this call commits nothing; and the damaged sync word,
    /// which only `open`'s first-sync-word probe names — a history read
    /// truncates nothing, so its own scan meets that frame as a corrupt run
    /// instead. And the fold's two — an undecodable record, a `Seq` presented
    /// twice — reach [`crate::Kernel::world_at`] and none of
    /// [`crate::Kernel::chain_at`], [`crate::Kernel::attestation_at`] and
    /// [`crate::Kernel::boundaries_above`], which fold nothing: what they
    /// read is framed bytes, and those verify.
    ///
    /// One cause of this can be transient: a commit whose barrier fails
    /// truncating its tail while this read is mid-file leaves the read
    /// holding a discontinuity that classifies as at-rest corruption
    /// ([`crate::Kernel::world_at`]); a retry that meets it again meets it at
    /// rest.
    Corruption {
        /// See [`OpenError::Corruption`].
        at: Seq,
        /// See [`OpenError::Corruption`].
        cause: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
}

/// Spells every coordinate as the operator's stream does, `position N`.
///
/// As [`OpenError`]'s sentence spells its own.
impl fmt::Display for HistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HistoryError::BeyondHead { head } => {
                write!(f, "boundary beyond the installed head, position {head}")
            }
            HistoryError::NotABoundary { nearest } => {
                write!(f, "not a committed boundary; nearest at or below is position {nearest}")
            }
            // Two independent facts — which floor, and why the newest base
            // refused — so the sentence is built rather than spelled out over
            // four arms.
            HistoryError::Reclaimed { floor, cause } => {
                match floor {
                    Some(floor) => write!(
                        f,
                        "history below the oldest retained checkpoint (position {floor}) has \
                         been reclaimed"
                    )?,
                    None => write!(
                        f,
                        "no checkpoint and no genesis-reaching journal; history unavailable"
                    )?,
                }
                match cause {
                    Some(e) => write!(f, "; the newest base refused: {e}"),
                    None => Ok(()),
                }
            }
            HistoryError::Unjournaled => {
                write!(f, "in-memory kernel: no journal to derive history from")
            }
            HistoryError::Io(e) => write!(f, "history read I/O failure: {e}"),
            HistoryError::Corruption { at, cause: None } => write!(
                f,
                "journal corrupt at rest; position {at} names the damage"
            ),
            HistoryError::Corruption { at, cause: Some(e) } => write!(
                f,
                "journal corrupt at rest; position {at} names the damage: {e}"
            ),
        }
    }
}

impl std::error::Error for HistoryError {
    /// Returns the variant's cause.
    ///
    /// Spelled out variant by variant, for the reason [`OpenError`]'s is.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HistoryError::Io(e) => Some(e),
            HistoryError::Corruption { cause, .. } | HistoryError::Reclaimed { cause, .. } => {
                cause.as_deref().map(|e| e as _)
            }
            HistoryError::BeyondHead { .. }
            | HistoryError::NotABoundary { .. }
            | HistoryError::Unjournaled => None,
        }
    }
}

impl From<io::Error> for HistoryError {
    fn from(e: io::Error) -> Self {
        HistoryError::Io(e)
    }
}

/// Failure of [`crate::Kernel::transact`] (§1/§3).
#[derive(Debug)]
pub enum TxnError<E> {
    /// `f`'s typed precondition failure, surfaced verbatim to M10.
    ///
    /// Never a silent skip. Nothing committed, no dangling state; the
    /// rejected call is an A1 zero-step case evaluated against the base
    /// committed index. It is also this error's `source`: a reporter walking
    /// the chain reaches the store's own refusal, and whatever that carries.
    Rejected(E),
    /// The journal failed the commit before install, and none of it survives.
    ///
    /// The per-commit barrier (the single records+marker fsync) failed before
    /// install — or a non-unwind `io::Error` from the append path preceded it
    /// (e.g. ENOSPC; §3), or one of the two failures that precede the first
    /// byte appended: the rotation's creation of the next segment, and the
    /// OS refusing entropy for the transaction's salt
    /// ([`crate::SaltSource::Os`], `SKJ4`) — *and* nothing of the transaction
    /// survives in the journal: its un-acked record+marker tail durably
    /// truncated, or never appended (Seqs burned per
    /// [`crate::BurnedSeqPolicy`]), so nothing was installed and no durable
    /// marker survives → a true no-op; the caller may safely re-invoke. If
    /// the truncation itself fails to complete durably the kernel poisons and
    /// the call returns [`Poisoned`] instead (§1: a surviving un-acked marker
    /// would let a successor collide on recovery).
    ///
    /// The error names the segment and the act that failed ahead of the OS's
    /// words — `seg-5.wal: fsync: Input/output error (os error 5)`, and
    /// `the journal directory: sync: …` where a rotation's directory sync
    /// failed, never the directory's path, since the account reaches the
    /// refused writer whole as M10's `durability` detail (PATTERNS SP-13) —
    /// and keeps the OS error's kind, so a full volume is `StorageFull`
    /// whatever step met it; the entropy refusal alone names no file, saying
    /// `OS entropy unavailable: …`, of kind `Other`.
    ///
    /// [`Poisoned`]: TxnError::Poisoned
    Durability(io::Error),
    /// The staged records could not be turned into journal frames at all.
    ///
    /// A record whose serializer refuses, or one whose serialized form
    /// exceeds the journal's frame cap. Nothing was appended and nothing
    /// installed, so this is a true no-op like [`Durability`] — but the
    /// refusal is a property of the records, so the remedy is to fix the
    /// record, where re-invoking unchanged fails the same way however healthy
    /// the disk.
    ///
    /// Carries the refusal's own account — the serializer's, since M2 never
    /// inspects `W::Record`, or the frame cap's. Nothing here is an I/O
    /// failure: the encode and the size judgment both precede the first file
    /// operation, and this variant arises on a kernel that has no file at all
    /// ([`crate::Durability::InMemory`]), which is why the cause travels as
    /// the error it is rather than as a disk's.
    ///
    /// Both halves arise in both durability modes: the encode runs before
    /// the journal is consulted, and the frame-cap half is judged there too
    /// — against the frames the journaled mode would build — so an in-memory
    /// kernel refuses exactly what a journaled one refuses.
    ///
    /// [`Durability`]: TxnError::Durability
    Unencodable(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The staged records exceed the journal's per-transaction budget.
    ///
    /// They all encode, and their whole encoded form — record frames, commit
    /// marker and headers — exceeds the budget, [`crate::MAX_TXN_BYTES`].
    /// Refused in both durability modes, above the journal's mode branch,
    /// before anything is appended or installed: a true no-op like
    /// [`Durability`]. Unlike [`Unencodable`] the refusal is a property of
    /// the staging, not of any one record — the serializer refused nothing —
    /// so the remedy is to split the transaction, where fixing a value cannot
    /// help and re-invoking unsplit fails the same way forever.
    ///
    /// **One exception**, where splitting cannot discharge that remedy: a
    /// single record whose own frame plus the commit marker exceeds
    /// [`crate::MAX_TXN_BYTES`] is refused this way too, and a caller splitting
    /// until one record remains meets it again. There the record must shrink.
    /// The largest committable record is [`crate::MAX_TXN_BYTES`] less the
    /// marker frame, the record's own frame header and its frame-payload
    /// overhead — a little under the frame cap, which is why the cap admits a
    /// record slightly larger than any transaction can carry.
    ///
    /// The budget is what keeps recovery's memory floor replica-independent:
    /// a transaction never spans a journal segment and recovery reads a
    /// segment whole, so an unbounded transaction would permanently raise the
    /// cost of every later `open()` of the journal it committed to.
    ///
    /// [`Durability`]: TxnError::Durability
    /// [`Unencodable`]: TxnError::Unencodable
    OverBudget {
        /// The transaction's accounted encoded size.
        ///
        /// It is what the journal would have had to hold, a filled slot's blob
        /// aside, and what the caller's split must get under
        /// [`crate::MAX_TXN_BYTES`].
        bytes: u64,
    },
    /// The kernel was halted by an unrecoverable failure (§1/§3).
    ///
    /// A durability-failure or panic-guard truncation that itself failed to
    /// complete durably, an unwind after a successful barrier but before
    /// install, or a `Seq` order with no room left for another transaction
    /// (§2 — its last coordinate would overflow, or would be the top
    /// coordinate itself, which leaves no successor and which recovery
    /// refuses as a committed head; renumbering over a committed predecessor
    /// is not an option). Returned by the poisoning call itself (in place of
    /// `Durability`; a panic-path poisoning propagates the panic instead) and
    /// by every later `transact`; reads (`snapshot`/`current_seq`) keep
    /// serving the last consistent root. Do not re-invoke. Which of these
    /// halted it, with the transaction's coordinates and the failures' own
    /// words, is [`crate::Kernel::poison_cause`]'s to say.
    Poisoned,
}

impl<E: fmt::Display> fmt::Display for TxnError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxnError::Rejected(e) => write!(f, "transaction rejected: {e}"),
            TxnError::Durability(e) => {
                write!(f, "durability barrier failed before install (true no-op): {e}")
            }
            TxnError::Unencodable(e) => {
                write!(f, "records cannot be journaled (true no-op, not retryable): {e}")
            }
            TxnError::OverBudget { bytes } => write!(
                f,
                "transaction encodes to {bytes} bytes, over the journal's per-transaction \
                 budget (true no-op; split the transaction)"
            ),
            TxnError::Poisoned => write!(f, "kernel is poisoned; write paths are halted"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for TxnError<E> {
    /// Returns the variant's cause.
    ///
    /// Spelled out variant by variant, for the reason [`OpenError`]'s is.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            // The store's own typed refusal is this error's cause, as every
            // other wrapped cause is: a reporter walking the chain reaches it,
            // and whatever it carries in turn.
            TxnError::Rejected(e) => Some(e),
            TxnError::Durability(e) => Some(e),
            TxnError::Unencodable(e) => Some(&**e),
            TxnError::OverBudget { .. } | TxnError::Poisoned => None,
        }
    }
}

#[cfg(test)]
mod tests;
