//! The blocked-prefix list and its supply file.

use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde_json::{Map, Value};
use skep_address::Address;
use skep_namespace::prefix_contains;

use super::prefix::NodePrefix;
use crate::codec::{check_keys, wire_address};

/// The byte cap on one issue of the blocked-prefix list ([`BlockedSupply`]).
///
/// A read that stops one byte past the cap refuses a longer file, rather
/// than reading it whole first.
///
/// The cap bounds the failure case and not the legitimate one: an entry is
/// two addresses in the registry's global form under a small JSON wrapper,
/// under a hundred bytes, so this admits order 90,000 standing takedown
/// records — four orders of magnitude above a board's plausible list. What
/// it removes is the unbounded one, which is a path that is *not* a list: a
/// read-to-end followed by a whole `serde_json::Value` over those bytes, at
/// the ~20× transient heap this crate prices on
/// [`crate::limits::MAX_REQUEST_BODY`]. It is paid at
/// [`super::AuthState::open`] before the daemon serves a request, where the
/// open promises a named refusal rather than a hang; and at every reissue
/// with the supply's `seen` held at the head of routing, so every request
/// that arrives meanwhile waits on it, `/health` and `/session` included.
///
/// The number is a relation to the frame routes' body cap,
/// [`crate::limits::MAX_REQUEST_BODY`], and moves with it: this file
/// carries strictly less per record than a frame does, so the same ceiling
/// is the same headroom or more.
const MAX_BLOCKED_SUPPLY_BYTES: usize = crate::limits::MAX_REQUEST_BODY;

// ── the blocked-prefix list (AUTH-1.44, AUTH-4.36 step 4b, AUTH-4.70) ────

/// One entry of the blocked-prefix list (AUTH-4.36 step 4b).
///
/// It is a prefix, and the version address of the takedown record the entry
/// cites — the one public datum the handshake's 403 carries (AUTH-6.5). The
/// daemon reads no record and knows no takedown: `record` is echoed and
/// never dereferenced, which is why it is held as the address it was issued
/// as and nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BlockedEntry {
    pub prefix: Address,
    pub record: Address,
}

/// The list's two-field header (AUTH-4.36 step 4b).
///
/// It is AUTH-4.70's "the header two values on it", read from config and
/// from nowhere else: the daemon derives neither field and reads no record
/// for one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockedHeader {
    /// The configured operator account.
    ///
    /// `None` where the header names none, and the claimant is then taken in
    /// its place.
    pub operator: Option<Address>,
    /// The board's binding-writing account.
    ///
    /// It is the claimant on an unforked lineage, the seat on a forked one,
    /// never the superseded claimant (REG-3.52). `None` where the header
    /// omits it, and the claimant is then taken in its place. Its second
    /// reader is AUTH-3.21's seat carve at slot (6), which reads it beside
    /// the claimant and compares it (RES-175), through
    /// [`BlockedPrefixes::header`].
    pub binding_writer: Option<Address>,
}

/// One issue of the list, as the operator supplies it.
///
/// It holds the header and every entry, in supply order, before the
/// install's comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct BlockedIssue {
    pub header: BlockedHeader,
    pub entries: Vec<BlockedEntry>,
}

/// Which inert comparand an entry covers (AUTH-4.36 step 4b).
///
/// The install has two, and the two carry REG-4.198: the block never
/// reaches the hand that lifts it and never takes a board from the party
/// that writes its bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparand {
    /// (a) the configured operator account.
    Operator,
    /// (b) the board's binding-writing account.
    ///
    /// It is a comparand only where the operator account is not an account
    /// of this board.
    BindingWriter,
}

/// The list in force: one issue, with the install's verdict on each entry.
///
/// An entry covering a comparand is inert — ignored at install and said so
/// in the log — and every other entry blocks.
///
/// The issue is kept whole, inert entries included, because the comparison
/// is run twice over one issue: at the install, and again at the claim
/// flip, where the claimant the header defers to first exists.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BlockedPrefixes {
    /// The issue as supplied, whole.
    ///
    /// It is private, and code outside this file reads it only through this
    /// type's methods — whole through [`BlockedPrefixes::issue()`], read-only
    /// — so an entry and its verdict in `inert` are built together and move
    /// together: [`BlockedPrefixes::judged`] states the invariant, and the
    /// fail-open a write here from any other file would buy.
    issue: BlockedIssue,
    /// Per entry of `issue.entries`, the comparand it covers.
    ///
    /// It is `None` for an entry in force.
    inert: Vec<Option<Comparand>>,
    /// Comparand (a) as this install resolved it.
    ///
    /// It is the header's operator, else the claimant, else none (an
    /// unclaimed board naming none).
    operator: Option<Address>,
    /// Comparand (b) as this install resolved it.
    ///
    /// It is `Some` only where it is live, which is where the operator
    /// account is off-board.
    binding_writer: Option<Address>,
    /// The node prefix the off-board test ran against (REG-1.69).
    ///
    /// `None` where the daemon was told none and the test was off — kept
    /// beside the verdicts so the log can say which.
    node_prefix: Option<NodePrefix>,
}

impl BlockedPrefixes {
    /// Returns `issue` judged by the install's comparison (AUTH-4.36 step 4b).
    ///
    /// It is the list in force. In the rule's own words: an entry covering (a)
    /// the configured operator account — the claimant where the header names
    /// none — or (b), where that account is not an account of this board, the
    /// board's binding-writing account — the claimant where the header omits
    /// it — is inert.
    ///
    /// "Not an account of this board" is the off-board test, and it reads the
    /// header's operator account against the board's node prefix (REG-1.69):
    /// `!prefix_contains(node_prefix, operator)`. *Never* against the local
    /// root `1` (REG-1.66), which the rule's sealed wording names and which
    /// this build does not keep beside it: every address in the registry's
    /// global form begins with `1`, so under that test a host's `1.3.0.7`
    /// reads as on-board, (b) goes silent, and the hosted board's claimant
    /// becomes blockable — the cell REG-4.198 rules out. Two arms beside the
    /// test: the claimant taken in the header's place is an account of this
    /// board by construction ((a) and (b) are one account where the header
    /// names none), so only a *named* operator is tested — the fold's
    /// claimant is in the local form, which no `1.N` contains; and with no
    /// node prefix supplied the daemon cannot tell, so every operator reads
    /// as on-board — (b) silent — and the log says so once. The named
    /// operator is read as spelled, against the prefix and against the
    /// entries alike: the header is the operator's to spell in the
    /// registry's global form, the form the boundary speaks (REG-1.66).
    ///
    /// So (a) and (b) are one account where the header names none and at
    /// the root; (b) is silent on a fork the community itself serves, whose
    /// seat is an account of the copy, so the old claimant stays blockable
    /// (RES-66); and (b) is live where the host is off-board — at a hosted
    /// tier, exempting the served board's claimant, and on a fork a third
    /// party serves, exempting the seat the field names and never the old
    /// claimant (RES-67, RES-68). On an unclaimed board whose header names
    /// none there is no comparand and every entry stands as issued (RES-65
    /// item 4's named residue) — until the claim flip re-runs this.
    ///
    /// **Cover, never descent** (AUTH-4.70): the test is
    /// `prefix_contains(entry.prefix, comparand)`, so an entry below a
    /// comparand — the agent space, a delegated subtree — blocks.
    pub(super) fn installed_under(
        issue: BlockedIssue,
        claimant: Option<&Address>,
        node_prefix: Option<&NodePrefix>,
    ) -> BlockedPrefixes {
        let operator = issue.header.operator.as_ref().or(claimant).cloned();
        let off_board = match (&issue.header.operator, node_prefix) {
            (Some(named), Some(prefix)) => !prefix_contains(prefix.address(), named),
            _ => false,
        };
        let binding_writer = if off_board {
            issue.header.binding_writer.as_ref().or(claimant).cloned()
        } else {
            None
        };
        let covers = |entry: &BlockedEntry, comparand: &Option<Address>| {
            comparand.as_ref().is_some_and(|c| prefix_contains(&entry.prefix, c))
        };
        let inert = issue
            .entries
            .iter()
            .map(|entry| {
                if covers(entry, &operator) {
                    Some(Comparand::Operator)
                } else if covers(entry, &binding_writer) {
                    Some(Comparand::BindingWriter)
                } else {
                    None
                }
            })
            .collect();
        BlockedPrefixes { issue, inert, operator, binding_writer, node_prefix: node_prefix.cloned() }
    }

    /// Answers AUTH-4.36 step 4b's one predicate for `account`.
    ///
    /// `Some` iff some entry in force contains `account` — M3's containment,
    /// [`prefix_contains`] — and the address carried is the longest covering
    /// prefix's record, the nearest ground. A party under more than one
    /// entry is admitted only when every one is lifted, which falls out:
    /// each lift leaves the next longest covering it. Two entries over one
    /// prefix tie, and the first in supply order answers — the operator's own
    /// order, so the datum is a function of the issue alone.
    ///
    /// A scan of the list per consult, and a list is as long as a board's
    /// standing takedown records.
    pub fn covers(&self, account: &Address) -> Option<&Address> {
        let mut longest: Option<&BlockedEntry> = None;
        for (entry, inert) in self.judged() {
            if inert.is_some() || !prefix_contains(&entry.prefix, account) {
                continue;
            }
            let depth = |e: &BlockedEntry| e.prefix.tumbler().len();
            if longest.is_none_or(|held| depth(entry) > depth(held)) {
                longest = Some(entry);
            }
        }
        longest.map(|entry| &entry.record)
    }

    /// Pairs each entry of the issue with the install's verdict on it.
    ///
    /// This is the one pairing, so the two vectors meet at one site rather
    /// than at four `zip`s. A `zip` truncates silently, and the direction
    /// that truncates is the one that fails *open*: an `inert` shorter than
    /// `entries` makes every entry past its end invisible to
    /// [`BlockedPrefixes::covers`], which is a standing block that stops
    /// blocking with nothing to say so.
    ///
    /// # Panics
    ///
    /// Panics in a debug build where the invariant fails. The invariant: the
    /// two have equal length, established by
    /// [`BlockedPrefixes::installed_under`], which maps one from the other,
    /// and by `Default`, which leaves both empty — and kept by there being no
    /// other writer: both fields are private to this file, and
    /// [`BlockedPrefixes::issue()`] hands the issue out read-only. A lift is a
    /// fresh issue and a fresh install.
    fn judged(&self) -> impl Iterator<Item = (&BlockedEntry, Option<Comparand>)> {
        debug_assert_eq!(
            self.issue.entries.len(),
            self.inert.len(),
            "an entry and its verdict are built together and never moved apart"
        );
        self.issue.entries.iter().zip(self.inert.iter().copied())
    }

    /// Returns the header as issued.
    ///
    /// It is what the log names, and the seat carve's read (AUTH-3.21,
    /// RES-175).
    pub fn header(&self) -> &BlockedHeader {
        &self.issue.header
    }

    /// Returns the issue as supplied, whole and read-only.
    ///
    /// It is what the claim flip re-judges against the claimant it first
    /// seats ([`super::AuthState::reinstall_blocked_at_claim`]). Read-only is
    /// what [`BlockedPrefixes::judged`]'s invariant rests on: no file but this
    /// one can move an entry without its verdict.
    pub(super) fn issue(&self) -> &BlockedIssue {
        &self.issue
    }

    /// Counts the issue's entries in force — all but the inert ones.
    fn in_force(&self) -> usize {
        self.judged().filter(|(_, inert)| inert.is_none()).count()
    }

    /// Returns whether the issue carries no entries.
    ///
    /// It is the question the claim flip's log asks, and about the issue
    /// rather than the entries in force: the flip's news is exactly that an
    /// entry became inert, so an inert entry is something to say and an
    /// absent one is not.
    pub fn issue_is_empty(&self) -> bool {
        self.issue.entries.is_empty()
    }

    /// Returns the list in force's log lines (AUTH-4.70; AUTH-4.36 step 4b).
    ///
    /// The rules' words are "the startup log names the list in force" and
    /// "ignored at install and said so in the log". The lines are one naming
    /// the count, the header as resolved and the node prefix the off-board
    /// test ran against — or, where none was supplied, that the test was
    /// off, said once per install and not per entry — then one per inert
    /// entry, by name, with the comparand it covers. Entries in force are
    /// counted and not listed: the file is theirs to be read from, and a line
    /// per standing takedown at every reissue is a log nobody reads.
    ///
    /// # Panics
    ///
    /// Panics in a debug build where an inert entry's comparand is `None`,
    /// which `BlockedPrefixes::installed_under` never builds.
    pub fn log_lines(&self) -> Vec<String> {
        let named = |field: &Option<Address>, resolved: &Option<Address>, absent: &str| {
            match (field, resolved) {
                (Some(a), _) => format!("{} (the header's)", a.tumbler()),
                (None, Some(a)) => format!("{} (the claimant — {absent})", a.tumbler()),
                (None, None) => format!("none ({absent}, and the board is unclaimed)"),
            }
        };
        let header = self.header();
        let operator = named(&header.operator, &self.operator, "the header names none");
        let binding_writer = match (&self.binding_writer, &self.node_prefix) {
            (live @ Some(_), Some(prefix)) => format!(
                "{} — exempt, the operator account being off-board (not under the node \
                 prefix {prefix})",
                named(&header.binding_writer, live, "the header omits it"),
            ),
            // Unreachable by construction — (b) is live only against a
            // prefix — and answered rather than asserted: a log line is not
            // the place to stop a daemon.
            (live @ Some(_), None) => format!(
                "{} — exempt, the operator account being off-board",
                named(&header.binding_writer, live, "the header omits it"),
            ),
            (None, Some(prefix)) => format!(
                "not a comparand (the operator account is an account of this board — under \
                 the node prefix {prefix}, or the claimant taken in the header's place — or \
                 there is none)"
            ),
            (None, None) => "not a comparand (no --node-prefix: the off-board test is off; a \
                             hosted board must supply one, --node-prefix or SKEPD_NODE_PREFIX, \
                             at a restart)"
                .to_string(),
        };
        let inert_entries = self.judged().filter(|(_, inert)| inert.is_some()).count();
        let mut lines = vec![format!(
            "{} of {} entries in force, {inert_entries} inert; operator account {operator}; \
             binding-writing account {binding_writer}",
            self.in_force(),
            self.issue.entries.len(),
        )];
        for (entry, inert) in self.judged() {
            let (covered, exempted) = match inert {
                None => continue,
                Some(Comparand::Operator) => ("the configured operator account", &self.operator),
                Some(Comparand::BindingWriter) => {
                    ("the board's binding-writing account", &self.binding_writer)
                }
            };
            // Unreachable by construction —
            // [`BlockedPrefixes::installed_under`] judges an entry against a
            // comparand only inside `covers`, which requires that comparand
            // `Some` — and answered rather than asserted, for the reason the
            // arm above gives. The cell is sharper here than there: this
            // renders from `credential_sequence` under the credential write
            // lock and the serialization lock after the claim has committed
            // ([`skep_util::notice`]), so a panic is `500 internal_panic` for a
            // one-time-only write that landed and whose retry meets
            // `already_claimed`. The debug assert is what makes the premise
            // loud where a test can see it.
            debug_assert!(exempted.is_some(), "an entry is inert only against a comparand");
            let account =
                exempted.as_ref().map(|a| format!(" {}", a.tumbler())).unwrap_or_default();
            lines.push(format!(
                "entry {} (record {}) is INERT — it covers {covered}{account}; ignored",
                entry.prefix.tumbler(),
                entry.record.tumbler(),
            ));
        }
        lines
    }
}

/// What one look at a moved supply file came to.
///
/// These are the reissue's two outcomes, for the log `skepd::Daemon`
/// writes.
#[derive(Debug)]
pub enum Reissue {
    /// The new issue is the list in force.
    Installed,
    /// The look refused the file, and nothing was installed.
    ///
    /// The path names no regular file, or the file could not be read, is
    /// not a list, or is past the byte cap; the list in force stands.
    Refused(io::Error),
}

/// The blocked-prefix list's supply channel (AUTH-4.70; RES-65 item 4).
///
/// The list's channel is the build's, and this is the recommended one, "a
/// file the flag `--blocked-prefixes <path>` names": a file the operator
/// owns, its path taken at open alone — a board opened with none installs
/// no list until a restart names one — and the file read at every start and
/// re-read when it moves, its identity checked at the head of every request
/// ([`super::AuthState::reissue_blocked_prefixes`]), one `stat`, so the
/// next request after a replace installs the new issue.
///
/// Not the conventional reload signal, deliberately. This daemon has no
/// signal handling at all (`main.rs`: crash-stop is the shutdown story), a
/// signal is the process's and a `skepd::Daemon` is a value — several
/// live in one process wherever the library is embedded, this crate's own
/// suites included — and a signal says only "look again", which the file's
/// identity already says without a second channel to keep in step with the
/// first. What the check buys beside that: the install happens *before* the
/// request that noticed it resolves its actor, so a reissue is in force at
/// the first presentation after it, with no window a sleeping watcher
/// thread would leave.
///
/// **The file** is one JSON object, strict keys, nothing else admitted:
///
/// ```json
/// {"operator": "<address>", "binding_writer": "<address>",
///  "entries": [{"prefix": "<address>", "record": "<address>"}, …]}
/// ```
///
/// `operator` and `binding_writer` are the two-field header, each optional
/// — absent is "the header names none", and there is no other spelling;
/// `entries` is required, and an empty array is the explicit empty list (a
/// lift of everything is an issue, never an absent file). Every address is
/// dotted decimal under the codec's own tumbler caps, T4-valid, in the form
/// its field is pinned to (AUTH-4.70): `operator` and every `record` in the
/// registry's global form — the board's node prefix in place of the local
/// form's leading `1` — and `binding_writer` and every `prefix` in the
/// board's local form, as its session accounts are. The read checks no
/// form: an address is taken as written, and the install's verdicts follow
/// what it says. JSON because a truncated object does not parse: a reader
/// racing a writer that did not replace the file atomically refuses the
/// torn issue and keeps the list in force, where a line format would
/// install the half it saw. The operator still owes the atomic replace
/// (write beside, rename over) — it is also what gives every issue a fresh
/// identity. Under a container the operator mounts the directory that
/// holds the file, never the file itself: a file's bind mount keeps the
/// inode it was made over, so a rename on the host moves no identity this
/// daemon can see, and the list in force stands with nothing said.
#[derive(Debug)]
pub(super) struct BlockedSupply {
    pub(super) path: PathBuf,
    /// The file's identity as last looked at.
    ///
    /// `None` for a file that was not there. A failed look is remembered
    /// too, so a bad issue is refused and logged once rather than at every
    /// request until it moves.
    seen: parking_lot::Mutex<Option<FileStamp>>,
}

/// A file's identity, cheaply: what moves when the operator replaces it.
///
/// The inode is what makes two issues written inside one timestamp tick
/// distinct (a rename-over is always a new file); where there is none, the
/// modification time and the length carry it alone.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStamp {
    modified: Option<SystemTime>,
    len: u64,
    #[cfg(unix)]
    inode: (u64, u64),
}

impl FileStamp {
    fn of(meta: &std::fs::Metadata) -> FileStamp {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        FileStamp {
            modified: meta.modified().ok(),
            len: meta.len(),
            #[cfg(unix)]
            inode: (meta.dev(), meta.ino()),
        }
    }

    /// Returns the identity of whatever is at `path` now.
    ///
    /// `None` where nothing can be stat'ed there.
    fn at(path: &Path) -> Option<FileStamp> {
        std::fs::metadata(path).ok().as_ref().map(FileStamp::of)
    }
}

impl BlockedSupply {
    /// Reads the start-up supply from `path`, or fails the open (RES-115).
    ///
    /// # Errors
    ///
    /// Fails as [`BlockedSupply::read`] does: the path names no regular
    /// file, or the file cannot be read, is not a list, or is past
    /// [`MAX_BLOCKED_SUPPLY_BYTES`].
    pub(super) fn open(path: &Path) -> io::Result<(BlockedSupply, BlockedIssue)> {
        let supply = BlockedSupply { path: path.to_path_buf(), seen: parking_lot::Mutex::new(None) };
        let (stamp, issue) = supply.read()?;
        *supply.seen.lock() = Some(stamp);
        Ok((supply, issue))
    }

    /// Reads the file once, at most a byte past the cap, with its identity.
    ///
    /// The path's kind is asked first, and a path that names no regular file
    /// is refused unopened: a FIFO's open waits for a writer, which at start
    /// would hang the open and at a reissue would hold `seen`, and with it
    /// every request. The identity comes off the open handle — so the stamp
    /// names the bytes read, and a replace landing between this and the next
    /// look is seen as one — then the byte cap, then the parse.
    ///
    /// # Errors
    ///
    /// Every failure is an `io::Error` naming the path: a stat, an open or a
    /// read that fails keeps its own kind; a path that names no regular file,
    /// a file that is not a list and one past [`MAX_BLOCKED_SUPPLY_BYTES`]
    /// are all `InvalidData`, so the channel's refusals travel as one kind.
    fn read(&self) -> io::Result<(FileStamp, BlockedIssue)> {
        use std::io::Read;
        let with_path =
            |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", self.path.display()));
        if !std::fs::metadata(&self.path).map_err(with_path)?.is_file() {
            return Err(with_path(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a regular file: the list is a file the operator replaces by rename",
            )));
        }
        let file = std::fs::File::open(&self.path).map_err(with_path)?;
        let stamp = FileStamp::of(&file.metadata().map_err(with_path)?);
        let mut bytes = Vec::new();
        // One past the cap, so a file that exactly fills it is told apart
        // from one that exceeds it — and `take` rather than a length test
        // off the stamp, which a file being appended to concurrently
        // outruns.
        file.take(MAX_BLOCKED_SUPPLY_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(with_path)?;
        if bytes.len() > MAX_BLOCKED_SUPPLY_BYTES {
            return Err(with_path(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the list is past the {MAX_BLOCKED_SUPPLY_BYTES}-byte supply cap"),
            )));
        }
        let issue = parse_issue(&bytes)
            .map_err(|detail| with_path(io::Error::new(io::ErrorKind::InvalidData, detail)))?;
        Ok((stamp, issue))
    }

    /// Looks at the file once, and installs its issue where it moved.
    ///
    /// This is the channel's whole operation, here because the identity it
    /// turns on is this type's own. `None` is the ordinary request's answer:
    /// nothing moved, at the cost of one `stat`.
    ///
    /// `install` is the caller's, because the list is replaced under a lock
    /// this type knows nothing about. It runs with `seen` held, so a request
    /// arriving mid-install waits for it rather than resolving under a list an
    /// earlier request has already seen superseded. Lock order is therefore
    /// `seen` → whatever `install` takes, and nothing holding that lock
    /// touches `seen`.
    ///
    /// A re-read that fails calls `install` not at all — the list is replaced
    /// whole or not — and the failed look is remembered, so the refusal is
    /// answered once rather than at every request until the file moves again.
    pub(super) fn reissue(&self, install: impl FnOnce(BlockedIssue)) -> Option<Reissue> {
        let current = FileStamp::at(&self.path);
        let mut seen = self.seen.lock();
        if *seen == current {
            return None;
        }
        match self.read() {
            Ok((stamp, issue)) => {
                install(issue);
                *seen = Some(stamp);
                Some(Reissue::Installed)
            }
            Err(e) => {
                *seen = current;
                Some(Reissue::Refused(e))
            }
        }
    }
}

/// Parses one issue of the list; [`BlockedSupply`] states the format.
///
/// The never-silent device throughout ([`check_keys`]): a field this daemon
/// does not read is a named refusal, never a header quietly ignored.
///
/// # Errors
///
/// `Err(detail)`, the detail naming the fault, for JSON that does not
/// parse, a list that is not an object, a member this daemon does not read,
/// a missing or non-array `entries`, an entry that is not an object or
/// lacks `prefix` or `record`, and an address member [`address_field`]
/// refuses.
fn parse_issue(bytes: &[u8]) -> Result<BlockedIssue, String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON: {e}"))?;
    let Value::Object(m) = v else {
        return Err("the list must be a JSON object".into());
    };
    check_keys(&m, &["operator", "binding_writer", "entries"])?;
    let header = BlockedHeader {
        operator: address_field(&m, "operator")?,
        binding_writer: address_field(&m, "binding_writer")?,
    };
    let entries = m
        .get("entries")
        .and_then(Value::as_array)
        .ok_or("missing or non-array field 'entries'")?
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let in_entry = |detail: String| format!("entries[{i}]: {detail}");
            let Value::Object(entry) = entry else {
                return Err(in_entry("expected a JSON object".into()));
            };
            check_keys(entry, &["prefix", "record"]).map_err(in_entry)?;
            let required = |k: &str| {
                address_field(entry, k)
                    .map_err(in_entry)?
                    .ok_or_else(|| in_entry(format!("missing field '{k}'")))
            };
            Ok(BlockedEntry { prefix: required("prefix")?, record: required("record")? })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(BlockedIssue { header, entries })
}

/// Reads one address member: absent ⇒ `None`; present ⇒ its address.
///
/// A present member is a dotted-decimal string through
/// [`crate::codec::wire_address`], the wire's one capped-and-T4 address door.
///
/// # Errors
///
/// A named refusal where the member is not a string or the door refuses
/// it, this file's own grammar supplying the field name and that door the
/// fault.
fn address_field(m: &Map<String, Value>, k: &str) -> Result<Option<Address>, String> {
    let Some(v) = m.get(k) else { return Ok(None) };
    let s = v.as_str().ok_or_else(|| format!("field '{k}' must be a dotted-decimal string"))?;
    wire_address(s).map(Some).map_err(|detail| format!("field '{k}': {detail}"))
}

#[cfg(test)]
mod tests;
