//! The blocked-prefix list and its supply file.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use serde_json::{Map, Value};
use skep_address::Address;
use skep_namespace::prefix_contains;

use super::options::AuthConfig;
use super::prefix::NodePrefix;
use crate::codec::{check_keys, wire_address};

/// The most bytes one ISSUE of the blocked-prefix list may carry
/// ([`BlockedSupply`]), refused before the read rather than after it.
///
/// The cap bounds the FAILURE case and not the legitimate one: an entry is
/// two addresses in the registry's global form under a small JSON wrapper,
/// under a hundred bytes, so this admits order 90,000 standing takedown
/// records — four orders of magnitude above a board's plausible list. What
/// it removes is the unbounded one, which is a path that is NOT a list: a
/// read-to-end followed by a whole `serde_json::Value` over those bytes, at
/// the ~20× transient heap this crate prices on [`crate::body_cap`]. It is
/// paid at [`super::AuthState::open`] before the listener binds, where the open
/// promises a named refusal rather than a hang; and at every reissue with
/// the supply's `seen` HELD at the head of routing, so every in-flight
/// request waits on it, `/health` and `/session` included.
///
/// The number is [`crate::body_cap`]'s own largest admitted input, cited
/// rather than re-derived: this file carries strictly less per record than a
/// frame does, so the same ceiling is the same headroom or more.
const MAX_BLOCKED_SUPPLY_BYTES: usize = 8 * 1024 * 1024;

// ── the blocked-prefix list (AUTH-1.44, AUTH-4.36 step 4b, AUTH-4.70) ────

/// One entry of the BLOCKED-PREFIX LIST (AUTH-4.36 step 4b): a prefix, and
/// the version address of the takedown record the entry cites — the ONE
/// public datum the handshake's 403 carries (AUTH-6.5). The daemon reads no
/// record and knows no takedown: `record` is echoed and never dereferenced,
/// which is why it is held as the address it was issued as and nothing
/// more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BlockedEntry {
    pub prefix: Address,
    pub record: Address,
}

/// The list's two-field HEADER (AUTH-4.36 step 4b; AUTH-4.70 "the header
/// two values on it"). Read from config and from nowhere else: the daemon
/// derives neither field and reads no record for one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BlockedHeader {
    /// The CONFIGURED OPERATOR ACCOUNT. `None` where the header names none,
    /// and the claimant is then taken in its place.
    pub operator: Option<Address>,
    /// The board's BINDING-WRITING ACCOUNT — the claimant on an unforked
    /// lineage, the SEAT on a forked one, never the superseded claimant
    /// (REG-3.52). `None` where the header omits it, and the claimant is
    /// then taken in its place. Its SECOND reader is AUTH-3.21's seat carve
    /// at slot (6), which reads it beside the claimant and compares it
    /// (RES-175), through [`BlockedPrefixes::header`].
    pub binding_writer: Option<Address>,
}

/// One ISSUE of the list, as the operator supplies it: the header and
/// every entry, in supply order, before the install's comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct BlockedIssue {
    pub header: BlockedHeader,
    pub entries: Vec<BlockedEntry>,
}

/// Which of the install's two INERT comparands an entry covers (AUTH-4.36
/// step 4b; REG-4.198: the block never reaches the hand that lifts it and
/// never takes a board from the party that writes its bindings).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparand {
    /// (a) the configured operator account.
    Operator,
    /// (b) the board's binding-writing account — a comparand only where the
    /// operator account is NOT an account of this board.
    BindingWriter,
}

/// The list IN FORCE: one issue, with the install's verdict on each entry
/// beside it. An entry covering a comparand is INERT — ignored at install
/// and said so in the log — and every other entry blocks.
///
/// The issue is kept WHOLE, inert entries included, because the comparison
/// is run twice over one issue: at the install, and again at the claim
/// flip, where the claimant the header defers to first exists.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct BlockedPrefixes {
    pub(super) issue: BlockedIssue,
    /// Per entry of `issue.entries`: the comparand it covers, or `None` for
    /// an entry in force.
    inert: Vec<Option<Comparand>>,
    /// Comparand (a) as this install resolved it: the header's operator,
    /// else the claimant, else none (an unclaimed board naming none).
    operator: Option<Address>,
    /// Comparand (b) as this install resolved it — `Some` only where it is
    /// LIVE, which is where the operator account is off-board.
    binding_writer: Option<Address>,
    /// The node prefix the off-board test ran against (REG-1.69), or `None`
    /// where the daemon was told none and the test was off — kept beside
    /// the verdicts so the log can say which.
    node_prefix: Option<NodePrefix>,
}

impl BlockedPrefixes {
    /// THE INSTALL'S COMPARISON (AUTH-4.36 step 4b, in its own words): an
    /// entry covering (a) the CONFIGURED OPERATOR ACCOUNT — the claimant
    /// where the header names none — or (b), where that account is NOT an
    /// account of this board, the board's BINDING-WRITING ACCOUNT — the
    /// claimant where the header omits it — is INERT.
    ///
    /// "NOT an account of this board" is THE OFF-BOARD TEST, and as ruled
    /// (2026-09-18, W2a's escalation 3) it reads the header's operator
    /// account against the board's NODE PREFIX (REG-1.69):
    /// `!prefix_contains(node_prefix, operator)`. NEVER against the local
    /// root `1` (REG-1.66), which the rule's sealed wording names and which
    /// this build does not keep beside it: every address in the registry's
    /// GLOBAL form begins with `1`, so under that test a host's `1.3.0.7`
    /// read as on-board, (b) went silent, and the hosted board's claimant
    /// became blockable — the cell REG-4.198 rules out. Two arms beside the
    /// test: the claimant taken in the header's place is an account of this
    /// board BY CONSTRUCTION ((a) and (b) are one account where the header
    /// names none), so only a NAMED operator is tested — the fold's claimant
    /// is in the local form, which no `1.N` contains; and with NO node
    /// prefix supplied the daemon CANNOT tell, so every operator reads as
    /// on-board — (b) silent — and the log says so once. The named operator
    /// is read AS SPELLED, against the prefix and against the entries alike:
    /// the header is the operator's to spell in the registry's global
    /// form, the form the boundary speaks (REG-1.66).
    ///
    /// So (a) and (b) are one account where the header names none and at
    /// the root; (b) is SILENT on a fork the community itself serves, whose
    /// seat is an account of the copy, so the old claimant stays blockable
    /// (RES-66); and (b) is LIVE where the host is off-board — at a hosted
    /// tier, exempting the served board's claimant, and on a fork a third
    /// party serves, exempting the SEAT the field names and never the old
    /// claimant (RES-67, RES-68). On an UNCLAIMED board whose header names
    /// none there is no comparand and every entry stands as issued (RES-65
    /// item 4's named residue) — until the claim flip re-runs this.
    ///
    /// COVER, never descent (AUTH-4.70): the test is
    /// `prefix_contains(entry.prefix, comparand)`, so an entry BELOW a
    /// comparand — the agent space, a delegated subtree — blocks as before.
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

    /// AUTH-4.36 step 4b's one predicate: `Some` iff some entry IN FORCE
    /// contains `account` — M3's containment, [`prefix_contains`] — and the
    /// address carried is the LONGEST covering prefix's record, the nearest
    /// ground. A party under more than one entry is admitted only when
    /// every one is lifted, which falls out: each lift leaves the next
    /// longest covering it. Two entries over ONE prefix tie, and the first
    /// in supply order answers — the operator's own order, so the
    /// datum is a function of the issue alone.
    ///
    /// A scan of the list per consult, and a list is as long as a board's
    /// STANDING takedown records.
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

    /// Each entry of the issue beside the install's verdict on it — THE one
    /// pairing, so the two vectors meet at one site rather than at three
    /// `zip`s. A `zip` truncates silently, and the direction that truncates
    /// is the one that fails OPEN: an `inert` shorter than `entries` makes
    /// every entry past its end invisible to [`BlockedPrefixes::covers`],
    /// which is a standing block that stops blocking with nothing to say so.
    ///
    /// INVARIANT: the two have equal length, established by
    /// [`BlockedPrefixes::installed_under`], which maps one from the other,
    /// and by `Default`, which leaves both empty. Nothing mutates either
    /// after the install; a lift is a fresh ISSUE and a fresh install.
    fn judged(&self) -> impl Iterator<Item = (&BlockedEntry, Option<Comparand>)> {
        debug_assert_eq!(
            self.issue.entries.len(),
            self.inert.len(),
            "an entry and its verdict are built together and never moved apart"
        );
        self.issue.entries.iter().zip(self.inert.iter().copied())
    }

    /// The header as issued — what the log names, and the seat carve's read
    /// (AUTH-3.21, RES-175).
    pub fn header(&self) -> &BlockedHeader {
        &self.issue.header
    }

    /// The entries in force — every entry of the issue but the inert ones.
    fn in_force(&self) -> usize {
        self.judged().filter(|(_, inert)| inert.is_none()).count()
    }

    /// Whether the issue carries NO entries — the question the claim flip's
    /// log asks, and about the ISSUE rather than the entries in force: the
    /// flip's news is exactly that an entry became INERT, so an inert entry
    /// is something to say and an absent one is not.
    pub fn issue_is_empty(&self) -> bool {
        self.issue.entries.is_empty()
    }

    /// THE LOG (AUTH-4.70 "the startup log names the list in force";
    /// AUTH-4.36 step 4b "ignored at install and said so in the log"): one
    /// line naming the count, the header as resolved and the node prefix
    /// the off-board test ran against — or, where none was supplied, that
    /// the test was off, said once per install and not per entry — then one
    /// line per INERT entry, by name, with the comparand it covers. Entries
    /// in force are counted and not listed: the file is theirs to be read
    /// from, and a line per standing takedown at every reissue is a log
    /// nobody reads.
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
                             hosted board must supply one)"
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
            // Unreachable by construction — [`BlockedPrefixes::installed_under`]
            // judges an entry against a comparand only inside `covers`, which
            // requires that comparand `Some` — and ANSWERED rather than
            // asserted, for the reason the arm above gives. The cell is
            // sharper here than there: this renders from
            // `credential_sequence` under both write locks AFTER the claim has
            // committed ([`crate::notice`]), so a panic is `500
            // internal_panic` for a one-time-only write that landed and whose
            // retry meets `already_claimed`. The debug assert is what makes
            // the premise loud where a test can see it.
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

/// The installed list — AUTH-4.36 step 4b's `blocked_prefixes(cfg)`, a pure
/// read of the list in force. By value (one pointer clone), so no reader
/// holds the cell's lock across its own work and an install never waits on
/// a handshake's verify loop.
pub(crate) fn blocked_prefixes(cfg: &AuthConfig) -> Arc<BlockedPrefixes> {
    Arc::clone(&cfg.blocked.read())
}

/// What one look at a moved supply file came to — the reissue's two
/// outcomes, for the log [`crate::Daemon`] writes.
#[derive(Debug)]
pub(crate) enum Reissue {
    /// The new issue is the list in force.
    Installed,
    /// The file could not be read, is not a list, or is past the byte cap:
    /// nothing was installed and the list in force stands.
    Refused(io::Error),
}

/// THE CHANNEL (AUTH-4.70: "its channel the build's"; RES-65 item 4's
/// recommendation, "a file the flag `--blocked-prefixes <path>` names"): a
/// file the operator owns, read at every start and RE-READ WHEN IT
/// MOVES — its identity checked at the head of every request
/// ([`super::AuthState::reissue_blocked_prefixes`]), one `stat`.
///
/// Not the conventional reload SIGNAL, deliberately. This daemon has no
/// signal handling at all (`main.rs`: crash-stop is the shutdown story), a
/// signal is the PROCESS's and a [`crate::Daemon`] is a value — several
/// live in one process wherever the library is embedded, this crate's own
/// suites included — and a signal says only "look again", which the file's
/// identity already says without a second channel to keep in step with the
/// first. What the check buys beside that: the install happens BEFORE the
/// request that noticed it resolves its actor, so a reissue is in force at
/// the first presentation after it, with no window a sleeping watcher
/// thread would leave.
///
/// THE FILE is one JSON object, strict keys, nothing else admitted:
///
/// ```json
/// {"operator": "<address>", "binding_writer": "<address>",
///  "entries": [{"prefix": "<address>", "record": "<address>"}, …]}
/// ```
///
/// `operator` and `binding_writer` are the two-field HEADER, each OPTIONAL
/// — absent is "the header names none", and there is no other spelling;
/// `entries` is REQUIRED, and an empty array is the explicit empty list (a
/// lift of everything is an ISSUE, never an absent file). Every address is
/// dotted decimal under the codec's own tumbler caps, T4-valid. JSON
/// because a truncated object does not parse: a reader racing a writer
/// that did not replace the file atomically REFUSES the torn issue and
/// keeps the list in force, where a line format would install the half it
/// saw. The operator still owes the ATOMIC REPLACE (write beside,
/// rename over) — it is also what gives every issue a fresh identity.
#[derive(Debug)]
pub(super) struct BlockedSupply {
    pub(super) path: PathBuf,
    /// The file's identity as last looked at — `None` for a file that was
    /// not there. A FAILED look is remembered too, so a bad issue is
    /// refused and logged once rather than at every request until it moves.
    seen: parking_lot::Mutex<Option<FileStamp>>,
}

/// A file's identity, cheaply: what moves when the operator replaces
/// it. The inode is what makes two issues written inside one timestamp tick
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

    /// The identity of whatever is at `path` now; `None` where nothing can
    /// be stat'ed there.
    fn at(path: &Path) -> Option<FileStamp> {
        std::fs::metadata(path).ok().as_ref().map(FileStamp::of)
    }
}

impl BlockedSupply {
    /// The START-UP SUPPLY (RES-115): read the named file, or fail the open.
    pub(super) fn open(path: &Path) -> io::Result<(BlockedSupply, BlockedIssue)> {
        let supply = BlockedSupply { path: path.to_path_buf(), seen: parking_lot::Mutex::new(None) };
        let (stamp, issue) = supply.read()?;
        *supply.seen.lock() = Some(stamp);
        Ok((supply, issue))
    }

    /// One read of the file, whole: its identity off the OPEN handle — so
    /// the stamp names the bytes read, and a replace landing between this
    /// and the next look is seen as one — then the byte cap, then the
    /// parse. Every failure is an `io::Error` naming the path; a file that
    /// is not a list, and one past [`MAX_BLOCKED_SUPPLY_BYTES`], are both
    /// `InvalidData`, so the channel's two refusals travel as one kind.
    fn read(&self) -> io::Result<(FileStamp, BlockedIssue)> {
        use std::io::Read;
        let with_path =
            |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", self.path.display()));
        let file = std::fs::File::open(&self.path).map_err(with_path)?;
        let stamp = FileStamp::of(&file.metadata().map_err(with_path)?);
        let mut bytes = Vec::new();
        // ONE PAST the cap, so a file that exactly fills it is told apart
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

    /// One look at the file, and the install where it MOVED — the channel's
    /// whole operation, here because the identity it turns on is this type's
    /// own. `None` is the ordinary request's answer: nothing moved, at the
    /// cost of one `stat`.
    ///
    /// `install` is the CALLER's, because the list is replaced under a gate
    /// this type knows nothing about. It runs with `seen` HELD, so a request
    /// arriving mid-install waits for it rather than resolving under a list an
    /// earlier request has already seen superseded. Lock order is therefore
    /// `seen` → whatever `install` takes, and nothing holding that gate
    /// touches `seen`.
    ///
    /// A re-read that FAILS calls `install` not at all — the list is replaced
    /// WHOLE or not — and the failed look is REMEMBERED, so the refusal is
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

/// Parse one issue of the list — [`BlockedSupply`] states the format. The
/// never-silent device throughout ([`check_keys`]): a field this daemon does
/// not read is a named refusal, never a header quietly ignored.
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

/// One address member: absent ⇒ `None`; present ⇒ a dotted-decimal string
/// through [`crate::codec::wire_address`], the wire's one capped-and-T4
/// address door — or a named refusal, this file's own grammar supplying the
/// field name and that door the fault.
fn address_field(m: &Map<String, Value>, k: &str) -> Result<Option<Address>, String> {
    let Some(v) = m.get(k) else { return Ok(None) };
    let s = v.as_str().ok_or_else(|| format!("field '{k}' must be a dotted-decimal string"))?;
    wire_address(s).map(Some).map_err(|detail| format!("field '{k}': {detail}"))
}

#[cfg(test)]
mod tests;
