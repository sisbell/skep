//! The manifest: how a second run knows the board is seeded.
//!
//! It also tells a killed run where to resume. It is one file beside the
//! key store, keyed by the board (`H.1`'s chain, 64 lowercase hex — the
//! term every attested write names, fixed from the claim for the life of
//! the board), holding what a seed landed as one JSON line per write, by
//! the write's own envelope `id` (`cut-00042:draft`, `:edition`, `:shot`,
//! `:link:3`), appended after the board's ack and never before —
//! `client.md` §3.5's discipline, "lands after the board answered". Its
//! first line is the header, the seed's key: the board, the account and
//! principal, the pin, the cut rule and subtree, the counts. A second run
//! under the same key skips every write the manifest holds — all of them,
//! and it adds nothing and says so — and a killed run resumes at the first
//! write not held, the staging draft and every address re-read from the
//! lines. What the lines cannot hold is the write the killed run had in
//! flight — sent, perhaps landed, its ack never read: the resume makes it
//! again under a session of its own, where its envelope `id` is no key
//! (wire.md §Correlation and idempotency: an `id` holds on its session
//! alone), so a mint or a shot that had landed lands twice; the run says so
//! as it opens a manifest it resumes. A manifest whose header is another
//! seed's is a halt naming the difference, never a guess at what another
//! run landed (the record's §5.1 arm (a); the probe of the board alone, arm
//! (c), is taken only where no manifest line stands: a board holding
//! documents past doc 1 then is not fresh, and is refused — a run stopped
//! inside its first write leaves a board so).
//!
//! The path follows the search index's precedent — "the index directory
//! beside the key store, never inside it", `<data>/index/<chain>/` — as
//! `<store's parent>/<store's name>-seed/<chain>.jsonl`: `~/.skep-seed/…`
//! for the default store. A line is one `write` of the whole line with its
//! newline; a torn final line — a run killed inside the write, or a write
//! cut short at a full volume — is no line and is ignored, as the bindings
//! file's reader ignores one (§3.7), so the write it would have recorded is
//! made again on the resume — whose first record cuts the fragment away
//! before it appends ([`Manifest::record`]), so no line is ever written
//! onto a torn one, where the two would read back as one line that is no
//! JSON and refuse every later run.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use skep_client::Halt;

/// The suffix of the manifest directory's name beside the store.
///
/// The name is the store's own name and this suffix.
pub const DIR_SUFFIX: &str = "-seed";

/// The header line's `kind`, so a reader knows the file as this tool's.
pub const KIND: &str = "seed";

/// The tool's name, as the header and the JSON object carry it.
pub const TOOL: &str = "skep-dev seed";

/// Returns the manifest's path for `store` and the board's `chain`.
pub fn path_for(store: &Path, chain: &str) -> PathBuf {
    let name = store
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "skep".to_string());
    let parent = store.parent().map(Path::to_path_buf).unwrap_or_default();
    parent.join(format!("{name}{DIR_SUFFIX}")).join(format!("{chain}.jsonl"))
}

/// The seed's key, the header line: what one seed of one board is.
///
/// So a run under any other settings is another seed, and refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// `H.1`'s chain, lowercase hex.
    pub chain: String,
    /// The origin dialed.
    pub board: String,
    /// The claimant's account and principal.
    pub account: String,
    pub principal: u64,
    /// The corpus: the pin, the cut rule, the subtree where one was given.
    pub pin: String,
    pub cut: String,
    pub from: Option<String>,
    /// The shapes' counts: the documents, the versions' period, the drafts.
    pub documents: usize,
    pub versions: usize,
    pub drafts: usize,
}

impl Header {
    fn to_value(&self) -> Value {
        json!({
            "kind": KIND,
            "tool": TOOL,
            "chain": self.chain,
            "board": self.board,
            "account": self.account,
            "principal": self.principal,
            "pin": self.pin,
            "cut": self.cut,
            "from": self.from,
            "documents": self.documents,
            "versions": self.versions,
            "drafts": self.drafts,
        })
    }

    /// Returns the members that differ between this key and `other`'s line.
    ///
    /// Each is spelled `name: <recorded> recorded, <asked> asked`.
    fn differences(&self, other: &Value) -> Vec<String> {
        let mine = self.to_value();
        let mut out = Vec::new();
        for name in [
            "chain",
            "board",
            "account",
            "principal",
            "pin",
            "cut",
            "from",
            "documents",
            "versions",
            "drafts",
        ] {
            if other[name] != mine[name] {
                out.push(format!("{name}: {} recorded, {} asked", other[name], mine[name]));
            }
        }
        out
    }
}

/// The manifest: what the lines hold, by id, and where they are written.
#[derive(Debug)]
pub struct Manifest {
    path: PathBuf,
    header: Header,
    items: BTreeMap<String, Value>,
    /// Whether the file stands on disk with its header written.
    on_disk: bool,
    /// Whether a file stood at the path when the run opened it.
    ///
    /// It counts whether its header line was complete or not.
    found: bool,
    /// The length of the file's complete lines, where a torn line followed.
    ///
    /// The torn line is the final one, found when the run opened the file;
    /// the length is what the next record cuts the file back to before it
    /// appends.
    torn_at: Option<u64>,
}

impl Manifest {
    /// Opens the manifest at `path` for `header`'s seed.
    ///
    /// It is read where the file stands — its header judged against
    /// `header`, each complete line an item by its id, a torn final line
    /// marked for the next record to cut away — else empty, its header
    /// written at the first record.
    ///
    /// # Errors
    ///
    /// Any difference between its header and `header` is a halt naming it;
    /// a file that cannot be read as this tool's is a halt naming why —
    /// unreadable, a first line that is no JSON or no seed's header, or a
    /// later line that is no JSON or names no `id`.
    pub fn open(path: PathBuf, header: Header) -> Result<Manifest, Halt> {
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Manifest {
                    path,
                    header,
                    items: BTreeMap::new(),
                    on_disk: false,
                    found: false,
                    torn_at: None,
                });
            }
            Err(e) => return Err(unreadable(&path, e.to_string())),
        };
        // Complete lines alone: a torn final line is no line.
        let complete = match text.rfind('\n') {
            Some(i) => &text[..=i],
            None => "",
        };
        let torn_at = (complete.len() < text.len()).then_some(complete.len() as u64);
        let mut lines = complete.lines();
        let Some(first) = lines.next() else {
            return Ok(Manifest {
                path,
                header,
                items: BTreeMap::new(),
                on_disk: false,
                found: true,
                torn_at,
            });
        };
        let recorded: Value = serde_json::from_str(first)
            .map_err(|e| unreadable(&path, format!("its first line is not JSON: {e}")))?;
        if recorded["kind"].as_str() != Some(KIND) {
            return Err(unreadable(&path, "its first line is not a seed's header".to_string()));
        }
        let differences = header.differences(&recorded);
        if !differences.is_empty() {
            return Err(Halt::face(
                format!("the manifest at {} records another seed of this board", path.display()),
                format!(
                    "the file is keyed by H.1's chain — one seed per board — and its header differs from this run's settings: {}",
                    differences.join("; ")
                ),
                "run with the settings the manifest records, or seed a FRESH board (a new data directory, claimed anew): this tool never guesses what another run landed",
            ));
        }
        let mut items = BTreeMap::new();
        for (n, line) in lines.enumerate() {
            let v: Value = serde_json::from_str(line)
                .map_err(|e| unreadable(&path, format!("line {} is not JSON: {e}", n + 2)))?;
            let Some(id) = v["id"].as_str() else {
                return Err(unreadable(&path, format!("line {} names no `id`", n + 2)));
            };
            items.insert(id.to_string(), v);
        }
        Ok(Manifest { path, header, items, on_disk: true, found: true, torn_at })
    }

    /// Returns where the manifest is written.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns whether no header line stands yet.
    ///
    /// No write of this seed is recorded: no file, or one holding no
    /// complete line ([`Manifest::is_torn`]).
    pub fn is_new(&self) -> bool {
        !self.on_disk
    }

    /// Returns whether a file stood holding no complete line.
    ///
    /// It is what a run stopped inside its first record leaves, its write
    /// landed and its line torn.
    pub fn is_torn(&self) -> bool {
        self.found && !self.on_disk
    }

    /// Returns the lines the manifest holds past its header.
    ///
    /// There is one per write recorded, one per ghost the links name, and
    /// the second account's step, the seed's last record.
    pub fn held(&self) -> usize {
        self.items.len()
    }

    /// Returns the item recorded under `id`, where one is.
    pub fn recorded(&self, id: &str) -> Option<&Value> {
        self.items.get(id)
    }

    /// Records one write, after its ack: `item`'s members under `id`.
    ///
    /// They are appended as one line — the header line first where the file
    /// is new, and a torn final line the run found cut away first, so the
    /// record lands on a line of its own.
    ///
    /// # Errors
    ///
    /// A write that cannot be made is a halt saying what it means: the board
    /// holds the write and the manifest does not — the lines it would have
    /// appended shown whole, for a person who keeps the board's shape exact
    /// to add by hand.
    ///
    /// # Panics
    ///
    /// Panics if `item` is neither a JSON object nor null: its `id` is set
    /// by `serde_json`'s index, which panics on any other value.
    pub fn record(&mut self, id: &str, mut item: Value) -> Result<(), Halt> {
        item["id"] = Value::String(id.to_string());
        let mut text = String::new();
        if !self.on_disk {
            text.push_str(&self.header.to_value().to_string());
            text.push('\n');
        }
        text.push_str(&item.to_string());
        text.push('\n');
        let written = (|| {
            if let Some(dir) = self.path.parent() {
                fs::create_dir_all(dir)?;
            }
            if let Some(complete) = self.torn_at {
                OpenOptions::new().write(true).open(&self.path)?.set_len(complete)?;
            }
            let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
            file.write_all(text.as_bytes())?;
            file.sync_data()
        })();
        if let Err(e) = written {
            let lines: Vec<&str> = text.lines().collect();
            return Err(Halt::face(
                format!("the manifest at {} could not be written", self.path.display()),
                format!(
                    "{e}; the write `{id}` LANDED on the board and is not recorded — the line{} this run would have appended:\n    {}",
                    if lines.len() == 1 { "" } else { "s" },
                    lines.join("\n    ")
                ),
                "clear what the error names — at a full volume, room where the manifest lives — then run again: the run cuts any partial \
                 last line away, resumes after the whole ones and makes this write again, a mint or a shot then landing twice; to keep \
                 the board's shape exact, first add the line(s) above to the manifest, whole and each ending in a newline, in place of \
                 any partial last line",
            ));
        }
        self.on_disk = true;
        self.torn_at = None;
        self.items.insert(id.to_string(), item);
        Ok(())
    }
}

/// Returns the halt a manifest that cannot be read as this tool's is.
///
/// It is a halt, never a guess.
fn unreadable(path: &Path, why: String) -> Halt {
    Halt::face(
        format!("the manifest at {} cannot be read as this tool's", path.display()),
        why,
        "move the file aside if it is not a seed's manifest; this tool never guesses what another run landed",
    )
}
