//! # skep-corpus — the prose corpus a dev board is seeded from
//!
//! ONE RULE IN ONE PLACE: THE CUT of a git repository's prose into
//! documents of 1–10 KiB, read at ONE PINNED COMMIT through `git` alone —
//! `ls-tree` for the tier, `cat-file --batch` for the bytes — never from the
//! working tree, and nothing of the repository copied anywhere. Two callers
//! take it: the search index's budgets suite
//! (`crates/skep-search/tests/it/budgets.rs`), which measures `search.md`
//! §7's pins over the design repository's prose, and the dev board's seeding
//! tool (`skep-dev seed`, a binary of `skep-cli`), which lands the same
//! documents on a running claimed board as editions, citation links, second
//! versions and drafts. The repository's path and the pin are the CALLERS'
//! — the suite reads its `SKEP_SEARCH_CORPUS`, the tool its `--repo` and
//! `--pin` — so this crate names no environment variable and reads none.
//!
//! THE RECORDS TIER ([`in_tier`]): every file tracked at the pin whose
//! basename is not `_context.*` and whose extension is not an image's or a
//! video's ([`MEDIA_EXTENSIONS`], compared case-insensitively) — the set the
//! index's ceiling was sized on (`search.md` §7.3: "the project's RECORDS
//! WITHOUT the generated `_context.*` bundles"; at the design repository's
//! `b17656e9`, 3,598 files and 93,075,924 bytes — two figures the budgets
//! suite asserts and this crate does not know).
//!
//! THE CUT, `cut-v1` ([`CUT_RULE`]), made deterministic so every run cuts
//! the same documents: the paragraph source is the tier's `.md` files in
//! `ls-tree` order, each split at BLANK LINES into paragraphs, trimmed, the
//! empty dropped, each paragraph capped at [`PARAGRAPH_CAP`] bytes on a
//! character boundary. Document `i` (from 0) has the TARGET `1 KiB × (1 +
//! 7·i mod 10)` — the ten sizes 1..10 KiB in a fixed cycle — and takes
//! paragraphs in order, joined by one blank line, until its size reaches the
//! target, or the next paragraph would carry it past [`CUT_MAX`]; so every
//! document holds between [`CUT_MIN`] and [`CUT_MAX`] bytes, and the first
//! `n` documents of a cut are the first `n` of every longer one (the 10³ cut
//! is the first thousand documents of the 10⁴ cut). A document is named
//! `cut-NNNNN`, from `cut-00001`.
//!
//! THE SUBTREE, `cut-v2` ([`CUT_RULE_SUBTREE`]): the same rule with the
//! paragraph source restricted to the tier's `.md` files under one path
//! ([`Corpus::under`]), `ls-tree` order kept — so a caller can cut the UX
//! designs or the client design into its first documents, where `cut-v1`'s
//! first thousand are the AUTH reviews. The rule's name follows the source:
//! the budgets suite keys its cache by the rule, so a cut over a subtree
//! never reads a cache cut over the whole tier, and the suite's own
//! documents never change.
//!
//! The cut comes in two shapes: [`Corpus::cut`], the documents alone —
//! [`Document`], a name and its bytes, the shape the budgets suite feeds —
//! and [`Corpus::cut_sourced`], each document with the PARAGRAPHS it was
//! joined from ([`Paragraph`]: the source file, the byte range, the heading
//! the paragraph opens where it is one), which the seeding tool reads to
//! anchor a citation's link, choose a version's paragraph and send a cited
//! section to the document holding it.
//!
//! Membership: `std` and a `git` child process, nothing else — no skep
//! crate, no feature, no platform call. Every `git` failure and every
//! shortfall is an [`Error`] a caller renders; nothing here panics on what a
//! repository holds.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The cut's smallest document: 1 KiB.
pub const CUT_MIN: usize = 1 << 10;

/// The cut's largest document: 10 KiB.
pub const CUT_MAX: usize = 10 << 10;

/// A paragraph longer than this is cut here, on a character boundary.
pub const PARAGRAPH_CAP: usize = 8 << 10;

/// The cut rule's name over the whole tier — part of the budgets suite's
/// cache key, so a rule change never reads a cache cut under the old one.
pub const CUT_RULE: &str = "cut-v1";

/// The cut rule's name over a chosen subtree ([`Corpus::under`]): the same
/// rule, another paragraph source, another name.
pub const CUT_RULE_SUBTREE: &str = "cut-v2";

/// The image and video extensions the tier excludes (SR-1's exclusion list),
/// compared case-insensitively.
pub const MEDIA_EXTENSIONS: [&str; 8] =
    ["png", "jpg", "jpeg", "gif", "webp", "avif", "mp4", "webm"];

/// Whether a tracked path belongs to the records tier.
pub fn in_tier(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path);
    if basename.starts_with("_context.") {
        return false;
    }
    match basename.rsplit_once('.') {
        Some((_, ext)) => !MEDIA_EXTENSIONS.iter().any(|m| m.eq_ignore_ascii_case(ext)),
        None => true,
    }
}

/// Whether `path` lies under `subtree`: the subtree's own path, or any path
/// beneath it by whole components — `ux/a.md` is under `ux`, `uxx/a.md` is
/// not — a trailing slash on the subtree ignored, and the empty subtree
/// holding everything.
pub fn under_subtree(path: &str, subtree: &str) -> bool {
    let subtree = subtree.trim_end_matches('/');
    if subtree.is_empty() {
        return true;
    }
    path == subtree || path.strip_prefix(subtree).is_some_and(|rest| rest.starts_with('/'))
}

/// One document of the corpus: its name — a tier file's path, or `cut-NNNNN`
/// — and its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// A tier file's path, or `cut-NNNNN` from `cut-00001`.
    pub name: String,
    /// The bytes at the pin, or the paragraphs joined by one blank line.
    pub bytes: Vec<u8>,
}

/// One tracked file of the records tier at the pin: its path and its size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The path as `ls-tree` lists it.
    pub path: String,
    /// The blob's size in bytes.
    pub size: u64,
}

/// One paragraph as a cut document holds it: where it came from, where it
/// lies in the document's bytes, and the heading it opens where it is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paragraph {
    /// The tier file the paragraph was read from.
    pub file: String,
    /// The paragraph's first byte in the document's bytes.
    pub offset: usize,
    /// The paragraph's length in bytes, as capped.
    pub len: usize,
    /// Where the paragraph's first line is a heading — it opens with `#` —
    /// the heading's text after the marks, trimmed; else none.
    pub heading: Option<String>,
}

/// A cut document with the paragraphs it was joined from, in order: the
/// bytes at each paragraph's range are its text, and two neighbours are
/// parted by one blank line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sourced {
    /// The document as [`Corpus::cut`] answers it.
    pub document: Document,
    /// Its paragraphs, in order.
    pub paragraphs: Vec<Paragraph>,
}

/// THE CUT WITH ITS SOURCES: the documents, each with its paragraphs, and
/// the paragraph source's files — the tier's `.md` files, or those under the
/// subtree — in `ls-tree` order, every one whether or not the cut reached it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cut {
    /// The documents, `cut-00001` first.
    pub documents: Vec<Sourced>,
    /// The paragraph source's files, in `ls-tree` order.
    pub sources: Vec<String>,
}

/// What the corpus could not do — a caller renders it; nothing is a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// `git` could not be run, or answered a failure: the command and what
    /// it said.
    Git {
        /// The command line, for the reader.
        command: String,
        /// Its stderr, or the spawn's error.
        said: String,
    },
    /// The pin names no commit of the repository.
    NoCommit {
        /// The repository's path.
        repo: PathBuf,
        /// The pin as given.
        pin: String,
    },
    /// A path the tier lists is not a blob at the pin: the header
    /// `cat-file --batch` answered for it.
    NotABlob {
        /// The path asked.
        path: String,
        /// The header line answered.
        header: String,
    },
    /// `ls-tree` answered a line the reader cannot parse.
    Unreadable {
        /// The line.
        line: String,
    },
    /// The paragraph source ran out before `wanted` documents were cut.
    Short {
        /// The documents the source yielded.
        cut: usize,
        /// The documents asked for.
        wanted: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Git { command, said } => write!(f, "`{command}` failed: {}", said.trim()),
            Error::NoCommit { repo, pin } => {
                write!(f, "{pin} is not a commit of the repository at {}", repo.display())
            }
            Error::NotABlob { path, header } => {
                write!(f, "`{path}` is not a blob at the pin: `{header}`")
            }
            Error::Unreadable { line } => {
                write!(f, "git ls-tree answered a line the reader cannot parse: `{line}`")
            }
            Error::Short { cut, wanted } => write!(
                f,
                "the paragraph source ran out at {cut} documents, short of the {wanted} asked"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// A git repository at one pinned commit, and the paragraph source the cut
/// reads — the whole tier, or one subtree of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Corpus {
    repo: PathBuf,
    pin: String,
    subtree: Option<String>,
}

/// One paragraph of the source, before the cut places it.
struct Source {
    file: String,
    text: String,
    heading: Option<String>,
}

impl Corpus {
    /// The repository at `repo` read at `pin` — judged now: `git cat-file -e
    /// <pin>^{commit}` answers whether the pin names a commit there
    /// ([`Error::NoCommit`] where it does not), and nothing else is read.
    pub fn open(repo: impl Into<PathBuf>, pin: &str) -> Result<Corpus, Error> {
        let corpus = Corpus { repo: repo.into(), pin: pin.to_string(), subtree: None };
        let mut cmd = corpus.git();
        cmd.args(["cat-file", "-e", &format!("{pin}^{{commit}}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let status = cmd.status().map_err(|e| Error::Git {
            command: format!("git -C {} cat-file -e {pin}^{{commit}}", corpus.repo.display()),
            said: e.to_string(),
        })?;
        if !status.success() {
            return Err(Error::NoCommit { repo: corpus.repo, pin: pin.to_string() });
        }
        Ok(corpus)
    }

    /// The same repository and pin with the paragraph source restricted to
    /// the tier's `.md` files under `subtree` ([`under_subtree`]) — the cut
    /// then named [`CUT_RULE_SUBTREE`]. The tier itself is unchanged: a
    /// caller resolving a name against the repository's files still sees
    /// them all ([`Corpus::markdown`]).
    pub fn under(mut self, subtree: &str) -> Corpus {
        self.subtree = Some(subtree.trim_end_matches('/').to_string());
        self
    }

    /// The repository's path.
    pub fn repo(&self) -> &Path {
        &self.repo
    }

    /// The pin as given.
    pub fn pin(&self) -> &str {
        &self.pin
    }

    /// The subtree the paragraph source is restricted to, where one is.
    pub fn subtree(&self) -> Option<&str> {
        self.subtree.as_deref()
    }

    /// The cut rule's name for this source: [`CUT_RULE`] over the whole
    /// tier, [`CUT_RULE_SUBTREE`] under a subtree.
    pub fn rule(&self) -> &'static str {
        if self.subtree.is_some() {
            CUT_RULE_SUBTREE
        } else {
            CUT_RULE
        }
    }

    fn git(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(&self.repo);
        cmd
    }

    /// The records tier's entries at the pin, in `ls-tree` order, with their
    /// sizes.
    pub fn tier(&self) -> Result<Vec<Entry>, Error> {
        let command = format!("git -C {} ls-tree -r -l {}", self.repo.display(), self.pin);
        let out = self
            .git()
            .args(["ls-tree", "-r", "-l", &self.pin])
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| Error::Git { command: command.clone(), said: e.to_string() })?;
        if !out.status.success() {
            return Err(Error::Git {
                command,
                said: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut entries = Vec::new();
        for line in text.lines() {
            let unreadable = || Error::Unreadable { line: line.to_string() };
            let (meta, path) = line.split_once('\t').ok_or_else(unreadable)?;
            let size = meta
                .split_whitespace()
                .nth(3)
                .and_then(|s| s.parse().ok())
                .ok_or_else(unreadable)?;
            if in_tier(path) {
                entries.push(Entry { path: path.to_string(), size });
            }
        }
        Ok(entries)
    }

    /// Every `.md` file of the tier at the pin, in `ls-tree` order — the
    /// whole tier's, whatever the subtree: the set a cited name is resolved
    /// against.
    pub fn markdown(&self) -> Result<Vec<String>, Error> {
        Ok(self.tier()?.into_iter().map(|e| e.path).filter(|p| p.ends_with(".md")).collect())
    }

    /// The paragraph source's files: the tier's `.md` files, under the
    /// subtree where one is set, in `ls-tree` order.
    pub fn sources(&self) -> Result<Vec<String>, Error> {
        let files = self.markdown()?;
        Ok(match &self.subtree {
            Some(subtree) => files.into_iter().filter(|p| under_subtree(p, subtree)).collect(),
            None => files,
        })
    }

    /// The bytes of `paths` at the pin, in order, through one `git cat-file
    /// --batch`.
    pub fn blobs(&self, paths: &[String]) -> Result<Vec<Vec<u8>>, Error> {
        let command = format!("git -C {} cat-file --batch", self.repo.display());
        let git = |e: String| Error::Git { command: command.clone(), said: e };
        let mut child = self
            .git()
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| git(e.to_string()))?;
        let mut stdin = child.stdin.take().ok_or_else(|| git("no stdin".into()))?;
        let asks: String = paths.iter().map(|p| format!("{}:{p}\n", self.pin)).collect();
        let writer = std::thread::spawn(move || stdin.write_all(asks.as_bytes()));
        let mut out = Vec::new();
        child
            .stdout
            .take()
            .ok_or_else(|| git("no stdout".into()))?
            .read_to_end(&mut out)
            .map_err(|e| git(e.to_string()))?;
        writer
            .join()
            .map_err(|_| git("the writer thread panicked".into()))?
            .map_err(|e| git(e.to_string()))?;
        let finished = child.wait_with_output().map_err(|e| git(e.to_string()))?;
        if !finished.status.success() {
            return Err(git(String::from_utf8_lossy(&finished.stderr).into_owned()));
        }

        let mut blobs = Vec::with_capacity(paths.len());
        let mut at = 0usize;
        for path in paths {
            let not_a_blob = |header: &[u8]| Error::NotABlob {
                path: path.clone(),
                header: String::from_utf8_lossy(header).into_owned(),
            };
            let nl =
                out[at..].iter().position(|&b| b == b'\n').ok_or_else(|| not_a_blob(&out[at..]))?
                    + at;
            let header = &out[at..nl];
            let fields: Vec<&[u8]> = header.split(|&b| b == b' ').collect();
            if fields.len() != 3 || fields[1] != b"blob" {
                return Err(not_a_blob(header));
            }
            let size: usize = std::str::from_utf8(fields[2])
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| not_a_blob(header))?;
            at = nl + 1;
            if out.len() < at + size {
                return Err(git(format!("the batch ended inside `{path}`")));
            }
            blobs.push(out[at..at + size].to_vec());
            at += size + 1;
        }
        Ok(blobs)
    }

    /// THE RECORDS TIER as it stands: each file one document, in `ls-tree`
    /// order, named by its path.
    pub fn records(&self) -> Result<Vec<Document>, Error> {
        let paths: Vec<String> = self.tier()?.into_iter().map(|e| e.path).collect();
        let blobs = self.blobs(&paths)?;
        Ok(paths.into_iter().zip(blobs).map(|(name, bytes)| Document { name, bytes }).collect())
    }

    /// THE PARAGRAPH SOURCE over `files`: each split at blank lines, trimmed,
    /// the empty dropped, each paragraph capped; a lossily decoded file is
    /// UTF-8 text by construction.
    fn paragraphs(&self, files: &[String]) -> Result<Vec<Source>, Error> {
        let mut out = Vec::new();
        for (file, blob) in files.iter().zip(self.blobs(files)?) {
            let text = String::from_utf8_lossy(&blob);
            let mut current = String::new();
            let mut flush = |current: &mut String| {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    let text = capped(trimmed);
                    let heading = heading_of(&text);
                    out.push(Source { file: file.clone(), text, heading });
                }
                current.clear();
            };
            for line in text.lines() {
                if line.trim().is_empty() {
                    flush(&mut current);
                } else {
                    if !current.is_empty() {
                        current.push('\n');
                    }
                    current.push_str(line);
                }
            }
            flush(&mut current);
        }
        Ok(out)
    }

    /// THE CUT WITH ITS SOURCES: the first `n` documents of the rule the
    /// crate doc states, each with the paragraphs it was joined from, and
    /// the source's files; [`Error::Short`] where the source yields fewer.
    pub fn cut_sourced(&self, n: usize) -> Result<Cut, Error> {
        let sources = self.sources()?;
        let paragraphs = self.paragraphs(&sources)?;
        let mut documents: Vec<Sourced> = Vec::with_capacity(n);
        let mut current = String::new();
        let mut taken: Vec<Paragraph> = Vec::new();
        let mut k = 0usize;
        let close =
            |documents: &mut Vec<Sourced>, current: &mut String, taken: &mut Vec<Paragraph>| {
                let bytes = std::mem::take(current).into_bytes();
                debug_assert!((CUT_MIN..=CUT_MAX).contains(&bytes.len()));
                let name = format!("cut-{:05}", documents.len() + 1);
                documents.push(Sourced {
                    document: Document { name, bytes },
                    paragraphs: std::mem::take(taken),
                });
            };
        while documents.len() < n && k < paragraphs.len() {
            let target = CUT_MIN * (1 + (7 * documents.len()) % 10);
            let paragraph = &paragraphs[k];
            let added =
                if current.is_empty() { paragraph.text.len() } else { 2 + paragraph.text.len() };
            if !current.is_empty() && current.len() + added > CUT_MAX {
                close(&mut documents, &mut current, &mut taken);
                continue;
            }
            if !current.is_empty() {
                current.push_str("\n\n");
            }
            taken.push(Paragraph {
                file: paragraph.file.clone(),
                offset: current.len(),
                len: paragraph.text.len(),
                heading: paragraph.heading.clone(),
            });
            current.push_str(&paragraph.text);
            k += 1;
            if current.len() >= target {
                close(&mut documents, &mut current, &mut taken);
            }
        }
        if documents.len() < n {
            return Err(Error::Short { cut: documents.len(), wanted: n });
        }
        Ok(Cut { documents, sources })
    }

    /// THE CUT: the first `n` documents of the rule the crate doc states —
    /// [`Corpus::cut_sourced`]'s documents alone.
    pub fn cut(&self, n: usize) -> Result<Vec<Document>, Error> {
        Ok(self.cut_sourced(n)?.documents.into_iter().map(|s| s.document).collect())
    }
}

/// `text` cut to at most [`PARAGRAPH_CAP`] bytes on a character boundary.
fn capped(text: &str) -> String {
    if text.len() <= PARAGRAPH_CAP {
        return text.to_string();
    }
    let mut end = PARAGRAPH_CAP;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// The heading a paragraph opens, where its first line is one: the text
/// after the `#` marks, trimmed — `None` where the line is no heading, or
/// the marks stand alone.
fn heading_of(paragraph: &str) -> Option<String> {
    let line = paragraph.lines().next()?;
    if !line.starts_with('#') {
        return None;
    }
    let text = line.trim_start_matches('#').trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// The sum of the documents' bytes.
pub fn total_bytes(docs: &[Document]) -> u64 {
    docs.iter().map(|d| d.bytes.len() as u64).sum()
}

#[cfg(test)]
mod tests;
