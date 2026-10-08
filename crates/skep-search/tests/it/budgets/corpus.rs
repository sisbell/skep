//! §7.3 THE CORPUS, external and pinned: "'The project's own prose' as the
//! investigation §5 cuts it: 10³ and 10⁴ documents of 1–10 KB from the design
//! repository's paragraphs … BESIDE THE CUTS, ONE TIER OF THE REPOSITORY's
//! RECORDS AS THEY STAND, unsplit — the project's RECORDS WITHOUT the
//! generated `_context.*` bundles: 93.1 MB over 3,598 files at the design
//! repo's `b17656e9`". The corpus is read from the design repository at that
//! ONE PIN through `git` — `ls-tree` for the tier, `cat-file --batch` for the
//! bytes — never from its working tree, and NOTHING of it enters this
//! repository: no fixture, no snapshot. The repository's path comes from the
//! environment variable [`VAR`]; where it is unset or the pin unreadable,
//! every budget test SKIPS by printing [`skip_line`] and returning.
//!
//! THE RECORDS TIER is the set the ceiling was sized on (`index.rs`,
//! `CEILING_BYTES`; lane SR-1's derivation): every file tracked at the pin
//! whose basename is not `_context.*` and whose extension is not an image's
//! or a video's — [`MEDIA_EXTENSIONS`] — 3,598 files, 93,075,924 bytes.
//! [`Corpus::records`] ASSERTS both against [`RECORDS_FILES`] and
//! [`RECORDS_BYTES`]: a different cut is a STOP, not a new number.
//!
//! THE CUT (the investigation §5: "cuts 10³ and 10⁴ 'documents' of 1–10 KB
//! from it by paragraph groups"), made deterministic so every run cuts the
//! same documents: the paragraph source is the records tier's `.md` files in
//! `ls-tree` order, each split at BLANK LINES into paragraphs, trimmed, the
//! empty dropped, each paragraph capped at [`PARAGRAPH_CAP`] bytes on a
//! character boundary. Document `i` (from 0) has the TARGET `1 KiB × (1 + 7·i
//! mod 10)` — the ten sizes 1..10 KiB in a fixed cycle — and takes paragraphs
//! in order, joined by one blank line, until its size reaches the target, or
//! the next paragraph would carry it past [`CUT_MAX`]; so every document
//! holds between [`CUT_MIN`] and [`CUT_MAX`] bytes. The 10³ cut is the first
//! thousand documents of the 10⁴ cut.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use skep_search::CEILING_BYTES;

/// The environment variable naming the design repository's checkout.
pub const VAR: &str = "SKEP_SEARCH_CORPUS";

/// THE PIN: the design repository's commit the corpus is read at.
pub const PIN: &str = "b17656e9";

/// The records tier's file count at the pin (§7.3: "3,598 files").
pub const RECORDS_FILES: usize = 3_598;

/// The records tier's bytes at the pin — the ceiling's derivation.
pub const RECORDS_BYTES: u64 = CEILING_BYTES;

/// The image and video extensions the tier excludes (SR-1's exclusion list),
/// compared case-insensitively.
pub const MEDIA_EXTENSIONS: [&str; 8] =
    ["png", "jpg", "jpeg", "gif", "webp", "avif", "mp4", "webm"];

/// The cut's smallest document: 1 KiB.
pub const CUT_MIN: usize = 1 << 10;

/// The cut's largest document: 10 KiB.
pub const CUT_MAX: usize = 10 << 10;

/// A paragraph longer than this is cut here, on a character boundary.
pub const PARAGRAPH_CAP: usize = 8 << 10;

/// The cut rule's version — part of the dev board cache's key, so a rule
/// change never reads a cache cut under the old one.
pub const CUT_RULE: &str = "cut-v1";

/// One document of the corpus: its name — a tier file's path, or `cut-NNNNN`
/// — and its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// The design repository at the pin.
#[derive(Debug, Clone)]
pub struct Corpus {
    repo: PathBuf,
}

/// The one line a budget test prints when it skips.
pub fn skip_line() -> String {
    format!(
        "SKIPPED: {VAR} is unset or names no checkout holding {PIN} — the corpus is the design \
         repository at {PIN}; set {VAR} to its path to measure"
    )
}

/// The corpus, where [`VAR`] names a checkout holding the pin; else the skip
/// line printed and `None`.
pub fn corpus() -> Option<Corpus> {
    let repo = match std::env::var_os(VAR) {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => {
            println!("{}", skip_line());
            return None;
        }
    };
    let readable = Command::new("git")
        .args(["-C"])
        .arg(&repo)
        .args(["cat-file", "-e", &format!("{PIN}^{{commit}}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !readable {
        println!("{}", skip_line());
        return None;
    }
    Some(Corpus { repo })
}

/// One tracked file at the pin: its path and its size.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    path: String,
    size: u64,
}

/// Whether a tracked path belongs to the records tier.
fn in_tier(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path);
    if basename.starts_with("_context.") {
        return false;
    }
    match basename.rsplit_once('.') {
        Some((_, ext)) => !MEDIA_EXTENSIONS.iter().any(|m| m.eq_ignore_ascii_case(ext)),
        None => true,
    }
}

impl Corpus {
    fn git(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(&self.repo);
        cmd
    }

    /// Every tracked file at the pin, in `ls-tree` order, with its size.
    fn tracked(&self) -> Vec<Entry> {
        let out =
            self.git().args(["ls-tree", "-r", "-l", PIN]).output().expect("git ls-tree at the pin");
        assert!(
            out.status.success(),
            "git ls-tree {PIN}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8(out.stdout).expect("ls-tree answers UTF-8 paths");
        text.lines()
            .map(|line| {
                let (meta, path) = line.split_once('\t').expect("ls-tree: a tab before the path");
                let size = meta
                    .split_whitespace()
                    .nth(3)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| panic!("ls-tree: no size in `{meta}`"));
                Entry { path: path.to_string(), size }
            })
            .collect()
    }

    /// The records tier's entries, in `ls-tree` order.
    fn tier(&self) -> Vec<Entry> {
        self.tracked().into_iter().filter(|e| in_tier(&e.path)).collect()
    }

    /// The bytes of `paths` at the pin, in order, through one `git cat-file
    /// --batch`.
    fn blobs(&self, paths: &[String]) -> Vec<Vec<u8>> {
        let mut child = self
            .git()
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("git cat-file --batch");
        let mut stdin = child.stdin.take().expect("piped stdin");
        let asks: String = paths.iter().map(|p| format!("{PIN}:{p}\n")).collect();
        let writer = std::thread::spawn(move || {
            stdin.write_all(asks.as_bytes()).expect("the asks written");
        });
        let mut out = Vec::new();
        child.stdout.take().expect("piped stdout").read_to_end(&mut out).expect("the blobs read");
        writer.join().expect("the writer thread");
        assert!(child.wait().expect("git exits").success(), "git cat-file --batch failed");

        let mut blobs = Vec::with_capacity(paths.len());
        let mut at = 0usize;
        for path in paths {
            let nl = out[at..].iter().position(|&b| b == b'\n').expect("a header line") + at;
            let header = std::str::from_utf8(&out[at..nl]).expect("an ASCII header");
            let fields: Vec<&str> = header.split_whitespace().collect();
            assert!(
                fields.len() == 3 && fields[1] == "blob",
                "STOP: `{PIN}:{path}` is not a blob at the pin: `{header}`"
            );
            let size: usize = fields[2].parse().expect("a size");
            at = nl + 1;
            blobs.push(out[at..at + size].to_vec());
            at += size + 1;
        }
        blobs
    }

    /// THE RECORDS TIER, as it stands: each file one document, in `ls-tree`
    /// order — ASSERTED to be the ceiling's derivation, 3,598 files and
    /// 93,075,924 bytes.
    pub fn records(&self) -> Vec<Document> {
        let tier = self.tier();
        let bytes: u64 = tier.iter().map(|e| e.size).sum();
        assert_eq!(
            (tier.len(), bytes),
            (RECORDS_FILES, RECORDS_BYTES),
            "STOP: the records tier at {PIN} is not the cut the ceiling was sized on (§7.3)"
        );
        let paths: Vec<String> = tier.iter().map(|e| e.path.clone()).collect();
        let blobs = self.blobs(&paths);
        let docs: Vec<Document> =
            paths.into_iter().zip(blobs).map(|(name, bytes)| Document { name, bytes }).collect();
        let read: u64 = docs.iter().map(|d| d.bytes.len() as u64).sum();
        assert_eq!(read, RECORDS_BYTES, "the blobs read are the tier's bytes");
        docs
    }

    /// THE PARAGRAPH SOURCE: the records tier's `.md` files in `ls-tree`
    /// order, split at blank lines, trimmed, capped.
    fn paragraphs(&self) -> Vec<String> {
        let paths: Vec<String> =
            self.tier().into_iter().filter(|e| e.path.ends_with(".md")).map(|e| e.path).collect();
        let mut out = Vec::new();
        for blob in self.blobs(&paths) {
            let text = String::from_utf8_lossy(&blob);
            let mut current = String::new();
            let mut flush = |current: &mut String| {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    out.push(capped(trimmed));
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
        out
    }

    /// THE CUT: the first `n` documents of the rule the module doc states.
    pub fn cut(&self, n: usize) -> Vec<Document> {
        let paragraphs = self.paragraphs();
        let mut docs: Vec<Document> = Vec::with_capacity(n);
        let mut current = String::new();
        let mut k = 0usize;
        let close = |docs: &mut Vec<Document>, current: &mut String| {
            let bytes = std::mem::take(current).into_bytes();
            debug_assert!((CUT_MIN..=CUT_MAX).contains(&bytes.len()));
            docs.push(Document { name: format!("cut-{:05}", docs.len() + 1), bytes });
        };
        while docs.len() < n && k < paragraphs.len() {
            let target = CUT_MIN * (1 + (7 * docs.len()) % 10);
            let paragraph = &paragraphs[k];
            let added = if current.is_empty() { paragraph.len() } else { 2 + paragraph.len() };
            if !current.is_empty() && current.len() + added > CUT_MAX {
                close(&mut docs, &mut current);
                continue;
            }
            if !current.is_empty() {
                current.push_str("\n\n");
            }
            current.push_str(paragraph);
            k += 1;
            if current.len() >= target {
                close(&mut docs, &mut current);
            }
        }
        assert_eq!(docs.len(), n, "the paragraph source ran out before {n} documents were cut");
        docs
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

/// The sum of the documents' bytes.
pub fn total_bytes(docs: &[Document]) -> u64 {
    docs.iter().map(|d| d.bytes.len() as u64).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tier_excludes_context_bundles_and_media_and_nothing_else() {
        assert!(in_tier("search.md"));
        assert!(in_tier("_designs/QUEUE.md"));
        assert!(in_tier("spikes/s11/results/chrome-3.json"));
        assert!(in_tier("designs/reviews/foundations/sweep-1/_skep_ref"));
        assert!(!in_tier("_designs/SEARCH/_context.search.md"));
        assert!(!in_tier("_context.md"));
        assert!(!in_tier("ux/mock.PNG"));
        assert!(!in_tier("spikes/s3/media/run.mp4"));
        assert!(!in_tier("a/b.webm"));
    }

    #[test]
    fn a_paragraph_is_capped_on_a_character_boundary() {
        let long = "é".repeat(PARAGRAPH_CAP);
        let cut = capped(&long);
        assert!(cut.len() <= PARAGRAPH_CAP);
        assert!(cut.len() >= PARAGRAPH_CAP - 1);
        assert!(std::str::from_utf8(cut.as_bytes()).is_ok());
        assert_eq!(capped("short"), "short");
    }
}
