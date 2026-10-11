//! §7.3 THE CORPUS, external and pinned — the suite's side of `skep-corpus`:
//! "'The project's own prose' as the investigation §5 cuts it: 10³ and 10⁴
//! documents of 1–10 KB from the design repository's paragraphs … BESIDE THE
//! CUTS, ONE TIER OF THE REPOSITORY's RECORDS AS THEY STAND, unsplit — the
//! project's RECORDS WITHOUT the generated `_context.*` bundles: 93.1 MB
//! over 3,598 files at the design repo's `b17656e9`". The tier's filter, the
//! paragraphs and THE CUT (`cut-v1`: the ten targets in their cycle, the
//! paragraph cap, the joins) are the crate's — `skep_corpus`, whose crate
//! doc states the rule, shared with the dev board's seeding tool so the two
//! cut the same documents — and are taken here by re-export. What is the
//! suite's alone stays here: the repository's path from the environment
//! variable [`VAR`], THE PIN, the two figures the records tier is ASSERTED
//! to ([`records`]), and the skip — where the variable is unset or the pin
//! unreadable, every budget test prints [`skip_line`] and returns. The
//! corpus is read from the design repository at that ONE PIN through `git`
//! — never from its working tree, and NOTHING of it enters this repository:
//! no fixture, no snapshot.

use std::path::PathBuf;

pub use skep_corpus::{total_bytes, Corpus, Document, CUT_MAX, CUT_MIN, CUT_RULE};
use skep_search::CEILING_BYTES;

/// The environment variable naming the design repository's checkout.
pub const VAR: &str = "SKEP_SEARCH_CORPUS";

/// THE PIN: the design repository's commit the corpus is read at.
pub const PIN: &str = "b17656e9";

/// The records tier's file count at the pin (§7.3: "3,598 files").
pub const RECORDS_FILES: usize = 3_598;

/// The records tier's bytes at the pin — the ceiling's derivation.
pub const RECORDS_BYTES: u64 = CEILING_BYTES;

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
    match Corpus::open(repo, PIN) {
        Ok(corpus) => Some(corpus),
        Err(_) => {
            println!("{}", skip_line());
            None
        }
    }
}

/// THE RECORDS TIER, as it stands: each file one document, in `ls-tree`
/// order — ASSERTED to be the ceiling's derivation, 3,598 files and
/// 93,075,924 bytes: a different cut is a STOP, not a new number.
pub fn records(c: &Corpus) -> Vec<Document> {
    let tier = c.tier().expect("git ls-tree at the pin");
    let bytes: u64 = tier.iter().map(|e| e.size).sum();
    assert_eq!(
        (tier.len(), bytes),
        (RECORDS_FILES, RECORDS_BYTES),
        "STOP: the records tier at {PIN} is not the cut the ceiling was sized on (§7.3)"
    );
    let docs = c.records().expect("git cat-file --batch at the pin");
    assert_eq!(total_bytes(&docs), RECORDS_BYTES, "the blobs read are the tier's bytes");
    docs
}
