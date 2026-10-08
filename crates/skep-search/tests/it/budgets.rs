//! §7 THE BUDGETS, REPORTED (`search.md` §7.1–§7.4; lane SR-4): every pin of
//! §7.1 measured over §7.3's corpus — the cuts at 10³ and 10⁴ documents and
//! the records tier as it stands — fed to the index EXACTLY as the shell
//! feeds it, through a dev board's `insert` and back through `retrieve_v`
//! (`board`), and each measurement printed beside its pin as one row of the
//! report table (`report`). The design's rule: "TIMING TESTS THAT REPORT,
//! never assert" — a miss prints `MISSED` and fails nothing, the design's
//! "what a miss would change" being the owner's decision; the rows the
//! design ASSERTS are two, M7's tree and the fuzzy row's `fuzzy_bounded`,
//! and the corpus's own fences assert beside them.
//!
//! Every timing row is `#[ignore = "timing test - gate-full only"]`, the
//! house partition the `full` profile re-admits. Without the corpus — the
//! environment variable `SKEP_SEARCH_CORPUS` naming the design repository's
//! checkout, read at the pin `b17656e9` — every budget test prints one line
//! saying it skipped and returns, so the gate is green on any machine and
//! silent about nothing. Two more variables shape a run and change no
//! measurement: `SKEP_SEARCH_TIERS`, a comma list of `10^3`, `10^4`,
//! `records`, restricts a row to those tiers (every tier when unset) — an
//! entry `10^4=10^3` hands a 10⁴ row the 10³ units for a dry run, the row
//! naming the tier it measured; and
//! `SKEP_SEARCH_RECORDS_BOARD`, when set, feeds the records tier through the
//! dev board too — a feed of some hours at the board's measured rate — where
//! by default that tier's 3,598 files enter the index DIRECTLY from the
//! corpus's bytes, each file one unit, and its rows say so by the tier's
//! name, `records(direct)`.

mod board;
mod corpus;
mod report;

use std::collections::BTreeMap;
use std::fs::File;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use skep_address::Address;
use skep_client::board::AtAnswer;
use skep_search::query::one_edit_apart;
use skep_search::rank;
use skep_search::{
    tokenize, Answer, Chain, ChainAt, Class, Header, Index, Item, Kind, Pair, Query, QueryOpts,
    RangeRecord, Unit, UnitKey, CEILING_BYTES, EXPANSION_BOUND_ENTRIES, FUZZY_MIN_CHARS,
    FUZZY_WORDS, POSITIONS_BOUND, PREFIX_MIN_CHARS, SNIPPET_BOUND,
};

use board::{parse_addr, DevBoard, Fed};
use corpus::{corpus, total_bytes, Corpus, Document, RECORDS_BYTES, RECORDS_FILES};
use report::{at_most, at_most_ratio, judged, note, reported, Sample, Verdict};

/// The tiers' names in the table.
const TIER_CUT_3: &str = "10^3";
const TIER_CUT_4: &str = "10^4";
const TIER_RECORDS: &str = "records";
/// The records tier's name where it entered the index directly, not through
/// the board.
const TIER_RECORDS_DIRECT: &str = "records(direct)";

/// The variable restricting a run's tiers.
const TIERS_VAR: &str = "SKEP_SEARCH_TIERS";
/// The variable that feeds the records tier through the board.
const RECORDS_BOARD_VAR: &str = "SKEP_SEARCH_RECORDS_BOARD";
/// The M5 probe child's variable: the index file it loads.
const M5_PROBE_VAR: &str = "SKEP_SEARCH_M5_PROBE";
/// The M5 probe child's class: `guest` or a principal's number.
const M5_CLASS_VAR: &str = "SKEP_SEARCH_M5_CLASS";

/// ONE FRAME, §7.1 M2's pin.
const FRAME: Duration = Duration::from_millis(16);
const MIB: u64 = 1 << 20;

// ── THE TIERS ─────────────────────────────────────────────────────────────

/// The tier this run measures where a row asks for `tier`: the tier itself
/// (every tier when `SKEP_SEARCH_TIERS` is unset, or one it lists), another
/// where the list maps it — `10^4=10^3` gives a 10⁴ row the 10³ units, a dry
/// run before the three-hour feed, the row naming the tier it measured —
/// or none where the list leaves it out.
fn tier_for(tier: &str) -> Option<&'static str> {
    let name = |t: &str| match t {
        TIER_CUT_3 => Some(TIER_CUT_3),
        TIER_CUT_4 => Some(TIER_CUT_4),
        TIER_RECORDS => Some(TIER_RECORDS),
        _ => None,
    };
    let Ok(list) = std::env::var(TIERS_VAR) else { return name(tier) };
    for entry in list.split(',') {
        let entry = entry.trim();
        match entry.split_once('=') {
            Some((want, use_)) if want.trim() == tier => return name(use_.trim()),
            None if entry == tier => return name(tier),
            _ => {}
        }
    }
    None
}

/// The 10³ cut's documents.
fn cut_3(c: &Corpus) -> Vec<Document> {
    c.cut(1_000)
}

/// The 10⁴ cut's documents.
fn cut_4(c: &Corpus) -> Vec<Document> {
    c.cut(10_000)
}

/// The records tier entered DIRECTLY: each file one unit of one text item,
/// under synthetic document addresses of one account, read at principal 1 —
/// the shape the board's units take, without the board.
fn direct(docs: Vec<Document>) -> Fed {
    let mut units = Vec::with_capacity(docs.len());
    let mut names = Vec::with_capacity(docs.len());
    for (i, doc) in docs.into_iter().enumerate() {
        let address = parse_addr(&format!("1.0.1.0.{}", i + 2));
        let item = Item::Text { start: 1, bytes: doc.bytes };
        let unit = Unit::new(
            UnitKey::new(address.clone()),
            Some(address),
            Kind::Draft,
            Class::Principal(1),
            0,
            vec![item],
        )
        .expect("one item");
        units.push(unit);
        names.push(doc.name);
    }
    Fed {
        units,
        names,
        mint_time: Duration::ZERO,
        insert_time: Duration::ZERO,
        read_time: Duration::ZERO,
        reads: 0,
        in_parts: 0,
        principal: 1,
        account: "1.0.1".into(),
        refused: Vec::new(),
        cached: false,
    }
}

/// The tier's units — through the dev board (or the cache an earlier test
/// fed), the records tier directly unless asked for through the board — with
/// the board's time printed apart from the index's; `None` where the run
/// leaves the tier out. The name the rows print rides beside.
fn units_of(c: &Corpus, tier: &str) -> Option<(Fed, &'static str)> {
    let Some(tier) = tier_for(tier) else {
        note(format!("tier {tier} left out of this run by {TIERS_VAR}"));
        return None;
    };
    let (fed, name) = match tier {
        TIER_CUT_3 => (board::fed(tier, || cut_3(c)), TIER_CUT_3),
        TIER_CUT_4 => (board::fed(tier, || cut_4(c)), TIER_CUT_4),
        TIER_RECORDS if std::env::var_os(RECORDS_BOARD_VAR).is_some() => {
            (board::fed(tier, || c.records()), TIER_RECORDS)
        }
        TIER_RECORDS => (direct(c.records()), TIER_RECORDS_DIRECT),
        other => panic!("no tier {other}"),
    };
    board_note(name, &fed);
    Some((fed, name))
}

/// The board's time, apart from the index's.
fn board_note(tier: &str, fed: &Fed) {
    if fed.reads == 0 {
        note(format!(
            "board {tier}: {} units, {} of text, ENTERED DIRECTLY from the corpus — not through the board (set {RECORDS_BOARD_VAR} to feed it through one)",
            fed.units.len(),
            report::bytes(fed.bytes()),
        ));
        return;
    }
    note(format!(
        "board {tier}: {} units, {} of text, mint {} + insert {} ({}/s of text) + read {} ({} retrieve_v frames, {} documents in parts){}",
        fed.units.len(),
        report::bytes(fed.bytes()),
        report::time(fed.mint_time),
        report::time(fed.insert_time),
        report::bytes((fed.bytes() as f64 / fed.insert_time.as_secs_f64().max(1e-9)) as u64),
        report::time(fed.read_time),
        fed.reads,
        fed.in_parts,
        if fed.cached { " [from the cache an earlier test fed]" } else { "" }
    ));
    if !fed.refused.is_empty() {
        note(format!(
            "board {tier}: the board REFUSED {} documents, whose units entered directly: {}",
            fed.refused.len(),
            fed.refused
                .iter()
                .map(|(name, refusal)| format!("`{name}` ({refusal})"))
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
}

/// The three tiers in order, each as the run admits it.
fn tiers(c: &Corpus) -> Vec<(Fed, &'static str)> {
    [TIER_CUT_3, TIER_CUT_4, TIER_RECORDS].iter().filter_map(|t| units_of(c, t)).collect()
}

// ── THE INDEX SIDE ────────────────────────────────────────────────────────

/// A fresh index of the units' class, every unit merged — `prepare` then
/// `merge`, the design's two operations — and the time it took, the units
/// consumed so nothing is cloned inside the timing.
fn build(units: Vec<Unit>) -> (Index, Duration) {
    let class = units.first().map_or(Class::Guest, Unit::class);
    let mut index = Index::new(class);
    let t = Instant::now();
    for unit in units {
        index.merge(Index::prepare(unit)).expect("under the ceiling, the units' class");
    }
    (index, t.elapsed())
}

/// The header a save takes: the board's chain where a live board gave one, a
/// fixed one otherwise — the line's bytes are the same size either way — and
/// the one range the published index holds, `held` at `at`.
fn header(board: Option<Chain>, at: ChainAt) -> Header {
    Header {
        board: board.unwrap_or_else(|| Chain::from_bytes([0xB0; 32])),
        floor: None,
        ranges: vec![RangeRecord {
            under: None,
            held: at,
            refusals: Vec::new(),
            bare_rows: 0,
            grant: None,
        }],
        head: None,
    }
}

/// A `(position, chain)` pair of the suite's own.
fn at(position: u64) -> ChainAt {
    ChainAt { position, chain: Chain::from_bytes([0x11; 32]) }
}

/// The index saved to bytes, and the time of the save.
fn saved(index: &Index) -> (Vec<u8>, Duration) {
    let mut out = Vec::new();
    let t = Instant::now();
    index.save(&header(None, at(1)), &mut out).expect("saved");
    (out, t.elapsed())
}

/// An unsigned LEB128 varint: its value and its length.
fn varint(bytes: &[u8]) -> (usize, usize) {
    let mut value = 0usize;
    let mut shift = 0;
    for (i, &b) in bytes.iter().enumerate() {
        value |= usize::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return (value, i + 1);
        }
        shift += 7;
    }
    panic!("an unterminated varint")
}

/// The saved file's seven sections' byte lengths, in `file.rs`'s order —
/// ranges, head, seen, dictionary, units (the stored text), postings, counts
/// — read off the length prefixes behind the header line.
fn sections(file: &[u8]) -> [usize; 7] {
    let mut at = file.iter().position(|&b| b == b'\n').expect("the header line") + 1;
    let mut out = [0usize; 7];
    for slot in &mut out {
        let (len, n) = varint(&file[at..]);
        at += n;
        *slot = len;
        at += len;
    }
    out
}

/// The postings section's bytes.
fn postings_bytes(file: &[u8]) -> u64 {
    sections(file)[5] as u64
}

/// The terms of a tier, tabulated from the units themselves — the sorted
/// dictionary, each term's units (`df`) and occurrences (`entries`), each
/// unit's token count (`dl`) — the inputs the keystroke sample, the bounds'
/// replica and the alternative rankings read.
struct Terms {
    terms: Vec<String>,
    df: Vec<usize>,
    entries: Vec<usize>,
    /// Per unit, in the units' order: its token count.
    dl: Vec<usize>,
    total_entries: usize,
    /// The cumulative occurrence counts, for drawing by token frequency.
    cumulative: Vec<u64>,
}

impl Terms {
    fn of(units: &[Unit]) -> Terms {
        let mut table: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        let mut dl = Vec::with_capacity(units.len());
        for unit in units {
            let tokens = tokenize(unit);
            dl.push(tokens.len());
            let mut per: BTreeMap<String, usize> = BTreeMap::new();
            for t in tokens {
                *per.entry(t.term).or_default() += 1;
            }
            for (term, n) in per {
                let e = table.entry(term).or_default();
                e.0 += 1;
                e.1 += n;
            }
        }
        let mut terms = Vec::with_capacity(table.len());
        let mut df = Vec::with_capacity(table.len());
        let mut entries = Vec::with_capacity(table.len());
        let mut cumulative = Vec::with_capacity(table.len());
        let mut total = 0u64;
        for (term, (d, e)) in table {
            terms.push(term);
            df.push(d);
            entries.push(e);
            total += e as u64;
            cumulative.push(total);
        }
        Terms { terms, df, entries, dl, total_entries: total as usize, cumulative }
    }

    /// A term drawn BY TOKEN FREQUENCY.
    fn draw<'a>(&'a self, rng: &mut Rng) -> &'a str {
        let r = rng.below(self.total_entries as u64);
        let i = self.cumulative.partition_point(|&c| c <= r);
        &self.terms[i.min(self.terms.len() - 1)]
    }

    fn index_of(&self, term: &str) -> Option<usize> {
        self.terms.binary_search_by(|t| t.as_str().cmp(term)).ok()
    }

    /// The dictionary range under `prefix`.
    fn under(&self, prefix: &str) -> std::ops::Range<usize> {
        let lo = self.terms.partition_point(|t| t.as_str() < prefix);
        let n = self.terms[lo..].iter().take_while(|t| t.starts_with(prefix)).count();
        lo..lo + n
    }

    /// THE EXPANSION's REPLICA (§3.2, as `query::expand` takes it): the
    /// candidates under `prefix` by df descending, the dictionary's order
    /// among equals, the prefix's own term first, taken while the entries
    /// stay within `bound` — the own term always. Answers the entries taken
    /// (the positions a bare prefix's walk merges), the terms taken, and
    /// whether the bound cut the expansion.
    fn expansion(&self, prefix: &str, bound: usize) -> (usize, usize, bool) {
        let mut candidates: Vec<usize> = self.under(prefix).collect();
        candidates.sort_by(|&a, &b| self.df[b].cmp(&self.df[a]).then(a.cmp(&b)));
        if let Some(pos) = candidates.iter().position(|&i| self.terms[i] == prefix) {
            let own = candidates.remove(pos);
            candidates.insert(0, own);
        }
        let (mut merged, mut taken, mut more) = (0usize, 0usize, false);
        for (i, &c) in candidates.iter().enumerate() {
            let cost = self.entries[c];
            let is_own = i == 0 && self.terms[c] == prefix;
            if !is_own && merged + cost > bound {
                more = true;
                break;
            }
            merged += cost;
            taken += 1;
        }
        (merged, taken, more)
    }

    fn avgdl(&self) -> f64 {
        if self.dl.is_empty() {
            0.0
        } else {
            self.total_entries as f64 / self.dl.len() as f64
        }
    }
}

/// xorshift64*: a deterministic draw, the same sample on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// M2's keystrokes: `n` queries, each 0–2 full words drawn by token
/// frequency and then a prefix of 1..=8 characters of a word drawn the same
/// way, the string ending in no whitespace so its last word is the prefix.
fn keystrokes(terms: &Terms, rng: &mut Rng, n: usize) -> Vec<String> {
    (0..n)
        .map(|_| {
            let mut s = String::new();
            for _ in 0..rng.below(3) {
                s.push_str(terms.draw(rng));
                s.push(' ');
            }
            let word = terms.draw(rng);
            let k = 1 + rng.below(8) as usize;
            s.extend(word.chars().take(k));
            s
        })
        .collect()
}

/// The pair the shell composes for a session over a dev board's units: an
/// empty published index and the supplement holding them.
fn session_pair<'a>(published: &'a Index, supplement: &'a Index) -> Pair<'a> {
    Pair::session(published, supplement, &[], &[])
}

/// One keystroke timed to the WHOLE `Answer`: the parse, the evaluation,
/// `limit`'s snippets.
fn timed_query(pair: Pair<'_>, text: &str) -> (Answer, Duration) {
    let t = Instant::now();
    let query = Query::parse(text);
    let answer = Index::query(pair, &query, &QueryOpts::default());
    (answer, t.elapsed())
}

/// The resident set of a process, through `ps` — a child process and no
/// unsafe code; rustix 1.1 exposes no `getrusage`, checked in its sources.
fn rss_of(pid: u32) -> u64 {
    let out = Command::new("ps").args(["-o", "rss=", "-p", &pid.to_string()]).output().expect("ps");
    let kb: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0);
    kb * 1024
}

/// A least-squares fit of `y = a + b·x1 + c·x2` by the normal equations.
fn fit3(rows: &[(f64, f64, f64)]) -> (f64, f64, f64) {
    let n = rows.len() as f64;
    let (mut s1, mut s2, mut s11, mut s12, mut s22, mut sy, mut sy1, mut sy2) =
        (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
    for &(x1, x2, y) in rows {
        s1 += x1;
        s2 += x2;
        s11 += x1 * x1;
        s12 += x1 * x2;
        s22 += x2 * x2;
        sy += y;
        sy1 += x1 * y;
        sy2 += x2 * y;
    }
    let m = [[n, s1, s2], [s1, s11, s12], [s2, s12, s22]];
    let v = [sy, sy1, sy2];
    let det = |m: &[[f64; 3]; 3]| {
        m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
            - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
            + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0])
    };
    let d = det(&m);
    if d.abs() < 1e-12 {
        return (0.0, 0.0, 0.0);
    }
    let solve = |col: usize| {
        let mut mm = m;
        for r in 0..3 {
            mm[r][col] = v[r];
        }
        det(&mm) / d
    };
    (solve(0), solve(1), solve(2))
}

/// The files a test writes, under the cache directory.
fn scratch(name: &str) -> PathBuf {
    let dir = board::cache_dir();
    std::fs::create_dir_all(&dir).expect("the cache dir");
    dir.join(name)
}

// ── THE FENCES ────────────────────────────────────────────────────────────

/// §7.3 THE CORPUS IS THE DESIGN's: the records tier at the pin is 3,598
/// files and 93,075,924 bytes — the ceiling's derivation — or the run STOPS.
#[test]
#[ignore = "timing test - gate-full only"]
fn the_corpus_is_the_designs_count_and_bytes() {
    let Some(c) = corpus() else { return };
    let records = c.records();
    assert_eq!(records.len(), RECORDS_FILES);
    assert_eq!(total_bytes(&records), RECORDS_BYTES);
    assert_eq!(RECORDS_BYTES, CEILING_BYTES, "the tier is the one the ceiling was sized on");
    let cut = cut_3(&c);
    assert_eq!(cut.len(), 1_000);
    assert!(cut.iter().all(|d| (corpus::CUT_MIN..=corpus::CUT_MAX).contains(&d.bytes.len())));
    let mut sizes: Vec<usize> = cut.iter().map(|d| d.bytes.len()).collect();
    sizes.sort_unstable();
    let mut records_sizes: Vec<usize> = records.iter().map(|d| d.bytes.len()).collect();
    records_sizes.sort_unstable();
    note(format!(
        "corpus: records tier {} files / {}, median {} bytes, {} files past 128 KiB, {} past 1 MiB; the 10^3 cut {} of text, documents {}..={} bytes, median {}",
        records.len(),
        report::bytes(total_bytes(&records)),
        records_sizes[records_sizes.len() / 2],
        records_sizes.iter().filter(|&&s| s > 1 << 17).count(),
        records_sizes.iter().filter(|&&s| s > 1 << 20).count(),
        report::bytes(total_bytes(&cut)),
        sizes[0],
        sizes[sizes.len() - 1],
        sizes[sizes.len() / 2]
    ));
}

/// §7.3 FED AS THE SHELL FEEDS IT: every unit the index takes came back
/// through `retrieve_v` over the wire — the 10³ cut written to a FRESH dev
/// board and read back, the round trip asserted byte-exact inside the feed,
/// the units' bytes the corpus's, the cache's codec exact over the units
/// delivered. The board and the units are kept for the other rows.
#[test]
#[ignore = "timing test - gate-full only"]
fn the_units_come_back_byte_exact_through_retrieve_v() {
    let Some(c) = corpus() else { return };
    let docs = cut_3(&c);
    board::forget(TIER_CUT_3);
    let fed = board::fed(TIER_CUT_3, || docs.clone());
    assert!(!fed.cached, "fed now, through the wire");
    assert_eq!(fed.units.len(), docs.len());
    assert_eq!(fed.bytes(), total_bytes(&docs), "the units' bytes are the corpus's bytes");
    for (unit, doc) in fed.units.iter().zip(&docs) {
        let delivered: Vec<u8> = unit
            .items()
            .iter()
            .filter_map(|i| match i {
                Item::Text { bytes, .. } => Some(bytes.as_slice()),
                Item::Gap { .. } => None,
            })
            .flatten()
            .copied()
            .collect();
        assert!(delivered == doc.bytes, "`{}` round-trips byte-exact", doc.name);
    }
    assert!(fed.units.iter().all(|u| u.class() == Class::Principal(fed.principal)));
    let again = board::roundtrip(&fed);
    assert_eq!(again.units, fed.units, "the cache's codec is exact");
    board_note(TIER_CUT_3, &fed);
}

/// REPORTED, NEVER GATED: a synthetic miss prints `MISSED` and the test
/// passes — no timing row can fail a test.
#[test]
fn a_synthetic_miss_prints_missed_and_passes() {
    let miss = at_most("fence", "-", Duration::from_millis(1), Duration::from_millis(2));
    assert_eq!(miss.verdict, Verdict::Missed);
    assert!(miss.line().ends_with("| MISSED"), "{}", miss.line());
    miss.print();
    let within = at_most("fence", "-", Duration::from_millis(2), Duration::from_millis(1));
    assert_eq!(within.verdict, Verdict::Within);
    let none = reported("fence", "-", "a number");
    assert_eq!(none.verdict, Verdict::Reported);
    assert!(none.line().starts_with("BUDGET | fence | - | - | a number | REPORTED"));
    let ratio = at_most_ratio("fence", "-", 1.0, 3, 2, "the text");
    assert_eq!(ratio.verdict, Verdict::Missed);
}

/// §7.1 M7 THE DEPENDENCY TREE — ASSERTED: `cargo tree -p skep-search -e
/// normal` names `unicode-segmentation`, `unicode-normalization` and the
/// one small pure-Rust crate the latter pulls, `tinyvec`, beyond the
/// workspace's `skep-address` and what it pulls; zero `-sys` crates, zero
/// `cc`. Each crate named, for the report. Not a timing test: it runs in
/// every gate.
#[test]
fn m7_the_dependency_tree_is_pure_rust() {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .args(["tree", "-p", "skep-search", "-e", "normal", "--prefix", "none"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree");
    assert!(out.status.success(), "cargo tree: {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).expect("UTF-8");
    let mut names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| !n.is_empty())
        .collect();
    names.sort_unstable();
    names.dedup();
    for required in ["unicode-segmentation", "unicode-normalization", "tinyvec", "skep-address"] {
        assert!(names.contains(&required), "{required} missing from the tree: {names:?}");
    }
    let suspect: Vec<&&str> = names.iter().filter(|n| n.ends_with("-sys") || **n == "cc").collect();
    assert!(suspect.is_empty(), "a native build in the tree: {suspect:?}");
    note(format!("m7 tree ({} crates): {}", names.len(), names.join(", ")));
    judged("m7-tree", "-", "zero -sys, zero cc", format!("{} crates, none", names.len()), true)
        .print();
}

// ── M1 ────────────────────────────────────────────────────────────────────

/// §7.1 M1 BUILD: the indexing time apart from the reads — `prepare` and
/// `merge` over the delivered units — at 10³ against ≤ 1 s, at 10⁴ against
/// ≤ 10 s, the records tier reported; and the real bytes per document, S3's
/// 6.6 KB being the planning figure.
#[test]
#[ignore = "timing test - gate-full only"]
fn m1_build_time_at_the_cuts_and_the_records_tier() {
    let Some(c) = corpus() else { return };
    for (fed, tier) in tiers(&c) {
        let units = fed.units.len();
        let bytes = fed.bytes();
        let (index, took) = build(fed.units);
        let stats = index.stats();
        let row = match tier {
            TIER_CUT_3 => at_most("m1-build", tier, Duration::from_secs(1), took),
            TIER_CUT_4 => at_most("m1-build", tier, Duration::from_secs(10), took),
            _ => reported("m1-build", tier, report::time(took)),
        };
        row.print();
        reported(
            "m1-bytes-per-document",
            tier,
            format!(
                "{} per unit over {} units ({} of text, {} tokens, {} terms)",
                report::bytes(bytes / units.max(1) as u64),
                units,
                report::bytes(bytes),
                report::count(stats.postings as u64),
                report::count(stats.terms as u64)
            ),
        )
        .print();
    }
}

/// §7.1 M1 SIZE: the postings' bytes — each occurrence's range among them —
/// against ≤ 1× the text indexed, and the saved file's against ≤ 2.5×, at
/// the three tiers; the records tier THE CEILING's input.
#[test]
#[ignore = "timing test - gate-full only"]
fn m1_size_on_disk_at_the_cuts_and_the_records_tier() {
    let Some(c) = corpus() else { return };
    for (fed, tier) in tiers(&c) {
        let text = fed.bytes();
        let (index, _) = build(fed.units);
        let (file, _) = saved(&index);
        let parts = sections(&file);
        at_most_ratio("m1-size-postings", tier, 1.0, parts[5] as u64, text, "the text").print();
        at_most_ratio("m1-size-file", tier, 2.5, file.len() as u64, text, "the text").print();
        reported(
            "m1-size-sections",
            tier,
            format!(
                "dictionary {} + units(stored text, item tables, term lists) {} + postings {} ({:.1} B per occurrence over {} occurrences)",
                report::bytes(parts[3] as u64),
                report::bytes(parts[4] as u64),
                report::bytes(parts[5] as u64),
                parts[5] as f64 / index.stats().postings.max(1) as f64,
                report::count(index.stats().postings as u64)
            ),
        )
        .print();
    }
}

// ── M2 ────────────────────────────────────────────────────────────────────

/// §7.1 M2 THE KEYSTROKE at 10⁴: 1,200 keystrokes of 1..8 characters drawn
/// by token frequency from the corpus's own words, 0–2 full words before the
/// prefix, each timed to the whole `Answer` at `limit`'s default; p99 against
/// ≤ 16 ms; and THE NAMED WORST-CASE SET apart — a one-letter prefix, the
/// common-word phrase-prefix `"of the d`, the longest unit's commonest
/// phrase as a phrase and as a phrase-prefix — with the expansion's and the
/// positions bound's flags counted beside.
#[test]
#[ignore = "timing test - gate-full only"]
fn m2_the_keystroke_at_ten_thousand_p99_and_the_worst_cases() {
    let Some(c) = corpus() else { return };
    let Some((fed, tier)) = units_of(&c, TIER_CUT_4) else { return };
    let terms = Terms::of(&fed.units);
    let longest = fed.units.iter().max_by_key(|u| tokenize(u).len()).expect("units").clone();
    let (index, _) = build(fed.units);
    let published = Index::new(Class::Guest);
    let pair = session_pair(&published, &index);

    let mut rng = Rng(0x5EED_0000_0000_0001);
    let strokes = keystrokes(&terms, &mut rng, 1_200);
    for s in strokes.iter().take(20) {
        timed_query(pair, s);
    }
    let mut sample = Sample::new();
    let (mut more_terms, mut bounded, mut hits) = (0usize, 0usize, 0usize);
    for s in &strokes {
        let (answer, took) = timed_query(pair, s);
        sample.push(took);
        more_terms += usize::from(answer.more_terms);
        bounded += usize::from(answer.positions_bounded);
        hits += usize::from(!answer.hits.is_empty());
    }
    at_most("m2-keystroke-p99", tier, FRAME, sample.p99()).print();
    reported(
        "m2-keystroke-sample",
        tier,
        format!(
            "{}; {} answered hits, more_terms on {}, positions_bounded on {}; bounds {} entries / {} positions",
            sample.summary(),
            hits,
            more_terms,
            bounded,
            EXPANSION_BOUND_ENTRIES,
            POSITIONS_BOUND
        ),
    )
    .print();

    // The worst cases, each the median of seven runs.
    let mut first_letters: BTreeMap<char, usize> = BTreeMap::new();
    for (i, t) in terms.terms.iter().enumerate() {
        if let Some(ch) = t.chars().next() {
            if ch.is_alphabetic() {
                *first_letters.entry(ch).or_default() += terms.entries[i];
            }
        }
    }
    let letter = first_letters.iter().max_by_key(|(_, &n)| n).map(|(&c, _)| c).unwrap_or('t');
    let longest_tokens: Vec<String> = tokenize(&longest).into_iter().map(|t| t.term).collect();
    let mut bigrams: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for w in longest_tokens.windows(2) {
        *bigrams.entry((&w[0], &w[1])).or_default() += 1;
    }
    let (phrase, phrase_prefix) = bigrams
        .iter()
        .max_by_key(|(_, &n)| n)
        .map(|((a, b), _)| {
            let first: String = b.chars().take(1).collect();
            (format!("\"{a} {b}\""), format!("\"{a} {first}"))
        })
        .unwrap_or_else(|| ("\"the the\"".into(), "\"the t".into()));
    let worst = [
        ("m2-worst-one-letter-prefix", letter.to_string()),
        ("m2-worst-common-phrase-prefix", "\"of the d".to_string()),
        ("m2-worst-longest-unit-phrase", phrase),
        ("m2-worst-longest-unit-phrase-prefix", phrase_prefix),
    ];
    for (row, text) in worst {
        let mut s = Sample::new();
        let mut last = None;
        for _ in 0..7 {
            let (answer, took) = timed_query(pair, &text);
            s.push(took);
            last = Some(answer);
        }
        let answer = last.expect("seven runs");
        let mut r = at_most(row, tier, FRAME, s.p50());
        r.measured = format!(
            "{} median ({} max); `{}` → total {}, more_terms {}, positions_bounded {}",
            report::time(s.p50()),
            report::time(s.max()),
            text,
            answer.total,
            answer.more_terms,
            answer.positions_bounded
        );
        r.print();
    }
    note(format!(
        "m2 longest unit: {} tokens, {} of text; the one-letter prefix is `{letter}`",
        longest_tokens.len(),
        report::bytes(longest.bytes())
    ));
}

/// A five-letter-or-longer word that is NO term: `base` with one character
/// substituted, the first substitution the dictionary lacks.
fn misspelled(terms: &Terms, base: &str) -> String {
    for (i, _) in base.char_indices() {
        for sub in ['q', 'x', 'z', 'k', 'j'] {
            let mut s = String::new();
            for (j, ch) in base.char_indices() {
                s.push(if i == j { sub } else { ch });
            }
            if terms.index_of(&s).is_none() {
                return s;
            }
        }
    }
    format!("{base}zq")
}

/// Twelve complete words of five characters or more, none a term.
fn twelve_non_terms(terms: &Terms) -> String {
    let stems = [
        "blorvex",
        "quantrile",
        "zyphorm",
        "kraltune",
        "vexomind",
        "jorquast",
        "plinthax",
        "drovelyn",
        "snorquil",
        "fablixor",
        "gruntolk",
        "whizmerk",
    ];
    let words: Vec<String> = stems
        .iter()
        .map(|s| {
            let mut w = s.to_string();
            while terms.index_of(&w).is_some() {
                w.push('q');
            }
            w
        })
        .collect();
    format!("{} ", words.join(" "))
}

/// §7.1 M2 FUZZY at 10⁴: one misspelled five-letter word, one inside a
/// phrase, and a pasted sentence of twelve complete words none of them a
/// term, each timed; p99 against ≤ 16 ms; `fuzzy_bounded` ASSERTED on the
/// last — the three-word bound.
#[test]
#[ignore = "timing test - gate-full only"]
fn m2_the_fuzzy_query_at_ten_thousand() {
    let Some(c) = corpus() else { return };
    let Some((fed, tier)) = units_of(&c, TIER_CUT_4) else { return };
    let terms = Terms::of(&fed.units);
    let (index, _) = build(fed.units);
    let published = Index::new(Class::Guest);
    let pair = session_pair(&published, &index);

    // A common five-letter word, misspelled; the same inside a phrase.
    let base = (0..terms.terms.len())
        .filter(|&i| {
            terms.terms[i].chars().count() == 5
                && terms.terms[i].chars().all(|c| c.is_ascii_lowercase())
        })
        .max_by_key(|&i| terms.entries[i])
        .map(|i| terms.terms[i].clone())
        .unwrap_or_else(|| "board".into());
    let word = misspelled(&terms, &base);
    let common = terms.draw(&mut Rng(7));
    let cases = [
        ("m2-fuzzy-word", format!("{word} ")),
        ("m2-fuzzy-in-phrase", format!("\"{common} {word}\"")),
        ("m2-fuzzy-twelve-words", twelve_non_terms(&terms)),
    ];
    let mut all = Sample::new();
    for (row, text) in &cases {
        let mut s = Sample::new();
        let mut last = None;
        for _ in 0..30 {
            let (answer, took) = timed_query(pair, text);
            s.push(took);
            all.push(took);
            last = Some(answer);
        }
        let answer = last.expect("thirty runs");
        if *row == "m2-fuzzy-twelve-words" {
            assert!(
                answer.fuzzy_bounded,
                "§7.1 M2 FUZZY: the three-word bound fires on twelve complete non-terms"
            );
        }
        let mut r = at_most(row, tier, FRAME, s.p99());
        r.measured = format!(
            "p99 {} (p50 {}); `{}` → total {}, fuzzy_bounded {}, more_terms {}, matched {}",
            report::time(s.p99()),
            report::time(s.p50()),
            text.trim_end(),
            answer.total,
            answer.fuzzy_bounded,
            answer.more_terms,
            answer.hits.first().map_or(0, |h| h.matched.len())
        );
        r.print();
    }
    at_most("m2-fuzzy-p99", tier, FRAME, all.p99()).print();
    note(format!(
        "m2 fuzzy: the misspelled word is `{word}` (from `{base}`), the dictionary holds {} terms, {} of five characters or more",
        terms.terms.len(),
        terms.terms.iter().filter(|t| t.chars().count() >= FUZZY_MIN_CHARS).count()
    ));
}

/// The 1 MB document: the first MiB of the records tier's largest file, cut
/// on a character boundary, as one unit of one text item under `key`.
fn megabyte(c: &Corpus, key: &UnitKey, class: Class) -> Vec<u8> {
    let records = c.records();
    let largest = records.iter().max_by_key(|d| d.bytes.len()).expect("the tier");
    let mut end = (MIB as usize).min(largest.bytes.len());
    if let Ok(text) = std::str::from_utf8(&largest.bytes) {
        while !text.is_char_boundary(end) {
            end -= 1;
        }
    }
    let _ = (key, class);
    largest.bytes[..end].to_vec()
}

fn unit_of(key: &UnitKey, class: Class, as_of: u64, bytes: Vec<u8>) -> Unit {
    let doc = key.doc().clone();
    Unit::new(
        key.clone(),
        Some(doc),
        Kind::Draft,
        class,
        as_of,
        vec![Item::Text { start: 1, bytes }],
    )
    .expect("one item")
}

/// §7.1 M2 UNDER A WRITER at 10⁴: the keystrokes while a save and a 1 MB
/// re-index run on another thread under a read-write lock as §5.6 shapes it
/// — the save on the read side, the tokenizing outside it, the merge alone
/// on the write side; p99 against ≤ 16 ms, the writer's holds reported.
#[test]
#[ignore = "timing test - gate-full only"]
fn m2_the_keystroke_under_a_writer_at_ten_thousand() {
    let Some(c) = corpus() else { return };
    let Some((fed, tier)) = units_of(&c, TIER_CUT_4) else { return };
    let terms = Terms::of(&fed.units);
    let class = fed.units[0].class();
    let (index, _) = build(fed.units);
    let lock = Arc::new(RwLock::new(index));
    let published = Index::new(Class::Guest);
    let key = UnitKey::new(parse_addr("1.0.1.0.999999"));
    let big = megabyte(&c, &key, class);

    let stop = Arc::new(AtomicBool::new(false));
    let saves = Arc::new(AtomicU64::new(0));
    let merges = Arc::new(AtomicU64::new(0));
    let merge_hold_max = Arc::new(AtomicU64::new(0));
    let write_wait_max = Arc::new(AtomicU64::new(0));
    let save_hold_max = Arc::new(AtomicU64::new(0));
    let writer = {
        let (lock, stop, saves, merges, merge_hold_max, write_wait_max, save_hold_max) = (
            lock.clone(),
            stop.clone(),
            saves.clone(),
            merges.clone(),
            merge_hold_max.clone(),
            write_wait_max.clone(),
            save_hold_max.clone(),
        );
        let path = scratch("m2-writer.index");
        std::thread::spawn(move || {
            let mut cycle = 0u64;
            while !stop.load(Ordering::Relaxed) {
                // The save, under the read side, beside the keystrokes.
                let t = Instant::now();
                {
                    let guard = lock.read().expect("the read side");
                    let mut file = File::create(&path).expect("the file");
                    guard.save(&header(None, at(cycle)), &mut file).expect("saved");
                }
                save_hold_max.fetch_max(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
                saves.fetch_add(1, Ordering::Relaxed);
                // The re-index: tokenized OUTSIDE the lock, merged under the write side.
                cycle += 1;
                let prepared = Index::prepare(unit_of(&key, class, cycle, big.clone()));
                let t = Instant::now();
                {
                    let mut guard = lock.write().expect("the write side");
                    write_wait_max.fetch_max(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
                    let held = Instant::now();
                    guard.merge(prepared).expect("merged");
                    merge_hold_max.fetch_max(held.elapsed().as_nanos() as u64, Ordering::Relaxed);
                }
                merges.fetch_add(1, Ordering::Relaxed);
            }
        })
    };

    // The keystrokes run until the writer has merged the 1 MB unit at least
    // five times beside them (and at least 1,200 keystrokes), so the merges
    // land among the keystrokes and not after them; a minute caps the run.
    let mut rng = Rng(0x5EED_0000_0000_0002);
    let strokes = keystrokes(&terms, &mut rng, 1_200);
    let mut sample = Sample::new();
    let mut waits = Sample::new();
    let began = Instant::now();
    let mut rounds = 0;
    while rounds == 0
        || (merges.load(Ordering::Relaxed) < 5 && began.elapsed() < Duration::from_secs(60))
    {
        for s in &strokes {
            let t = Instant::now();
            let guard = lock.read().expect("the read side");
            waits.push(t.elapsed());
            let pair = session_pair(&published, &guard);
            let (_, took) = timed_query(pair, s);
            drop(guard);
            sample.push(t.elapsed());
            let _ = took;
        }
        rounds += 1;
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().expect("the writer");
    at_most("m2-keystroke-under-writer-p99", tier, FRAME, sample.p99()).print();
    reported(
        "m2-keystroke-under-writer-sample",
        tier,
        format!(
            "{} in {} rounds over {}; the wait for the read side p99 {} / max {}; the writer made {} saves (read side held at most {}) and {} merges of the 1 MB unit (write side held at most {}, waited for at most {} behind the readers)",
            sample.summary(),
            rounds,
            report::time(began.elapsed()),
            report::time(waits.p99()),
            report::time(waits.max()),
            saves.load(Ordering::Relaxed),
            report::time(Duration::from_nanos(save_hold_max.load(Ordering::Relaxed))),
            merges.load(Ordering::Relaxed),
            report::time(Duration::from_nanos(merge_hold_max.load(Ordering::Relaxed))),
            report::time(Duration::from_nanos(write_wait_max.load(Ordering::Relaxed)))
        ),
    )
    .print();
}

/// THE TWO DERIVED BOUNDS AT M2: the per-occurrence cost of the evaluator's
/// dependent accesses, measured over the 10⁴ corpus — bare-prefix keystrokes
/// whose merged positions the expansion's replica counts, their times fit as
/// a fixed cost plus a cost per position merged plus a cost per unit scored
/// — against the 100 ns SR-3 assumed; and the keystrokes at the bound itself
/// timed. Where the cost differs from 100 ns by more than a factor of two,
/// `EXPANSION_BOUND_ENTRIES` and `POSITIONS_BOUND` move to the power of two
/// at or below half a frame over the measured cost; else they stand.
#[test]
#[ignore = "timing test - gate-full only"]
fn m2_the_two_derived_bounds_per_occurrence_cost() {
    let Some(c) = corpus() else { return };
    let Some((fed, tier)) = units_of(&c, TIER_CUT_4) else { return };
    let terms = Terms::of(&fed.units);
    let (index, _) = build(fed.units);
    let published = Index::new(Class::Guest);
    let pair = session_pair(&published, &index);

    // Bare prefixes of 1..8 characters, by token frequency.
    let mut rng = Rng(0x5EED_0000_0000_0003);
    let mut rows: Vec<(f64, f64, f64)> = Vec::new();
    let mut at_bound = Sample::new();
    let mut under = Sample::new();
    for _ in 0..1_500 {
        let word = terms.draw(&mut rng);
        let k = 1 + rng.below(8) as usize;
        let prefix: String = word.chars().take(k).collect();
        let (merged, _, _) = terms.expansion(&prefix, EXPANSION_BOUND_ENTRIES);
        let merged = merged.min(POSITIONS_BOUND);
        let (answer, took) = timed_query(pair, &prefix);
        rows.push((merged as f64, answer.total as f64, took.as_nanos() as f64));
        if merged >= POSITIONS_BOUND * 9 / 10 {
            at_bound.push(took);
        } else {
            under.push(took);
        }
    }
    let (fixed, per_position, per_unit) = fit3(&rows);
    let merged_total: f64 = rows.iter().map(|r| r.0).sum();
    let time_total: f64 = rows.iter().map(|r| r.2).sum();
    let naive = time_total / merged_total.max(1.0);
    let frame_half_ns = FRAME.as_nanos() as f64 / 2.0;
    let power_at_or_below = |n: f64| -> usize {
        let n = n.max(1.0) as usize;
        1usize << (usize::BITS - 1 - n.leading_zeros())
    };
    // The bound the per-position cost alone would admit, half a frame over it.
    let implied = power_at_or_below(frame_half_ns / per_position.max(1e-9));
    // The frame at the bound as MEASURED — the keystrokes that merged at least
    // nine tenths of it — scaled to the implied bound: the value that holds
    // the one-frame pin is the one whose projected p99 stays within the frame.
    let at_bound_p99 = at_bound.p99();
    let projected = at_bound_p99.mul_f64(implied as f64 / POSITIONS_BOUND as f64);
    let within_factor_two = (0.5..=2.0).contains(&(per_position / 100.0));
    judged(
        "m2-per-occurrence-cost",
        tier,
        "100 ns assumed, within a factor of 2",
        format!(
            "{per_position:.1} ns per position merged (+ {per_unit:.0} ns per unit scored + {:.3} ms fixed) over {} bare prefixes; whole-time over positions {naive:.1} ns; at the bound (>= 90%): {}; under it: {}",
            fixed / 1e6,
            rows.len(),
            at_bound.summary(),
            under.summary()
        ),
        within_factor_two,
    )
    .print();
    let verdict = if implied == POSITIONS_BOUND {
        "CONFIRMED: the measured cost implies the figure that stands".to_string()
    } else if implied > POSITIONS_BOUND && projected > FRAME {
        format!(
            "CONFIRMED: the per-position cost alone would admit {implied}, but the frame at the bound is already spent — the keystrokes at the bound p99 {} against the 16 ms frame, the per-unit scoring ({per_unit:.0} ns over up to every unit) taking what the merge leaves — so {implied} projects to {} and misses; the figure stands",
            report::time(at_bound_p99),
            report::time(projected)
        )
    } else {
        format!(
            "MOVE to {implied}: the keystrokes at the bound p99 {} project to {} there, within the frame",
            report::time(at_bound_p99),
            report::time(projected)
        )
    };
    reported(
        "m2-bounds-verdict",
        tier,
        format!(
            "EXPANSION_BOUND_ENTRIES = POSITIONS_BOUND = {} ({}): half a frame over {per_position:.1} ns/position is {:.0} positions, the power of two at or below it {implied}; {verdict}",
            POSITIONS_BOUND,
            1usize << 16,
            frame_half_ns / per_position.max(1e-9)
        ),
    )
    .print();
}

// ── M3 ────────────────────────────────────────────────────────────────────

/// §7.1 M3: the corpus's distinct-term count at each tier, reported — the
/// cases are SR-1's suite, already asserted.
#[test]
#[ignore = "timing test - gate-full only"]
fn m3_the_distinct_term_count_at_each_tier() {
    let Some(c) = corpus() else { return };
    for (fed, tier) in tiers(&c) {
        let (index, _) = build(fed.units);
        let stats = index.stats();
        reported(
            "m3-distinct-terms",
            tier,
            format!(
                "{} distinct terms over {} tokens in {} units (avgdl {:.1} tokens)",
                report::count(stats.terms as u64),
                report::count(stats.postings as u64),
                stats.units,
                stats.postings as f64 / stats.units.max(1) as f64
            ),
        )
        .print();
    }
}

// ── M4 ────────────────────────────────────────────────────────────────────

/// §7.1 M4 RE-INDEX: a 10 KB draft replaced 100 cycles (tombstone + add)
/// against ≤ 100 ms per cycle, the index's growth before compaction
/// reported; a 1 MB document re-indexed 10 cycles, each read back through
/// the dev board in eight parts, against ≤ 2 s per cycle, the read apart.
#[test]
#[ignore = "timing test - gate-full only"]
fn m4_the_re_index_of_a_draft_and_of_a_megabyte() {
    let Some(c) = corpus() else { return };
    let Some((fed, tier)) = units_of(&c, TIER_CUT_4) else { return };
    let class = fed.units[0].class();
    let draft = fed.units.iter().max_by_key(|u| u.bytes()).expect("units").clone();
    let (mut index, _) = build(fed.units);
    let live = index.stats().postings;

    // The 10 KB draft, 100 cycles.
    let bytes: Vec<u8> = draft
        .items()
        .iter()
        .filter_map(|i| match i {
            Item::Text { bytes, .. } => Some(bytes.clone()),
            Item::Gap { .. } => None,
        })
        .flatten()
        .collect();
    let mut cycles = Sample::new();
    let mut due_at = None;
    for k in 1..=100u64 {
        let mut text = bytes.clone();
        text.extend_from_slice(format!(" cycle{k}").as_bytes());
        let t = Instant::now();
        let prepared = Index::prepare(unit_of(draft.key(), class, k, text));
        index.merge(prepared).expect("replaced");
        cycles.push(t.elapsed());
        if due_at.is_none() && index.compaction_due() {
            due_at = Some(k);
        }
    }
    let after = index.stats();
    at_most("m4-draft-cycle", tier, Duration::from_millis(100), cycles.p99()).print();
    reported(
        "m4-draft-growth",
        tier,
        format!(
            "{} ({} of text); after 100 cycles {} tombstones, {} dead postings beside {} live ({:.1}% growth); compaction due {}",
            cycles.summary(),
            report::bytes(draft.bytes()),
            after.tombstones,
            report::count(after.dead_postings as u64),
            report::count(after.postings as u64),
            100.0 * after.dead_postings as f64 / live.max(1) as f64,
            due_at.map_or("never".to_string(), |k| format!("from cycle {k}"))
        ),
    )
    .print();

    // The 1 MB document, through a fresh board in eight parts, 10 cycles.
    let board = DevBoard::spawn();
    let big = megabyte(&c, draft.key(), class);
    let doc = board.create(None);
    let t = Instant::now();
    board.insert(&doc, 1, &big);
    let inserted = t.elapsed();
    let mut reads = Sample::new();
    let mut reindex = Sample::new();
    let mut parts_seen = 0;
    for k in 1..=10u64 {
        let t = Instant::now();
        let (unit, parts) = board.read_unit(&doc, Kind::Draft, Some(doc.clone()));
        reads.push(t.elapsed());
        parts_seen = parts;
        assert_eq!(unit.bytes(), big.len() as u64, "the 1 MB unit read whole");
        let t = Instant::now();
        let prepared = Index::prepare(unit);
        index.merge(prepared).expect("merged");
        reindex.push(t.elapsed());
        let _ = k;
    }
    at_most("m4-megabyte-cycle", tier, Duration::from_secs(2), reindex.max()).print();
    reported(
        "m4-megabyte-read",
        tier,
        format!(
            "{} inserted in {}; read back in {} parts a read: {}; the re-index (prepare + merge) {}",
            report::bytes(big.len() as u64),
            report::time(inserted),
            parts_seen,
            reads.summary(),
            reindex.summary()
        ),
    )
    .print();
    let before = index.stats();
    let t = Instant::now();
    let compacted = index.compacted();
    let built = t.elapsed();
    let t = Instant::now();
    index.install(compacted);
    let installed = t.elapsed();
    reported(
        "m4-compaction",
        tier,
        format!(
            "{} tombstones and {} dead postings compacted in {} (+ install {}); live postings {} → {}",
            before.tombstones,
            report::count(before.dead_postings as u64),
            report::time(built),
            report::time(installed),
            report::count(before.postings as u64),
            report::count(index.stats().postings as u64)
        ),
    )
    .print();
    drop(board);
}

// ── M5 ────────────────────────────────────────────────────────────────────

/// The M5 probe's child: loads the index file the variable names and prints
/// its resident set before and after — run by `m5_memory…` as a child of
/// the test binary, so the set measured is an index loaded whole and nothing
/// else; alone, it prints why it did nothing.
#[test]
#[ignore = "timing test - gate-full only"]
fn m5_probe_child() {
    let Some(path) = std::env::var_os(M5_PROBE_VAR) else {
        println!("SKIPPED: m5_probe_child runs as m5_memory's child alone ({M5_PROBE_VAR} unset)");
        return;
    };
    let class = match std::env::var(M5_CLASS_VAR).ok().as_deref() {
        Some("guest") | None => Class::Guest,
        Some(n) => Class::Principal(n.parse().expect("a principal")),
    };
    let pid = std::process::id();
    let before = rss_of(pid);
    let mut file = File::open(&path).expect("the index file");
    let t = Instant::now();
    let (index, _) = Index::load(&mut file, class).expect("the index loads");
    let took = t.elapsed();
    let after = rss_of(pid);
    println!(
        "M5PROBE before={before} after={after} load_ns={} units={} bytes={}",
        took.as_nanos(),
        index.stats().units,
        index.stats().bytes
    );
    drop(index);
}

/// The probe run over `path`: `(rss before, rss after, load time)`.
fn probe(path: &PathBuf, class: Class) -> (u64, u64, Duration) {
    let class = match class {
        Class::Guest => "guest".to_string(),
        Class::Principal(n) => n.to_string(),
    };
    let out = Command::new(std::env::current_exe().expect("this binary"))
        .args(["budgets::m5_probe_child", "--exact", "--ignored", "--nocapture"])
        .env(M5_PROBE_VAR, path)
        .env(M5_CLASS_VAR, class)
        .output()
        .expect("the probe child");
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.starts_with("M5PROBE")).unwrap_or_else(|| {
        panic!(
            "the probe printed no M5PROBE line:\n{text}\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let field = |name: &str| -> u64 {
        line.split_whitespace()
            .find_map(|f| {
                f.strip_prefix(name).and_then(|v| v.strip_prefix('=')).and_then(|v| v.parse().ok())
            })
            .unwrap_or_else(|| panic!("{name} in {line}"))
    };
    (field("before"), field("after"), Duration::from_nanos(field("load_ns")))
}

/// §7.1 M5 MEMORY at 10⁴ and the records tier: the resident set with the
/// index loaded whole — a child process that loads the saved file and
/// nothing else — against ≤ 2× the file's bytes; the dead postings' resident
/// residue between compactions and the two copies of the postings across a
/// compaction's swap, both reported.
#[test]
#[ignore = "timing test - gate-full only"]
fn m5_memory_at_ten_thousand_and_the_records_tier() {
    let Some(c) = corpus() else { return };
    for tier in [TIER_CUT_4, TIER_RECORDS] {
        let Some((fed, tier)) = units_of(&c, tier) else { continue };
        let class = fed.units[0].class();
        let replaced: Vec<Unit> = fed.units.iter().step_by(16).cloned().collect();
        let (mut index, _) = build(fed.units);
        let (file, _) = saved(&index);
        let path = scratch(&format!("m5-{}.index", tier.replace(['^', '(', ')'], "_")));
        std::fs::write(&path, &file).expect("the index file");
        let (before, after, load) = probe(&path, class);
        at_most_ratio("m5-resident", tier, 2.0, after, file.len() as u64, "the file").print();
        reported(
            "m5-resident-detail",
            tier,
            format!(
                "child's resident set {} before the load, {} after (+{}); the file {}; the load took {}",
                report::bytes(before),
                report::bytes(after),
                report::bytes(after.saturating_sub(before)),
                report::bytes(file.len() as u64),
                report::time(load)
            ),
        )
        .print();

        // The residue: one unit in sixteen replaced, its postings dead until compaction.
        let per_entry = postings_bytes(&file) as f64 / index.stats().postings.max(1) as f64;
        for (k, unit) in replaced.into_iter().enumerate() {
            let fresh = unit_of(
                unit.key(),
                class,
                1 + k as u64,
                unit.items()
                    .iter()
                    .filter_map(|i| match i {
                        Item::Text { bytes, .. } => Some(bytes.clone()),
                        Item::Gap { .. } => None,
                    })
                    .flatten()
                    .collect(),
            );
            index.merge(Index::prepare(fresh)).expect("replaced");
        }
        let stats = index.stats();
        let pid = std::process::id();
        let resident_before = rss_of(pid);
        let compacted = index.compacted();
        let resident_two_copies = rss_of(pid);
        index.install(compacted);
        let resident_after = rss_of(pid);
        reported(
            "m5-dead-residue",
            tier,
            format!(
                "{} tombstones holding {} dead postings ≈ {} at the file's {:.1} B per occurrence, beside {} live; compaction due: {}",
                stats.tombstones,
                report::count(stats.dead_postings as u64),
                report::bytes((stats.dead_postings as f64 * per_entry) as u64),
                per_entry,
                report::count(stats.postings as u64),
                index.compaction_due()
            ),
        )
        .print();
        reported(
            "m5-two-copies",
            tier,
            format!(
                "this process resident {} before `compacted`, {} with both copies (+{}), {} after `install`",
                report::bytes(resident_before),
                report::bytes(resident_two_copies),
                report::bytes(resident_two_copies.saturating_sub(resident_before)),
                report::bytes(resident_after)
            ),
        )
        .print();
        let _ = std::fs::remove_file(&path);
    }
}

// ── M6 ────────────────────────────────────────────────────────────────────

/// The last component of an I-address, its ordinal.
fn ordinal_of(i_addr: &str) -> u64 {
    i_addr.rsplit_once('.').and_then(|(_, last)| last.parse().ok()).expect("a dotted address")
}

/// The head's arrangement as the runs a shot re-supplies: its image, each
/// run `(i_start, width)` — a window onto a draft's I-space — and its extent.
fn head_runs(board: &DevBoard, doc: &Address) -> (Vec<(Address, u64)>, u64) {
    let extent = board.extent(doc);
    let (runs, _) = board.image(doc, 1, extent);
    (runs.into_iter().map(|(i_start, w)| (parse_addr(&i_start), w)).collect(), extent)
}

/// A draft holding `text`, and the window a shot places it by.
fn staged(board: &DevBoard, text: &[u8]) -> (Address, u64) {
    staged_in(board, text).1
}

/// [`staged`], with the draft's own address.
fn staged_in(board: &DevBoard, text: &[u8]) -> (Address, (Address, u64)) {
    let draft = board.create(None);
    board.insert(&draft, 1, text);
    let (runs, _) = board.image(&draft, 1, text.len() as u64);
    assert_eq!(runs.len(), 1, "one fresh run");
    (draft, (parse_addr(&runs[0].0), runs[0].1))
}

/// The pairs of a `compare` answer as `(u1, u2, width)`, or the refusal's code.
fn pairs_of(v: &serde_json::Value) -> Result<Vec<(u64, u64, u64)>, String> {
    if v["resp"].as_str() == Some("rejected") {
        return Err(v["code"].as_str().unwrap_or("?").to_string());
    }
    let ordinal = |u: &serde_json::Value| -> u64 {
        u["ordinal"].as_str().and_then(|o| o.parse().ok()).unwrap_or(0)
    };
    Ok(v["pairs"]
        .as_array()
        .map(|ps| {
            ps.iter()
                .map(|p| {
                    (
                        ordinal(&p["u1"]),
                        ordinal(&p["u2"]),
                        p["width"].as_str().and_then(|w| w.parse().ok()).unwrap_or(0),
                    )
                })
                .collect()
        })
        .unwrap_or_default())
}

/// §7.1 M6 THE JUMP's `compare` against the daemon: the viewport's band at a
/// member against the head, the document moved on by 1 and by 10 members;
/// the two-`image` form beside it; the landing where several pairs answer
/// the band — a passage held twice, half cut, split by a run boundary; and a
/// head fragmented past `MAX_COMPARE_OPERAND_BLOCKS`, the refusal — each
/// timed over the wire against ≤ 100 ms. On a CLAIMED board, the members
/// published by attested shots from the claimant's signed session, each
/// shot's runs windows onto the drafts that hold the text.
#[test]
#[ignore = "timing test - gate-full only"]
fn m6_the_jumps_compare_against_the_daemon() {
    let Some(c) = corpus() else { return };
    let pin = Duration::from_millis(100);
    let text = cut_3(&c).into_iter().max_by_key(|d| d.bytes.len()).expect("the cut").bytes;
    let n = text.len() as u64;
    assert!(n >= 8_400, "the largest cut document holds {n} bytes");
    let board = DevBoard::spawn();
    let signed = board.signed();
    let d = board.create_edition(&signed);
    let (source_draft, source) = staged_in(&board, &text);
    let m1 = board.publish_windows(&signed, &d, None, &[source.clone()]);
    assert_eq!(board.extent(&m1), n, "the birth member holds the text");
    let band = (n / 2 - 200, 400u64);
    let (band_runs, _) = board.image(&m1, band.0, band.1);
    assert!(
        band_runs.len() == 1 && band_runs[0].1 >= 400,
        "the band's I-range is one run: {band_runs:?}"
    );
    let band_start = parse_addr(&band_runs[0].0);

    // Moved on by one member: a paragraph prepended, the head's runs carried by reference.
    let mut head = m1.clone();
    let mut shots = 0;
    let shot = |head: &Address, k: u64| -> Address {
        let (mut runs, extent) = head_runs(&board, &d);
        let fresh = staged(
            &board,
            format!("Paragraph {k}, added at the front of the document.\n\n").as_bytes(),
        );
        runs.insert(0, fresh);
        board.publish_windows(&signed, &d, Some((head, extent)), &runs)
    };
    head = shot(&head, 1);
    shots += 1;
    let head_extent = board.extent(&d);
    let (v, took) = board.compare((&m1, band.0, band.1), (&d, 1, head_extent));
    let pairs = pairs_of(&v);
    let mut r = at_most("m6-compare-moved-by-1", "-", pin, took);
    r.measured = format!(
        "{} ; {} pairs over the band ({:?})",
        report::time(took),
        pairs.as_ref().map_or(0, Vec::len),
        pairs.as_ref().ok().and_then(|p| p.first().copied())
    );
    r.print();

    // Moved on by ten.
    for k in 2..=10 {
        head = shot(&head, k);
        shots += 1;
    }
    let head_extent = board.extent(&d);
    let (v, took) = board.compare((&m1, band.0, band.1), (&d, 1, head_extent));
    let pairs = pairs_of(&v);
    let mut r = at_most("m6-compare-moved-by-10", "-", pin, took);
    r.measured = format!(
        "{} ; {} pairs over the band, the head {} positions after {shots} shots",
        report::time(took),
        pairs.as_ref().map_or(0, Vec::len),
        head_extent
    );
    r.print();

    // The two-image form: the band's image at the member, the head's whole image, intersected.
    let (band_image, t1) = board.image(&m1, band.0, band.1);
    let (head_image, t2) = board.image(&d, 1, head_extent);
    let shared: u64 = head_image
        .iter()
        .flat_map(|(h, hw)| {
            band_image.iter().filter_map(move |(b, bw)| {
                if board::origin_of(h) != board::origin_of(b) {
                    return None;
                }
                let (h0, b0) = (ordinal_of(h), ordinal_of(b));
                let lo = h0.max(b0);
                let hi = (h0 + hw).min(b0 + bw);
                (hi > lo).then_some(hi - lo)
            })
        })
        .sum();
    let mut r = at_most("m6-two-image", "-", pin, t1 + t2);
    r.measured = format!(
        "{} (band image {} + head image {}); {} head runs, {} of the band's {} positions found in them",
        report::time(t1 + t2),
        report::time(t1),
        report::time(t2),
        head_image.len(),
        shared,
        band.1
    );
    r.print();

    // Several pairs: the band's first half held twice, its second half cut, a paragraph between.
    let half = (band_start.clone(), 200u64);
    let p = staged(&board, b"A paragraph before the passage.\n\n");
    let q = staged(&board, b"A paragraph between the two copies.\n\n");
    let (_, extent_before) = head_runs(&board, &d);
    board.publish_windows(
        &signed,
        &d,
        Some((&head, extent_before)),
        &[p, half.clone(), q, half.clone()],
    );
    let head_extent = board.extent(&d);
    let (v, took) = board.compare((&m1, band.0, band.1), (&d, 1, head_extent));
    let pairs = pairs_of(&v);
    let mut r = at_most("m6-compare-several-pairs", "-", pin, took);
    r.measured = format!(
        "{} ; {} pairs answer the band: {:?}",
        report::time(took),
        pairs.as_ref().map_or(0, Vec::len),
        pairs.as_ref().ok()
    );
    r.print();

    // A head fragmented past MAX_COMPARE_OPERAND_BLOCKS. No SHOT fragments
    // a member that far: the request envelope caps an array at 4,096
    // elements, so a `runs` array of 4,100 is `malformed` at the wire ahead
    // of the arrangement's own run budget — a finding for the design, the
    // fragmented head reachable only by deposits appended past the extent
    // or by a transclusion-heavy DRAFT. The case is built as the latter:
    // 4,100 `copy` ops, each one position of the text at an odd offset, a
    // run apiece, and the compare's `rho2` that draft.
    let fragmented = board.create(None);
    let t = Instant::now();
    for i in 0..4_100u64 {
        board.copy(&fragmented, i + 1, &source_draft, 1 + 2 * i, 1);
    }
    let copied = t.elapsed();
    let frag_extent = board.extent(&fragmented);
    let (v, took) = board.compare((&m1, band.0, band.1), (&fragmented, 1, frag_extent));
    let pairs = pairs_of(&v);
    let mut r = at_most("m6-compare-fragmented-head", "-", pin, took);
    r.measured = format!(
        "{} ; the head {} runs of width 1 (4,100 copies in {}) → {}; a shot of 4,100 runs is `malformed` at the wire's 4,096-element array cap",
        report::time(took),
        frag_extent,
        report::time(copied),
        match &pairs {
            Ok(p) => format!("{} pairs", p.len()),
            Err(code) => format!("refused `{code}`, the pinned member the landing"),
        }
    );
    r.print();
    drop(signed);
    drop(board);
}

// ── LOAD / SAVE ───────────────────────────────────────────────────────────

/// §7.1 LOAD at 10⁴ against ≤ 500 ms, the records tier reported: the whole
/// file from bytes in memory, and from the file on disk.
#[test]
#[ignore = "timing test - gate-full only"]
fn load_at_ten_thousand_and_the_records_tier() {
    let Some(c) = corpus() else { return };
    for tier in [TIER_CUT_4, TIER_RECORDS] {
        let Some((fed, tier)) = units_of(&c, tier) else { continue };
        let class = fed.units[0].class();
        let (index, _) = build(fed.units);
        let (file, _) = saved(&index);
        drop(index);
        let t = Instant::now();
        let (loaded, _) = Index::load(&mut &file[..], class).expect("loads");
        let from_memory = t.elapsed();
        drop(loaded);
        let path = scratch(&format!("load-{}.index", tier.replace(['^', '(', ')'], "_")));
        std::fs::write(&path, &file).expect("the file");
        let t = Instant::now();
        let mut f = File::open(&path).expect("open");
        let (loaded, _) = Index::load(&mut f, class).expect("loads");
        let from_disk = t.elapsed();
        drop(loaded);
        let _ = std::fs::remove_file(&path);
        let row = if tier == TIER_CUT_4 {
            at_most("load", tier, Duration::from_millis(500), from_disk)
        } else {
            reported("load", tier, report::time(from_disk))
        };
        row.print();
        reported(
            "load-detail",
            tier,
            format!(
                "from disk {} / from memory {}; the file {}",
                report::time(from_disk),
                report::time(from_memory),
                report::bytes(file.len() as u64)
            ),
        )
        .print();
    }
}

/// §7.1 SAVE at 10⁴ against ≤ 1 s, the records tier reported; and BYTES
/// WRITTEN PER HOUR at `client.md` §4e.2's cadence — every 64 changed units
/// or 30 seconds, so on a board whose text changes at least every 30 s 120
/// saves an hour, each the whole file — reported, no pin.
#[test]
#[ignore = "timing test - gate-full only"]
fn save_at_ten_thousand_and_the_records_tier_and_the_bytes_per_hour() {
    let Some(c) = corpus() else { return };
    for tier in [TIER_CUT_4, TIER_RECORDS] {
        let Some((fed, tier)) = units_of(&c, tier) else { continue };
        let (index, _) = build(fed.units);
        let (bytes, to_memory) = saved(&index);
        let path = scratch(&format!("save-{}.index", tier.replace(['^', '(', ')'], "_")));
        let t = Instant::now();
        let mut f = File::create(&path).expect("create");
        index.save(&header(None, at(1)), &mut f).expect("saved");
        f.sync_all().expect("synced");
        let to_disk = t.elapsed();
        let _ = std::fs::remove_file(&path);
        let row = if tier == TIER_CUT_4 {
            at_most("save", tier, Duration::from_secs(1), to_disk)
        } else {
            reported("save", tier, report::time(to_disk))
        };
        row.print();
        reported(
            "save-detail",
            tier,
            format!(
                "to disk with sync {} / to memory {}; the file {}",
                report::time(to_disk),
                report::time(to_memory),
                report::bytes(bytes.len() as u64)
            ),
        )
        .print();
        reported(
            "save-bytes-per-hour",
            tier,
            format!(
                "{} an hour at 120 saves (every 30 s, the whole file of {})",
                report::bytes(bytes.len() as u64 * 120),
                report::bytes(bytes.len() as u64)
            ),
        )
        .print();
    }
}

/// §7.1 THE SAVE PATH's `/chain?at`: at every save, one read per moved range
/// — the board's range at the pair a fresh commit gave, and a widened range
/// beside it at an older position — its latency, the time it holds one of
/// the board's two reconstruction permits, timed beside two concurrent
/// `/op-at` readers, the `503 history_busy` answers both sides meet; the
/// index at 10⁴, the live board a fresh one fed the 10³ cut here — some
/// eight million journal records for the chain read to verify — since a fed
/// board is never reopened (`board`'s doc) and the 10⁴ board's own history
/// is a half-hour feed per run.
#[test]
#[ignore = "timing test - gate-full only"]
fn the_save_paths_chain_at_beside_a_history_reader() {
    let Some(c) = corpus() else { return };
    let Some((fed, tier)) = units_of(&c, TIER_CUT_4) else { return };
    let board = DevBoard::spawn();
    let fed3 = board.feed(&cut_3(&c));
    board_note("10^3 (the live board)", &fed3);
    let (index, _) = build(fed.units);
    let doc = fed3.units[0].key().doc().clone();
    let extent = fed3.units[0].positions();
    // The widened range's older position: the claim's, where the journal still
    // reaches it, else the reclaim floor — the oldest position `/chain?at`
    // answers, whose verification walks the longest surviving journal.
    let claim_at = board
        .board_chain()
        .map(|_| board.board.board_term().expect("term").expect("H.1").log_position)
        .unwrap_or(0);
    let floor = board.reclaim_floor();
    let old_at = claim_at.max(floor);
    note(format!(
        "save path: the claim's position {claim_at}, the journal's reclaim floor {floor}; the older read at {old_at}"
    ));
    let board = Arc::new(board);

    // The saves and their chain reads ALONE first: the read's own latency,
    // the time it holds a reconstruction permit.
    let scratch_doc = board.create(None);
    let path = scratch("save-path.index");
    let mut saves = Sample::new();
    let mut chain_fresh = Sample::new();
    let mut chain_old = Sample::new();
    let mut save_and_read =
        |k: u64, chain_fresh: &mut Sample, chain_old: &mut Sample| -> (u64, u64) {
            let held = board.insert(&scratch_doc, 1, format!("save {k}").as_bytes());
            let t = Instant::now();
            let mut f = File::create(&path).expect("create");
            index.save(&header(board.board_chain(), at(held)), &mut f).expect("saved");
            saves.push(t.elapsed());
            let (mut answered, mut busy) = (0u64, 0u64);
            for (position, sample) in [(held, &mut *chain_fresh), (old_at, &mut *chain_old)] {
                let (status, chain, took) = board.chain_at(position);
                if status == 503 {
                    busy += 1;
                } else {
                    assert_eq!(status, 200, "/chain?at={position}");
                    assert!(chain.is_some());
                    answered += 1;
                    sample.push(took);
                }
            }
            (answered, busy)
        };
    let (mut alone_answered, mut alone_busy) = (0u64, 0u64);
    for k in 0..10u64 {
        let (a, b) = save_and_read(k, &mut chain_fresh, &mut chain_old);
        alone_answered += a;
        alone_busy += b;
    }

    // Then beside TWO history readers, each `/op-at` at a fresh position,
    // which materializes a world and holds one of the two permits.
    let fresh = board.insert(&scratch_doc, 1, b"the readers' position");
    let stop = Arc::new(AtomicBool::new(false));
    let reader_busy = Arc::new(AtomicU64::new(0));
    let reader_reads = Arc::new(AtomicU64::new(0));
    let reader_time = Arc::new(AtomicU64::new(0));
    let readers: Vec<_> = (0..2)
        .map(|_| {
            let (board, stop, busy, reads, time, doc) = (
                board.clone(),
                stop.clone(),
                reader_busy.clone(),
                reader_reads.clone(),
                reader_time.clone(),
                doc.clone(),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let t = Instant::now();
                    match board.op_at_retrieve(fresh, &doc, 1, extent) {
                        AtAnswer::Busy => {
                            busy.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {
                            reads.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    time.fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
                }
            })
        })
        .collect();
    let mut beside_fresh = Sample::new();
    let mut beside_old = Sample::new();
    let (mut beside_answered, mut beside_busy) = (0u64, 0u64);
    for k in 10..20u64 {
        let (a, b) = save_and_read(k, &mut beside_fresh, &mut beside_old);
        beside_answered += a;
        beside_busy += b;
    }
    stop.store(true, Ordering::Relaxed);
    for r in readers {
        r.join().expect("a reader");
    }
    let _ = std::fs::remove_file(&path);
    let reader_total = reader_reads.load(Ordering::Relaxed) + reader_busy.load(Ordering::Relaxed);
    reported(
        "save-path-chain-at",
        tier,
        format!(
            "alone: fresh position {}; the oldest answerable position (the surviving journal verified) {}; {alone_answered} answered, {alone_busy} history_busy over 10 saves",
            chain_fresh.summary(),
            chain_old.summary()
        ),
    )
    .print();
    reported(
        "save-path-chain-at-beside-readers",
        tier,
        format!(
            "beside 2 /op-at readers ({} reads answered, {} history_busy, {} mean a read): fresh position {}; the oldest answerable position {}; {beside_answered} answered, {beside_busy} history_busy over 10 saves; the saves {}",
            reader_reads.load(Ordering::Relaxed),
            reader_busy.load(Ordering::Relaxed),
            report::time(Duration::from_nanos(
                reader_time.load(Ordering::Relaxed) / reader_total.max(1)
            )),
            beside_fresh.summary(),
            beside_old.summary(),
            saves.summary()
        ),
    )
    .print();
}

// ── RANK ──────────────────────────────────────────────────────────────────

/// The rank row's queries: each with the record that is its right answer.
const RANK_QUERIES: [(&str, &str); 20] = [
    ("PUB-7.37", "_designs/PUB/spec/07-performance.md"),
    ("AUTH-5.55", "_designs/AUTH/spec/05-ceremonies.md"),
    ("REG-1.69", "_designs/REGISTRY/spec/01-model.md"),
    ("PUB-2.33", "_designs/PUB/spec/02-versions.md"),
    ("AUTH-6.38", "_designs/AUTH/spec/06-wire.md"),
    ("PUB-8.38", "_designs/PUB/spec/08-wire.md"),
    ("AUTH-4.57", "_designs/AUTH/spec/04-handshake.md"),
    ("PUB-6.65", "_designs/PUB/spec/06-enforcement.md"),
    ("AUTH-2.79", "_designs/AUTH/spec/02-fold.md"),
    ("PUB-5.115", "_designs/PUB/spec/05-grants.md"),
    ("\"the back-end-to-back-end protocol\"", "bebe.md"),
    ("\"images and video in the docuverse\"", "media.md"),
    ("\"private documents as unpublished documents\"", "publication.md"),
    ("\"the attacker-tier register\"", "_designs/CLIENT/tiers.md"),
    ("\"mechanism shapes, proven by reuse\"", "_designs/PATTERNS.md"),
    ("\"cross-cutting laws, proven by repetition\"", "_designs/DOCTRINE.md"),
    ("\"the project's terms, in plain words\"", "_designs/GLOSSARY.md"),
    ("\"empirical inputs to the design phase\"", "spikes/README.md"),
    ("\"the engine seam\"", "search.md"),
    ("\"the model the frontend teaches\"", "designs/foundations.md"),
];

/// §7.1 RANK — LONG-UNIT RANKING (S22 folded): over the records tier's
/// unsplit units of 1 KB–1 MB, twenty queries with known right answers —
/// ten rule ids, each the spec file that states it, ten record title
/// phrases, each its record — the RANK of the right document under BM25
/// b = 0.75 (the crate's), b = 0.3 and BM25+ δ = 1 (the last two rescored
/// in the suite from the hits' occurrences and the units' lengths), reported.
#[test]
#[ignore = "timing test - gate-full only"]
fn rank_long_unit_ranking_over_the_records_tier() {
    let Some(c) = corpus() else { return };
    let Some((fed, tier)) = units_of(&c, TIER_RECORDS) else { return };
    let keep: Vec<usize> =
        (0..fed.units.len()).filter(|&i| (1024..=MIB).contains(&fed.units[i].bytes())).collect();
    let units: Vec<Unit> = keep.iter().map(|&i| fed.units[i].clone()).collect();
    let names: Vec<&str> = keep.iter().map(|&i| fed.names[i].as_str()).collect();
    let by_doc: BTreeMap<Address, usize> =
        units.iter().enumerate().map(|(i, u)| (u.key().doc().clone(), i)).collect();
    let terms = Terms::of(&units);
    let n_units = units.len();
    let (index, _) = build(units);
    let published = Index::new(Class::Guest);
    let pair = session_pair(&published, &index);
    let avgdl = terms.avgdl();
    note(format!(
        "rank: {n_units} units of 1 KB–1 MB out of {} (avgdl {avgdl:.0} tokens)",
        fed.units.len()
    ));

    for (query_text, right) in RANK_QUERIES {
        let Some(right_i) = names.iter().position(|n| *n == right) else {
            reported(
                "rank",
                tier,
                format!("`{query_text}` → {right}: the record is outside 1 KB–1 MB"),
            )
            .print();
            continue;
        };
        let query = Query::parse(query_text);
        let t = Instant::now();
        let answer = Index::query(pair, &query, &QueryOpts { offset: 0, limit: n_units });
        let took = t.elapsed();
        // The query's idf as §3.3 scores it: a word's, or a phrase's words' summed.
        let words: Vec<&str> = query
            .forms()
            .iter()
            .flat_map(|f| match f {
                skep_search::Form::Word(w) | skep_search::Form::Prefix(w) => vec![w.term.as_str()],
                skep_search::Form::Phrase(ws) => ws.iter().map(|w| w.term.as_str()).collect(),
                skep_search::Form::PhrasePrefix { fixed, prefix } => {
                    fixed.iter().chain(std::iter::once(prefix)).map(|w| w.term.as_str()).collect()
                }
            })
            .collect();
        let idf: f64 = words
            .iter()
            .map(|w| rank::idf(n_units, terms.index_of(w).map_or(0, |i| terms.df[i])))
            .sum();
        let rescored = |b: f64, delta: f64| -> Vec<(f64, Address)> {
            let mut v: Vec<(f64, Address)> = answer
                .hits
                .iter()
                .map(|h| {
                    let dl = by_doc.get(&h.doc).map_or(0, |&i| terms.dl[i]) as f64;
                    let tf = h.occurrences as f64;
                    let score = idf
                        * (tf * (rank::K1 + 1.0)
                            / (tf + rank::K1 * (1.0 - b + b * dl / avgdl.max(1.0)))
                            + delta);
                    (score, h.doc.clone())
                })
                .collect();
            v.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
            v
        };
        let right_doc = Some(fed.units[keep[right_i]].key().doc().clone());
        let rank_in = |list: &[(f64, Address)]| -> String {
            right_doc
                .as_ref()
                .and_then(|d| list.iter().position(|(_, a)| a == d))
                .map_or("absent".to_string(), |p| (p + 1).to_string())
        };
        let crate_rank = right_doc
            .as_ref()
            .and_then(|d| answer.hits.iter().position(|h| &h.doc == d))
            .map_or("absent".to_string(), |p| (p + 1).to_string());
        let b03 = rescored(0.3, 0.0);
        let plus = rescored(rank::B, 1.0);
        let right_len = terms.dl[right_i];
        reported(
            "rank",
            tier,
            format!(
                "`{query_text}` → {right} ({} tokens, {:.1}x avgdl): rank {crate_rank} of {} under b=0.75; {} under b=0.3; {} under BM25+ δ=1; positions_bounded {}, more_terms {}; {}",
                right_len,
                right_len as f64 / avgdl.max(1.0),
                answer.total,
                rank_in(&b03),
                rank_in(&plus),
                answer.positions_bounded,
                answer.more_terms,
                report::time(took)
            ),
        )
        .print();
    }
}

// ── THE OTHER INTERIM PINS ────────────────────────────────────────────────

/// §7.1's paragraph, each pin stated with what the corpus shows of it at
/// 10⁴: the prefix minimum (1), the fuzzy edit distance (1), its minimum
/// length (5), its per-word cap, the three words, the snippet window (240
/// bytes either side), the compaction trigger (one eighth).
#[test]
#[ignore = "timing test - gate-full only"]
fn the_other_interim_pins_reported_against_the_corpus() {
    let Some(c) = corpus() else { return };
    let Some((fed, tier)) = units_of(&c, TIER_CUT_4) else { return };
    let terms = Terms::of(&fed.units);
    let paragraphs: Vec<usize> = fed
        .units
        .iter()
        .flat_map(|u| {
            u.items().iter().filter_map(|i| match i {
                Item::Text { bytes, .. } => Some(
                    String::from_utf8_lossy(bytes)
                        .split("\n\n")
                        .map(|p| p.len())
                        .collect::<Vec<_>>(),
                ),
                Item::Gap { .. } => None,
            })
        })
        .flatten()
        .collect();
    let (index, _) = build(fed.units);
    let published = Index::new(Class::Guest);
    let pair = session_pair(&published, &index);

    // The prefix minimum, 1 character.
    let letter = {
        let mut counts: BTreeMap<char, usize> = BTreeMap::new();
        for (i, t) in terms.terms.iter().enumerate() {
            if let Some(ch) = t.chars().next().filter(char::is_ascii_lowercase) {
                *counts.entry(ch).or_default() += terms.entries[i];
            }
        }
        counts.into_iter().max_by_key(|(_, n)| *n).map(|(c, _)| c).unwrap_or('t')
    };
    let under = terms.under(&letter.to_string());
    let (merged, taken, more) = terms.expansion(&letter.to_string(), EXPANSION_BOUND_ENTRIES);
    let (answer, took) = timed_query(pair, &letter.to_string());
    reported(
        "pin-prefix-minimum",
        tier,
        format!(
            "PREFIX_MIN_CHARS {PREFIX_MIN_CHARS}: the one-letter prefix `{letter}` has {} terms under it; the bound takes {taken} ({merged} entries, more_terms {more}); the answer total {} in {}, more_terms {}",
            under.len(),
            answer.total,
            report::time(took),
            answer.more_terms
        ),
    )
    .print();

    // The fuzzy edit distance, 1, and the minimum length, 5.
    let short = terms.terms.iter().filter(|t| t.chars().count() < FUZZY_MIN_CHARS).count();
    let samples = ["the", "board", "position", "document", "principal"];
    let mut detail = Vec::new();
    for base in samples {
        let word = misspelled(&terms, base);
        let candidates: Vec<usize> =
            (0..terms.terms.len()).filter(|&i| one_edit_apart(&word, &terms.terms[i])).collect();
        let entries: usize = candidates.iter().map(|&i| terms.entries[i]).sum();
        detail.push(format!(
            "`{word}`: {} terms within one edit holding {entries} entries",
            candidates.len()
        ));
    }
    reported(
        "pin-fuzzy-edit-distance-and-length",
        tier,
        format!(
            "one edit, FUZZY_MIN_CHARS {FUZZY_MIN_CHARS}: {short} of {} terms are shorter than five characters and never corrected; {}",
            terms.terms.len(),
            detail.join("; ")
        ),
    )
    .print();
    reported(
        "pin-fuzzy-per-word-cap",
        tier,
        format!("EXPANSION_BOUND_ENTRIES {EXPANSION_BOUND_ENTRIES} per fuzzy word, the same figure as the prefix expansion's; the samples above stay under it"),
    )
    .print();
    let sentence = twelve_non_terms(&terms);
    let (answer, took) = timed_query(pair, &sentence);
    reported(
        "pin-fuzzy-three-words",
        tier,
        format!(
            "FUZZY_WORDS {FUZZY_WORDS}: twelve complete non-terms → fuzzy_bounded {} in {}",
            answer.fuzzy_bounded,
            report::time(took)
        ),
    )
    .print();

    // The snippet window, 240 bytes either side.
    let mut sorted = paragraphs.clone();
    sorted.sort_unstable();
    let mut snippet_lengths = Vec::new();
    for word in ["board", "document", "position", "the", "client"] {
        let (answer, _) = timed_query(pair, &format!("{word} "));
        snippet_lengths
            .extend(answer.hits.iter().filter_map(|h| h.snippet.as_ref().map(|s| s.text.len())));
    }
    snippet_lengths.sort_unstable();
    reported(
        "pin-snippet-window",
        tier,
        format!(
            "SNIPPET_BOUND {SNIPPET_BOUND} bytes either side (a window of {}): the corpus's paragraphs median {} bytes, p90 {}, {}% longer than the window; {} snippets over five common words: median {} bytes, max {}",
            2 * SNIPPET_BOUND,
            sorted.get(sorted.len() / 2).copied().unwrap_or(0),
            sorted.get(sorted.len() * 9 / 10).copied().unwrap_or(0),
            100 * sorted.iter().filter(|&&p| p as u64 > 2 * SNIPPET_BOUND).count() / sorted.len().max(1),
            snippet_lengths.len(),
            snippet_lengths.get(snippet_lengths.len() / 2).copied().unwrap_or(0),
            snippet_lengths.last().copied().unwrap_or(0)
        ),
    )
    .print();

    // The compaction trigger, one eighth.
    let stats = index.stats();
    let per_draft = terms.dl.iter().max().copied().unwrap_or(0);
    reported(
        "pin-compaction-trigger",
        tier,
        format!(
            "one eighth of {} live postings = {} dead entries; a 10 KB draft of ~{per_draft} tokens re-indexed {} times reaches it",
            report::count(stats.postings as u64),
            report::count((stats.postings / 8) as u64),
            (stats.postings / 8) / per_draft.max(1)
        ),
    )
    .print();
}

// ── THE CEILING ───────────────────────────────────────────────────────────

/// §7.4 THE CEILING: `CEILING_BYTES` CONFIRMED where M1 (build, size), M5,
/// load and save HOLD over the records tier — the pinned ratios there, the
/// postings ≤ 1× the text, the file ≤ 2.5×, the resident set ≤ 2× the file;
/// the build, the load and the save reported against the 10⁴ pins for the
/// owner's eye — else MOVED DOWN to the largest tier where all do, the cuts'
/// tiers giving the curve, and the remedy §7.1 names reported.
#[test]
#[ignore = "timing test - gate-full only"]
fn the_ceiling_confirmed_or_moved_over_the_records_tier() {
    let Some(c) = corpus() else { return };
    let mut largest_holding: Option<(&str, u64)> = None;
    let mut records_holds = None;
    for (fed, tier) in tiers(&c) {
        let class = fed.units[0].class();
        let text = fed.bytes();
        let (index, built) = build(fed.units);
        let (file, save_time) = saved(&index);
        let postings = postings_bytes(&file);
        let path = scratch(&format!("ceiling-{}.index", tier.replace(['^', '(', ')'], "_")));
        std::fs::write(&path, &file).expect("the file");
        let (_, resident, load_time) = probe(&path, class);
        let _ = std::fs::remove_file(&path);
        let size_holds = postings <= text && (file.len() as u64) * 2 <= text * 5;
        let memory_holds = resident <= 2 * file.len() as u64;
        let holds = size_holds && memory_holds;
        judged(
            "ceiling-tier",
            tier,
            "postings <= 1x text, file <= 2.5x text, resident <= 2x file",
            format!(
                "text {}; postings {:.3}x; file {:.3}x; resident {:.3}x the file; build {} (10^4 pin 10 s), load {} (10^4 pin 500 ms), save {} (10^4 pin 1 s)",
                report::bytes(text),
                postings as f64 / text.max(1) as f64,
                file.len() as f64 / text.max(1) as f64,
                resident as f64 / file.len().max(1) as f64,
                report::time(built),
                report::time(load_time),
                report::time(save_time)
            ),
            holds,
        )
        .print();
        if holds {
            largest_holding = Some((tier, text));
        }
        if tier.starts_with(TIER_RECORDS) {
            records_holds = Some(holds);
        }
    }
    let verdict = match (records_holds, largest_holding) {
        (Some(true), _) => format!("CONFIRMED at {} ({}), the records tier's own size, where the pinned ratios hold", CEILING_BYTES, report::bytes(CEILING_BYTES)),
        (Some(false), Some((tier, text))) => format!(
            "MOVE DOWN: the records tier misses; the largest tier where every pinned ratio holds is {tier} at {} — the remedies §7.1 names ahead of any disk-backed index: the lazy stored text (the load row's), the cadence scaled to the file (the save row's)",
            report::bytes(text)
        ),
        (Some(false), None) => format!(
            "NO TIER HOLDS: the pinned ratio that misses misses at every tier measured, so the miss is the index's SHAPE and not its size, and no lower tier would hold it — the figure {} stands UNCONFIRMED at the records tier's size for the owner's decision, with §7.1's remedies ahead of any disk-backed index: the lazy stored text (the load row's), the cadence scaled to the file (the save row's), the compaction trigger tightened (M5's)",
            report::bytes(CEILING_BYTES)
        ),
        (None, _) => "the records tier was not in this run (SKEP_SEARCH_TIERS)".to_string(),
    };
    reported("ceiling-verdict", "-", verdict).print();
}
