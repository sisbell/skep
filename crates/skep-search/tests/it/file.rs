//! THE FILE at the public surface (`search.md` §5.1, §5.4; §8.3's file items,
//! one test each): a saved file loads whole with its header; a newer `v`
//! faced "written by a newer skep" and left untouched; an older tokenizer
//! revision migrated from its own stored text and saved under the running
//! revision so the next load migrates nothing; a newer one faced as a newer
//! `v` is; another class's file refused at `load(…, expected)` and moved
//! aside; the unknown member refused; a damaged body refused; a flipped
//! header digit refused as DAMAGED under the trailer and a header re-spelled
//! with a recomputed trailer refused the same; the aside's two spellings and
//! ordinal 2; and `load`'s order — `v`, the class, the tokenizer, the body.

use skep_search::header::{self, Parsed};
use skep_search::{
    aside_name, crc32c, Class, Grant, GrantKind, HeadRecord, Header, Index, LoadError, RangeRecord,
    Refusal, Revision, REVISION,
};

use crate::{addr, at, chain, text_unit};

fn guest(n: u32, text: &str) -> Index {
    let mut index = Index::new(Class::Guest);
    index.index(text_unit(Class::Guest, n, text.as_bytes())).expect("admitted");
    index
}

/// The board's one range and a granted document range, with the newest
/// head.
fn header() -> Header {
    Header {
        board: chain(0xB0),
        floor: Some(10),
        ranges: vec![
            RangeRecord {
                under: None,
                held: at(500, 0x11),
                refusals: Vec::new(),
                bare_rows: 0,
                grant: None,
            },
            RangeRecord {
                under: Some(addr(&[1, 0, 2, 0, 4])),
                held: at(480, 0x12),
                refusals: vec![Refusal {
                    doc: addr(&[1, 0, 2, 0, 4]),
                    reason: "withheld".to_string(),
                }],
                bare_rows: 1,
                grant: Some(Grant { kind: GrantKind::Named, issuer: addr(&[1, 0, 2]) }),
            },
        ],
        head: Some(HeadRecord { member: addr(&[1, 1, 0, 1, 0, 2, 4]), at: at(400, 0x22) }),
    }
}

fn save(index: &Index, header: &Header) -> Vec<u8> {
    let mut out = Vec::new();
    index.save(header, &mut out).expect("a Vec takes every write");
    out
}

fn load(file: &[u8], class: Class) -> Result<(Index, Header), LoadError> {
    Index::load(&mut &file[..], class)
}

/// The refusal `load` answers; a file that loads is the test's failure.
fn refused(file: &[u8], class: Class) -> LoadError {
    match load(file, class) {
        Err(refusal) => refusal,
        Ok(_) => panic!("the file loaded"),
    }
}

/// A saved file cut at its header line: the line and the body, the trailer
/// dropped.
fn cut(file: &[u8]) -> (Parsed, Vec<u8>) {
    let line_len = file.iter().position(|&b| b == b'\n').expect("a line") + 1;
    let parsed = header::parse(&file[..line_len]).expect("the one spelling");
    (parsed, file[line_len..file.len() - 4].to_vec())
}

/// A file from a header line and a body, under a fresh trailer over both.
fn file_of(line: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = line.to_vec();
    out.extend_from_slice(body);
    out.extend_from_slice(&crc32c(&out).to_le_bytes());
    out
}

fn terms(index: &Index) -> Vec<String> {
    index.terms().map(str::to_string).collect()
}

/// §1.4, §5.1: the whole index to one writer and back from one reader — the
/// header typed, the index's class, revision, terms and every statistic as
/// saved, and the file a fixed point under a second save.
#[test]
fn a_saved_file_loads_whole_with_its_header_and_a_second_save_writes_the_same_bytes() {
    let mut index = guest(1, "alpha beta");
    index.index(text_unit(Class::Guest, 2, b"gamma")).expect("admitted");
    index.index(text_unit(Class::Guest, 1, b"beta")).expect("replaced");
    let file = save(&index, &header());
    let (loaded, read) = load(&file, Class::Guest).expect("loads");
    assert_eq!(read, header());
    assert_eq!(loaded.class(), Class::Guest);
    assert_eq!(loaded.revision(), REVISION);
    assert_eq!(loaded.migrated_from(), None);
    assert_eq!(loaded.stats(), index.stats());
    assert_eq!(terms(&loaded), ["beta", "gamma"]);
    assert_eq!(save(&loaded, &read), file);
}

/// §5.1: a `v` above 1 is faced "written by a newer skep" and the crate
/// writes nothing in its place — whatever the rest of the line says, and
/// whatever class the file is opened as; the bytes are the shell's to leave.
#[test]
fn a_newer_v_is_faced_written_by_a_newer_skep_and_left_untouched() {
    let mut file = b"{\"type\":\"skep-index\",\"v\":2,\"custody\":\"keychain\"}\n".to_vec();
    file.extend_from_slice(b"a body this skep cannot read");
    let before = file.clone();
    assert_eq!(refused(&file, Class::Guest), LoadError::NewerVersion { v: 2 });
    assert_eq!(refused(&file, Class::Principal(1)), LoadError::NewerVersion { v: 2 });
    assert_eq!(file, before);
    assert_eq!(
        LoadError::NewerVersion { v: 2 }.to_string(),
        "this index was written by a newer skep than this one (v 2)"
    );
}

/// §5.1, §6: an older tokenizer revision is MIGRATED — re-indexed locally
/// from the file's own stored text, no board read, nothing lost — and the
/// migrated index saved under the running crate's revision so the next
/// `load` migrates nothing.
#[test]
fn an_older_tokenizer_revision_is_migrated_from_its_own_stored_text_and_saved_under_the_running_revision(
) {
    let index = guest(1, "Émile's café");
    let file = save(&index, &header());
    let (mut parsed, body) = cut(&file);
    let older = Revision { rule: REVISION.rule, unicode: (REVISION.unicode.0 - 1, 0, 0) };
    parsed.tokenizer = older;
    let old = file_of(&parsed.encode(), &body);
    let (migrated, read) = load(&old, Class::Guest).expect("migrated");
    assert_eq!(migrated.migrated_from(), Some(older));
    assert_eq!(migrated.revision(), REVISION);
    assert_eq!(terms(&migrated), ["cafe", "emile's"]);
    assert_eq!(migrated.stats(), index.stats());
    assert_eq!(read, header());
    let saved = save(&migrated, &read);
    assert_eq!(saved, file, "the running revision's bytes");
    let (again, _) = load(&saved, Class::Guest).expect("loads");
    assert_eq!(again.migrated_from(), None);
}

/// §5.1: a `tokenizer` revision NEWER than the running crate's is faced as a
/// newer `v` is — searched not, written not, never migrated down — the body
/// unread: one that would fail its trailer is not called damaged.
#[test]
fn a_newer_tokenizer_revision_is_faced_as_a_newer_v_is_and_never_migrated_down() {
    let file = save(&guest(1, "alpha"), &header());
    let (mut parsed, body) = cut(&file);
    let newer = Revision { rule: REVISION.rule + 1, unicode: REVISION.unicode };
    parsed.tokenizer = newer;
    let mut faced = file_of(&parsed.encode(), &body);
    let last = faced.len() - 1;
    faced[last] ^= 0xFF;
    assert_eq!(refused(&faced, Class::Guest), LoadError::NewerTokenizer { revision: newer });
}

/// §1.4, §5.4: another class's file is refused at `load(…, expected)`
/// before any query can run over it, both classes named — and the shell
/// moves it aside under its own board's chain.
#[test]
fn another_classs_file_is_refused_at_load_naming_both_and_moved_aside() {
    let mut supplement = Index::new(Class::Principal(3));
    supplement.index(text_unit(Class::Principal(3), 1, b"a draft")).expect("admitted");
    let file = save(&supplement, &header());
    let refusal = load(&file, Class::Principal(7)).unwrap_err();
    assert_eq!(
        refusal,
        LoadError::OtherClass { file: Class::Principal(3), expected: Class::Principal(7) }
    );
    assert_eq!(
        refusal.to_string(),
        "this is an index of class principal 3, opened where an index of class principal 7 was expected"
    );
    assert_eq!(
        refused(&save(&guest(1, "x"), &header()), Class::Principal(3)),
        LoadError::OtherClass { file: Class::Guest, expected: Class::Principal(3) }
    );
    assert_eq!(
        aside_name("principal-7.index", &header().board, 1),
        format!("principal-7.index.aside.{}.1", "b0".repeat(32))
    );
}

/// §5.1: an unknown member at the file's own `v` refuses the file by name,
/// a trailer recomputed over it notwithstanding.
#[test]
fn an_unknown_member_refuses_the_file() {
    let file = save(&guest(1, "alpha"), &header());
    let (parsed, body) = cut(&file);
    let line = String::from_utf8(parsed.encode()).expect("ASCII");
    let line = line.replacen("}\n", ",\"custody\":\"keychain\"}\n", 1);
    let extra = file_of(line.as_bytes(), &body);
    assert_eq!(
        refused(&extra, Class::Guest),
        LoadError::UnknownMember { name: "custody".to_string() }
    );
}

/// §5.1, §5.4: a damaged body — a flipped byte under the trailer, a section
/// that overruns its length under a recomputed one — is refused DAMAGED,
/// naming what, and is the shell's to rebuild.
#[test]
fn a_damaged_body_is_refused_as_damaged_naming_what() {
    let file = save(&guest(1, "alpha beta"), &header());
    let (parsed, body) = cut(&file);
    let mut flipped = file.clone();
    let inside = file.len() - 10;
    flipped[inside] ^= 0x01;
    match load(&flipped, Class::Guest) {
        Err(LoadError::Damaged { what }) => assert!(what.contains("the trailer"), "{what}"),
        other => panic!("{other:?}"),
    }
    // The first section's length prefix set past the body.
    let mut overrun = body.clone();
    overrun[0] = 0xFF;
    overrun.insert(1, 0x7F);
    let mut reset = parsed.clone();
    reset.body = overrun.len() as u64;
    match load(&file_of(&reset.encode(), &overrun), Class::Guest) {
        Err(LoadError::Damaged { what }) => {
            assert_eq!(what, "the `ranges` section: it overruns the body")
        }
        other => panic!("{other:?}"),
    }
}

/// §5.1: the CRC-32C covers the HEADER LINE's bytes, its `\n` included, so a
/// flipped digit in `floor` is DAMAGED and never loaded as written.
#[test]
fn a_flipped_header_digit_is_refused_as_damaged_under_the_trailer() {
    let file = save(&guest(1, "alpha"), &header());
    let line_len = file.iter().position(|&b| b == b'\n').expect("a line") + 1;
    let line = String::from_utf8(file[..line_len].to_vec()).expect("ASCII");
    let mut flipped = line.replacen("\"floor\":10,", "\"floor\":11,", 1).into_bytes();
    flipped.extend_from_slice(&file[line_len..]);
    assert_eq!(flipped.len(), file.len());
    match load(&flipped, Class::Guest) {
        Err(LoadError::Damaged { what }) => assert!(what.contains("the trailer"), "{what}"),
        other => panic!("{other:?}"),
    }
}

/// §5.1: a header re-spelled with a RECOMPUTED trailer is refused the same,
/// canonical bytes alone admitted — the key file's lenient read is not this
/// file's.
#[test]
fn a_header_re_spelled_with_a_recomputed_trailer_is_refused_the_same() {
    let file = save(&guest(1, "alpha"), &header());
    let (parsed, body) = cut(&file);
    let canonical = String::from_utf8(parsed.encode()).expect("ASCII");
    for respelled in [
        canonical.replacen(",\"v\":1,", ", \"v\":1,", 1),
        canonical.replacen(
            "{\"type\":\"skep-index\",\"v\":1,",
            "{\"v\":1,\"type\":\"skep-index\",",
            1,
        ),
        canonical.replacen("}\n", "}\r\n", 1),
        canonical.replacen("\"floor\":10", "\"floor\":1e1", 1),
    ] {
        assert_ne!(respelled, canonical);
        match load(&file_of(respelled.as_bytes(), &body), Class::Guest) {
            Err(LoadError::Damaged { what }) => {
                assert!(what.starts_with("the header line"), "{respelled}: {what}")
            }
            other => panic!("{respelled}: {other:?}"),
        }
    }
}

/// §5.4: the aside — `published.index.aside.<64 hex>.1`,
/// `principal-<n>.index.aside.<64 hex>.1`, a second mismatch landing at
/// ordinal 2 — spelled under the misplaced file's OWN board's chain, which
/// `load` hands back in its header.
#[test]
fn the_aside_is_spelled_under_the_files_own_chain_and_a_second_mismatch_lands_at_ordinal_2() {
    let misplaced = save(&guest(1, "alpha"), &header());
    let (_, read) = load(&misplaced, Class::Guest).expect("CRC-valid");
    let own = read.board;
    assert_ne!(own, chain(0xC0), "another board's");
    let hex = "b0".repeat(32);
    assert_eq!(aside_name("published.index", &own, 1), format!("published.index.aside.{hex}.1"));
    assert_eq!(
        aside_name("principal-3.index", &own, 1),
        format!("principal-3.index.aside.{hex}.1")
    );
    assert_eq!(aside_name("published.index", &own, 2), format!("published.index.aside.{hex}.2"));
}

/// §5.1, §5.4 `load`'s ORDER: the version first, then the class, then the
/// tokenizer, then the body — each later check unreached while an earlier
/// one refuses.
#[test]
fn loads_order_is_v_then_the_class_then_the_tokenizer_then_the_body() {
    let file = save(&guest(1, "alpha"), &header());
    let (parsed, body) = cut(&file);
    let newer = Revision { rule: REVISION.rule + 1, unicode: REVISION.unicode };
    let mut torn = body.clone();
    torn[0] ^= 0xFF;

    // (a) A newer `v`, another class, a newer tokenizer and a torn body.
    let mut all = b"{\"type\":\"skep-index\",\"v\":2}\n".to_vec();
    all.extend_from_slice(&torn);
    assert_eq!(refused(&all, Class::Principal(3)), LoadError::NewerVersion { v: 2 });

    // (b) `v` 1, another class, a newer tokenizer, a torn body.
    let mut other = parsed.clone();
    other.tokenizer = newer;
    let mut faced = other.encode();
    faced.extend_from_slice(&torn);
    faced.extend_from_slice(&[0; 4]);
    assert_eq!(
        refused(&faced, Class::Principal(3)),
        LoadError::OtherClass { file: Class::Guest, expected: Class::Principal(3) }
    );

    // (c) The class right, a newer tokenizer, a torn body.
    assert_eq!(refused(&faced, Class::Guest), LoadError::NewerTokenizer { revision: newer });

    // (d) The class and the tokenizer right: the torn body is damaged.
    let mut damaged = parsed.encode();
    damaged.extend_from_slice(&torn);
    damaged.extend_from_slice(&[0; 4]);
    assert!(matches!(load(&damaged, Class::Guest), Err(LoadError::Damaged { .. })));

    // (e) Everything right: the file loads.
    let (index, _) = load(&file, Class::Guest).expect("loads");
    assert_eq!(index.stats().units, 1);
}
