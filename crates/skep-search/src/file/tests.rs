//! The file's fence (`search.md` §5.1, §5.4; PATTERNS P22, P35, P38): the
//! CRC-32C check value; the varint and address codecs; the layout as landed
//! — the header line, the seven length-prefixed sections, the trailer; the
//! round trip and the file as a fixed point; THE TRAILER COVERS THE HEADER
//! LINE (a flipped digit in `floor` or in a range's `held` is DAMAGED — a
//! test that fails if the CRC skips the header); NEVER MIGRATED DOWN (a
//! newer tokenizer is faced with the body unread); the class judged before
//! the body; the MIGRATION round trip; a damaged body named by section;
//! `seen` and the tombstones surviving a save; the aside's spelling; the
//! faces' facts; a failing writer or reader.

use std::io;

use super::*;
use crate::index::Stats;

const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn addr(comps: &[u32]) -> Address {
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
    validate(t).expect("a T4-valid address")
}

/// The document `1.0.1.0.n`.
fn key(n: u32) -> UnitKey {
    UnitKey::new(addr(&[1, 0, 1, 0, n]))
}

fn text(start: u64, bytes: &[u8]) -> Item {
    Item::Text { start, bytes: bytes.to_vec() }
}

/// A unit of one text item at ordinal 1.
fn unit(class: Class, n: u32, s: &str) -> Unit {
    Unit::new(key(n), None, Kind::Edition, class, 1, vec![text(1, s.as_bytes())])
        .expect("one extent")
}

fn guest(n: u32, s: &str) -> Unit {
    unit(Class::Guest, n, s)
}

fn chain(fill: u8) -> Chain {
    Chain::from_bytes([fill; 32])
}

fn at(position: u64, fill: u8) -> ChainAt {
    ChainAt { position, chain: chain(fill) }
}

/// A header carrying every kind of member: two ranges — the board's and a
/// granted account prefix with two refusals and three bare rows — and the
/// newest head.
fn rich_header() -> Header {
    Header {
        board: Chain::parse(HEX).expect("hex"),
        floor: Some(2048),
        ranges: vec![
            RangeRecord {
                under: None,
                held: at(4096, 0x11),
                refusals: Vec::new(),
                bare_rows: 0,
                grant: None,
            },
            RangeRecord {
                under: Some(addr(&[1, 0, 2])),
                held: at(4100, 0x12),
                refusals: vec![
                    Refusal { doc: addr(&[1, 0, 2, 0, 5]), reason: "withheld".to_string() },
                    Refusal { doc: addr(&[1, 0, 2, 0, 6]), reason: "too_many_items".to_string() },
                ],
                bare_rows: 3,
                grant: Some(Grant { kind: GrantKind::AnyPrincipal, issuer: addr(&[1, 0, 2]) }),
            },
        ],
        head: Some(HeadRecord { member: addr(&[1, 1, 0, 1, 0, 2, 9]), at: at(4000, 0x22) }),
    }
}

fn plain_header() -> Header {
    Header { board: chain(0xB0), floor: Some(10), ranges: Vec::new(), head: None }
}

/// An index of three guest units — one with a gap, a hex stretch and a
/// member — and one replacement, so a tombstone and a dead-only term stand.
fn sample() -> Index {
    let mut index = Index::new(Class::Guest);
    index.index(guest(1, "alpha beta gamma")).expect("admitted");
    let items = vec![
        text(1, b"delta beta"),
        Item::Gap {
            start: 11,
            width: 5,
            kind: GapKind::Withheld { origin: addr(&[1, 0, 1, 0, 9]) },
        },
        text(16, b"eps\xFFilon alpha"),
    ];
    let edition =
        Unit::new(key(2), Some(addr(&[1, 0, 1, 0, 2, 3])), Kind::Edition, Class::Guest, 7, items)
            .expect("one extent");
    index.index(edition).expect("admitted");
    index.index(guest(3, "zeta")).expect("admitted");
    index.index(guest(1, "beta omega")).expect("the replacement: gamma dies with unit 1");
    index
}

fn save(index: &Index, header: &Header) -> Vec<u8> {
    let mut out = Vec::new();
    index.save(header, &mut out).expect("a Vec takes every write");
    out
}

fn load(bytes: &[u8], class: Class) -> Result<(Index, Header), LoadError> {
    Index::load(&mut &bytes[..], class)
}

/// The refusal `load` answers; a file that loads is the test's failure.
fn refused(file: &[u8], class: Class) -> LoadError {
    match load(file, class) {
        Err(refusal) => refusal,
        Ok(_) => panic!("the file loaded"),
    }
}

/// A saved file cut into its header line and its seven sections.
fn split(file: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let line_len = file.iter().position(|&b| b == b'\n').expect("a line") + 1;
    let parsed = header::parse(&file[..line_len]).expect("canonical");
    let body = &file[line_len..line_len + parsed.body as usize];
    let mut r = Reader::new("body", body);
    let sections = (0..7).map(|_| r.bytes().expect("a section").to_vec()).collect();
    r.done().expect("seven sections");
    (file[..line_len].to_vec(), sections)
}

fn with_trailer(line: Vec<u8>, body: Vec<u8>) -> Vec<u8> {
    let trailer = extend(crc32c(&line), &body).to_le_bytes();
    let mut out = line;
    out.extend_from_slice(&body);
    out.extend_from_slice(&trailer);
    out
}

/// The file rebuilt from a header line's facts and sections, `body` re-set
/// and the trailer recomputed.
fn rebuild(line: &[u8], sections: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for section in sections {
        put_bytes(&mut body, section);
    }
    let mut parsed = header::parse(line).expect("canonical");
    parsed.body = body.len() as u64;
    with_trailer(parsed.encode(), body)
}

/// The same file under another header line, the trailer recomputed.
fn reheaded(file: &[u8], change: impl FnOnce(&mut header::Parsed)) -> Vec<u8> {
    let (line, sections) = split(file);
    let mut body = Vec::new();
    for section in &sections {
        put_bytes(&mut body, section);
    }
    let mut parsed = header::parse(&line).expect("canonical");
    change(&mut parsed);
    with_trailer(parsed.encode(), body)
}

/// The live postings of `term`: `(key, occurrences)` per live unit.
fn postings_of(index: &Index, term: &str) -> Vec<(UnitKey, Vec<Occurrence>)> {
    let Some(&id) = index.body.dictionary.get(term) else {
        return Vec::new();
    };
    index.body.terms[id]
        .postings
        .iter()
        .filter_map(|p| match &index.body.units[p.unit] {
            Record::Live { unit, .. } => Some((unit.key().clone(), p.occurrences.clone())),
            Record::Dead => None,
        })
        .collect()
}

fn terms(index: &Index) -> Vec<String> {
    index.terms().map(str::to_string).collect()
}

fn damaged_what(result: Result<(Index, Header), LoadError>) -> String {
    match result {
        Err(LoadError::Damaged { what }) => what,
        other => panic!("not Damaged: {other:?}"),
    }
}

/// §5.1: the trailer is CRC-32C, Castagnoli — the standard check value over
/// `123456789`, the empty input's zero, and the extension that lets the
/// header line and the body be covered as one.
#[test]
fn crc32c_of_the_check_string_is_the_standard_check_value() {
    assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    assert_eq!(crc32c(b""), 0);
    assert_eq!(extend(crc32c(b"1234"), b"56789"), 0xE306_9283);
    assert_eq!(extend(crc32c(b""), b"123456789"), 0xE306_9283);
    assert_ne!(crc32c(b"123456788"), 0xE306_9283);
    assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA, "the 32 zero bytes' known value");
}

/// The varint codec: every value round-trips in its one spelling; an
/// overlong, an overflowing and a cut-short varint are damage by name.
#[test]
fn varints_round_trip_and_an_overlong_or_overflowing_one_is_refused() {
    for value in [0, 1, 127, 128, 300, 16_383, 16_384, u64::from(u32::MAX), u64::MAX] {
        let mut bytes = Vec::new();
        put_varint(&mut bytes, value);
        let mut r = Reader::new("x", &bytes);
        assert_eq!(r.varint(), Ok(value));
        r.done().expect("consumed whole");
    }
    let mut max = Vec::new();
    put_varint(&mut max, u64::MAX);
    assert_eq!(max.len(), 10);
    let refused = |bytes: &[u8], fault: &str| {
        let what = match Reader::new("x", bytes).varint() {
            Err(LoadError::Damaged { what }) => what,
            other => panic!("not Damaged: {other:?}"),
        };
        assert!(what.contains(fault), "{what}");
    };
    refused(&[0x80, 0x00], "overlong");
    refused(&[0xFF, 0x80, 0x00], "overlong");
    refused(&[0xFF; 11], "overflows");
    refused(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02], "overflows");
    refused(&[0x80], "overruns");
    refused(&[], "overruns");
}

/// An address round-trips through the body — a component past `u64`
/// included — and a component in another spelling, an address of no
/// components and one that is not T4-valid are damage.
#[test]
fn an_address_round_trips_through_the_body_and_a_non_canonical_component_is_refused() {
    let big = Nat::parse_bytes(b"123456789012345678901234567890123456789", 10).expect("decimal");
    let wide = validate(Tumbler::new([Nat::from(1u32), Nat::from(0u32), big]).expect("nonempty"))
        .expect("an account address");
    for address in [addr(&[1, 0, 1, 0, 5]), addr(&[1, 1, 0, 1, 0, 2, 9]), wide] {
        let mut bytes = Vec::new();
        put_address(&mut bytes, &address);
        let mut r = Reader::new("x", &bytes);
        assert_eq!(r.address(), Ok(address));
        r.done().expect("consumed whole");
    }
    let refused = |bytes: &[u8], fault: &str| {
        let what = match Reader::new("x", bytes).address() {
            Err(LoadError::Damaged { what }) => what,
            other => panic!("not Damaged: {other:?}"),
        };
        assert!(what.contains(fault), "{what}");
    };
    // `1.0.1` with the last component spelled as two bytes `[1, 0]`.
    refused(&[3, 1, 1, 1, 0, 2, 1, 0], "one spelling");
    // `1.0.1` with the first component spelled as no bytes.
    refused(&[3, 0, 1, 0, 1, 1], "one spelling");
    refused(&[0], "no components");
    // `0.0.1`: a leading zero is no address.
    refused(&[3, 1, 0, 1, 0, 1, 1], "T4-valid");
}

/// §5.1 THE LAYOUT as landed: the header line in its one spelling, its
/// `body` the body's length; seven sections, each length-prefixed, in the
/// module doc's order — `seen` in its own, the dictionary sorted and holding
/// the dead-only term; the trailer the CRC-32C over the line and the body.
#[test]
fn save_writes_the_header_line_the_seven_sections_and_the_trailer() {
    let mut index = Index::with_ceiling(Class::Guest, 40);
    index.index(guest(1, "alpha beta gamma")).expect("16 of 40");
    index.index(guest(1, "beta omega")).expect("replaced: gamma dies");
    assert!(index.index(guest(2, "a unit too long for the ceiling here")).is_err());
    assert_eq!(index.stats().seen, 1);
    let file = save(&index, &rich_header());

    let line_len = file.iter().position(|&b| b == b'\n').expect("a line") + 1;
    let line = &file[..line_len];
    let parsed = header::parse(line).expect("the one spelling");
    assert_eq!(parsed.board, rich_header().board);
    assert_eq!(parsed.class, Class::Guest);
    assert_eq!(parsed.floor, Some(2048));
    assert_eq!(parsed.tokenizer, REVISION);
    assert_eq!(
        parsed.body as usize,
        file.len() - line_len - TRAILER_LEN,
        "`body` names the body alone"
    );

    let (_, sections) = split(&file);
    assert_eq!(sections.len(), 7);
    let framed: usize = sections
        .iter()
        .map(|s| {
            let mut prefix = Vec::new();
            put_varint(&mut prefix, s.len() as u64);
            prefix.len() + s.len()
        })
        .sum();
    assert_eq!(framed, parsed.body as usize, "every section is one varint length and its bytes");
    let mut seen = Reader::new("seen", &sections[2]);
    assert_eq!(seen.varint(), Ok(1));
    seen.done().expect("the count alone");
    let mut dictionary = Reader::new("dictionary", &sections[3]);
    assert_eq!(dictionary.varint(), Ok(4));
    let listed: Vec<String> = (0..4).map(|_| dictionary.string().expect("a term")).collect();
    assert_eq!(listed, ["alpha", "beta", "gamma", "omega"], "sorted; the dead-only term resident");
    assert_eq!(terms(&index), ["beta", "omega"]);
    let mut units = Reader::new("units", &sections[4]);
    assert_eq!(units.varint(), Ok(2), "the tombstone and the live record");
    assert_eq!(units.byte(), Ok(0), "the tombstone first");
    assert_eq!(units.byte(), Ok(1));
    let mut counts = Reader::new("counts", &sections[6]);
    let read: Vec<u64> = (0..6).map(|_| counts.varint().expect("a count")).collect();
    assert_eq!(read, [1, 2, 2, 10, 1, 3]);
    counts.done().expect("six counts");

    let body = &file[line_len..file.len() - TRAILER_LEN];
    let trailer = u32::from_le_bytes(file[file.len() - TRAILER_LEN..].try_into().expect("four"));
    assert_eq!(trailer, extend(crc32c(line), body));
    assert_eq!(
        trailer,
        crc32c(&file[..file.len() - TRAILER_LEN]),
        "over the line and the body as one"
    );
}

/// §1.4, §5.1: `load(save(index, header))` is the index and the header —
/// the class, the revision, every statistic, the dictionary with its
/// dead-only term, every live posting with its ordinals and ranges, the
/// member and the items of a unit, `seen` — nothing migrated; and the file
/// is a fixed point: a second save writes the same bytes.
#[test]
fn load_of_save_round_trips_the_index_and_the_header_and_the_file_is_a_fixed_point() {
    let index = sample();
    let header = rich_header();
    let file = save(&index, &header);
    let (loaded, read) = load(&file, Class::Guest).expect("the file loads");
    assert_eq!(read, header);
    assert_eq!(loaded.class(), Class::Guest);
    assert_eq!(loaded.revision(), REVISION);
    assert_eq!(loaded.migrated_from(), None);
    assert_eq!(loaded.stats(), index.stats());
    assert_eq!(terms(&loaded), terms(&index));
    let dictionary: Vec<&String> = loaded.body.dictionary.keys().collect();
    assert_eq!(dictionary, index.body.dictionary.keys().collect::<Vec<_>>());
    for term in index.body.dictionary.keys() {
        assert_eq!(postings_of(&loaded, term), postings_of(&index, term), "{term}");
    }
    assert_eq!(loaded.body.keys, index.body.keys);
    let Record::Live { unit, .. } = &loaded.body.units[1] else { panic!("unit 2 is live") };
    assert_eq!(unit.member(), Some(&addr(&[1, 0, 1, 0, 2, 3])));
    assert_eq!(unit.as_of(), 7);
    assert_eq!(unit.items().len(), 3);
    assert_eq!(unit.item_at(12), Some(1), "the withheld run, at its width");
    assert!(matches!(loaded.body.units[0], Record::Dead));
    assert_eq!(save(&loaded, &read), file, "a fixed point");
    let mut compacted = loaded.clone();
    let built = compacted.compacted();
    compacted.install(built);
    assert_eq!(compacted.stats(), Stats { tombstones: 0, dead_postings: 0, ..index.stats() });
    assert_eq!(terms(&compacted), terms(&index));
}

/// §5.1 THE TRAILER COVERS THE HEADER LINE: a flipped digit in `floor`, and
/// a flipped byte in a range's `held`, are DAMAGED under the trailer — never
/// loaded as written — and a header re-spelled with a RECOMPUTED trailer is
/// damaged the same, canonical bytes alone admitted. Start the CRC after the
/// header and the first case loads as written: this test fails.
#[test]
fn the_trailer_covers_the_header_line_a_flipped_digit_in_floor_or_held_is_damaged() {
    let index = sample();
    let file = save(&index, &rich_header());
    assert!(load(&file, Class::Guest).is_ok());

    let line_len = file.iter().position(|&b| b == b'\n').expect("a line") + 1;
    let line = String::from_utf8(file[..line_len].to_vec()).expect("ASCII");
    let mut flipped = line.replacen("\"floor\":2048", "\"floor\":2049", 1).into_bytes();
    flipped.extend_from_slice(&file[line_len..]);
    assert_eq!(flipped.len(), file.len());
    assert!(header::parse(&flipped[..line_len]).is_ok(), "canonical still, one digit off");
    assert!(damaged_what(load(&flipped, Class::Guest)).contains("the trailer"), "`floor`");

    let mut held = file.clone();
    let at = held.windows(32).position(|w| w == [0x11; 32]).expect("the first range's chain");
    held[at + 5] ^= 0x01;
    assert!(damaged_what(load(&held, Class::Guest)).contains("the trailer"), "`held`");

    let mut position = file.clone();
    position[at - 2] ^= 0x01;
    assert!(
        damaged_what(load(&position, Class::Guest)).contains("the trailer"),
        "`held`'s position"
    );

    let (line, sections) = split(&file);
    let spaced = String::from_utf8_lossy(&line).replacen(",\"v\":1,", ", \"v\":1,", 1).into_bytes();
    let mut body = Vec::new();
    for section in &sections {
        put_bytes(&mut body, section);
    }
    let recomputed = with_trailer(spaced, body);
    let what = damaged_what(load(&recomputed, Class::Guest));
    assert!(what.contains("the header line"), "{what}");
    assert!(!what.contains("trailer"), "the trailer agrees; the spelling refuses: {what}");
}

/// §5.1 NEVER MIGRATED DOWN: a `tokenizer` revision newer than the running
/// crate's — a newer rule, a newer Unicode version — is FACED with the body
/// unread: a body that would fail its trailer is not reported damaged behind
/// it. Judge the trailer first and this test fails.
#[test]
fn a_newer_tokenizer_is_faced_with_the_body_unread() {
    for revision in [
        Revision { rule: REVISION.rule + 1, unicode: REVISION.unicode },
        Revision { rule: REVISION.rule, unicode: (REVISION.unicode.0 + 1, 0, 0) },
        Revision { rule: REVISION.rule, unicode: (REVISION.unicode.0, REVISION.unicode.1 + 1, 0) },
        Revision { rule: REVISION.rule + 1, unicode: (1, 0, 0) },
    ] {
        let line = header::encode(&plain_header(), Class::Guest, revision, 5);
        let mut file = line;
        file.extend_from_slice(b"junk!");
        file.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            refused(&file, Class::Guest),
            LoadError::NewerTokenizer { revision },
            "{revision}"
        );
    }
    assert!(!newer(REVISION));
    assert!(!newer(Revision { rule: REVISION.rule, unicode: (REVISION.unicode.0 - 1, 9, 9) }));
}

/// §5.1 `v` FIRST at `load`: a newer `v` is faced before the class, the
/// tokenizer and the body are judged.
#[test]
fn a_newer_v_is_faced_before_the_class_and_the_body() {
    let mut file =
        b"{\"type\":\"skep-index\",\"v\":2,\"kind\":\"supplement\",\"principal\":3}\n".to_vec();
    file.extend_from_slice(b"no body of ours");
    assert_eq!(refused(&file, Class::Guest), LoadError::NewerVersion { v: 2 });
    assert_eq!(refused(&file, Class::Principal(3)), LoadError::NewerVersion { v: 2 });
}

/// §5.4 THE CLASS MISMATCH IS JUDGED BEFORE THE BODY: another class's file
/// is `OtherClass`, both named — a published file opened as a supplement, a
/// supplement opened as the published index or as another principal's —
/// even where its body is damaged.
#[test]
fn another_classs_file_is_other_class_before_its_body_is_read() {
    let published = save(&sample(), &plain_header());
    assert_eq!(
        refused(&published, Class::Principal(3)),
        LoadError::OtherClass { file: Class::Guest, expected: Class::Principal(3) }
    );
    let mut supplement = Index::new(Class::Principal(3));
    supplement.index(unit(Class::Principal(3), 1, "a draft")).expect("admitted");
    let file = save(&supplement, &plain_header());
    assert_eq!(
        refused(&file, Class::Principal(7)),
        LoadError::OtherClass { file: Class::Principal(3), expected: Class::Principal(7) }
    );
    assert_eq!(
        refused(&file, Class::Guest),
        LoadError::OtherClass { file: Class::Principal(3), expected: Class::Guest }
    );
    let mut torn = file.clone();
    let last = torn.len() - 1;
    torn[last] ^= 0xFF;
    assert!(matches!(load(&torn, Class::Principal(3)), Err(LoadError::Damaged { .. })));
    assert_eq!(
        refused(&torn, Class::Principal(7)),
        LoadError::OtherClass { file: Class::Principal(3), expected: Class::Principal(7) },
        "the class before the body"
    );
    assert!(load(&file, Class::Principal(3)).is_ok());
}

/// §5.1 MIGRATION ROUND-TRIP: a file cut under an OLDER tokenizer revision
/// loads MIGRATED — every live unit re-tokenized from its STORED TEXT under
/// the running revision, the file's own postings discarded (a term the text
/// never held is gone), the tombstones with them, the header kept, the
/// result at `REVISION` and tagged `migrated_from` — and `load(save(…))` of
/// it migrates nothing and writes the same bytes a fresh index would.
#[test]
fn an_older_tokenizer_revision_is_migrated_from_the_stored_text_and_the_round_trip_migrates_nothing(
) {
    let mut stale = sample();
    // Postings an older rule would have cut: a term the text never held,
    // written consistently so the file passes every structural check.
    let id = stale.body.terms.len();
    stale.body.dictionary.insert("zzzz".to_string(), id);
    stale.body.terms.push(TermEntry {
        postings: vec![Posting {
            unit: 1,
            occurrences: vec![Occurrence { ordinal: 0, offset: 0, len: 4 }],
        }],
        live_units: 1,
    });
    let Record::Live { terms, entries, .. } = &mut stale.body.units[1] else { panic!("live") };
    terms.push(id);
    *entries += 1;
    stale.body.counts.terms += 1;
    stale.body.counts.postings += 1;
    assert!(terms_of(&stale).contains(&"zzzz".to_string()));

    let header = rich_header();
    let current = save(&stale, &header);
    assert!(load(&current, Class::Guest).is_ok(), "consistent as written");
    for older in [
        Revision { rule: REVISION.rule, unicode: (REVISION.unicode.0 - 1, 0, 0) },
        Revision { rule: REVISION.rule - 1, unicode: REVISION.unicode },
        Revision { rule: REVISION.rule - 1, unicode: (REVISION.unicode.0 + 5, 0, 0) },
    ] {
        let old = reheaded(&current, |parsed| parsed.tokenizer = older);
        let (migrated, read) = load(&old, Class::Guest).expect("migrated, not refused");
        assert_eq!(read, header, "the header kept");
        assert_eq!(migrated.migrated_from(), Some(older));
        assert_eq!(migrated.revision(), REVISION);
        assert_eq!(migrated.class(), Class::Guest);
        let fresh = {
            let mut fresh = Index::new(Class::Guest);
            fresh.install(sample().compacted());
            fresh
        };
        assert_eq!(terms_of(&migrated), terms_of(&fresh), "cut from the stored text");
        assert!(!migrated.body.dictionary.contains_key("zzzz"));
        assert_eq!(migrated.stats(), fresh.stats(), "the tombstone has no text and is dropped");
        for term in fresh.body.dictionary.keys() {
            assert_eq!(postings_of(&migrated, term), postings_of(&fresh, term), "{term}");
        }
        let saved = save(&migrated, &read);
        assert_eq!(saved, save(&fresh, &header), "saved under the running revision");
        let (again, _) = load(&saved, Class::Guest).expect("loads");
        assert_eq!(again.migrated_from(), None, "the next load migrates nothing");
        assert_eq!(again.revision(), REVISION);
        assert_eq!(terms_of(&again), terms_of(&fresh));
    }
}

fn terms_of(index: &Index) -> Vec<String> {
    terms(index)
}

/// §5.1 DAMAGED, by name: a section that overruns the body, a section that
/// underruns its length, a body shorter or longer than the header's `body`,
/// a dictionary out of order, a term id past the dictionary, a unit id past
/// the records, two live units under one key, a term list or the counts
/// that disagree with the postings, a unit of another class, an item of no
/// known kind, an extent that is not one.
#[test]
fn a_damaged_body_is_damaged_by_name() {
    let file = save(&sample(), &rich_header());
    let (line, sections) = split(&file);
    let variant = |change: &dyn Fn(&mut Vec<Vec<u8>>)| {
        let mut sections = sections.clone();
        change(&mut sections);
        rebuild(&line, &sections)
    };
    let what = |file: &[u8]| damaged_what(load(file, Class::Guest));

    let mut truncated = file.clone();
    truncated.truncate(file.len() - 1);
    assert!(what(&truncated).contains("overrun the file"), "{}", what(&truncated));
    let mut longer = file.clone();
    longer.push(0);
    assert!(what(&longer).contains("past the trailer"), "{}", what(&longer));

    // The ranges section's length prefix past the body: `rebuild` frames
    // sections, so the overrun is made by hand under a fresh trailer.
    let mut body = Vec::new();
    put_varint(&mut body, 200);
    body.extend_from_slice(&sections[0]);
    let mut parsed = header::parse(&line).expect("canonical");
    parsed.body = body.len() as u64;
    let overrun = with_trailer(parsed.encode(), body);
    assert_eq!(what(&overrun), "the `ranges` section: it overruns the body");

    let underrun = variant(&|s| s[2].push(0));
    assert_eq!(
        what(&underrun),
        "the `seen` section: it underruns its length: bytes stand past its last member"
    );
    let eighth = variant(&|s| s.push(vec![0]));
    assert!(what(&eighth).contains("the `body` section: it underruns"), "{}", what(&eighth));
    let six = variant(&|s| {
        s.pop();
    });
    assert_eq!(what(&six), "the `counts` section: it overruns the body");

    let unsorted = variant(&|s| {
        let mut d = Vec::new();
        put_varint(&mut d, 2);
        put_bytes(&mut d, b"beta");
        put_bytes(&mut d, b"alpha");
        s[3] = d;
    });
    assert_eq!(what(&unsorted), "the `dictionary` section: a term out of the sorted order");

    let fewer_terms = variant(&|s| {
        let mut d = Vec::new();
        put_varint(&mut d, 1);
        put_bytes(&mut d, b"alpha");
        s[3] = d;
    });
    assert!(what(&fewer_terms).contains("a term id past the dictionary"), "{}", what(&fewer_terms));

    let no_units = variant(&|s| s[4] = vec![0]);
    assert_eq!(what(&no_units), "the `postings` section: a unit id past the unit records");

    let counts = variant(&|s| {
        let mut c = Vec::new();
        for n in [9u64, 9, 9, 9, 9, 9] {
            put_varint(&mut c, n);
        }
        s[6] = c;
    });
    assert_eq!(what(&counts), "the `counts` section: it disagrees with the units and the postings");

    // Unit records cut by hand: a `units` section of two live records under
    // one key, of a unit of another class, of a term list the postings do
    // not bear out, of an item of no known kind, of a broken extent.
    let record = |key: u32, class_tag: &[u8], items: &[u8], list: &[u8]| {
        let mut r = vec![1];
        put_address(&mut r, &addr(&[1, 0, 1, 0, key]));
        r.push(0);
        r.push(0);
        r.extend_from_slice(class_tag);
        put_varint(&mut r, 1);
        r.extend_from_slice(items);
        r.extend_from_slice(list);
        r
    };
    let one_text = |bytes: &[u8]| {
        let mut i = Vec::new();
        put_varint(&mut i, 1);
        i.push(0);
        put_varint(&mut i, 1);
        put_bytes(&mut i, bytes);
        i
    };
    let units_of = |records: &[Vec<u8>]| {
        let mut u = Vec::new();
        put_varint(&mut u, records.len() as u64);
        for r in records {
            u.extend_from_slice(r);
        }
        u
    };
    let duplicate = variant(&|s| {
        s[3] = {
            let mut d = Vec::new();
            put_varint(&mut d, 1);
            put_bytes(&mut d, b"alpha");
            d
        };
        s[4] = units_of(&[
            record(1, &[0], &one_text(b"alpha"), &[1, 0]),
            record(1, &[0], &one_text(b"alpha"), &[1, 0]),
        ]);
        s[5] = vec![2, 0, 1, 0, 0, 5, 0, 1, 0, 0, 5];
    });
    assert_eq!(what(&duplicate), "the `units` section: two live units under one key");
    let other_class = variant(&|s| {
        s[4] = units_of(&[record(1, &[1, 3], &one_text(b"alpha"), &[0])]);
    });
    assert_eq!(what(&other_class), "the `units` section: a unit of another class than the file's");
    let list = variant(&|s| {
        s[3] = {
            let mut d = Vec::new();
            put_varint(&mut d, 1);
            put_bytes(&mut d, b"alpha");
            d
        };
        s[4] = units_of(&[record(1, &[0], &one_text(b"alpha"), &[0])]);
        s[5] = vec![1, 0, 1, 0, 0, 5];
    });
    assert_eq!(what(&list), "the `units` section: a term list disagrees with the postings");
    let item = variant(&|s| {
        let mut items = Vec::new();
        put_varint(&mut items, 1);
        items.push(9);
        s[4] = units_of(&[record(1, &[0], &items, &[0])]);
    });
    assert_eq!(what(&item), "the `units` section: an item of no known kind");
    let extent = variant(&|s| {
        let mut items = Vec::new();
        put_varint(&mut items, 2);
        items.push(0);
        put_varint(&mut items, 1);
        put_bytes(&mut items, b"ab");
        items.push(1);
        put_varint(&mut items, 7);
        put_varint(&mut items, 1);
        s[4] = units_of(&[record(1, &[0], &items, &[0])]);
    });
    assert_eq!(what(&extent), "the `units` section: a unit whose items are not one extent");
}

/// §4, §7.4: `seen` survives a restart, so `past_the_ceiling` composes after
/// it; a tombstone and its dead postings are resident in the file until the
/// compacting save, and compaction after a load drops them.
#[test]
fn seen_and_the_tombstones_survive_a_save() {
    let mut index = Index::with_ceiling(Class::Guest, 24);
    index.index(guest(1, "alpha beta")).expect("10 of 24");
    index.index(guest(2, "gamma")).expect("15 of 24");
    assert!(index.index(guest(3, "a unit past the ceiling")).is_err());
    assert!(index.index(guest(4, "and another one")).is_err());
    index.index(guest(1, "delta")).expect("replaced: alpha and beta die");
    let before = index.stats();
    assert_eq!((before.seen, before.tombstones, before.dead_postings), (2, 1, 2));
    let file = save(&index, &plain_header());
    let (loaded, _) = load(&file, Class::Guest).expect("loads");
    assert_eq!(loaded.stats(), Stats { ceiling: CEILING_BYTES, ..before });
    assert_eq!(terms(&loaded), ["delta", "gamma"]);
    assert!(loaded.body.dictionary.contains_key("alpha"), "dead-only, resident");
    assert!(loaded.compaction_due());
    let mut loaded = loaded;
    let compacted = loaded.compacted();
    loaded.install(compacted);
    assert!(!loaded.body.dictionary.contains_key("alpha"));
    assert_eq!(
        loaded.stats(),
        Stats { ceiling: CEILING_BYTES, tombstones: 0, dead_postings: 0, ..before }
    );
}

/// §5.4 THE ASIDE's spelling: `<name>.aside.<its own board's chain>.<n>`,
/// the two names §5.4 shows at ordinal 1, and a second mismatch at ordinal
/// 2 — a name alone; no file moves here.
#[test]
fn aside_name_spells_the_two_names_and_ordinal_2() {
    let chain = Chain::parse(HEX).expect("hex");
    assert_eq!(aside_name("published.index", &chain, 1), format!("published.index.aside.{HEX}.1"));
    assert_eq!(
        aside_name("principal-7.index", &chain, 1),
        format!("principal-7.index.aside.{HEX}.1")
    );
    assert_eq!(aside_name("published.index", &chain, 2), format!("published.index.aside.{HEX}.2"));
    assert_eq!(
        aside_name("principal-7.index", &Chain::from_bytes([0xAB; 32]), 2),
        format!("principal-7.index.aside.{}.2", "ab".repeat(32))
    );
}

/// The refusals render the fact each disposition names.
#[test]
fn the_refusals_display_their_facts() {
    assert_eq!(
        LoadError::NewerVersion { v: 2 }.to_string(),
        "this index was written by a newer skep than this one (v 2)"
    );
    assert_eq!(
        LoadError::NewerTokenizer { revision: Revision { rule: 2, unicode: (18, 0, 0) } }
            .to_string(),
        "this index was cut under a newer tokenizer than this one (2/18.0.0 against 1/17.0.0)"
    );
    assert_eq!(
        LoadError::OtherClass { file: Class::Principal(3), expected: Class::Guest }.to_string(),
        "this is an index of class principal 3, opened where an index of class guest was expected"
    );
    assert_eq!(
        LoadError::UnknownMember { name: "custody".to_string() }.to_string(),
        "the header names a member this skep does not know: `custody`"
    );
    assert_eq!(
        LoadError::Damaged { what: "the trailer: it disagrees".to_string() }.to_string(),
        "this index is damaged: the trailer: it disagrees"
    );
    assert_eq!(
        LoadError::Read { kind: io::ErrorKind::Other, detail: "boom".to_string() }.to_string(),
        "the index could not be read: boom (Other)"
    );
    assert_eq!(
        IndexError::Write { kind: io::ErrorKind::Other, detail: "boom".to_string() }.to_string(),
        "the index could not be written: boom (Other)"
    );
    assert_eq!(
        LoadError::from(HeaderError::Damaged { what: "no `v` member" }),
        LoadError::Damaged { what: "the header line: no `v` member".to_string() }
    );
}

/// A writer or a reader that fails is reported as the embedder's I/O, no
/// disposition of the file's own.
#[test]
fn a_failing_writer_or_reader_is_reported() {
    struct Failing;
    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::StorageFull, "no room"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "no read"))
        }
    }
    assert_eq!(
        sample().save(&plain_header(), &mut Failing),
        Err(IndexError::Write { kind: io::ErrorKind::StorageFull, detail: "no room".to_string() })
    );
    assert_eq!(
        Index::load(&mut Failing, Class::Guest).unwrap_err(),
        LoadError::Read { kind: io::ErrorKind::PermissionDenied, detail: "no read".to_string() }
    );
}

/// A file with no header line, or one that is no index's, is damaged — the
/// header line named — and never faced as a newer skep's.
#[test]
fn a_file_without_a_header_line_or_not_an_indexs_is_damaged() {
    for file in [
        &b""[..],
        b"garbage",
        b"\n",
        b"{}\n",
        b"{\"type\":\"skep-key\",\"v\":1}\n",
        &[0xFF, 0xFE, 0x0A][..],
    ] {
        let what = damaged_what(load(file, Class::Guest));
        assert!(what.starts_with("the header line"), "{what}");
    }
}
