//! §3.1's HIT at the public surface: `Held` across a restart off the range's
//! record with its cell's keys — the kind and the issuer off the grant, the
//! rung the range's own shape — a hit a second honored grant covers
//! `YoursToRead`, an ancestor's draft never `Held`, a draft's hit never
//! `Public` (§8.3's standing items); the span and `as_of` the jump needs,
//! byte-exact in the member's V-ordinals (§3.4, fact 11); and §6's SNIPPET
//! cases — a multi-byte character at the bound, a `Gap` inside, a wide
//! conjunction.

use skep_search::GapKind;
use skep_search::{
    Answer, Class, Grant, GrantKind, Header, Index, Item, Kind, Mark, MarkKind, Pair, Prefix,
    Query, QueryOpts, RangeRecord, Rung, Span, Standing, Unit, UnitKey, SNIPPET_BOUND,
};

use crate::{addr, at, chain, doc, draft, text_unit};

fn ask(pair: Pair<'_>, text: &str) -> Answer {
    Index::query(pair, &Query::parse(text), &QueryOpts::default())
}

fn range(under: &[u32], grant: Option<(GrantKind, &[u32])>) -> RangeRecord {
    RangeRecord {
        under: Some(addr(under)),
        held: at(100, 0x11),
        refusals: Vec::new(),
        bare_rows: 0,
        grant: grant.map(|(kind, issuer)| Grant { kind, issuer: addr(issuer) }),
    }
}

/// §3.1, §8.3: `Held` across a restart off the range's record — the
/// supplement saved with its header and loaded back, the ranges the file's —
/// carrying the departed grant's kind and issuer and the range's own rung,
/// by document and by account; a hit a second honored grant covers
/// `YoursToRead`; an ancestor's draft never `Held`.
#[test]
fn held_is_composed_across_a_restart_off_the_ranges_record_with_its_cells_keys() {
    let mut published = Index::new(Class::Guest);
    published.index(text_unit(Class::Guest, 1, b"the published words")).expect("admitted");
    let principal = Class::Principal(3);
    let mut supplement = Index::new(principal);
    let issuer_a = [1u32, 0, 2];
    let issuer_b = [1u32, 0, 4];
    let under_document = [1u32, 0, 2, 0, 4];
    let under_account = [1u32, 0, 4];
    let ancestor = [1u32, 0, 3];
    supplement
        .index(draft(principal, &addr(&under_document), b"a granted draft's words"))
        .expect("admitted");
    supplement
        .index(draft(principal, &addr(&[1, 0, 4, 0, 9]), b"an account grant's words"))
        .expect("admitted");
    supplement
        .index(draft(principal, &addr(&[1, 0, 3, 0, 1, 0, 5]), b"an ancestor's draft's words"))
        .expect("admitted");
    let header = Header {
        board: chain(0xB0),
        floor: None,
        ranges: vec![
            range(&ancestor, None),
            range(&under_document, Some((GrantKind::Named, &issuer_a))),
            range(&under_account, Some((GrantKind::AnyPrincipal, &issuer_b))),
        ],
        head: None,
    };
    // The restart: the file written and read back; the ranges are the
    // file's, not the honored set's.
    let mut file = Vec::new();
    supplement.save(&header, &mut file).expect("a Vec takes every write");
    let (supplement, header) = Index::load(&mut &file[..], principal).expect("loads");
    assert_eq!(header.ranges.len(), 3);

    // Every grant departed: the honored set holds none of them.
    let pair = Pair::session(&published, &supplement, &header.ranges, &[]);
    let answer = ask(pair, "words ");
    assert_eq!(answer.hits.len(), 4);
    let standing = |doc: &[u32]| {
        answer.hits.iter().find(|h| h.doc == addr(doc)).expect("the hit").standing.clone()
    };
    assert_eq!(standing(&[1, 0, 1, 0, 1]), Standing::Public);
    assert_eq!(
        standing(&under_document),
        Standing::Held { kind: GrantKind::Named, rung: Rung::Document, issuer: addr(&issuer_a) },
        "the departed document grant's cell and issuer"
    );
    assert_eq!(
        standing(&[1, 0, 4, 0, 9]),
        Standing::Held {
            kind: GrantKind::AnyPrincipal,
            rung: Rung::Account,
            issuer: addr(&issuer_b)
        },
        "the account rung is the range's own shape"
    );
    assert_eq!(
        standing(&[1, 0, 3, 0, 1, 0, 5]),
        Standing::YoursToRead,
        "an ancestor's draft is never Held"
    );

    // A second honored grant covering the document admits it.
    let honored = [Prefix::new(addr(&[1, 0, 2]))];
    let pair = Pair::session(&published, &supplement, &header.ranges, &honored);
    let answer = ask(pair, "granted ");
    assert_eq!(answer.hits[0].standing, Standing::YoursToRead);
    // The grant itself still honored: not departed.
    let honored = [Prefix::new(addr(&under_document))];
    let pair = Pair::session(&published, &supplement, &header.ranges, &honored);
    assert_eq!(ask(pair, "granted ").hits[0].standing, Standing::YoursToRead);
}

/// §3.1: a draft's hit is `YoursToRead` for its class and never `Public`,
/// and the standing is never defaulted — a published edition is `Public`.
#[test]
fn a_drafts_hit_is_never_public() {
    let mut published = Index::new(Class::Guest);
    published.index(text_unit(Class::Guest, 1, b"shared words")).expect("admitted");
    let mut supplement = Index::new(Class::Principal(5));
    supplement
        .index(draft(Class::Principal(5), &addr(&[1, 0, 5, 0, 1]), b"shared draft words"))
        .expect("admitted");
    let ranges = [range(&[1, 0, 5], None)];
    let answer = ask(Pair::session(&published, &supplement, &ranges, &[]), "shared ");
    assert_eq!(answer.hits.len(), 2);
    for hit in &answer.hits {
        match hit.kind {
            Kind::Edition => assert_eq!(hit.standing, Standing::Public),
            Kind::Draft => assert_eq!(hit.standing, Standing::YoursToRead),
        }
    }
    assert!(answer.hits.iter().any(|h| h.kind == Kind::Draft));
}

/// §3.4, fact 11: what the hit carries for the jump — the pinned member,
/// `as_of` and the span in the member's V-ordinals, byte-exact off the
/// postings' ranges, the extent's start counted in.
#[test]
fn the_span_is_byte_exact_in_the_members_v_ordinals_with_the_member_and_as_of() {
    let member = addr(&[1, 0, 1, 0, 8, 3]);
    let unit = Unit::new(
        UnitKey::new(doc(8)),
        Some(member.clone()),
        Kind::Edition,
        Class::Guest,
        4_242,
        vec![
            Item::Text { start: 1_000, bytes: "Émile wrote ".as_bytes().to_vec() },
            Item::Gap { start: 1_013, width: 7, kind: GapKind::Atom },
            Item::Text { start: 1_020, bytes: b"the publish shot".to_vec() },
        ],
    )
    .expect("one extent");
    let mut index = Index::new(Class::Guest);
    index.index(unit).expect("admitted");
    let pair = Pair::guest(&index);
    let emile = ask(pair, "emile ").hits.remove(0);
    assert_eq!(emile.member, Some(member.clone()));
    assert_eq!(emile.as_of, 4_242);
    assert_eq!(
        emile.span,
        Span { start: 1_000, width: 6 },
        "the six bytes of a precomposed `Émile`"
    );
    let shot = ask(pair, "\"publish shot\"").hits.remove(0);
    assert_eq!(shot.span, Span { start: 1_024, width: 12 }, "after the gap's seven positions");
    let both = ask(pair, "wrote shot ").hits.remove(0);
    assert_eq!(
        both.span,
        Span { start: 1_007, width: 29 },
        "the window crosses the gap at its width"
    );
    assert_eq!(both.occurrences, 2);
}

fn snippet_of(answer: &Answer) -> &skep_search::Snippet {
    answer.hits[0].snippet.as_ref().expect("the stored text")
}

/// §6, §8.3: a multi-byte character at the bound is never split — the
/// window's bounds move inward to a character boundary.
#[test]
fn a_multi_byte_character_at_the_snippets_bound_is_never_split() {
    let run = "é".repeat(200);
    let text = format!("{run} word {run}");
    let mut index = Index::new(Class::Guest);
    index.index(text_unit(Class::Guest, 1, text.as_bytes())).expect("admitted");
    let answer = ask(Pair::guest(&index), "word ");
    let snippet = snippet_of(&answer);
    assert_eq!(snippet.start, 1 + 162, "401 − 240 = 161 lies inside a character; moved to 162");
    assert_eq!(snippet.text.len(), 644 - 162);
    assert!(snippet.text.starts_with('é') && snippet.text.ends_with('é'));
    assert_eq!(
        snippet.marks,
        [
            Mark { offset: 239, len: 4, kind: MarkKind::Span },
            Mark { offset: 239, len: 4, kind: MarkKind::Term { term: "word".to_string() } }
        ]
    );
    assert_eq!(SNIPPET_BOUND, 240);
}

/// §6, §8.3: a `Gap` inside the window — a withheld run — is cut out of the
/// text and carried as a gap mark at its offset with its width, never
/// rendered as text; an invalid byte of a `hex` stretch the same.
#[test]
fn a_gap_inside_the_snippets_window_is_marked_and_never_rendered() {
    let origin = addr(&[1, 0, 2, 0, 9]);
    let unit = Unit::new(
        UnitKey::new(doc(1)),
        None,
        Kind::Edition,
        Class::Guest,
        1,
        vec![
            Item::Text { start: 1, bytes: b"before the hole ".to_vec() },
            Item::Gap { start: 17, width: 40, kind: GapKind::Withheld { origin } },
            Item::Text { start: 57, bytes: b" after\xFF the hole".to_vec() },
        ],
    )
    .expect("one extent");
    let mut index = Index::new(Class::Guest);
    index.index(unit).expect("admitted");
    let answer = ask(Pair::guest(&index), "after ");
    let snippet = snippet_of(&answer);
    assert_eq!(
        snippet.text, "before the hole  after the hole",
        "the hole's forty positions hold no text"
    );
    assert_eq!(snippet.start, 1);
    assert_eq!(
        snippet.marks,
        [
            Mark { offset: 16, len: 0, kind: MarkKind::Gap { width: 40 } },
            Mark { offset: 17, len: 5, kind: MarkKind::Span },
            Mark { offset: 17, len: 5, kind: MarkKind::Term { term: "after".to_string() } },
            Mark { offset: 22, len: 0, kind: MarkKind::Gap { width: 1 } },
        ]
    );
}

/// §6, §8.3: a conjunction whose tightest window is wider than the bound is
/// centred on its rarest matched word, the others marked where they fall
/// inside — the far word's absence from the marks saying it was dropped.
#[test]
fn a_wide_conjunctions_snippet_is_centred_on_its_rarest_word() {
    let filler = "common ".repeat(100);
    let text = format!("{filler}alpha {filler}rare {filler}");
    let mut index = Index::new(Class::Guest);
    index.index(text_unit(Class::Guest, 1, text.as_bytes())).expect("admitted");
    index.index(text_unit(Class::Guest, 2, b"alpha alpha alpha")).expect("admitted");
    index.index(text_unit(Class::Guest, 3, b"alpha again")).expect("admitted");
    let answer = ask(Pair::guest(&index), "alpha rare ");
    assert_eq!(answer.hits.len(), 1);
    let hit = &answer.hits[0];
    assert!(hit.span.width > SNIPPET_BOUND, "alpha … rare is {} positions wide", hit.span.width);
    let snippet = hit.snippet.as_ref().expect("the stored text");
    let rare_at = text.find("rare").expect("present") as u64;
    assert_eq!(snippet.start, 1 + rare_at - SNIPPET_BOUND, "centred on `rare`, the rarest");
    assert!(snippet.text.contains("rare") && !snippet.text.contains("alpha"));
    let terms: Vec<&str> = snippet
        .marks
        .iter()
        .filter_map(|m| match &m.kind {
            MarkKind::Term { term } => Some(term.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(terms, ["rare"], "`alpha` fell outside the window and is absent from the marks");
    assert_eq!(snippet.marks[0].kind, MarkKind::Span);
    assert_eq!(snippet.marks[0].len, SNIPPET_BOUND as usize + 4, "the span clipped to the window");
}
