use std::path::Path;
use std::sync::Arc;

use skep_arrangement::as_ordinal_vspan;
use skep_discovery::project_on;
use skep_engine::Engine;
use skep_links::FROM;
use skep_media::index::CellIndex;
use skep_registry::commons_type;

use super::*;
use crate::commits::sidecar::CommitMeta;
use crate::commits::tests::fsync_engine;

/// Opens an engine and the write path over `dir`, as the daemon's open does.
fn open(dir: &Path) -> (Engine, Commits) {
    let engine = fsync_engine(dir);
    let wp = Commits::open(dir, &engine, Arc::new(CellIndex::new())).expect("the write path opens");
    (engine, wp)
}

/// Runs the seed under the guard, as the daemon's open does.
fn seed(wp: &Commits) -> Seeded {
    let serial = wp.serial_lock();
    wp.seed_registry(&serial)
}

/// The `defines` links of `def`'s address as a GUEST's query answers them,
/// narrowed to the links whose stored `to` is exactly the type's own unit
/// span: a type's span covers its subtypes' (L10), so the raw answer for a
/// type with subtypes carries their links too.
fn definition_links(engine: &Engine, def_address: &Address) -> Vec<Address> {
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    let to = enc([def_address]);
    let q = FourSet {
        to: SlotSpec::Spans(to.clone()),
        ty: SlotSpec::Spans(enc([defines_type()])),
        ..FourSet::any()
    };
    findlinks_ftt_on(&snap, &q, &|doc| world.readable_guest(doc))
        .into_iter()
        .filter(|a| world.links().readlink(a).is_some_and(|l| *l.to_slot() == to))
        .collect()
}

/// The text a link's `from` covers, read as a client reads it: the slot
/// projected into the registry document (its reading surface, the trunk
/// head member) and the positions retrieved there, concatenated.
fn from_text(engine: &Engine, link: &Address) -> String {
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    let registry = ghost_home_document();
    let set = project_on(&snap, link, FROM, &registry, &|doc| world.readable_guest(doc))
        .expect("the from slot projects into the registry document");
    let surface = trunk_head(world.m3(), &registry).expect("a member stands");
    let mut bytes = Vec::new();
    for span in set.iter() {
        let v = as_ordinal_vspan(span).expect("a depth-2 content span");
        let (ordinal, count) =
            (u64::try_from(v.ordinal).expect("fits"), u64::try_from(v.count).expect("fits"));
        for p in ordinal..ordinal + count {
            let at = VPos::content(Nat::from(usize::try_from(p).expect("fits")));
            let i_addr = world.m5().point(&surface, &at).expect("a placed position");
            bytes.extend_from_slice(world.content().value_at(i_addr.tumbler()).expect("a value").as_bytes());
        }
    }
    String::from_utf8(bytes).expect("prose")
}

/// The seed's lines among those said through the write path's door — the
/// feed's own open lines stand in the same record beside them.
fn lines_said(wp: &Commits) -> Vec<String> {
    wp.lines_said().lock().iter().filter(|l| l.contains("link-type registry")).cloned().collect()
}

/// The registry document's trunk head member, or `None` while memberless.
fn registry_head(engine: &Engine) -> Option<Address> {
    trunk_head(engine.kernel().snapshot().world().m3(), &ghost_home_document())
}

/// R1 — EVERY TYPE, ONCE, ON A FRESH BOARD, before any claim: the seed writes
/// every row and finds none standing; a guest's query constrained in `to`
/// and `ty` answers exactly one link per row, whose `to` is the type's
/// address in addrs form (one unit span, never a resolved content span),
/// whose `from` lies in the registry document and reads back as the row's
/// section, the name alone on its first line; a type not in the table
/// answers none. And THE COUNT a fresh board stands at after the seed: one
/// draft mint, one insert of every section, one publish, one link per row.
#[test]
fn a_fresh_board_names_every_type_once_to_a_guest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (engine, wp) = open(dir.path());
    let table = vocabulary();
    assert_eq!(engine.kernel().current_seq().0, 0, "a fresh board");
    assert_eq!(registry_head(&engine), None, "the registry document is memberless at genesis");

    let seeded = seed(&wp);
    assert_eq!(seeded, Seeded { written: table.len(), stood: 0, refused: None });

    // The commits: the staging draft's mint, the sections' insert, the
    // member's publish, then one `make_link` per row — each link three
    // records (mint, link, seat) — and the whole the figure skepd's suites
    // pin as `SEED_HEAD`.
    let entries = wp.feed.entries_above(0);
    assert_eq!(entries.len(), 3 + table.len(), "one commit per act, one link per row");
    let ats: Vec<u64> = entries.iter().map(|(at, _)| *at).collect();
    assert_eq!(ats[0], 1, "the draft's mint: one record");
    let (insert_records, publish_records) = (ats[1] - ats[0], ats[2] - ats[1]);
    assert!(ats[3..].windows(2).all(|w| w[1] - w[0] == 3), "each link is three records: {ats:?}");
    assert_eq!(ats[3] - ats[2], 3, "the first link: three records");
    let head = engine.kernel().current_seq().0;
    assert_eq!(head, *ats.last().expect("entries"), "the head is the last link's position");
    println!(
        "the seed's layout on a fresh board: {} rows; the draft's mint at 1, the insert {} \
         records to {}, the publish {} records to {}, {} links of 3 records to {}: SEED_HEAD = {}",
        table.len(),
        insert_records,
        ats[1],
        publish_records,
        ats[2],
        table.len(),
        head,
        head
    );
    for (_, meta) in &entries {
        assert!(
            matches!(meta, CommitMeta::Recorded { key: Some(key), .. } if key == SYSTEM_TESTIMONY),
            "every seed commit is the system principal's: {meta:?}"
        );
    }

    // One member, holding every section: the meta-type's first, then the
    // rest in path order.
    let member = registry_head(&engine).expect("the seed published one member");
    assert_eq!(member.tumbler().to_string(), "1.1.0.1.0.1.1");
    let snap = engine.kernel().snapshot();
    let text: Vec<u8> = content_text(snap.world(), &member).into_iter().map(|(_, b)| b).collect();
    let in_write_order = || {
        table
            .iter()
            .filter(|d| d.address == *defines_type())
            .chain(table.iter().filter(|d| d.address != *defines_type()))
    };
    let whole: String = in_write_order().map(Definition::section).collect();
    assert_eq!(String::from_utf8(text).expect("prose"), whole, "the member is the sections, in order");

    for def in table {
        let links = definition_links(&engine, &def.address);
        assert_eq!(links.len(), 1, "{}: exactly one definition link", def.address);
        let link = snap.world().links().readlink(&links[0]).expect("resident");
        assert_eq!(*link.to_slot(), enc([&def.address]), "{}: the to in addrs form", def.address);
        assert_eq!(*link.type_slot(), enc([defines_type()]), "{}: typed defines", def.address);
        assert!(lies_in(link.from_slot(), &ghost_home_document()), "{}: from in the registry", def.address);
        assert!(
            links[0].tumbler().to_string().starts_with("1.1.0.1.0.1.0.2."),
            "{}: the link is homed in the registry document's link subspace: {}",
            def.address,
            links[0]
        );
        let text = from_text(&engine, &links[0]);
        assert_eq!(text, def.section(), "{}: the from span is the section", def.address);
        assert_eq!(text.lines().next(), Some(def.name), "{}: the first line is the name", def.address);
    }
    // `defines` itself: the first link written, typed by itself; the rest
    // follow in path order, `3.1`'s second.
    let defines = definition_links(&engine, defines_type());
    assert_eq!(defines[0].tumbler().to_string(), "1.1.0.1.0.1.0.2.1", "3.50's link is the first");
    let enroll = definition_links(&engine, &table[0].address);
    assert_eq!(enroll[0].tumbler().to_string(), "1.1.0.1.0.1.0.2.2", "3.1's link is the second");
    // A type not in the table — the literary set's free `3.106`, the test-only `3.90.1`, an
    // address beneath a row — answers none.
    for absent in [commons_type(&[106]), commons_type(&[90, 1]), commons_type(&[13, 1])] {
        assert!(definition_links(&engine, &absent).is_empty(), "{absent}: no definition");
    }
    assert!(lines_said(&wp).iter().all(|l| !l.contains("link-type registry")), "nothing refused");
}

/// R2 — A REOPEN WRITES NOTHING: a seeded board reopened finds every row
/// standing; the journal's committed position is unchanged, no second
/// member is published, and each type still has one link.
#[test]
fn a_reopen_of_a_seeded_board_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let table = vocabulary();
    let position = {
        let (engine, wp) = open(dir.path());
        seed(&wp);
        drop(wp);
        engine.kernel().current_seq().0
    };
    let (engine, wp) = open(dir.path());
    assert_eq!(engine.kernel().current_seq().0, position, "the reopen recovered the seeded board");
    assert_eq!(seed(&wp), Seeded { written: 0, stood: table.len(), refused: None });
    assert_eq!(engine.kernel().current_seq().0, position, "nothing committed");
    assert_eq!(registry_head(&engine).map(|m| m.tumbler().to_string()), Some("1.1.0.1.0.1.1".into()));
    for def in table {
        assert_eq!(definition_links(&engine, &def.address).len(), 1, "{}: one link", def.address);
    }
    // Twice more, the same: a reopen is idempotent however many times.
    assert_eq!(seed(&wp), Seeded { written: 0, stood: table.len(), refused: None });
    assert_eq!(engine.kernel().current_seq().0, position);
}

/// R3 — AN ADDITION: a board seeded under the table less one row (the test
/// seam hiding it) gains exactly that row's section and link at the next
/// open under the whole table — one new member carrying every earlier
/// section after the new one, so the registry's reading surface still holds
/// the whole vocabulary — and nothing else: every other row stands.
#[test]
fn a_board_seeded_under_a_smaller_table_gains_the_added_row_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let table = vocabulary();
    let citation = commons_type(&[13]);
    hide_a_type_from_the_seed(dir.path(), citation.clone());
    let position = {
        let (engine, wp) = open(dir.path());
        assert_eq!(seed(&wp), Seeded { written: table.len() - 1, stood: 0, refused: None });
        assert!(definition_links(&engine, &citation).is_empty(), "the hidden row has no link");
        assert_eq!(seed(&wp), Seeded { written: 0, stood: table.len() - 1, refused: None });
        drop(wp);
        engine.kernel().current_seq().0
    };
    unhide_every_type_from_the_seed(dir.path());
    let (engine, wp) = open(dir.path());
    assert_eq!(seed(&wp), Seeded { written: 1, stood: table.len() - 1, refused: None });
    // One insert, one publish with its correspondence record, one link:
    // 3 + 7 + 3 records.
    assert_eq!(engine.kernel().current_seq().0, position + 13, "the addition's three commits");
    let member = registry_head(&engine).expect("a member");
    assert_eq!(member.tumbler().to_string(), "1.1.0.1.0.1.2", "a second member");
    let snap = engine.kernel().snapshot();
    let text: Vec<u8> = content_text(snap.world(), &member).into_iter().map(|(_, b)| b).collect();
    let text = String::from_utf8(text).expect("prose");
    let citation_def = skep_registry::definition_at(&citation).expect("a row");
    assert!(text.starts_with(&citation_def.section()), "the new section comes first");
    for def in table {
        assert!(text.contains(&def.section()), "{}: the surface holds every section", def.address);
        let links = definition_links(&engine, &def.address);
        assert_eq!(links.len(), 1, "{}: one link, never two", def.address);
        assert_eq!(from_text(&engine, &links[0]), def.section(), "{}: readable off the surface", def.address);
    }
    assert_eq!(seed(&wp), Seeded { written: 0, stood: table.len(), refused: None });
}

/// R4 — CUT SHORT: a refusal injected on the seed's fifth commit of its own
/// — the third row's link, after the insert, the publish, `defines`' link
/// and `3.1`'s — ends the seed: said once, naming the type, the cause as the
/// wire renders it, the two types standing and that the rest wait; the first
/// two rows are defined and the third is not; the sections all stand in the
/// one member. The next open writes the rest from where it stopped —
/// linking the sections that stand, publishing no second member — and none
/// twice.
#[test]
fn a_refused_commit_ends_the_seed_once_and_the_next_open_finishes_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let table = vocabulary();
    // The write order: `3.50`, then the table from `3.1`.
    let (first, second, third) = (
        skep_registry::definition_at(defines_type()).expect("defines"),
        &table[0],
        &table[1],
    );
    refuse_the_seeds_commit_once(dir.path(), 5);
    let position = {
        let (engine, wp) = open(dir.path());
        assert_eq!(
            seed(&wp),
            Seeded { written: 2, stood: 0, refused: Some(third.address.clone()) }
        );
        let said = lines_said(&wp);
        assert_eq!(
            said,
            [format!(
                "failure: link-type registry: the make_link for the type {} ({}) was refused \
                 (durability: the test seam's refusal); 2 of {} types stand, the rest wait for \
                 the next open; the board serves",
                third.address,
                third.name,
                table.len()
            )],
            "said once, naming the row"
        );
        assert_eq!(definition_links(&engine, &first.address).len(), 1, "defines stands");
        assert_eq!(definition_links(&engine, &second.address).len(), 1, "the first row stands");
        assert!(definition_links(&engine, &third.address).is_empty(), "the refused one does not");
        assert!(definition_links(&engine, &table[2].address).is_empty(), "nor any after it");
        assert_eq!(registry_head(&engine).map(|m| m.tumbler().to_string()), Some("1.1.0.1.0.1.1".into()));
        // The refused link committed nothing: the head is the second link's
        // position, three records past the first's.
        let ats: Vec<u64> = wp.feed.entries_above(0).into_iter().map(|(at, _)| at).collect();
        assert_eq!(ats.len(), 5, "the mint, the insert, the publish and two links: {ats:?}");
        assert_eq!(engine.kernel().current_seq().0, ats[4]);
        assert_eq!(ats[4] - ats[3], 3);
        drop(wp);
        engine.kernel().current_seq().0
    };
    let (engine, wp) = open(dir.path());
    assert_eq!(seed(&wp), Seeded { written: table.len() - 2, stood: 2, refused: None });
    assert_eq!(
        engine.kernel().current_seq().0,
        position + 3 * (table.len() as u64 - 2),
        "the rest of the links alone: no new section, no new member"
    );
    assert_eq!(registry_head(&engine).map(|m| m.tumbler().to_string()), Some("1.1.0.1.0.1.1".into()));
    for def in table {
        let links = definition_links(&engine, &def.address);
        assert_eq!(links.len(), 1, "{}: one link, none twice", def.address);
        assert_eq!(from_text(&engine, &links[0]), def.section());
    }
    assert!(lines_said(&wp).is_empty(), "the finishing open says no failure");
}

/// R4 at the sections' insert — the seed's first commit of its own: nothing
/// is published and nothing linked, the line names the first row written
/// (`defines`) and the `insert`, and the next open writes everything, the
/// draft standing from the first open so no second mint is made.
#[test]
fn a_refusal_at_the_sections_insert_leaves_the_next_open_the_whole_table() {
    let dir = tempfile::tempdir().expect("tempdir");
    let table = vocabulary();
    let defines = skep_registry::definition_at(defines_type()).expect("defines");
    refuse_the_seeds_commit_once(dir.path(), 1);
    let whole_head = {
        let (engine, wp) = open(dir.path());
        assert_eq!(seed(&wp), Seeded { written: 0, stood: 0, refused: Some(defines.address.clone()) });
        let said = lines_said(&wp);
        assert_eq!(said.len(), 1);
        assert!(
            said[0].starts_with(&format!(
                "failure: link-type registry: the insert for the type {} ({}) was refused \
                 (durability: the test seam's refusal); 0 of {} types stand",
                defines.address,
                defines.name,
                table.len()
            )),
            "{}",
            said[0]
        );
        assert_eq!(engine.kernel().current_seq().0, 1, "the draft's mint alone landed");
        assert_eq!(registry_head(&engine), None, "no member");
        drop(wp);
        // A whole seed on another fresh board, for the figure to hold the
        // finishing open to.
        let other = tempfile::tempdir().expect("tempdir");
        let (engine, wp) = open(other.path());
        seed(&wp);
        drop(wp);
        engine.kernel().current_seq().0
    };
    let (engine, wp) = open(dir.path());
    assert_eq!(seed(&wp), Seeded { written: table.len(), stood: 0, refused: None });
    assert_eq!(engine.kernel().current_seq().0, whole_head, "the draft stood: no second mint");
    for def in table {
        assert_eq!(definition_links(&engine, &def.address).len(), 1, "{}", def.address);
    }
}

/// R5 — THE WRITER: every seed commit testifies `system`; the staging draft
/// is `1.1.0.1.0.3`, unpublished, and no other document is minted under the
/// system account by the seed — doc 4 is unregistered after it, and row
/// 40's line is never said.
#[test]
fn the_seed_writes_as_the_system_principal_through_the_one_staging_draft() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (engine, wp) = open(dir.path());
    seed(&wp);
    let snap = engine.kernel().snapshot();
    let m3 = snap.world().m3();
    let draft = super::super::head::staging_draft_address();
    assert_eq!(draft.tumbler().to_string(), "1.1.0.1.0.3");
    assert!(m3.is_registered_document(&draft) && !m3.published(&draft), "the draft, private");
    let doc4 = crate::codec::wire_address("1.1.0.1.0.4").expect("an address");
    assert!(!m3.is_registered_document(&doc4), "the system principal minted no other document");
    assert!(
        lines_said(&wp).iter().all(|l| !l.contains("staging draft minted at")),
        "row 40's line never said: {:?}",
        lines_said(&wp)
    );
    for (_, meta) in wp.feed.entries_above(0) {
        match meta {
            CommitMeta::Recorded { key, signed, .. } => {
                assert_eq!(key.as_deref(), Some(SYSTEM_TESTIMONY));
                assert!(signed.is_none(), "the seed's commits are unsigned");
            }
            other => panic!("a bare entry on a fresh board's own feed: {other:?}"),
        }
    }
}

/// THE LINE's WORDS at fixed inputs: the act as the wire names the op, the
/// type by address and name, the cause as the wire renders a rejection, the
/// count standing and the rest's fate.
#[test]
fn the_refusal_line_names_the_act_the_type_the_cause_and_what_stands() {
    let def = skep_registry::definition_at(&commons_type(&[13])).expect("citation");
    assert_eq!(
        TypeRefusedLine { def, act: "publish", cause: "durability: the volume is full", standing: 0, total: 94 }
            .to_string(),
        "link-type registry: the publish for the type 1.1.0.1.0.1.0.3.13 (citation) was refused \
         (durability: the volume is full); 0 of 94 types stand, the rest wait for the next open; \
         the board serves"
    );
}

/// THE SECTION SEARCH: a section is found at the text's start or after a
/// newline alone, over consecutive positions alone, and answers its first
/// position and its width.
#[test]
fn a_section_is_found_at_a_line_start_over_consecutive_positions() {
    let text = |s: &str, from: u64| -> Vec<(u64, u8)> {
        s.bytes().enumerate().map(|(i, b)| (from + i as u64, b)).collect()
    };
    let t = text("ab\ncd\nef\n", 7);
    assert_eq!(find_section(&t, "cd\n"), Some((10, 3)));
    assert_eq!(find_section(&t, "ab\n"), Some((7, 3)));
    assert_eq!(find_section(&t, "b\n"), None, "not at a line start");
    assert_eq!(find_section(&t, "xy\n"), None);
    assert_eq!(find_section(&t, ""), None);
    let mut gap = text("ab\ncd\n", 1);
    gap[4].0 = 40; // a hole in the positions
    assert_eq!(find_section(&gap, "cd\n"), None, "not consecutive");
    assert_eq!(
        content_span(5, 3),
        Span::new(
            Tumbler::new([Nat::from(1u32), Nat::from(5u32)]).expect("nonempty"),
            Tumbler::new([Nat::from(0u32), Nat::from(3u32)]).expect("nonempty")
        )
        .expect("a span")
    );
}
