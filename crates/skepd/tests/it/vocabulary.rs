//! The link-type registry, seeded at every open (wire.md §Registry, §Link
//! discovery reads; `skep-core`'s `commits/registry.rs`): on every board the
//! daemon writes, as the system principal, one named section and one
//! `defines` link into the registry document `1.1.0.1.0.1` for every link
//! type of `skep-registry`'s vocabulary the board lacks — all of them on a
//! fresh board, the missing ones on an upgraded or interrupted one — so any
//! board answers "what is `3.13` called?" to a guest.
//!
//! The fence, keyed to the owner's three rulings (every board, not the dev
//! seed; commits, not Σ₀; a reopen writes what is missing): R1 every type
//! once, read by a GUEST over the wire as a client reads it; R2 a reopen
//! writes nothing; R3 an addition writes the added row alone; R4 a seed cut
//! short is finished at the next open, none twice; R5 the writer is the
//! system principal through the one staging draft; R6 the ceremony's numbers
//! on the seeded board, and the seed's layout every position pin derives from
//! held equal to what a fresh board counts; R7 every pin the workspace holds
//! in non-test code is a row of the table. R8, the open's line off the
//! binary's stderr, is `open.rs`'s. Two cells hold the reader-state family
//! `3.46` beside them: with R3, a board seeded before the family gains its
//! five rows at the next open; with R7, no source outside the table names
//! an address of the family.

use std::path::Path;

use serde_json::Value;
use skep_core::commits::{
    hide_a_type_from_the_seed, refuse_the_seeds_commit_once, unhide_every_type_from_the_seed,
};
use skep_registry::{definition_at, defines_type, vocabulary, Definition};
use skepd::Skepd;

use crate::common::{
    addrs_of, board_term, claim_board, doc_metadata, expect_resp, get, head_position, json,
    nth_document, op, open_session, read_link, region, seed_ats, spawn, spawn_unclaimed,
    system_accounts_first_mint, BLIND_KIND, SEED_HEAD, SEED_LINK_RECORDS, SEED_PUBLISH_AT,
    SEED_TYPES,
};

/// The registry document: doc 1 of the system account.
const REGISTRY: &str = "1.1.0.1.0.1";

/// The staging draft the seed and the head writer share.
const STAGING_DRAFT: &str = "1.1.0.1.0.3";

/// The time document: doc 4 of the system account.
const TIME_DOCUMENT: &str = "1.1.0.1.0.4";

/// The reader-state family's rows, by path: the parent `3.46` and its four
/// states. `3.46.2` is reserved and holds no row.
const READER_STATE: [&[u32]; 5] = [&[46], &[46, 1], &[46, 3], &[46, 4], &[46, 5]];

/// A `retrieve_v` spec's span over a document's first content position.
const FIRST_POSITION: &str = r#""span":{"start":"1.1","width":"0.1"}"#;

/// The unit span of `addr` as a client spells a type in a four-set slot or
/// reads one back off a stored addrs-form endset: the address as the start
/// and a width of as many components, zeros then one.
fn unit_span(addr: &str) -> Value {
    let depth = addr.split('.').count();
    let width: Vec<&str> = std::iter::repeat_n("0", depth - 1).chain(["1"]).collect();
    serde_json::json!([{"start": addr, "width": width.join(".")}])
}

/// THE LOOKUP AS A CLIENT MAKES IT (wire.md §Link discovery reads): the
/// `defines` links of `ty` — `find_links_ftt` constrained in `to` and `ty`,
/// served from the coverage index and no class scan — narrowed to the links
/// whose stored `to` is exactly the type's own unit span: a type's span
/// covers its subtypes' (L10), so the raw answer for a type with subtypes
/// carries their links too.
fn definition_links(port: u16, token: Option<&str>, ty: &str) -> Vec<String> {
    let q = serde_json::json!({
        "from": "any",
        "home": "any",
        "to": unit_span(ty),
        "ty": unit_span(&defines_type().to_string()),
    });
    let v = op(port, token, &serde_json::json!({"op": "find_links_ftt", "q": q}).to_string());
    addrs_of(&v)
        .into_iter()
        .filter(|a| read_link(port, token, a)["slots"][1] == unit_span(ty))
        .collect()
}

/// THE READ AS A CLIENT MAKES IT: the link's `from` slot projected into the
/// registry document — its reading surface, the latest member, which holds
/// every section — and the span retrieved there; the text, whose first line
/// is the name.
fn from_text(port: u16, token: Option<&str>, link: &str) -> String {
    let v = op(port, token, &format!(r#"{{"a":"{link}","d":"{REGISTRY}","op":"project","slot":1}}"#));
    let set = expect_resp(&v, "span_set")["set"].as_array().expect("a span set").clone();
    assert_eq!(set.len(), 1, "one section, one span: {set:?}");
    let span = set[0].clone();
    let v = op(
        port,
        token,
        &serde_json::json!({"op": "retrieve_v", "specs": [{"doc": REGISTRY, "span": span}]}).to_string(),
    );
    let items = expect_resp(&v, "delivery")["items"].as_array().expect("items").clone();
    items.iter().map(|i| i["content"].as_str().expect("prose, per byte").to_string()).collect()
}

/// The lines the registry seed said this uptime, through the daemon's record.
fn seed_lines(sd: &Skepd) -> Vec<String> {
    sd.daemon().lines_said().into_iter().filter(|l| l.contains("link-type registry")).collect()
}

/// The one `open:` line a seed that wrote says, `written` of the table and
/// `stood` standing, its duration read out.
fn open_line(sd: &Skepd, written: usize, stood: usize) -> Vec<String> {
    let prefix = format!(
        "open: link-type registry {REGISTRY}: {written} of {} types written, {stood} stood, in ",
        vocabulary().len()
    );
    seed_lines(sd).into_iter().filter(|l| l.starts_with(&prefix) && l.ends_with(" ms")).collect()
}

/// `/health`'s `log_position`.
fn log_position(port: u16) -> u64 {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200);
    json(&body)["log_position"].as_u64().expect("log_position")
}

/// R1 — EVERY TYPE, ONCE, before any claim, to a GUEST: for every row of the
/// table one `defines` link, its `to` the type's address in addrs form, its
/// `from` a span in the registry document that reads back as the section,
/// the name alone on the first line; a type not in the table answers none.
/// R6's constants too: the fresh board stands at `SEED_HEAD`, the size the
/// seed's layout spells (`SEED_TYPES`) is the table's, and the `open:` line
/// says every type written.
#[test]
fn a_fresh_board_names_every_type_once_to_a_guest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    let table = vocabulary();

    assert_eq!(log_position(port), SEED_HEAD, "the fresh board stands at the seed's head");
    assert_eq!(SEED_TYPES, table.len() as u64, "the seed's layout spells the table's size");
    assert_eq!(
        open_line(&sd, table.len(), 0).len(),
        1,
        "the open's one line: every type written, none stood: {:?}",
        seed_lines(&sd)
    );
    assert_eq!(seed_lines(&sd).len(), 1, "and no failure line");

    for def in table {
        let ty = def.address.to_string();
        let links = definition_links(port, None, &ty);
        assert_eq!(links.len(), 1, "{ty}: exactly one definition link: {links:?}");
        assert!(links[0].starts_with(&format!("{REGISTRY}.0.2.")), "{ty}: homed in the registry: {}", links[0]);
        let stored = read_link(port, None, &links[0]);
        assert_eq!(stored["slots"][2], unit_span(&defines_type().to_string()), "{ty}: typed defines");
        let from = stored["slots"][0].as_array().expect("the from endset").clone();
        assert!(
            from.iter().all(|s| s["start"].as_str().is_some_and(|st| st.starts_with(&format!("{REGISTRY}.0.1.")))),
            "{ty}: the from is a span of the registry document's content: {from:?}"
        );
        let text = from_text(port, None, &links[0]);
        assert_eq!(text, def.section(), "{ty}: the section");
        assert_eq!(text.lines().next(), Some(def.name), "{ty}: the first line is the name");
    }
    // `defines` itself is the first link written, typed by itself.
    assert_eq!(definition_links(port, None, &defines_type().to_string()), [format!("{REGISTRY}.0.2.1")]);
    // A type not in the table — the literary set's free `3.106`, the
    // test-only `3.90.1`, an address beneath a row, the reader-state
    // family's reserved `3.46.2` — answers none.
    for absent in [
        "1.1.0.1.0.1.0.3.106",
        "1.1.0.1.0.1.0.3.90.1",
        "1.1.0.1.0.1.0.3.13.1",
        "1.1.0.1.0.1.0.3.46.2",
    ] {
        assert!(definition_links(port, None, absent).is_empty(), "{absent}: no definition");
    }
    sd.shutdown();
}

/// R2 — A REOPEN WRITES NOTHING: the committed position is unchanged, no
/// `open:` seed line is said, and every type still has one link.
#[test]
fn a_reopen_of_a_seeded_board_writes_nothing_and_says_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let table = vocabulary();
    {
        let sd = spawn_unclaimed(dir.path());
        assert_eq!(log_position(sd.port()), SEED_HEAD);
        sd.shutdown();
    }
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    assert_eq!(log_position(port), SEED_HEAD, "nothing committed at the reopen");
    assert!(seed_lines(&sd).is_empty(), "no seed line at a reopen: {:?}", seed_lines(&sd));
    for def in table {
        assert_eq!(definition_links(port, None, &def.address.to_string()).len(), 1, "{}", def.address);
    }
    sd.shutdown();
}

/// R3 — AN ADDITION: a board seeded under the table less one row gains that
/// row's section and link at the next open under the whole table, and
/// nothing else; the open's line says `1 of N`.
#[test]
fn a_board_seeded_under_a_smaller_table_gains_the_added_row_at_the_next_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let table = vocabulary();
    let citation = "1.1.0.1.0.1.0.3.13";
    let citation_def = definition_at(&skep_registry::commons_type(&[13])).expect("citation");
    hide_a_type_from_the_seed(dir.path(), citation_def.address.clone());
    let position = {
        let sd = spawn_unclaimed(dir.path());
        let port = sd.port();
        assert_eq!(open_line(&sd, table.len() - 1, 0).len(), 1, "{:?}", seed_lines(&sd));
        assert!(definition_links(port, None, citation).is_empty(), "the hidden row has no link");
        let position = log_position(port);
        assert_eq!(position, SEED_HEAD - 3, "one link fewer");
        sd.shutdown();
        position
    };
    unhide_every_type_from_the_seed(dir.path());
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    assert_eq!(
        open_line(&sd, 1, table.len() - 1),
        seed_lines(&sd),
        "the one line: one type written, the rest stood"
    );
    assert_eq!(
        log_position(port),
        position + 13,
        "one insert (3), one publish with its correspondence record (7), one link (3)"
    );
    let links = definition_links(port, None, citation);
    assert_eq!(links.len(), 1, "the added row's link");
    assert_eq!(from_text(port, None, &links[0]), citation_def.section());
    // THE SEED SHOT TWICE FROM ONE DRAFT (the link-sets design §5.7): the
    // first open's publish and this addition's each minted one
    // correspondence record in the staging draft — read as the system
    // principal, the draft's owner — the second's `from` the addition's
    // run, which begins right after the first seed's sections (the first
    // record's `from`, from the draft's first position, as wide as those
    // bytes), and its `to` the second member's own run; no fence met, the
    // run fresh.
    let system = open_session(port, 9_000_000_000_000_000);
    let record = |k: u64| read_link(port, Some(&system), &format!("{STAGING_DRAFT}.0.2.{k}"));
    let (first, second) = (record(1), record(2));
    assert!(record(3).is_null(), "two seeds, two records: {}", record(3));
    let span = |r: &Value, slot: usize| -> (String, u64) {
        let s = &r["slots"][slot][0];
        let width = s["width"].as_str().expect("a width").rsplit('.').next().expect("a last component");
        (s["start"].as_str().expect("a start").to_string(), width.parse().expect("a count"))
    };
    let (first_from, first_width) = span(&first, 0);
    assert_eq!(first_from, format!("{STAGING_DRAFT}.0.1.1"), "the first seed's sections, from the draft's first position");
    let (second_from, second_width) = span(&second, 0);
    assert_eq!(
        second_from,
        format!("{STAGING_DRAFT}.0.1.{}", first_width + 1),
        "the addition's section follows the first seed's bytes in the draft"
    );
    assert_eq!(second_width as usize, citation_def.section().len(), "as wide as the added section");
    let (second_to, _) = span(&second, 1);
    let v = op(port, None, &format!(r#"{{"op":"image",{}}}"#, region(&format!("{REGISTRY}.2"), 1, 1)));
    assert_eq!(
        expect_resp(&v, "runs")["runs"][0]["i_start"].as_str(),
        Some(second_to.as_str()),
        "the second record's `to` is the second member's own run"
    );
    assert_eq!(span(&second, 2).0, "1.1.0.1.0.1.0.3.102.1", "typed the correspondence class");
    for def in table {
        let links = definition_links(port, None, &def.address.to_string());
        assert_eq!(links.len(), 1, "{}: one link, never two", def.address);
        assert_eq!(from_text(port, None, &links[0]), def.section(), "{}: readable off the surface", def.address);
    }
    sd.shutdown();
}

/// R3 FOR A FAMILY — THE READER-STATE ROWS: a board seeded under the table
/// less the five rows of `3.46`, the parent and its four states hidden from
/// its first open, gains the five at the next open under the whole table,
/// and nothing else. The addition is one insert of the five sections, one
/// publish and five links — 25 records — and the open's one line says
/// `5 of N`. Each of the five then has one link whose `from` reads as its
/// section, the family's reserved `3.46.2` has none, and every other row
/// keeps the one link it had. A guest reads all of it: the cell opens no
/// session as the system principal.
#[test]
fn a_board_seeded_before_the_reader_state_rows_gains_the_five_at_the_next_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let table = vocabulary();
    let family: Vec<&Definition> = READER_STATE
        .iter()
        .map(|ordinals| {
            definition_at(&skep_registry::commons_type(ordinals))
                .unwrap_or_else(|| panic!("3.{ordinals:?} is a row of the table"))
        })
        .collect();
    for def in &family {
        hide_a_type_from_the_seed(dir.path(), def.address.clone());
    }
    let position = {
        let sd = spawn_unclaimed(dir.path());
        let port = sd.port();
        assert_eq!(open_line(&sd, table.len() - 5, 0).len(), 1, "{:?}", seed_lines(&sd));
        for def in &family {
            let links = definition_links(port, None, &def.address.to_string());
            assert!(links.is_empty(), "{}: a hidden row has no link: {links:?}", def.address);
        }
        let position = log_position(port);
        assert_eq!(position, SEED_HEAD - 5 * SEED_LINK_RECORDS, "five links fewer");
        sd.shutdown();
        position
    };
    unhide_every_type_from_the_seed(dir.path());
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    let said = seed_lines(&sd);
    assert_eq!(said.len(), 1, "one line, and no failure: {said:?}");
    assert_eq!(open_line(&sd, 5, table.len() - 5), said, "five types written, the rest stood");
    assert_eq!(
        log_position(port),
        position + 25,
        "one insert (3), one publish with its correspondence record (7), five links (15)"
    );
    for def in table {
        let links = definition_links(port, None, &def.address.to_string());
        assert_eq!(links.len(), 1, "{}: one link, never two", def.address);
        assert_eq!(
            from_text(port, None, &links[0]),
            def.section(),
            "{}: readable off the surface",
            def.address
        );
    }
    let reserved = definition_links(port, None, "1.1.0.1.0.1.0.3.46.2");
    assert!(reserved.is_empty(), "the family's reserved 3.46.2 has no definition: {reserved:?}");
    sd.shutdown();
}

/// The registration kind's ten rows, by their ordinals: the kind, its parent
/// rows `request` and `reply` with the rows beneath each, the vouch and the
/// approval (REG-1.14, REG-1.15).
const REGISTRATION: [&[u32]; 10] = [
    &[54],
    &[54, 1],
    &[54, 1, 1],
    &[54, 1, 2],
    &[54, 2],
    &[54, 2, 1],
    &[54, 2, 2],
    &[54, 2, 3],
    &[54, 3],
    &[54, 4],
];

/// REG-1.32 — A BOARD SEEDED BEFORE THE REGISTRATION KIND GAINS ITS TEN ROWS
/// AT THE NEXT OPEN AND KEEPS ITS OTHERS: a kind or subtype row added later
/// is an image fact, a pin of a newer image seeded at that board's next
/// open. A board whose first open ran under the table less the ten rows —
/// the kind `3.54`, its parent rows, the rows beneath them, the vouch and
/// the approval hidden from it — stands ten links short of a fresh board's
/// head; the next open under the whole table writes the ten sections in one
/// insert, publishes them and links each — 40 records — and its one line
/// says `10 of N`. Each of the ten then has one `defines` link whose `from`
/// reads as its section, the map's words; every other row keeps the one
/// link it had, never two; the reserve's other ordinals `3.51` to `3.53`
/// and the ordinals no row takes under the kind have none; and the board
/// stands where a fresh board of this build stands, `SEED_HEAD`, its head
/// moved by the ten rows.
#[test]
fn a_board_seeded_before_the_registration_rows_gains_the_ten_at_the_next_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let table = vocabulary();
    let family: Vec<&Definition> = REGISTRATION
        .iter()
        .map(|ordinals| {
            definition_at(&skep_registry::commons_type(ordinals))
                .unwrap_or_else(|| panic!("3.{ordinals:?} is a row of the table"))
        })
        .collect();
    let rows = family.len() as u64;
    for def in &family {
        hide_a_type_from_the_seed(dir.path(), def.address.clone());
    }
    let position = {
        let sd = spawn_unclaimed(dir.path());
        let port = sd.port();
        assert_eq!(open_line(&sd, table.len() - family.len(), 0).len(), 1, "{:?}", seed_lines(&sd));
        for def in &family {
            let links = definition_links(port, None, &def.address.to_string());
            assert!(links.is_empty(), "{}: a hidden row has no link: {links:?}", def.address);
        }
        let position = log_position(port);
        assert_eq!(position, SEED_HEAD - rows * SEED_LINK_RECORDS, "ten links fewer: the head before the kind");
        sd.shutdown();
        position
    };
    unhide_every_type_from_the_seed(dir.path());
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    let said = seed_lines(&sd);
    assert_eq!(said.len(), 1, "one line, and no failure: {said:?}");
    assert_eq!(open_line(&sd, family.len(), table.len() - family.len()), said, "ten types written, the rest stood");
    assert_eq!(
        log_position(port),
        position + 3 + 7 + rows * SEED_LINK_RECORDS,
        "one insert (3), one publish with its correspondence record (7), ten links (30)"
    );
    for def in table {
        let links = definition_links(port, None, &def.address.to_string());
        assert_eq!(links.len(), 1, "{}: one link, never two", def.address);
        assert_eq!(
            from_text(port, None, &links[0]),
            def.section(),
            "{}: readable off the surface",
            def.address
        );
    }
    for def in &family {
        let links = definition_links(port, None, &def.address.to_string());
        let section = from_text(port, None, &links[0]);
        assert_eq!(section.lines().next(), Some(def.name), "{}: the name alone on the first line", def.address);
    }
    for unnamed in ["51", "52", "53", "54.5", "54.1.3", "54.2.4"] {
        let links = definition_links(port, None, &format!("1.1.0.1.0.1.0.3.{unnamed}"));
        assert!(links.is_empty(), "3.{unnamed} names nothing: {links:?}");
    }
    sd.shutdown();

    // A fresh board of this build stands at the new figure: every row of the
    // table, the ten among them, a link each.
    let fresh = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(fresh.path());
    assert_eq!(vocabulary().len() as u64, SEED_TYPES, "the layout's size is the table's");
    assert_eq!(log_position(sd.port()), SEED_HEAD, "a fresh board's head");
    assert_eq!(SEED_HEAD, 415, "the head a fresh board stands at, every row of the table a link");
    sd.shutdown();
}

/// R4 — CUT SHORT: a refusal injected on the seed's fifth commit of its own
/// — the third link, `3.2`'s, after the insert, the publish, `defines`' and
/// `3.1`'s — is said once as a failure naming the type; the board serves;
/// the guest reads the two rows before it; the next open writes the rest and
/// none twice.
#[test]
fn a_seed_cut_short_by_a_refusal_is_said_once_and_finished_at_the_next_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let table = vocabulary();
    let (defines, enroll, retire) = (
        defines_type().to_string(),
        table[0].address.to_string(),
        &table[1],
    );
    refuse_the_seeds_commit_once(dir.path(), 5);
    {
        let sd = spawn_unclaimed(dir.path());
        let port = sd.port();
        let said = seed_lines(&sd);
        assert_eq!(said.len(), 2, "the failure, then the open's line of what was written: {said:?}");
        assert_eq!(
            said[0],
            format!(
                "failure: link-type registry: the make_link for the type {} ({}) was refused \
                 (durability: the test seam's refusal); 2 of {} types stand, the rest wait for \
                 the next open; the board serves",
                retire.address,
                retire.name,
                table.len()
            )
        );
        assert_eq!(open_line(&sd, 2, 0), said[1..], "two types written before the refusal");
        // The board serves: health answers, a guest reads the two rows.
        let (st, _) = get(port, "/health");
        assert_eq!(st, 200, "the board serves on");
        assert_eq!(definition_links(port, None, &defines).len(), 1);
        assert_eq!(definition_links(port, None, &enroll).len(), 1);
        assert!(definition_links(port, None, &retire.address.to_string()).is_empty());
        assert!(definition_links(port, None, &table[2].address.to_string()).is_empty());
        assert_eq!(
            log_position(port),
            SEED_PUBLISH_AT + SEED_LINK_RECORDS * 2,
            "the insert, the publish with its correspondence record, and two links"
        );
        sd.shutdown();
    }
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    assert_eq!(open_line(&sd, table.len() - 2, 2), seed_lines(&sd), "the rest written, two stood, no failure");
    assert_eq!(log_position(port), SEED_HEAD, "the links alone: no second section, no second member");
    for def in table {
        let links = definition_links(port, None, &def.address.to_string());
        assert_eq!(links.len(), 1, "{}: one link, none twice", def.address);
        assert_eq!(from_text(port, None, &links[0]), def.section());
    }
    sd.shutdown();
}

/// R5 — THE WRITER: every seed commit's row on `/changes` testifies
/// `system`; the staging draft `1.1.0.1.0.3` is the one private document
/// under the system account, withheld from a guest on `doc_metadata` and
/// `retrieve_v` alike, and no document is minted under the account across
/// the seed and the claim's head: the time document `1.1.0.1.0.4` answers
/// published, as genesis seeds it, and the account's second document by its
/// counter — where its first mint would land, past the reserved block — is
/// unregistered. The address probed is held to the namespace's own answer
/// for that mint, so the probe cannot pass by reading a number no mint
/// fills.
#[test]
fn the_seed_writes_as_the_system_principal_through_the_one_staging_draft() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let (st, body) = get(port, "/changes?since=0&limit=4096");
    assert_eq!(st, 200);
    let rows = json(&body)["changes"].as_array().expect("changes").clone();
    let seed_rows: Vec<&Value> = rows.iter().filter(|r| r["at"].as_u64().is_some_and(|at| at <= SEED_HEAD)).collect();
    assert_eq!(
        seed_rows.iter().map(|r| r["at"].as_u64().expect("at")).collect::<Vec<_>>(),
        seed_ats(),
        "the guest sees the publish and the links; the draft's one write is masked"
    );
    assert_eq!(seed_rows[0]["op"].as_str(), Some("publish"));
    assert_eq!(seed_rows[0]["docs"], serde_json::json!([format!("{REGISTRY}.1")]), "the member minted");
    for row in &seed_rows[1..] {
        assert_eq!(row["op"].as_str(), Some("make_link"), "{row}");
        assert_eq!(row["docs"], serde_json::json!([REGISTRY]), "homed in the registry: {row}");
        assert!(row["link"].as_str().is_some_and(|l| l.starts_with(&format!("{REGISTRY}.0.2."))), "{row}");
    }
    for row in &seed_rows {
        assert_eq!(row["key"].as_str(), Some("system"), "the system principal's: {row}");
        assert!(row.get("attest").is_none(), "unsigned: {row}");
    }
    // The staging draft, private, on both reads that take a document; the
    // time document, published; and no document minted under the system
    // account after the seed and the claim's head.
    let draft = doc_metadata(port, None, STAGING_DRAFT);
    assert_eq!(expect_resp(&draft, "rejected")["code"].as_str(), Some("withheld"), "{draft}");
    let read = op(
        port,
        None,
        &format!(
            r#"{{"op":"retrieve_v","specs":[{{"doc":"{STAGING_DRAFT}",{}}}]}}"#,
            FIRST_POSITION
        ),
    );
    assert_eq!(expect_resp(&read, "rejected")["code"].as_str(), Some("withheld"), "{read}");
    let time = doc_metadata(port, None, TIME_DOCUMENT);
    assert_eq!(expect_resp(&time, "doc_metadata")["published"].as_bool(), Some(true), "{time}");
    let first_mint = nth_document(&skep_namespace::system_account().to_string(), 2);
    assert_eq!(
        first_mint,
        system_accounts_first_mint(),
        "the probe reads where a mint under the system account would land"
    );
    let unminted = doc_metadata(port, None, &first_mint);
    assert_eq!(
        expect_resp(&unminted, "rejected")["code"].as_str(),
        Some("doc_not_registered"),
        "{unminted}"
    );
    sd.shutdown();
}

/// R6 — THE CEREMONY's NUMBERS on the seeded board: the claim lands at
/// `SEED_HEAD + 12`, `H.1` names it and its records above it are the head's
/// insert and publish (the draft stands from genesis), and `/changes` from
/// position 0 lists the seed's commits first, each the system principal's,
/// then the ceremony's.
#[test]
fn the_claim_lands_twelve_records_above_the_seed_and_the_feed_lists_the_seed_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    claim_board(port);
    let claim_at = board_term(port).expect("H.1").log_position;
    assert_eq!(claim_at, SEED_HEAD + 12, "the ceremony's fifth commit, twelve records above the seed");
    assert_eq!(
        head_position(port),
        claim_at + 10,
        "H.1: the insert (3) and the publish with its correspondence record (7), no draft mint"
    );
    let (st, body) = get(port, "/changes?since=0&limit=4096");
    assert_eq!(st, 200);
    let rows = json(&body)["changes"].as_array().expect("changes").clone();
    let ats: Vec<u64> = rows.iter().map(|r| r["at"].as_u64().expect("at")).collect();
    let mut want = seed_ats();
    want.extend([SEED_HEAD + 2, SEED_HEAD + 3, SEED_HEAD + 6, SEED_HEAD + 9, SEED_HEAD + 12, claim_at + 10]);
    assert_eq!(ats, want, "the seed's rows, the ceremony's five, H.1's publish");
    for row in rows.iter().take(seed_ats().len()) {
        assert_eq!(row["key"].as_str(), Some("system"), "{row}");
    }
    sd.shutdown();
}

/// R7 — THE PINS EQUAL THE TABLE: every commons type address the workspace
/// pins in code is a row — the engine's ledger, the registry's rows, the
/// link store's `replaces`, the media crate's picture kind and the blind
/// kind the suites spell, each read as a value where this crate can see it;
/// and every `1.1.0.1.0.1.0.3.<path>` literal in a crate's non-test source
/// (the client's, the command's and the resolver's among them), read off
/// the sources themselves, since no suite here links them.
#[test]
fn every_pin_the_workspace_holds_is_a_row_of_the_table() {
    use skep_engine::types;

    let row = |a: &skep_address::Address| definition_at(a).map(|d| d.name);
    let typed: &[(&str, &skep_address::Address)] = &[
        ("enroll", types::t_enroll()),
        ("retire", types::t_retire()),
        ("claim", types::t_claim()),
        ("grant", types::t_grant()),
        ("edition", types::t_edition()),
        ("successor-of", types::t_successor_of()),
        ("endorse", types::t_endorse()),
        ("consumption-marker", types::t_consumption_marker()),
        ("journal-designation", types::t_journal_designation()),
        ("rail-record", types::t_rail_record()),
        ("steward-classification", types::t_steward_classification()),
        ("replaces", types::t_replaces()),
        ("registration", types::t_registration()),
        ("request", types::t_request()),
        ("fresh", types::t_request_fresh()),
        ("board-carries-on", types::t_request_board_carries_on()),
        ("reply", types::t_reply()),
        ("approved", types::t_reply_approved()),
        ("refused", types::t_reply_refused()),
        ("denied", types::t_reply_denied()),
        ("vouch", types::t_vouch()),
        ("approval", types::t_approval()),
        ("binding", types::t_binding()),
        ("endpoint", types::t_endpoint()),
        ("takedown-record", types::t_takedown()),
        ("takedown", types::t_takedown_base()),
        ("lifted", types::t_takedown_lifted()),
        ("policy-link", types::t_policy_link()),
        ("policy", types::t_policy_link_own()),
        ("disavowal", types::t_disavowal()),
        ("expulsion-ground", types::t_expulsion_ground()),
        ("succession-ground", types::t_succession_ground()),
        ("succession-policy", types::t_succession_policy()),
        ("read-with", types::t_read_with()),
        ("correspondence", types::t_correspondence()),
        ("held-removal", types::t_held_removal()),
        ("marks", types::t_marks()),
    ];
    for &(name, pin) in typed {
        assert_eq!(row(pin), Some(name), "the engine's pin {pin} is the row named {name}");
    }
    for r in skep_registry::rows() {
        assert!(row(&r.address).is_some(), "the registry row {} is in the table", r.address);
    }
    assert_eq!(row(skep_links::replaces_type()), Some("replaces"), "the link store's own spelling");
    assert_eq!(row(skep_links::correspondence_type()), Some("correspondence"), "the link store's second own spelling");
    let address = |s: &str| skep_core::codec::wire_address(s).expect("an address");
    assert_eq!(row(&address(skep_media::cell::KIND)), Some("picture-cell"), "the picture cell's kind");
    assert_eq!(row(&address(BLIND_KIND)), Some("blind-cell"), "the blind cell's kind, as the suites spell it");

    // Every literal in non-test source, workspace-wide.
    let mut literals = std::collections::BTreeSet::new();
    for (file, code) in non_test_sources() {
        for literal in type_literals(&code) {
            literals.insert((literal, file.clone()));
        }
    }
    assert!(literals.len() >= 10, "the pins were read: {literals:?}");
    let mut unknown = Vec::new();
    for (literal, file) in &literals {
        if definition_at(&address(literal)).is_none() {
            unknown.push(format!("{literal} in {file}"));
        }
    }
    assert!(unknown.is_empty(), "every pinned type is a row of the table; these are not:\n{}", unknown.join("\n"));
    println!("{} type literals in non-test code, each a row: {literals:?}", literals.len());
}

/// Every `1.1.0.1.0.1.0.3.<digits[.digits]*>` literal in `code`.
fn type_literals(code: &str) -> Vec<String> {
    const PREFIX: &str = "1.1.0.1.0.1.0.3.";
    let mut out = Vec::new();
    for (at, _) in code.match_indices(PREFIX) {
        let rest = &code[at + PREFIX.len()..];
        let path: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        let path = path.trim_end_matches('.');
        if !path.is_empty() && path.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())) {
            out.push(format!("{PREFIX}{path}"));
        }
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("a directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every crate's non-test source, as R7 walks it: each `.rs` file under a
/// crate's `src` that is no `tests.rs` and lies under no `tests` directory,
/// by its path under `crates/`, its text cut at its inline test module.
fn non_test_sources() -> Vec<(String, String)> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&crates).expect("the crates directory") {
        let src = entry.expect("an entry").path().join("src");
        if src.is_dir() {
            rust_files(&src, &mut files);
        }
    }
    assert!(files.len() > 100, "the workspace's sources were walked: {}", files.len());
    let mut sources = Vec::new();
    for file in &files {
        let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let in_tests = name == "tests.rs" || file.iter().any(|c| c == "tests");
        if in_tests {
            continue;
        }
        let text = std::fs::read_to_string(file).expect("a source file");
        let code = text.split("\nmod tests {").next().unwrap_or("");
        let code = code.split("\n    mod tests {").next().unwrap_or("");
        let file = file.strip_prefix(&crates).expect("under crates").display().to_string();
        sources.push((file, code.to_string()));
    }
    sources
}

/// THE READER-STATE FAMILY IS THE TABLE's ALONE: no source outside
/// `skep-registry`'s vocabulary names an address at or under `3.46`. Over
/// R7's walk no dotted literal names one — R7 itself passes such a literal,
/// since it is a row — and over the same files, the table's own apart, none
/// is spelled through a commons-type builder at the ordinal or as an address
/// array through the type subspace. THE BOARD's HALF IS FOR GOOD: a board
/// never asks for a reader's state link, writes one or derives one (the
/// mailbox decision, item J), so no crate the daemon is built from names
/// the family. THE CLIENTS' HALF HOLDS WHILE NO CLIENT WRITES ONE: it is
/// lifted for the client crate that builds a reader's own setting, and for
/// no other.
#[test]
fn no_source_outside_the_table_names_a_reader_state_address() {
    // The readers see each form they are to refuse and pass its near misses.
    for refused in [
        "commons_type(&[46])",
        "skep_registry::commons_type(&[46, 1])",
        "commons_type( &[ 46 , 3 ] )",
        "commons_type(46)",
        "commons_subtype(&[46, 1])",
        "Tumbler::new([1u32, 1, 0, 1, 0, 1, 0, 3, 46].map(Nat::from))",
        "addr(&[1, 1, 0, 1, 0, 1, 0, 3, 46, 5])",
    ] {
        assert_eq!(reader_state_spellings(refused).len(), 1, "the reader sees {refused:?}");
    }
    for passed in [
        "commons_type(&[45])",
        "commons_type(&[460])",
        "commons_type(ordinals)",
        "commons_subtype(&[102, 46])",
        "addr(&[1, 1, 0, 1, 0, 1, 0, 3, 4, 6])",
        "addr(&[1, 1, 0, 1, 0, 1, 0, 3, 461])",
        "addr(&[1, 0, 1, 0, 3, 46])",
        "[45, 46, 47]",
        "the rule AUTH-3.46",
    ] {
        assert!(reader_state_spellings(passed).is_empty(), "the reader passes {passed:?}");
    }
    for (literal, named) in [
        ("1.1.0.1.0.1.0.3.46", true),
        ("1.1.0.1.0.1.0.3.46.1", true),
        ("1.1.0.1.0.1.0.3.45", false),
        ("1.1.0.1.0.1.0.3.460", false),
        ("1.1.0.1.0.1.0.3.4", false),
    ] {
        assert_eq!(
            type_literals(&format!("the type `{literal}`.")),
            [literal],
            "R7's reader sees {literal}"
        );
        assert_eq!(names_reader_state(literal), named, "{literal}: at or under 3.46");
    }

    // The tree: the table's own file is walked and spells the family, and no
    // other source does.
    const TABLE: &str = "skep-registry/src/vocabulary.rs";
    let sources = non_test_sources();
    let table = sources.iter().find(|(file, _)| file == TABLE).map(|(_, code)| code.as_str());
    assert!(
        table.is_some_and(|code| code.contains("ordinals: &[46, 1],")),
        "the walk reads the table's own file, where the family's rows are spelled: {TABLE}"
    );
    let mut literals = 0;
    let mut named = Vec::new();
    for (file, code) in &sources {
        for literal in type_literals(code) {
            literals += 1;
            if names_reader_state(&literal) {
                named.push(format!("{literal} in {file}"));
            }
        }
        if file != TABLE {
            named.extend(
                reader_state_spellings(code).into_iter().map(|form| format!("{form} in {file}")),
            );
        }
    }
    assert!(literals >= 10, "the pins were read: {literals}");
    assert!(
        named.is_empty(),
        "no source outside the table names a reader-state address — a board never asks for, writes \
         or derives one, and no client writes one; these do:\n{}",
        named.join("\n")
    );
}

/// Whether `literal` is the reader-state family's parent `3.46` or an
/// address under it.
fn names_reader_state(literal: &str) -> bool {
    literal
        .strip_prefix("1.1.0.1.0.1.0.3.46")
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
}

/// The spellings of a reader-state address `code` holds that are no dotted
/// literal: a commons-type builder called at the family's ordinal —
/// `skep-registry`'s `commons_type(&[46, …])`, the engine's twins
/// `commons_type(46)` and `commons_subtype(&[46, …])` — and an address array
/// through the commons type subspace to it, `[1, 1, 0, 1, 0, 1, 0, 3, 46,
/// …]`. `code` is read with its white space and its integer suffixes taken
/// out, and a longer number (`460`) is no match.
fn reader_state_spellings(code: &str) -> Vec<&'static str> {
    const FORMS: [&str; 4] =
        ["commons_type(&[46", "commons_type(46", "commons_subtype(&[46", "[1,1,0,1,0,1,0,3,46"];
    let joined: String = code.split_whitespace().collect();
    let mut text = String::with_capacity(joined.len());
    let mut rest = joined.as_str();
    while let Some(c) = rest.chars().next() {
        text.push(c);
        rest = &rest[c.len_utf8()..];
        if c.is_ascii_digit() {
            let suffix =
                ["u32", "u64", "usize"].into_iter().find(|suffix| rest.starts_with(suffix));
            rest = &rest[suffix.map_or(0, str::len)..];
        }
    }
    FORMS
        .into_iter()
        .filter(|form| {
            text.match_indices(form)
                .any(|(at, _)| !text[at + form.len()..].starts_with(|c: char| c.is_ascii_digit()))
        })
        .collect()
}

/// The table's own shape, as the wire reads it: a client that links
/// `skep-registry` reads a type's name off the table without a board, and
/// the board's answer agrees with it.
#[test]
fn the_tables_names_and_the_boards_agree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    let citation: &Definition = definition_at(&skep_registry::commons_type(&[13])).expect("citation");
    assert_eq!(citation.name, "citation");
    let links = definition_links(port, None, "1.1.0.1.0.1.0.3.13");
    assert_eq!(from_text(port, None, &links[0]).lines().next(), Some("citation"));
    sd.shutdown();
}
