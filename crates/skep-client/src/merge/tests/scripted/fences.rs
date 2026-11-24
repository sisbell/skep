//! The fences the merge module keeps, over the scripted board.
//!
//! The suite checks that the one class scan the module sends is the
//! journal's find, that `head_of` walks the feed to the last trunk
//! publish, that a composition and a landing read nothing at a
//! position, so a busy history pool stops neither, and that a walk of the
//! drafts supplement asks the wire's whole page.

use super::*;

/// A COMPOSITION AND A LANDING REBUILD NO PAST STATE (skep #1144; the
/// owner's ruling of 2026-11-22): the race shape composed and landed by a
/// shot, and a draft side composed and landed by a shot — its words read
/// by identity — or in its draft, send no frame through `/op-at`, every
/// read at the head, the sides that can change fenced and every value read
/// at the head. So a board whose history pool answers `history_busy` to
/// every read at a position composes and lands each all the same, the pool
/// never asked (the mutant that leaves any read at the composition's
/// position meets the busy pool and refuses `HistoryBusy`).
#[test]
fn a_composition_and_a_landing_read_nothing_at_a_position_and_a_busy_history_stops_neither() {
    let draft_side = Inputs { sides: vec![Side::Draft { at: a(S), position: None }], ..race_inputs() };
    let race = World::race as fn() -> World;
    let cells = [
        ("the race shape, by a shot", race, race_inputs(), false),
        ("a draft side, by a shot", World::window_and_draft, draft_side.clone(), false),
        ("a draft side, in its draft", World::window_and_draft, draft_side, true),
    ];
    for busy in [0, 10] {
        for (cell, world, inputs, in_draft) in &cells {
            let mut w = world();
            w.busy = busy;
            let (dialer, board, signer) = open(w);
            let session = sign_in(&board, &signer);
            let merged = compose(&board, Some(session.token()), inputs)
                .unwrap_or_else(|e| panic!("{cell}, busy {busy}: {e:?}"));
            let landing = if *in_draft {
                draft_landing(&session, &signer, Some(a(S)))
            } else {
                shot(&session, &signer)
            };
            land(&board, &merged, landing).unwrap_or_else(|e| panic!("{cell}, busy {busy}: {e:?}"));
            let ops = dialer.ops();
            assert!(ops.iter().all(|o| !o.starts_with("at:")), "{cell}: nothing read at a position: {ops:?}");
            assert_eq!(dialer.world().busy, busy, "{cell}: the history pool never asked");
        }
    }
}

/// THE ONE CLASS SCAN IS THE JOURNAL'S FIND: of every link query the
/// module sends — composing, landing, looking a record up, finding the
/// journal — the ones that walk every home under an account are the
/// default journal's find, `window_ftt` pages of one link with `home` the
/// merger's account and `ty` the kind (the `journal` module's doc): one
/// page for each record written with no journal named into an account
/// holding none, and for `journal::of` one page past each journal and one
/// more; every `find_links_ftt` constrains `to` or `from`, or a `home`
/// naming one document, and takes no permit (wire.md §Link discovery
/// reads). A record written into a journal named sends no class scan. The
/// frame constructors answer the same test.
#[test]
fn the_one_class_scan_the_module_sends_is_the_journals_find() {
    let class_scan = |q: &Value| {
        let home = q["home"][0]["start"].as_str();
        let one_document =
            home.is_some_and(|h| crate::address::document_of(h).as_deref() == Some(h));
        q["to"] == "any" && q["from"] == "any" && !one_document
    };
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    current(&board, Some(&token()), &a(K), &merged.key).expect("the lookup");
    let found = journal::of(&board, &merger(&session, &signer), &a(K), None).expect("the journal");
    let journal = dialer.frames("insert")[0]["doc"]
        .as_str()
        .expect("the record's journal")
        .to_string();
    assert_eq!(
        found.to_string(),
        journal,
        "the premise: `journal::of` finds the journal minted"
    );
    let queries = dialer.frames("find_links_ftt");
    assert!(!queries.is_empty(), "the premise: the lookups sent their reads");
    assert!(
        queries.iter().all(|f| !class_scan(&f["q"])),
        "no class scan: {queries:?}"
    );
    let pages = dialer.frames("window_ftt");
    for page in &pages {
        let q = &page["q"];
        assert!(class_scan(q), "{q}");
        assert_eq!(
            (
                q["home"][0]["start"].as_str(),
                q["ty"][0]["start"].as_str(),
                page["n"].as_u64()
            ),
            (Some(ACCOUNT), Some(K), Some(1)),
            "{page}"
        );
    }
    let cursors: Vec<&Value> = pages.iter().map(|page| &page["cur"]).collect();
    assert_eq!(
        cursors,
        [&Value::Null, &Value::Null, &json!(format!("{journal}.0.3"))],
        "the landing's record into an account holding none, then `journal::of` past the journal"
    );
    // The record written into a journal named: no class scan.
    let (dialer, board, signer) = open(World::race());
    dialer.world().doc("1.0.1.0.68", false, ACCOUNT, Vec::new());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let named = Landing::Shot {
        merger: merger(&session, &signer),
        draft: None,
        answers: Answers::default(),
        journal: Some(a("1.0.1.0.68")),
    };
    land(&board, &merged, named).expect("landed");
    assert_eq!(
        dialer.frames("insert")[0]["doc"],
        "1.0.1.0.68",
        "the premise: the record in the journal named"
    );
    assert!(
        dialer.frames("find_links_ftt").iter().all(|f| !class_scan(&f["q"])),
        "no class scan: {:?}",
        dialer.frames("find_links_ftt")
    );
    assert_eq!(
        dialer.frames("window_ftt"),
        Vec::<Value>::new(),
        "no page of the account's homes"
    );
    for frame in [
        frames::find_links_ftt(K, D),
        frames::find_links_ftt_from(K, D),
        frames::find_links_ftt_home(K, DOC1),
    ] {
        assert!(!class_scan(&frame["q"]), "no class scan: {frame}");
    }
    let account = frames::unit_span(ACCOUNT).as_array().cloned().unwrap_or_default();
    let kind = frames::unit_span(K).as_array().cloned().unwrap_or_default();
    let walked = frames::window_four(
        frames::Slot::Spans(&account),
        frames::Slot::Any,
        frames::Slot::Any,
        frames::Slot::Spans(&kind),
        None,
        1,
    );
    for frame in [frames::find_links_ftt_home(K, ACCOUNT), walked] {
        assert!(class_scan(&frame["q"]), "an account's homes, walked: {frame}");
    }
}

/// THE HEAD-MEMBER FALLBACK: `head_of` walks the document's feed rows
/// to the last `publish` row naming a TRUNK member — a daughter's row
/// after it does not move the head — and follows the trunk after a
/// shot; `None` for a document with no member.
#[test]
fn head_of_walks_the_feed_to_the_last_trunk_publish() {
    let (dialer, board, signer) = open(World::race());
    assert_eq!(
        head_of(&board, Some(&token()), &a(D)).expect("walked"),
        Some(a(&format!("{D}.2"))),
        "the daughter's later row does not move the head"
    );
    assert_eq!(head_of(&board, Some(&token()), &a(Z)).expect("walked"), None);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    assert_eq!(
        head_of(&board, Some(&token()), &a(D)).expect("walked"),
        Some(a(&format!("{D}.3")))
    );
    let under: Vec<String> =
        dialer.ops().into_iter().filter(|o| o.starts_with("GET /changes?")).collect();
    assert!(
        under.iter().all(|u| u.contains("&under=")),
        "every walk is narrowed to its document: {under:?}"
    );
    assert_eq!(
        under.iter().filter(|u| u.ends_with(&format!("under={D}"))).count(),
        2,
        "{under:?}"
    );
}

/// A WALK OF THE DRAFTS SUPPLEMENT ASKS THE WIRE'S WHOLE PAGE: a draft's own
/// rows carry no `attest`, so every walk over them asks 4096 rows a page, the
/// wire's most, and the walk that judges a draft with no recorded base reads
/// its 600 and its 1,200 plain rows in one `GET /changes` each (the mutant
/// asking the default 256 a page reads three and five).
#[test]
fn a_walk_of_the_drafts_supplement_asks_the_wires_whole_page() {
    for plain in [600, 1200] {
        let mut w = World::window_and_draft();
        for _ in 0..plain {
            w.position += 1;
            let at = w.position;
            w.rows.push(FeedRow {
                at,
                op: "set_arrangement",
                docs: vec![S.into()],
                terms: Some((None, None)),
            });
        }
        let (dialer, board, _) = open(w);
        assert_eq!(
            baseless_landing(&board, Some(&token()), &a(S)),
            Ok(None),
            "{plain} rows, no landing"
        );
        let pages: Vec<String> = dialer
            .ops()
            .into_iter()
            .filter(|o| o.starts_with("GET /changes?"))
            .collect();
        assert_eq!(pages.len(), 1, "{plain} rows: {pages:?}");
        assert!(pages[0].contains("limit=4096"), "{pages:?}");
    }
}
