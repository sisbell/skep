//! The merge journal over the scripted board: named, found or minted.
//!
//! The suite checks `journal::of` — the journal named answered with no
//! read, the default found by the account's own links of the kind, or a
//! private draft minted where none is found — the find, a class scan,
//! reissued while the board is busy, and walked a journal at a time, so its
//! cost is the journals' count and never the records'.

use super::*;

/// `journal::of`: the journal named is answered with no read; the
/// default is found by the account's own links of the kind — `window_ftt`
/// pages of one link with `home` the account, one past each home and one
/// more — each home read by its earliest link alone: a home whose link's
/// `from` lies outside it is no journal, a sub-account's home ends the walk
/// and is never read, and the journals are taken in the order their
/// earliest links were minted, the first a private draft of the account's
/// — a published one passed over — read before it is taken; with none, a
/// PRIVATE draft is minted.
#[test]
fn the_journal_is_named_found_or_minted() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merger = merger(&session, &signer);
    dialer.clear();
    assert_eq!(
        journal::of(&board, &merger, &a(K), Some(a("1.0.1.0.69"))).expect("named"),
        a("1.0.1.0.69")
    );
    assert!(dialer.ops().is_empty());
    let minted = journal::of(&board, &merger, &a(K), None).expect("minted");
    assert_eq!(minted, a("1.0.1.0.72"));
    assert_eq!(dialer.frames("create_new_document")[0]["published"], false);
    assert_eq!(dialer.ops(), ["window_ftt", "create_new_document"]);
    let page = &dialer.frames("window_ftt")[0];
    let q = &page["q"];
    assert_eq!(
        (
            q["home"][0]["start"].as_str(),
            q["ty"][0]["start"].as_str(),
            q["from"].as_str(),
            q["to"].as_str(),
            &page["cur"],
            page["n"].as_u64()
        ),
        (Some(ACCOUNT), Some(K), Some("any"), Some("any"), &Value::Null, Some(1)),
        "the account's own links of the kind, a page of one from the start"
    );
    let record = compose(&board, Some(&token()), &race_inputs()).expect("composed").record;
    {
        let mut w = dialer.world();
        w.doc("1.0.1.0.68", false, ACCOUNT, Vec::new());
        file(&mut w, "1.0.1.0.68", &record, &[&format!("{D}.1.1")], Some(30));
    }
    dialer.clear();
    assert_eq!(journal::of(&board, &merger, &a(K), None).expect("found"), a("1.0.1.0.68"));
    assert_eq!(dialer.ops(), ["window_ftt", "window_ftt", "read_link", "doc_metadata"]);
    assert_eq!(
        dialer.frames("window_ftt")[1]["cur"],
        "1.0.1.0.68.0.3",
        "the next page asked past the journal's every link"
    );
    // A second journal, at a greater address, whose first record went
    // in earlier, holding two: its earliest link alone read, and it is
    // the journal the account's first record went to.
    {
        let mut w = dialer.world();
        w.doc("1.0.1.0.74", false, ACCOUNT, Vec::new());
        file(&mut w, "1.0.1.0.74", &record, &[&format!("{D}.1.1")], Some(20));
        file(&mut w, "1.0.1.0.74", &record, &[&format!("{D}.1.1")], Some(40));
    }
    dialer.clear();
    assert_eq!(
        journal::of(&board, &merger, &a(K), None).expect("found"),
        a("1.0.1.0.74"),
        "the journal the first record went to"
    );
    assert_eq!(
        dialer.ops(),
        ["window_ftt", "window_ftt", "window_ftt", "read_link", "read_link", "doc_metadata"]
    );
    assert_eq!(
        dialer.frames("read_link").iter().map(|f| f["a"].clone()).collect::<Vec<_>>(),
        [json!("1.0.1.0.68.0.2.1"), json!("1.0.1.0.74.0.2.1")],
        "each home's earliest link, once"
    );
    assert_eq!(dialer.frames("doc_metadata")[0]["doc"], "1.0.1.0.74");
    // That journal published: passed over for the next.
    dialer.world().docs.get_mut("1.0.1.0.74").unwrap().published = true;
    dialer.clear();
    assert_eq!(
        journal::of(&board, &merger, &a(K), None).expect("found"),
        a("1.0.1.0.68"),
        "the private draft, never the published document"
    );
    assert_eq!(
        dialer.ops(),
        [
            "window_ftt",
            "window_ftt",
            "window_ftt",
            "read_link",
            "read_link",
            "doc_metadata",
            "doc_metadata"
        ]
    );
    // A link of the kind homed in doc 1, its `from` in a journal, and a
    // sub-account's record: no journal of the account's own, so doc 1's
    // link is read and passed over, the sub-account's ends the walk and is
    // never read, and a journal minted.
    {
        let mut w = dialer.world();
        w.links.clear();
        w.links.push(LinkRow {
            addr: format!("{DOC1}.0.2.1"),
            home: DOC1.into(),
            from: vec![i_addr(&a("1.0.1.0.68"), 1)],
            to: vec![format!("{D}.1.1")],
            ty: K.into(),
            width: 1,
            at: Some(10),
        });
        file(&mut w, "1.0.1.2.0.65", &record, &[&format!("{D}.1.1")], Some(5));
    }
    dialer.clear();
    assert_eq!(
        journal::of(&board, &merger, &a(K), None).expect("minted"),
        a("1.0.1.0.72"),
        "the mint's id answered by the board's memo"
    );
    assert_eq!(dialer.ops(), ["window_ftt", "window_ftt", "read_link", "create_new_document"]);
    assert_eq!(
        dialer.frames("read_link")[0]["a"],
        format!("{DOC1}.0.2.1"),
        "doc 1's link alone read"
    );
}

/// THE JOURNAL'S FIND IS REISSUED WHILE THE BOARD IS BUSY: the find, a
/// class scan, refused `scan_busy` on its first send and on each of its
/// reissues but the last is sent again, nothing written between, and the
/// record is written once. Refused on every send, the record is not
/// written: `land` answers the merge standing with its record unwritten,
/// a halt naming the board's busy refusal, no journal minted and no atom
/// or link sent; `journal::of` answers the board's refusal itself.
#[test]
fn the_journals_find_is_reissued_while_the_board_is_busy() {
    let reissues = crate::publication::SCAN_BUSY_REISSUES as usize;
    let account_finds = |dialer: &Scripted| {
        dialer
            .frames("window_ftt")
            .iter()
            .filter(|f| f["q"]["home"][0]["start"] == ACCOUNT)
            .count()
    };
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.world().scan_busy = reissues;
    dialer.clear();
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    assert!(matches!(landed, Landed::Member { .. }), "{landed:?}");
    assert_eq!(account_finds(&dialer), reissues + 1, "the first send and each reissue");
    assert_eq!(
        (
            dialer.frames("create_new_document").len(),
            dialer.frames("insert").len(),
            dialer.frames("make_link").len()
        ),
        (1, 1, 1),
        "the record, once: {:?}",
        dialer.ops()
    );
    // Busy on every send: the merge standing, nothing of the record sent.
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    too_busy_for_the_find(&mut dialer.world());
    dialer.clear();
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("the record unwritten");
    let Refusal::Halt(halt) = &err else { panic!("{err:?}") };
    assert_eq!(halt.exit_code(), 3, "a halt, never the board's refusal: {err:?}");
    let Halt::Halt(face) = halt else { panic!("{err:?}") };
    assert!(
        face.state
            .contains(&format!("the merge stands at {D}.3, and its record is not written")),
        "{face}"
    );
    assert!(face.cause.starts_with("scan_busy:"), "{face}");
    assert_eq!(account_finds(&dialer), reissues + 1, "never past the bound");
    for op in ["create_new_document", "insert", "make_link"] {
        assert!(dialer.frames(op).is_empty(), "no `{op}`: {:?}", dialer.ops());
    }
    assert!(dialer.world().docs.contains_key(&format!("{D}.3")), "the shot stands");
    too_busy_for_the_find(&mut dialer.world());
    let err = journal::of(&board, &merger(&session, &signer), &a(K), None).expect_err("busy");
    assert!(
        matches!(&err, Refusal::Halt(Halt::Refused(r)) if r.code == "scan_busy" && r.status == 503),
        "{err:?}"
    );
}

/// THE FIND COSTS A PAGE A JOURNAL, WHATEVER THE RECORDS: `journal::of`
/// over an account with R records in one journal, one in another and three
/// in a sub-account's journal answers the journal the first record went to
/// with three `window_ftt` pages of one link at R = 2 and at R = 40 alike —
/// a page per journal of the account's own and the page whose link is the
/// sub-account's, which ends the walk — and reads each journal's earliest
/// link alone, the sub-account's never. So no answer of the find grows with
/// the records an account holds (the mutant reading every record link in
/// one `find_links_ftt` sends no page; the one resuming past the link and
/// not past its home pages through every record).
#[test]
fn the_journals_find_costs_a_page_a_journal_whatever_the_records() {
    for records in [2u64, 40] {
        let (dialer, board, signer) = open(World::race());
        let session = sign_in(&board, &signer);
        let merger = merger(&session, &signer);
        let record = compose(&board, Some(&token()), &race_inputs()).expect("composed").record;
        {
            let mut w = dialer.world();
            w.doc("1.0.1.0.68", false, ACCOUNT, Vec::new());
            w.doc("1.0.1.0.74", false, ACCOUNT, Vec::new());
            for k in 0..records {
                file(&mut w, "1.0.1.0.68", &record, &[&format!("{D}.1.1")], Some(10 + k));
            }
            file(&mut w, "1.0.1.0.74", &record, &[&format!("{D}.1.1")], Some(100));
            for k in 0..3 {
                file(&mut w, "1.0.1.1.0.5", &record, &[&format!("{D}.1.1")], Some(1 + k));
            }
        }
        dialer.clear();
        assert_eq!(
            journal::of(&board, &merger, &a(K), None).expect("found"),
            a("1.0.1.0.68"),
            "R = {records}: the journal the account's first record went to"
        );
        assert_eq!(
            dialer.ops(),
            ["window_ftt", "window_ftt", "window_ftt", "read_link", "read_link", "doc_metadata"],
            "R = {records}"
        );
        let pages = dialer.frames("window_ftt");
        assert_eq!(
            pages
                .iter()
                .map(|page| (page["cur"].clone(), page["n"].clone()))
                .collect::<Vec<_>>(),
            [
                (Value::Null, json!(1)),
                (json!("1.0.1.0.68.0.3"), json!(1)),
                (json!("1.0.1.0.74.0.3"), json!(1))
            ],
            "R = {records}: one page past each journal, a link a page"
        );
        assert_eq!(
            dialer.frames("read_link").iter().map(|f| f["a"].clone()).collect::<Vec<_>>(),
            [json!("1.0.1.0.68.0.2.1"), json!("1.0.1.0.74.0.2.1")],
            "R = {records}: each journal's earliest link, the sub-account's never"
        );
    }
}
