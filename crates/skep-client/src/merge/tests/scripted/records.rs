//! The merge record over the scripted board: its currency and `verify`.
//!
//! The suite checks that a record this library writes is an atom no
//! publication publishes; `current` — the trunk owner's home first, then
//! the newest, the record whose link was minted last, and the owner's over
//! a sub-account's; `landing_record`, a draft's own landing record read
//! through the draft once the merge landed in another, another account's
//! records, another merge's, a landing past the marker's and a record a
//! take-back replaced passed over; `verify`'s verdicts, a withheld input
//! withholding the verdict and an unregistered one refused, a withheld run
//! in a readable side refused naming its origin, its images read as of one
//! position and its values at the head, a moved gap of two groups
//! landing and verifying equal; and the `Record`'s JSON round trip, its
//! `type` fixed.

use super::*;

/// A record this library writes is an atom no publication publishes.
///
/// Its JSON as a journal's atom carries it is a merge record by the
/// publication's one test (`publication::is_merge_record`), at another
/// schema version too; a text, another JSON kind and a bare word are
/// none.
#[test]
fn a_record_this_library_writes_is_one_no_publication_publishes() {
    let (_, board, _) = open(World::race());
    let merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
    let atom = merged.record.to_value();
    assert!(crate::publication::is_merge_record(atom.to_string().as_bytes()), "{atom}");
    let mut later = atom.clone();
    later["v"] = json!(record::SCHEMA_VERSION + 1);
    assert!(
        crate::publication::is_merge_record(later.to_string().as_bytes()),
        "another schema version stays private too"
    );
    for other in [&b"merge"[..], b"{", br#"{"type":"skep-head"}"#, br#"["merge"]"#, b"m"] {
        assert!(
            !crate::publication::is_merge_record(other),
            "{}",
            String::from_utf8_lossy(other)
        );
    }
}

/// `current` finds the newest record per key, the trunk owner's home
/// over another account's: another account's landed record loses to
/// the owner's question; two in the owner's home, the later link wins;
/// a record of another key is no candidate, nor one whose journal is
/// unreadable. The atom is read THROUGH the journal's arrangement.
#[test]
fn current_prefers_the_trunk_owners_home_then_the_newest() {
    let (dialer, board, _) = open(World::race());
    let merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
    assert_eq!(merged.prior, None);
    let daughter = format!("{D}.1.1");
    let mut other = merged.record.clone();
    other.landed = Some(RecordLanding::Member { member: a(&format!("{D}.3")), position: 99 });
    let other_link = {
        let mut w = dialer.world();
        w.doc("1.0.2.0.67", false, "1.0.2", Vec::new());
        file(&mut w, "1.0.2.0.67", &other, &[&format!("{D}.3"), &daughter], None)
    };
    let found = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(
        (found.link.as_ref().map(ToString::to_string), found.landed.clone()),
        (Some(other_link.clone()), other.landed.clone()),
        "the one record stands"
    );
    let question = merged.record.clone();
    let owners_link = {
        let mut w = dialer.world();
        w.doc("1.0.1.0.67", false, ACCOUNT, Vec::new());
        file(&mut w, "1.0.1.0.67", &question, &[&daughter], None)
    };
    let found = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(
        (found.link.as_ref().map(ToString::to_string), found.landed.clone()),
        (Some(owners_link), None),
        "the trunk owner's home is current over another's"
    );
    let mut later = merged.record.clone();
    later.landed = Some(RecordLanding::Member { member: a(&format!("{D}.3")), position: 120 });
    let later_link =
        file(&mut dialer.world(), "1.0.1.0.67", &later, &[&format!("{D}.3"), &daughter], None);
    let mut another_key = merged.record.clone();
    another_key.base = a(&format!("{D}.2"));
    file(&mut dialer.world(), "1.0.1.0.67", &another_key, &[&daughter], None);
    dialer.clear();
    let found = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(
        (found.link.as_ref().map(ToString::to_string), found.landed.clone()),
        (Some(later_link.clone()), later.landed.clone()),
        "the newest in the owner's home"
    );
    let ops = dialer.ops();
    assert!(!ops.iter().any(|o| o == "retrieve_i"), "{ops:?}");
    assert!(
        ops.contains(&"image".to_string()) && ops.contains(&"retrieve_v".to_string()),
        "read through the arrangement: {ops:?}"
    );
    // A later compose carries the current record as prior and names it
    // as what the next record replaces.
    let merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
    assert_eq!(
        merged.prior.as_ref().and_then(|p| p.link.as_ref()).map(ToString::to_string),
        Some(later_link.clone())
    );
    assert_eq!(merged.record.replaces.as_ref().map(ToString::to_string), Some(later_link));
    // The owner's journal unreadable: the other account's record stands.
    dialer.world().withheld.insert("1.0.1.0.67".into());
    let found = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(found.link.map(|l| l.to_string()), Some(other_link));
}

/// THE NEWEST RECORD IS THE ONE WHOSE LINK WAS MINTED LAST (§4, "Its
/// currency"): two records of one key in two journals of the account's,
/// the later link at the lower address, and every read that picks the
/// newest picks the later — `current` and the composition's `prior`,
/// the landing's read-first, whose record replaces it, and a take-back's
/// read of the record naming its draft, whose record replaces that one.
#[test]
fn the_newest_record_is_the_one_whose_link_was_minted_last() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let daughter = format!("{D}.1.1");
    let later = {
        let mut w = dialer.world();
        file(&mut w, "1.0.1.0.74", &merged.record, &[&daughter], Some(20));
        file(&mut w, "1.0.1.0.68", &merged.record, &[&daughter], Some(40))
    };
    let link = |r: Option<Record>| r.and_then(|r| r.link).map(|l| l.to_string());
    assert_eq!(
        link(current(&board, Some(&token()), &a(K), &merged.key).expect("the lookup")),
        Some(later.clone()),
        "`current`"
    );
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    assert_eq!(link(again.prior.clone()), Some(later.clone()), "the composition's prior");
    dialer.clear();
    land(&board, &again, shot(&session, &signer)).expect("landed");
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(later.as_str()),
        "the landing's record replaces the later"
    );
    // The record naming a draft landing: the take-back's read.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let (merged, landed) = landed_in_s(&board, &session, &signer);
    let (position, first) = landing_of(&landed);
    assert!(
        first.to_string().starts_with("1.0.1.0.72.0.2."),
        "the premise: the landing's record at the greater address"
    );
    let mut record = merged.record.clone();
    record.landed = Some(RecordLanding::Draft { draft: a(S), position });
    let later = {
        let mut w = dialer.world();
        let at = w.position + 100;
        file(&mut w, "1.0.1.0.68", &record, &[S], Some(at))
    };
    dialer.clear();
    withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect("withdrawn");
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(later.as_str()),
        "the withdrawal's record replaces the later"
    );
}

/// THE TRUNK OWNER'S RECORD IS CURRENT OVER A SUB-ACCOUNT'S (§4, "Its
/// currency"; decision 8): the owner's record of the key in a journal of
/// its own and a sub-account's in the sub-account's, at the greater
/// address and minted later — `current` and the composition's `prior`
/// answer the owner's, an account's records being those whose links lie
/// in it exactly, never in an account nested under it. With the owner's
/// journal withheld, the sub-account's record stands.
#[test]
fn the_trunk_owners_record_is_current_over_a_sub_accounts() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let daughter = format!("{D}.1.1");
    let (owners, subs) = {
        let mut w = dialer.world();
        let owners = file(&mut w, "1.0.1.0.68", &merged.record, &[&daughter], Some(20));
        let subs = file(&mut w, "1.0.1.2.0.65", &merged.record, &[&daughter], Some(40));
        (owners, subs)
    };
    let link = |r: Option<Record>| r.and_then(|r| r.link).map(|l| l.to_string());
    assert_eq!(
        link(current(&board, Some(&token()), &a(K), &merged.key).expect("the lookup")),
        Some(owners.clone()),
        "`current`"
    );
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    assert_eq!(link(again.prior), Some(owners), "the composition's prior");
    dialer.world().withheld.insert("1.0.1.0.68".into());
    assert_eq!(
        link(current(&board, Some(&token()), &a(K), &merged.key).expect("the lookup")),
        Some(subs),
        "the owner's journal unreadable"
    );
}

/// THE RECORD A DRAFT'S LANDING STANDS ON IS READ THROUGH THE DRAFT (skep
/// #1140): case (j)'s fork `F` lands in a fresh draft `L`; edited by the
/// forker, the merge composed again lands in a fresh draft `L2`, whose
/// record is the merger's newest of the merge (`landed_draft`). By each
/// draft's marker, `landing_record` answers that draft's own record, and
/// it goes on answering `L`'s as records stand beside it, one at a time:
/// a sub-account's record of the merge naming `L` at the marker's position,
/// newer (the mutant that keeps every account's records answers it); that
/// sub-account's take-back replacing `L`'s record (the mutant that lets
/// another account's records replace the merger's answers none); the
/// merger's record of another merge in `L` (the mutant that tests no head
/// and sides answers it); the merger's record of this merge naming `L` past
/// the marker's position (the mutant that bounds no position answers it);
/// and a newer record of the merger's naming `L` at that position, replaced
/// by a take-back of theirs (the mutant that reads no replacement answers
/// it).
#[test]
fn a_drafts_landing_record_is_read_through_the_draft_whatever_landed_since() {
    let mut w = World::race();
    w.fork(F, "1.0.2", &format!("{D}.1"), vec![run(D, 1, 7)]);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let inputs = Inputs { sides: vec![Side::Fork(a(F))], ..race_inputs() };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    let first = land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed");
    let Landed::Draft { into: l, record: own, .. } = first else { panic!("{first:?}") };
    dialer.world().change(F, vec![run(D, 5, 3)]);
    let again = compose(&board, Some(session.token()), &inputs).expect("composed again");
    let second = land(&board, &again, draft_landing(&session, &signer, None)).expect("landed");
    let Landed::Draft { into: l2, record: elsewhere, .. } = second else { panic!("{second:?}") };
    assert_ne!(l2, l, "the premise: a fresh draft of its own");
    assert_eq!(
        landed_draft(&board, Some(session.token()), &a(K), &merged.key, ACCOUNT)
            .expect("the lookup")
            .and_then(|r| r.link),
        Some(elsewhere.clone()),
        "the premise: the merger's newest record of the merge names L2"
    );
    let marker = |draft: &Address| {
        let frame = frames::doc_metadata(&draft.to_string());
        let Answer::Document(v) = board.op(Some(session.token()), &frame).expect("the read") else {
            panic!("closed")
        };
        crate::board::answers::merge_marker(&v).flatten().expect("the draft's marker")
    };
    let (marked, marked_elsewhere) = (marker(&l), marker(&l2));
    let at = marked.at.expect("the marker's position");
    let standing = |draft: &Address, marker: &crate::board::answers::MergeMarker| {
        landing_record(&board, Some(session.token()), &a(K), draft, marker, ACCOUNT)
            .expect("the lookup")
            .and_then(|r| r.link)
    };
    assert_eq!(standing(&l2, &marked_elsewhere), Some(elsewhere.clone()), "L2's own");
    assert_eq!(standing(&l, &marked), Some(own.clone()), "L's own, the merge landed in L2 since");
    // Each record stands beside L's in turn, its link minted after every
    // other, as a later write's is.
    let to = [l.to_string(), F.to_string()];
    let plant = |journal: &str, record: &Record| {
        let mut w = dialer.world();
        w.position += 1;
        let minted = w.position;
        a(&file(&mut w, journal, record, &[&to[0], &to[1]], Some(minted)))
    };
    let landed_in_l = |record: &Record, position: u64| Record {
        landed: Some(RecordLanding::Draft { draft: l.clone(), position }),
        ..record.clone()
    };
    let (sub, theirs) = ("1.0.1.2.0.65", "1.0.1.0.90");
    plant(sub, &landed_in_l(&merged.record, at));
    assert_eq!(standing(&l, &marked), Some(own.clone()), "a sub-account's record, newer");
    plant(sub, &Record { landed: None, replaces: Some(own.clone()), ..merged.record.clone() });
    assert_eq!(standing(&l, &marked), Some(own.clone()), "a sub-account's take-back of L's");
    let another = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    plant(theirs, &landed_in_l(&another.record, at));
    assert_eq!(standing(&l, &marked), Some(own.clone()), "the merger's record of another merge");
    plant(theirs, &landed_in_l(&merged.record, at + 1));
    assert_eq!(standing(&l, &marked), Some(own.clone()), "a landing past the marker's");
    let newer = plant(theirs, &landed_in_l(&merged.record, at));
    plant(theirs, &Record { landed: None, replaces: Some(newer), ..merged.record.clone() });
    assert_eq!(standing(&l, &marked), Some(own), "a newer record of the merger's, taken back");
}

/// `verify`'s three verdicts: Equal where the member holds M over its
/// `placed` positions, Differs at the first V-ordinal where it does not,
/// Unreadable where the member is withheld — M recomputed from the
/// record's inputs, `compare` asked once as the oracle of the join.
#[test]
fn verify_answers_equal_differs_and_unreadable() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    let record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("the record");
    dialer.clear();
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
    let ops = dialer.names();
    assert_eq!(ops.iter().filter(|o| *o == "compare").count(), 1, "{ops:?}");
    assert!(!ops.iter().any(|o| ["publish", "insert", "make_link"].contains(&o.as_str())));
    let compare = &dialer.frames("compare")[0];
    assert_eq!(compare["rho1"][0]["doc"], format!("{D}.1"));
    assert_eq!(
        compare["rho2"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["doc"].as_str().unwrap().to_string())
            .collect::<Vec<_>>(),
        [format!("{D}.2"), format!("{D}.1.1")]
    );
    let mut differs = record.clone();
    differs.landed = Some(RecordLanding::Member { member: a(&format!("{D}.2")), position: 0 });
    assert_eq!(
        verify(&board, Some(&token()), &differs),
        Ok(Verdict::Differs { at: 12 }),
        "the head keeps ' sat' past M's eleven positions"
    );
    let mut another = record.clone();
    another.landed =
        Some(RecordLanding::Member { member: a(&format!("{D}.1.1")), position: 0 });
    assert_eq!(
        verify(&board, Some(&token()), &another),
        Ok(Verdict::Differs { at: 5 }),
        "the daughter has no 'big ' at V 5"
    );
    dialer.world().withheld.insert(format!("{D}.3"));
    assert_eq!(
        verify(&board, Some(&token()), &record),
        Ok(Verdict::Unreadable(a(&format!("{D}.3"))))
    );
    let mut question = record.clone();
    question.landed = None;
    assert!(matches!(verify(&board, Some(&token()), &question), Err(Refusal::Halt(_))));
    // The oracle in parts: a compare budget of one block is halved until
    // each part answers, and the join still agrees.
    dialer.world().withheld.clear();
    dialer.world().compare_cap = 1;
    dialer.clear();
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
    assert!(dialer.frames("compare").len() > 1, "{:?}", dialer.ops());
}

/// A withheld input withholds the verdict; an unregistered one is refused.
///
/// The race shape landed by a shot verifies Equal; with the trunk, the
/// head, the base or the daughter withheld alone, `verify` answers
/// Unreadable naming it. A grant withdrawn between the daughter's image
/// and the join's `compare` refuses the compare naming the daughter in
/// its `site.addr`, and the verdict names the daughter, not the base the
/// compare's first region holds. A side the board has never registered
/// is no withheld document: it is refused `NoSuchDocument` (merge record
/// §4, testimony; D14; wire.md §The read predicate).
#[test]
fn a_withheld_input_withholds_the_verdict_and_an_unregistered_one_is_refused() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    let record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("the record");
    dialer.clear();
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal), "the premise");
    let compare_at = dialer
        .served
        .lock()
        .unwrap()
        .iter()
        .position(|(line, _)| line == "at:compare")
        .expect("the join's compare");
    let daughter = format!("{D}.1.1");
    for hidden in [D.to_string(), format!("{D}.2"), format!("{D}.1"), daughter.clone()] {
        dialer.world().withheld = BTreeSet::from([hidden.clone()]);
        assert_eq!(
            verify(&board, Some(&token()), &record),
            Ok(Verdict::Unreadable(a(&hidden))),
            "{hidden} withheld"
        );
    }
    // The daughter's grant withdrawn after its image, before the compare.
    dialer.world().withheld.clear();
    dialer.world().withhold = Some((compare_at + 1, daughter.clone()));
    dialer.clear();
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Unreadable(a(&daughter))));
    assert!(dialer.world().withhold.is_none(), "the grant withdrawn mid-walk");
    let ops = dialer.ops();
    assert!(
        dialer.frames("image").iter().any(|f| f["d"].as_str() == Some(daughter.as_str())),
        "the daughter imaged before its grant was withdrawn: {ops:?}"
    );
    assert_eq!(
        ops.last().map(String::as_str),
        Some("at:compare"),
        "the refused compare is the last read: {ops:?}"
    );
    // A side the board has never registered: refused, no verdict.
    dialer.world().withheld.clear();
    assert_eq!(record.sides[1], SideAt::Member { at: a(&daughter), role: Role::Alternative });
    let unregistered = a(&format!("{D}.1.7"));
    let mut naming = record.clone();
    naming.sides[1] = SideAt::Member { at: unregistered.clone(), role: Role::Alternative };
    assert_eq!(
        verify(&board, Some(&token()), &naming),
        Err(Refusal::NoSuchDocument(unregistered))
    );
}

/// A run a readable side windows from a document the reader may not
/// read refuses where the value rule reads it, naming that document.
///
/// The race shape with a second daughter `D.1.2` adding "big " at `D·4|D·5`
/// as a window onto `W`, another account's draft, beside the head's own
/// fresh "big ": the dedup reads both groups, keeps the head's and drops
/// the daughter's copy, the record naming that place and the window
/// dropped, read back from its JSON too, and a record of it landed on the
/// head verifies Equal. With `W` withheld the daughter stays readable and
/// is imaged whole, and its delivery masks the window as a `withheld` item
/// at its own position (wire.md §Value encodings): `compose` refuses
/// `Unreadable(W)` at the value read through the daughter, and `verify`
/// answers `Unreadable(W)`, the verdict withheld (merge record §4; D14). A
/// reference in the window's place is no withheld run: it is faced as a
/// board fault.
#[test]
fn a_withheld_run_in_a_readable_side_refuses_naming_its_origin() {
    const W: &str = "1.0.2.0.70";
    let daughter = format!("{D}.1.2");
    let mut w = World::race();
    w.text(W, 1, "big ");
    w.doc(W, false, "1.0.2", vec![run(W, 1, 4)]);
    w.member(&daughter, vec![run(D, 1, 4), run(W, 1, 4), run(D, 5, 7)], Some(11));
    let (dialer, board, _) = open(w);
    let inputs = Inputs { sides: vec![Side::Member(a(&daughter))], ..race_inputs() };
    // The premise, `W` readable: the dedup fires at the order gap.
    let merged = compose(&board, Some(&token()), &inputs).expect("composed");
    assert_eq!(
        m_runs(&merged),
        vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)],
        "the head's 'big ' kept, the daughter's copy dropped"
    );
    assert_eq!(merged.composed.values.applied, vec![GapId(1)]);
    let dropped = vec![(SideIx(1), run(W, 1, 4))];
    let once = vec![Deduped { gap: GapId(1), kept: vec![SideIx(0)], dropped }];
    assert_eq!(merged.record.deduped(), once, "the place kept once, the daughter's window dropped");
    let back = Record::from_value(&merged.record.to_value()).expect("the record reads back");
    assert_eq!(back.deduped(), once, "named by a record read back from its JSON");
    let mut record = merged.record.clone();
    record.landed = Some(RecordLanding::Member { member: a(&format!("{D}.2")), position: 0 });
    dialer.clear();
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal), "the premise");
    // The recomputation's metadata and images as of one position, its
    // values at the head (skep #1144).
    let p = dialer.world().position;
    let imaged = dialer.positions("image");
    assert!(!imaged.is_empty() && imaged.iter().all(|at| *at == p), "the images as of one position: {:?}", dialer.ops());
    assert!(
        !dialer.frames("retrieve_v").is_empty() && dialer.positions("retrieve_v").is_empty(),
        "the values at the head: {:?}",
        dialer.ops()
    );
    // `W` withheld: the daughter readable, its window masked.
    dialer.world().withheld.insert(W.to_string());
    dialer.clear();
    assert_eq!(compose(&board, Some(&token()), &inputs), Err(Refusal::Unreadable(a(W))));
    let ops = dialer.ops();
    assert!(
        dialer.frames("image").iter().any(|f| f["d"].as_str() == Some(daughter.as_str())),
        "the daughter imaged whole: {ops:?}"
    );
    assert_eq!(
        ops.last().map(String::as_str),
        Some("retrieve_v"),
        "the masked value read is the last, at the head: {ops:?}"
    );
    let masked = dialer.frames("retrieve_v").pop().expect("a value read");
    assert_eq!(
        masked["specs"][0]["doc"].as_str(),
        Some(daughter.as_str()),
        "read through the daughter by its V-ordinals, which the board answered"
    );
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Unreadable(a(W))));
    // A reference in the window's place: no withheld run, a board fault.
    dialer.world().withheld.clear();
    dialer.world().values.insert((W.to_string(), 1), Val::Ref(format!("{W}.0.2.1")));
    match compose(&board, Some(&token()), &inputs) {
        Err(Refusal::Halt(Halt::Halt(face))) => {
            assert!(face.cause.contains("a reference"), "{face}");
            assert!(face.act.contains("board fault"), "{face}");
        }
        other => panic!("a reference is a board fault: {other:?}"),
    }
}

/// A gap of two groups the merger moved lands, and its record verifies.
///
/// The race shape with a second daughter adding "fat " at `D·4|D·5`:
/// the merger moves the order gap after `D·11`, so M is one run; the
/// record read back holds the gap where M holds it and re-states the
/// move, so `verify` composes the landed M again and answers `Equal`
/// (merge record §4).
#[test]
fn a_moved_gap_of_two_groups_lands_and_verifies_equal() {
    let mut w = World::race();
    w.text(D, 16, "fat ");
    w.member(&format!("{D}.1.2"), vec![run(D, 1, 4), run(D, 16, 4), run(D, 5, 7)], Some(11));
    let (_, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let end = a(&format!("{D}.0.1.11"));
    let inputs = Inputs {
        sides: vec![Side::Member(a(&format!("{D}.1.2")))],
        options: Options {
            resolutions: vec![Resolution {
                gap: GapId(1),
                choice: Choice::After(end.clone()),
                by: ResolvedBy::Person,
            }],
            ..Options::default()
        },
        ..race_inputs()
    };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    assert!(merged.composed.ignored.is_empty(), "{:?}", merged.composed.ignored);
    assert_eq!(m_runs(&merged), vec![run(D, 1, 19)], "the cat satbig fat ");
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    let record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("the record");
    let gap = &record.gaps[0];
    assert_eq!(
        (gap.kind, gap.after.clone(), gap.before.clone()),
        (GapKind::Order, Some(end), None),
        "the gap where M holds it"
    );
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
}

/// The `Record` round-trips through its JSON, its `type` fixed `merge`.
///
/// Its gaps keep their runs and the resolutions they re-state, a draft
/// side and a draft landing included; an object of another type or
/// version is no record, nor is one whose gap names a side past the one
/// byte a side is numbered by.
#[test]
fn the_record_round_trips_and_names_its_type() {
    let (_, board, _) = open(World::race());
    let mut merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
    merged.record.sides.push(SideAt::Draft {
        at: a(S),
        position: Some(7),
        arranged: SideState::At(7),
    });
    merged.record.landed = Some(RecordLanding::Draft { draft: a(S), position: 9 });
    merged.record.claims = vec![a(&format!("{DOC1}.0.2.4"))];
    merged.record.replaces = Some(a(&format!("{DOC1}.0.2.2")));
    merged.record.gaps = vec![
        Gap {
            id: GapId(1),
            kind: GapKind::Order,
            after: Some(a(&format!("{D}.0.1.4"))),
            before: Some(a(&format!("{D}.0.1.5"))),
            runs: vec![(SideIx(0), run(D, 12, 4)), (SideIx(1), run(D, 16, 4))],
            placed: Placement::Order(vec![SideIx(1), SideIx(0)]),
            settled: true,
            resolved_by: Some(ResolvedBy::Agent),
            spots: vec![],
        },
        Gap {
            id: GapId(2),
            kind: GapKind::Corner,
            after: None,
            before: Some(a(&format!("{D}.0.1.1"))),
            runs: vec![(SideIx(1), run(Z, 3, 2))],
            placed: Placement::Omitted,
            settled: true,
            resolved_by: Some(ResolvedBy::Answer(a(&format!("{DOC1}.0.1.7")))),
            spots: vec![],
        },
        Gap {
            id: GapId(3),
            kind: GapKind::Anchor,
            after: Some(a(&format!("{D}.0.1.4"))),
            before: Some(a(&format!("{D}.0.1.8"))),
            runs: vec![(SideIx(1), run(D, 15, 1))],
            placed: Placement::Before,
            settled: true,
            resolved_by: Some(ResolvedBy::Rule),
            spots: vec![],
        },
    ];
    merged.record.values.applied = vec![GapId(1)];
    let v = merged.record.to_value();
    assert_eq!(
        (v["type"].as_str(), v["v"].as_u64(), v["rules"].as_str()),
        (Some("merge"), Some(1), Some("merge-rules-2"))
    );
    assert_eq!(
        v["gaps"][0]["runs"][0],
        json!({"side": 0, "i_start": format!("{D}.0.1.12"), "width": "4"})
    );
    assert_eq!(
        (
            v["gaps"][0]["placed"].clone(),
            v["gaps"][1]["placed"].clone(),
            v["gaps"][2]["placed"].clone()
        ),
        (json!([1, 0]), json!("omitted"), json!("before"))
    );
    assert_eq!(v["gaps"][1]["resolved_by"], format!("answer:{DOC1}.0.1.7"));
    assert_eq!(
        v["sides"][2],
        json!({"at": {"draft": S, "position": 7}, "role": "draft", "arranged": 7})
    );
    assert_eq!(v["landed"], json!({"draft": S, "position": 9}));
    assert!(v.get("link").is_none(), "the link is no member of the body");
    let back = Record::from_value(&v).expect("a record");
    assert_eq!(back, merged.record);
    let answer = ResolvedBy::Answer(a(&format!("{DOC1}.0.1.7")));
    assert_eq!(
        back.options().resolutions,
        vec![
            Resolution {
                gap: GapId(1),
                choice: Choice::After(a(&format!("{D}.0.1.4"))),
                by: ResolvedBy::Agent
            },
            Resolution {
                gap: GapId(1),
                choice: Choice::Order(vec![SideIx(1), SideIx(0)]),
                by: ResolvedBy::Agent
            },
            Resolution {
                gap: GapId(2),
                choice: Choice::Before(a(&format!("{D}.0.1.1"))),
                by: answer.clone()
            },
            Resolution { gap: GapId(2), choice: Choice::Omit, by: answer }
        ],
        "each gap a merger settled re-stated as its place, then its placement"
    );
    let mut other = v.clone();
    other["type"] = json!("skep-head");
    assert_eq!(Record::from_value(&other), None);
    other["type"] = json!("merge");
    other["v"] = json!(2);
    assert_eq!(Record::from_value(&other), None);
    // A gap naming a side past the one byte a side is numbered by, in its
    // runs or its order, is no record; 255, the last, reads.
    let mut wide = v.clone();
    wide["gaps"][0]["runs"][0]["side"] = json!(255);
    assert_eq!(Record::from_value(&wide).map(|r| r.gaps[0].runs[0].0), Some(SideIx(255)));
    wide["gaps"][0]["runs"][0]["side"] = json!(256);
    assert_eq!(Record::from_value(&wide), None, "never read as the head's 0");
    let mut wide = v.clone();
    wide["gaps"][0]["placed"] = json!([1, 256]);
    assert_eq!(Record::from_value(&wide), None);
}
