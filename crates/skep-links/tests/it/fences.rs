//! The sole-writer fences over a real kernel: the `[R]` and `[K_sup]` fences
//! on the open surface beside the classes they do not name, and the `replaces`
//! class's fence on all three open writes beside that class's one writer.

use crate::common;

use common::*;
use skep_arrangement::HasM5;
use skep_kernel::{
    Attestation, BurnedSeqPolicy, CheckpointPolicy, Durability, HistoryError, Kernel, KernelConfig,
    SaltSource, Seq, TxnError,
};
use skep_links::{
    enc, is_replaces_class, replaces_type, EditLinkError, EmitError, Endset, HasLinks, Link,
    LinkWriter, MakeLinkError, SlotArg, View,
};
use tempfile::tempdir;

// ---- the sole-writer fences, on the open surface ----

#[test]
fn makelink_cannot_forge_a_retraction_of_a_foreign_link() {
    // The hint fold recognizes a deposit by its type slot's CLASS, so the
    // K ≁ R fence has to hold on every surface that deposits, not only on
    // the one whose gate states it. Without it, a principal owning any one
    // document names the shipped `[R]` address in an `Addrs` type slot and
    // tombstones every link its TO slot denotes — with no ownership check on
    // any of them, and irreversibly, the tombstone set being monotone and
    // re-derived at every replay.
    let k = kernel();
    let w = writer(&k);
    let (victim, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("P1's own tuple");
    let before = k.current_seq();
    assert!(matches!(
        w.makelink(
            P2,
            &sib_doc(), // a home P2 does own — the ω gate is satisfied
            SlotArg::Addrs(vec![sib_doc()]),
            SlotArg::Addrs(vec![victim.clone()]),
            SlotArg::Addrs(vec![reserved().retraction]),
        ),
        Err(TxnError::Rejected(MakeLinkError::RetractionClass))
    ));
    assert_eq!(k.current_seq(), before, "the refusal is pre-deposit");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_active(&victim));
    assert!(!links.is_nullified(&victim));
    assert!(links.type_slice(&pred_def_ty(), View::Active).contains(&victim));
    // The owner's own retraction is the one path that reaches the tombstone.
    w.nullify(P1, &doc1(), &victim).expect("owner retraction");
    assert!(k.snapshot().world().links().is_nullified(&victim));
}

#[test]
fn makelink_cannot_forge_a_supersession_claim() {
    // The `[K_sup]` fence, the exact parallel. assert_sup and editlink both
    // establish the Df-DISC(ii) schema — resident endpoints, single denoted
    // addresses, irreflexivity — before a claim enters the adjacency the
    // walk family reads back as fact; the open surface establishes none of
    // it, and its slots are lists, so one deposit would fold |F|×|G| edges.
    let k = kernel();
    let w = writer(&k);
    let before = k.current_seq();
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![la(90), la(91)]), // ghosts: neither is resident
            SlotArg::Addrs(vec![la(92), la(93)]),
            SlotArg::Addrs(vec![reserved().supersedes]),
        ),
        Err(TxnError::Rejected(MakeLinkError::SupersessionClass))
    ));
    assert_eq!(k.current_seq(), before, "the refusal is pre-deposit");
    let snap = k.snapshot();
    let links = snap.world().links();
    let sup = supersedes_ty();
    assert!(links.succs(&sup, &la(90)).is_empty());
    // The ghost is its own sink with nothing claiming it: no forged edge
    // entered the adjacency, and no forged claim entered the disclosure.
    let cur = links.current(&la(90));
    assert_eq!(cur.len(), 1);
    assert_eq!(cur[0].member, la(90));
    assert!(cur[0].claims.is_empty());
    // A self-superseding claim over one ghost is refused by the same fence,
    // so irreflexivity is not reachable around it either.
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![la(90)]),
            SlotArg::Addrs(vec![la(90)]),
            SlotArg::Addrs(vec![reserved().supersedes]),
        ),
        Err(TxnError::Rejected(MakeLinkError::SupersessionClass))
    ));
}

#[test]
fn makelink_still_admits_every_class_the_fences_do_not_name() {
    // The control for the two fences above: they name two classes, not the
    // registry. A shipped class with no sole writer (Retired), a second
    // shipped class, and a class outside the registry all deposit through the
    // open surface as before.
    let k = kernel();
    let w = writer(&k);
    for ty in [reserved().retired, reserved().pred_def, unregistered_ta(10)] {
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(1)]),
            SlotArg::Addrs(vec![ca(2)]),
            SlotArg::Addrs(vec![ty.clone()]),
        )
        .unwrap_or_else(|e| panic!("open surface admits {ty:?}: {e:?}"));
    }
}

// ---- the `replaces` class: its one writer, and the fence around it ----

/// THE `replaces` FENCE, the `[K_sup]` fence's twin (PUB-5.15; RES-309/310):
/// the authority successor has ONE writer — the MAKELINK that carries the
/// member, in its record's own transaction — so no open write deposits one
/// by itself. A `replaces` link at a record's next address is what the grant
/// fold reads as the state that record replaces; minted by any other act it
/// would name a state for a record whose signed bytes named none. So the
/// class is refused on all three open writes — `makelink`, alone and beside
/// a subtype of its own (one coverage class), `emit` (pre-transact) and an
/// `editlink` successor — and at `makelink_replacing` itself where its
/// RECORD is of the class, which would make the record a `replaces` link of
/// its own. Nothing commits, and the class's slice stays empty.
#[test]
fn makelink_cannot_forge_an_authority_successor() {
    let k = kernel();
    let w = writer(&k);
    let record = open_deposit(&w, &[ca(1)], &[ca(2)], &[unregistered_ta(10)]);
    let replaces = replaces_type().clone();
    let subtype = a(&[1, 1, 0, 1, 0, 1, 0, 3, 12, 1]);
    let before = k.current_seq();
    for ty in [vec![replaces.clone()], vec![replaces.clone(), subtype.clone()]] {
        assert!(
            matches!(
                w.makelink(
                    P1,
                    &doc1(),
                    SlotArg::Addrs(vec![record.clone()]),
                    SlotArg::Addrs(vec![la(9)]),
                    SlotArg::Addrs(ty.clone()),
                ),
                Err(TxnError::Rejected(MakeLinkError::ReplacesClass))
            ),
            "a bare makelink typed {ty:?}"
        );
    }
    assert!(matches!(
        w.emit(P1, &doc1(), &enc([&replaces]), &record, &[la(9)]),
        Err(TxnError::Rejected(EmitError::ReplacesClass))
    ));
    let successor = Link::triple(enc([&record]), enc([&la(9)]), enc([&replaces]));
    assert!(matches!(
        w.editlink(P1, &record, successor, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::DcViolation))
    ));
    assert!(matches!(
        w.makelink_replacing(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![record.clone()]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![replaces.clone()]),
            &la(9),
        ),
        Err(TxnError::Rejected(MakeLinkError::ReplacesClass))
    ));
    assert_eq!(k.current_seq(), before, "every refusal is pre-deposit");
    let snap = k.snapshot();
    assert!(
        snap.world().links().type_slice(&enc([&replaces]), View::Audit).is_empty(),
        "no `replaces` link was deposited"
    );
    // The one predicate every fence above reads: the class, never a subtype
    // alone — the grant fold reads the class by its exact address.
    assert!(is_replaces_class(&enc([&replaces])));
    assert!(is_replaces_class(&enc([&replaces, &subtype])));
    assert!(!is_replaces_class(&enc([&subtype])), "a subtype alone is not the class");
    assert!(!is_replaces_class(&Endset::from_spans([iext(1, 3)])), "content is not the class");
}

/// THE ONE WRITER (PUB-5.15 (iii); RES-308/309): `makelink_replacing` stages
/// the record exactly as `makelink` does, then its `replaces` link — `from`
/// the record, `to` the state named, typed the class — in ONE transaction
/// under ONE attestation, and answers the RECORD. The link sits at the
/// record's own NEXT address, which is where the grant fold reads a record's
/// `replaces`; both are seated in the home's link subspace, the record and
/// then its link, as ONE run; and a later plain `makelink` lands past both. ONE
/// transaction, and not two that happen to be adjacent: the attestation
/// rides the one commit marker, and every position the two deposits took
/// below it is interior — no boundary a reader could stop between them at.
#[test]
fn makelink_replacing_commits_record_and_link_together() {
    let dir = tempdir().expect("tempdir");
    let cfg = KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.path().to_path_buf(),
            retain_checkpoints: 1,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    let k = Kernel::open(cfg, genesis_world()).expect("journaled open");
    seed_content(&k, &doc1(), 2);
    let tag1 = Attestation::new(1, vec![0x22; 3_373]).expect("tag 1");
    let w = LinkWriter::attested(&k, &ALL_VISIBLE, Some(&tag1));
    // The state the record names: a NAME, checked for nothing here — whether
    // it is current is the fold's question, never the write's.
    let named = la(7);
    let before = k.current_seq();
    let (record, at) = w
        .makelink_replacing(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(1)]),
            SlotArg::Addrs(vec![ca(2)]),
            SlotArg::Addrs(vec![unregistered_ta(11)]),
            &named,
        )
        .expect("the record and its replaces link commit");
    assert_eq!(record, la(1), "the ack is the record's, at the home's next address");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        let value = links.readlink(&record).expect("the record is resident");
        assert_eq!(
            *value,
            Link::triple(enc([&ca(1)]), enc([&ca(2)]), enc([&unregistered_ta(11)])),
            "the record is the plain makelink's deposit"
        );
        let pair =
            links.readlink(&la(2)).expect("the replaces link sits at the record's next address");
        assert_eq!(
            *pair,
            Link::triple(enc([&record]), enc([&named]), enc([replaces_type()])),
            "from the record, to the state it names, typed the class"
        );
        assert_eq!(snap.world().m5().link_count(&doc1()), n(2), "both seated: the record and its link");
        let mut runs = snap.world().m5().link_runs(&doc1());
        assert_eq!(
            runs.next().expect("a seated link run").i_start(),
            &record,
            "one run, starting at the record, its link seated right after it"
        );
        assert!(runs.next().is_none(), "the pair seats as ONE run — no fragment per re-share");
    }
    assert_eq!(k.attestation_at(at).unwrap(), Some(tag1), "one marker carries the attestation");
    assert!(at.0 > before.0 + 1, "the pair takes more than one position");
    for interior in before.0 + 1..at.0 {
        assert!(
            matches!(k.attestation_at(Seq(interior)), Err(HistoryError::NotABoundary { .. })),
            "position {interior} is interior to the one commit"
        );
    }
    let (next, _) = writer(&k)
        .makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(1)]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(12)]),
        )
        .expect("a later makelink");
    assert_eq!(next, la(3), "a later deposit lands past both");
}
