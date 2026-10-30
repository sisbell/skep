use skep_address::Span;
use skep_febe::{Codec, OpKind};
use skep_identity::{entry_body_publish, entry_body_record, EntrySlot};
use skep_links::{enc, registry, ShippedType};

use super::*;
use crate::codec::op_name;
use crate::codec::JsonCodec;

/// Returns an endset's spans, owned, in stored order.
///
/// They are what the unit-span pins below compare against.
fn spans_of(endset: &Endset) -> Vec<Span> {
    endset.spans().cloned().collect()
}

/// Checks that each body's `op` member is its op's wire name.
///
/// The frame's `op` member (the design record §2.5) is the op-kind token
/// as the wire spells it: each entry-grade body `skep_identity` builds —
/// one per kind of the checked set — carries the codec's own name for its
/// op, so a wire rename meets this test before it can move a signed
/// preimage. One exception, the frame merge's: `record` names the record
/// grade's body and no wire op — the codec parses no such op, and the
/// body's token says which grammar a `sig` was made over.
#[test]
fn each_body_carries_the_wire_name_of_its_op() {
    let empty = EntrySlot(&[]);
    let slots = LinkSlots { from: empty, to: empty, ty: empty };
    let original = skep_address::validate(
        skep_address::Tumbler::new([1u32, 0, 1, 0, 1, 0, 2, 1].map(skep_address::Nat::from))
            .expect("a tumbler"),
    )
    .expect("an address");
    for (body, kind) in [
        (entry_body_empty(ContentFreeOp::CreateNewDocument), OpKind::CreateNewDocument),
        (entry_body_empty(ContentFreeOp::Fork), OpKind::Fork),
        (entry_body_empty(ContentFreeOp::Version), OpKind::Version),
        (entry_body_insert(None, std::iter::empty()), OpKind::Insert),
        (entry_body_make_link(slots), OpKind::MakeLink),
        (entry_body_emit(slots), OpKind::Emit),
        (entry_body_nullify(slots), OpKind::Nullify),
        (entry_body_assert_sup(slots), OpKind::AssertSup),
        (entry_body_edit_link(slots, &unit_span(&original)), OpKind::EditLink),
        (entry_body_publish(std::iter::empty(), None), OpKind::Publish),
    ] {
        assert_eq!(body.op(), op_name(kind), "{kind:?}");
        assert!(crate::codec::in_checked_set(kind), "{kind:?}: every body's kind is of the checked set");
    }
    let ty = skep_address::validate(
        skep_address::Tumbler::new([1u32, 1, 0, 1, 0, 1, 0, 3, 1].map(skep_address::Nat::from))
            .expect("a tumbler"),
    )
    .expect("an address");
    let record = entry_body_record(RecordRows {
        ty: &ty,
        to: &[],
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: b"",
    });
    assert_eq!(record.op(), "record", "the record grade's grammar token");
    assert!(
        JsonCodec.parse(br#"{"op":"record"}"#).is_err(),
        "`record` is a grammar token with no wire op: the codec parses none by that name"
    );
}

/// Checks that the unit span is M7's own spelling.
///
/// The span the frame's `unit_span` gives an address — the start the
/// address, the width the unit at its length — is the span M7's `enc`
/// stores for a slot that names it, at every depth an address takes, and
/// over a list the two agree span for span and in order. So a slot row
/// composed from addresses alone — a `nullify`'s, an `assert_sup`'s, an
/// `emit`'s, the `edit_link` claim's `from` — is the row a verifier
/// composes from `read_link`.
#[test]
fn the_unit_span_is_the_span_enc_stores() {
    let addr = |comps: &[u32]| {
        skep_address::validate(
            skep_address::Tumbler::new(comps.iter().map(|&c| skep_address::Nat::from(c)))
                .expect("a tumbler"),
        )
        .expect("an address")
    };
    let addrs = [
        addr(&[1, 0, 1]),
        addr(&[1, 0, 1, 0, 1]),
        addr(&[1, 0, 1, 0, 1, 0, 2, 1]),
        addr(&[1, 1, 0, 1, 0, 1, 0, 1, 5]),
        addr(&[1, 0, 1, 0, 1, 2, 0, 1, 7]),
    ];
    for a in &addrs {
        assert_eq!(enc([a]).spans().cloned().collect::<Vec<_>>(), vec![unit_span(a)], "{a}");
    }
    assert_eq!(
        spans_of(&enc(addrs.iter())),
        addrs.iter().map(unit_span).collect::<Vec<_>>(),
        "over a list, span for span and in order"
    );
    assert_eq!(
        spans_of(registry().reserved_type(ShippedType::Retraction)),
        vec![unit_span(&addr(&[1, 1, 0, 1, 0, 1, 0, 1, 5]))],
        "the retraction class's type slot is its ghost address's one unit span"
    );
    assert_eq!(
        spans_of(registry().reserved_type(ShippedType::Supersedes)),
        vec![unit_span(&addr(&[1, 1, 0, 1, 0, 1, 0, 1, 4]))],
        "the supersedes class's type slot is its ghost address's one unit span"
    );
}

/// Checks that compose's precondition is never answered as a fault.
///
/// For a principal with a prefix — the account term read ahead of the op
/// — an op outside the checked set stops loudly. A fault here would be
/// one the check passes through, committing the write with its marker
/// slot empty — the silent drop the checked set's card rules out — and no
/// refusal the check could give is true of a build whose two tables
/// disagree.
#[test]
#[should_panic(expected = "compose's precondition")]
fn an_op_outside_the_checked_set_stops_compose_loudly() {
    use skep_arrangement::VPos;
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
    use skep_namespace::{head_document, BOOTSTRAP_PRINCIPAL};

    let engine = skep_engine::Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    assert!(
        world.m3().principal_prefix(BOOTSTRAP_PRINCIPAL).is_some(),
        "the premise: genesis seats principal 0, so its account term is read"
    );
    let board = BoardTerm { log_position: 1, chain: [0; 32] };
    let delete = Op::Delete {
        doc: head_document(),
        p: VPos::content(Nat::from(1u32)),
        width: Nat::from(1u32),
    };
    let _ = compose(world, &delete, BOOTSTRAP_PRINCIPAL, board);
}

/// Checks that the publish body's grain is per value, whatever M4 holds.
///
/// **The preimage pin.** The body composed over a run M4 holds as *one*
/// stretch is byte-equal to the body composed over the same bytes M4
/// holds as one-byte values — one row per byte either way — and both
/// equal the body the client composes from the values it inserted, one
/// row apiece. A row per piece would spell one N-byte value where the
/// client spelled N one-byte values, and every attested per-byte publish
/// would be refused for its signature. The two worlds are built through
/// the stores' own public doors: M3's mints and M4's two stage doors,
/// under the content key, into the head document genesis registers.
#[test]
fn the_publish_body_spells_a_stretch_one_row_per_byte_as_it_spells_values() {
    use std::sync::Arc;

    use skep_arrangement::{InsertError, Run, SegmentRun, Shot};
    use skep_content::{stage_stretch, stage_write, Val};
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
    use skep_namespace::{head_document, M3State};

    let open = || {
        skep_engine::Engine::open(KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(0),
        })
        .expect("in-memory genesis cannot fail")
    };
    let doc = head_document();
    let keys = [M3State::content_lock_key(&doc)];
    // The per-value world: three one-byte values, three mints, three
    // writes — the form a board written without stretches holds.
    let values = open();
    let (first_of_values, _) = values
        .kernel()
        .transact::<_, InsertError>(&keys, |stg| {
            let mut first = None;
            for byte in b"abc" {
                let (addr, mint) = stg.working().m3().mint_content(&doc)?;
                stg.push(mint.into());
                let write = stage_write(stg.working().content(), addr.clone(), Val::new([*byte]))?;
                stg.push(write.into());
                first.get_or_insert(addr);
            }
            Ok(first.expect("three values"))
        })
        .expect("three values commit");
    // The stretch world: one range mint, one stretch.
    let stretch = open();
    let (first_of_stretch, _) = stretch
        .kernel()
        .transact::<_, InsertError>(&keys, |stg| {
            let (first, range) = stg.working().m3().mint_content_range(&doc, &Nat::from(3u32))?;
            stg.push(range.into());
            let rec = stage_stretch(stg.working().content(), first.clone(), Arc::from(&b"abc"[..]))?;
            stg.push(rec.into());
            Ok(first)
        })
        .expect("a range and its stretch commit");
    assert_eq!(first_of_values, first_of_stretch, "B2: one chain, one first address");
    let run = Run::new(first_of_stretch, Nat::from(3u32)).expect("a three-position run");
    let shot = Shot { base: None, draft: None, also: vec![], runs: Vec::new() };
    let body_of = |engine: &skep_engine::Engine| {
        let snap = engine.kernel().snapshot();
        publish_body(snap.world(), &shot, &[SegmentRun::Value(run.clone())])
            .expect("the body composes")
            .as_bytes()
            .to_vec()
    };
    let over_values = body_of(&values);
    let over_stretch = body_of(&stretch);
    assert_eq!(over_stretch, over_values, "the body's grain parted from per value");
    // …and both are the client's own composition: one row per value.
    let mut by_hand = PublishBody::within(MAX_SHOT_BODY_BYTES, None).expect("an empty base");
    for byte in b"abc" {
        by_hand = by_hand.push(std::slice::from_ref(byte)).expect("three one-byte rows");
    }
    assert_eq!(over_stretch, by_hand.finish().as_bytes().to_vec());
    // The control that the grain is what is pinned: a one-row body over
    // the three bytes is another preimage.
    let one_row = PublishBody::within(MAX_SHOT_BODY_BYTES, None)
        .expect("an empty base")
        .push(b"abc")
        .expect("one row")
        .finish();
    assert_ne!(over_stretch, one_row.as_bytes().to_vec(), "a row per piece is another body");
    // A run short of its stored bytes is still composed per value, and
    // one past them is the missing value.
    let snap = stretch.kernel().snapshot();
    let short = Run::new(run.i_start().clone(), Nat::from(2u32)).expect("a two-position run");
    assert!(publish_body(snap.world(), &shot, &[SegmentRun::Value(short)]).is_ok());
    let long = Run::new(run.i_start().clone(), Nat::from(4u32)).expect("a four-position run");
    assert!(matches!(
        publish_body(snap.world(), &shot, &[SegmentRun::Value(long)]),
        Err(ComposeFault::MissingValue)
    ));
}
