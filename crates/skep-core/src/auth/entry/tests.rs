use skep_address::Span;
use skep_febe::{Codec, OpKind};
use skep_identity::{entry_body_publish, entry_body_record, EntrySlot};
use skep_links::{enc, registry, ShippedType};
use skep_kernel::Seq;

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
        (
            entry_body_empty(ContentFreeOp::CreateWellKnownDocument),
            OpKind::CreateWellKnownDocument,
        ),
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
        as_of: Seq(7),
    };
    let _ = compose(world, &delete, BOOTSTRAP_PRINCIPAL, board);
}

/// Checks the well-known creation's cell: its frame names its slot.
///
/// The frame composed for a `create_well_known_document` is the empty body
/// under the op's own token over the slot document's own address,
/// `<account>.0.<slot>`, at every slot — the address M3 computes from the
/// request's account and slot, registry-free, so before anything stands
/// there. It is never the frame over the parent account, the mints' term,
/// which every slot of the account would share; never another slot's; and
/// never under `create_new_document`'s token. An `account` of another tier
/// anchors no document chain and so names no slot: the composer answers
/// the fault the check passes through to the store's `not_an_account`,
/// never a frame over the address as sent.
#[test]
fn a_well_known_creations_frame_names_the_slot_documents_own_address() {
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
    use skep_namespace::{WellKnownSlot, BOOTSTRAP_PRINCIPAL};

    let engine = skep_engine::Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    let own = world.m3().principal_prefix(BOOTSTRAP_PRINCIPAL).expect("genesis seats principal 0").clone();
    let board = BoardTerm { log_position: 1, chain: [7; 32] };
    let alg = "mldsa65-ed25519";
    let address = |text: &str| crate::codec::wire_address(text).expect("a test address");
    let account = address("1.0.7");
    let spelled = |doc: &Address, op: ContentFreeOp| {
        entry_frame(alg, board, &own, DocTerm::One(doc), &entry_body_empty(op))
    };
    let composed = |slot: WellKnownSlot| {
        let op = Op::CreateWellKnownDocument { account: account.clone(), slot };
        match compose(world, &op, BOOTSTRAP_PRINCIPAL, board) {
            Ok(frame) => frame.to_bytes(alg),
            Err(fault) => panic!("{slot:?}: the creation's frame composes: {fault:?}"),
        }
    };
    for slot in WellKnownSlot::ALL {
        let document = address(&format!("1.0.7.0.{}", slot.number()));
        let frame = composed(slot);
        assert_eq!(
            frame,
            spelled(&document, ContentFreeOp::CreateWellKnownDocument),
            "{slot:?}: the empty body, the op's own token, over {document}"
        );
        assert_ne!(
            frame,
            spelled(&account, ContentFreeOp::CreateWellKnownDocument),
            "{slot:?}: never the parent account"
        );
        assert_ne!(
            frame,
            spelled(&document, ContentFreeOp::CreateNewDocument),
            "{slot:?}: never `create_new_document`'s token"
        );
        for other in WellKnownSlot::ALL.into_iter().filter(|other| *other != slot) {
            assert_ne!(frame, composed(other), "{slot:?}: never {other:?}'s frame");
        }
    }
    // No slot stands under a node's address or a document's.
    for no_account in [address("1"), address("1.0.7.0.1")] {
        let op = Op::CreateWellKnownDocument { account: no_account.clone(), slot: WellKnownSlot::Policy };
        assert!(
            matches!(compose(world, &op, BOOTSTRAP_PRINCIPAL, board), Err(ComposeFault::NoSlotAddress)),
            "{no_account}: an address that anchors no document chain names no slot"
        );
    }
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
    let shot = Shot { base: None, draft: None, also: vec![], keep_base: false, runs: Vec::new() };
    let body_of = |engine: &skep_engine::Engine| {
        let snap = engine.kernel().snapshot();
        publish_body(snap.world(), &shot, &[SegmentRun::Value(run.clone())], &mut |_| {})
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
    assert!(publish_body(snap.world(), &shot, &[SegmentRun::Value(short)], &mut |_| {}).is_ok());
    let long = Run::new(run.i_start().clone(), Nat::from(4u32)).expect("a four-position run");
    assert!(matches!(
        publish_body(snap.world(), &shot, &[SegmentRun::Value(long)], &mut |_| {}),
        Err(ComposeFault::MissingValue)
    ));
}

/// Checks the supersession claim's rows (the merge bridge lane, brief A).
///
/// A `supersede` entry's planned deposit spells, in the trunk's home by
/// address, the `assert_sup` body's rows over the claim the store deposits:
/// the supersedes class's one unit span — the type slot of
/// `supersession_claim` itself, so the row and the stored link agree by
/// construction — `from` the daughter's unit span, and `to` ONE TAG
/// ELEMENT, the member the commit mints, whose address no signer holds
/// before the commit.
#[test]
fn the_supersession_claims_rows_are_the_class_the_daughter_and_the_member_by_tag() {
    use skep_links::{DepositPlan, PlannedHome};

    let addr = |comps: &[u32]| {
        skep_address::validate(
            skep_address::Tumbler::new(comps.iter().map(|&c| skep_address::Nat::from(c)))
                .expect("a tumbler"),
        )
        .expect("an address")
    };
    let (trunk, daughter) = (addr(&[1, 0, 1, 0, 65]), addr(&[1, 0, 1, 0, 65, 1, 1]));
    let plan = DepositPlan {
        homes: vec![PlannedHome {
            home: NamedAddress::Address(trunk.clone()),
            deposits: vec![PlannedDeposit::Supersede { index: 0, old: daughter.clone() }],
        }],
        originals: vec![],
    };
    let rows = deposit_rows(&plan, Some(&trunk));
    assert_eq!(rows.len(), 1);
    let sup = unit_span(&addr(&[1, 1, 0, 1, 0, 1, 0, 1, 4]));
    let old = unit_span(&daughter);
    assert_eq!(
        rows[0].borrow(),
        DepositRow {
            home: DepositHome::Address(&trunk),
            kind: DepositKind::Supersede,
            ty: DepositSlot::Stored(vec![SlotElement::Span(&sup)]),
            from: DepositSlot::Stored(vec![SlotElement::Span(&old)]),
            to: DepositSlot::Stored(vec![SlotElement::Member]),
        }
    );
    assert_eq!(
        spans_of(supersession_claim(&daughter, &trunk).type_slot()),
        vec![sup],
        "the type row is the stored claim's own type slot"
    );
}

/// An in-memory engine at genesis, for the shot's body over a real world.
fn genesis() -> skep_engine::Engine {
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
    skep_engine::Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail")
}

/// A private draft of the system principal's holding `values`, typed in by
/// one insert: the draft, and the address of its first value.
fn draft_holding(engine: &skep_engine::Engine, values: Vec<skep_content::Val>) -> (Address, Address) {
    use skep_arrangement::{AsOf, VPos};
    use skep_namespace::{system_account, SYSTEM_PRINCIPAL};
    let (draft, _) = engine
        .namespace()
        .create_new_document(SYSTEM_PRINCIPAL, &system_account(), Some(false))
        .expect("the system principal mints a private draft in its own account");
    let first = engine
        .vstream()
        .insert(Caller::Principal(SYSTEM_PRINCIPAL), &draft, VPos::content(Nat::from(1u32)), values, Deposit::Undeclared, AsOf::Typed(engine.kernel().current_seq()))
        .expect("the insert commits")
        .0;
    (draft, first)
}

/// The birth shot of the head document from `width` positions of `draft`
/// from `first`: its body as the composer builds it, and the stored pieces
/// the store's count read ahead of its rows.
fn body_counting(engine: &skep_engine::Engine, draft: &Address, first: &Address, width: usize) -> (Result<EntryBody, ComposeFault>, u64) {
    use skep_arrangement::{Run, ShotRun};
    let run = Run::new(first.clone(), Nat::from(width)).expect("a run of one position or more");
    let shot = Shot { base: None, draft: Some(draft.clone()), also: vec![], keep_base: false, runs: vec![ShotRun { origin: draft.clone(), run }] };
    let snap = engine.kernel().snapshot();
    let mut walked = 0u64;
    let body = publish_body(snap.world(), &shot, &shot.address_form(&skep_namespace::head_document()), &mut |pieces| walked += pieces);
    (body, walked)
}

/// [`body_counting`]'s body alone.
fn body_over(engine: &skep_engine::Engine, draft: &Address, first: &Address, width: usize) -> Result<EntryBody, ComposeFault> {
    body_counting(engine, draft, first, width).0
}

/// Checks that the composer asks the store's count of a shot's units before
/// it builds a row.
///
/// A draft of two-byte atoms, one more than the store's units budget and
/// far inside its positions budget: the shot naming them all is one the
/// store refuses `too_many_values` on its units before it stages a record,
/// and the composer answers it [`ComposeFault::PastReinsertBudget`] — the
/// fault the check passes through unattested — where a composer asking the
/// positions alone would build every row, a body well inside its budget,
/// and hand the check a frame to verify for a shot nothing commits. Naming
/// exactly the budget, the body composes, a row an atom.
#[test]
fn a_shot_past_the_stores_units_is_refused_before_a_row_is_built() {
    use skep_arrangement::{MAX_REINSERTED_UNITS, MAX_REINSERTED_VALUES};
    use skep_content::Val;
    let engine = genesis();
    let atoms = MAX_REINSERTED_UNITS + 1;
    assert!(atoms < MAX_REINSERTED_VALUES, "premise: inside the positions' budget");
    let (draft, first) = draft_holding(&engine, vec![Val::new(&b"at"[..]); atoms]);
    let (refused, walked) = body_counting(&engine, &draft, &first, atoms);
    assert!(matches!(refused, Err(ComposeFault::PastReinsertBudget)), "past the units: no row built");
    assert_eq!(walked, atoms as u64, "the count stopped at the atom that passed the budget");
    let at_the_budget = body_over(&engine, &draft, &first, MAX_REINSERTED_UNITS).expect("the units' budget of atoms composes");
    let one_atom = body_over(&engine, &draft, &first, 1).expect("one atom composes");
    assert_eq!(at_the_budget.as_bytes().len() - one_atom.as_bytes().len(), (MAX_REINSERTED_UNITS - 1) * (4 + 2), "a row an atom: its length and its two bytes");
}

/// Checks that the positions' arithmetic answers ahead of every stored piece,
/// and that text of the positions' budget composes, one row a byte.
///
/// A draft holding nothing where the shot points: one position past the
/// store's positions budget is [`ComposeFault::PastReinsertBudget`] — the
/// count's arithmetic, which reads nothing — where a count that walked
/// first would have met the first address holding no value and answered
/// [`ComposeFault::MissingValue`], as the shot naming exactly the budget
/// does; and over a draft holding one more typed byte than the budget the
/// same refusal is answered with no stored piece read, where the budget's
/// own number of them is read as one piece. And a draft holding the
/// budget's own number of typed bytes, one
/// stretch and so one unit: its shot is inside both budgets, and the body
/// spells it in as many rows as it has bytes — the walk the positions'
/// budget bounds — within the body budget, the next power of two of
/// one-byte rows being past it.
#[test]
fn the_positions_budget_is_asked_by_arithmetic_and_its_text_composes_one_row_a_byte() {
    use skep_arrangement::MAX_REINSERTED_VALUES;
    use skep_content::Val;
    let engine = genesis();
    let (draft, first) = draft_holding(&engine, vec![Val::new(&b"x"[..])]);
    let past_the_draft = skep_address::validate(skep_address::shift(first.tumbler(), &Nat::from(1u32))).expect("the next content address");
    assert!(matches!(body_over(&engine, &draft, &past_the_draft, MAX_REINSERTED_VALUES + 1), Err(ComposeFault::PastReinsertBudget)));
    assert!(matches!(body_over(&engine, &draft, &past_the_draft, MAX_REINSERTED_VALUES), Err(ComposeFault::MissingValue)));
    // One typed byte more than the budget, all of it stored — one insert,
    // one stretch: refused by the arithmetic, no stored piece read.
    let (text, first) = draft_holding(&engine, vec![Val::new(&b"x"[..]); MAX_REINSERTED_VALUES + 1]);
    let (refused, walked) = body_counting(&engine, &text, &first, MAX_REINSERTED_VALUES + 1);
    assert!(matches!(refused, Err(ComposeFault::PastReinsertBudget)));
    assert_eq!(walked, 0, "a shot the arithmetic refuses reads no stored piece");
    // The budget's own number of them: one unit, read as one stored piece.
    let (body, walked) = body_counting(&engine, &text, &first, MAX_REINSERTED_VALUES);
    let body = body.expect("text of the positions' budget composes");
    assert_eq!(walked, 1, "the count's walk: the one stretch");
    let rows = |count: usize| body_over(&engine, &text, &first, count).expect("a prefix of the text composes").as_bytes().len();
    let row = rows(2) - rows(1);
    assert_eq!(row, 4 + 1, "a one-byte row: its four-byte length and the byte");
    assert_eq!(body.as_bytes().len() - rows(1), (MAX_REINSERTED_VALUES - 1) * row, "one row a byte");
    let fits = |positions: usize| positions * row <= MAX_SHOT_BODY_BYTES;
    assert!(fits(MAX_REINSERTED_VALUES) && !fits(2 * MAX_REINSERTED_VALUES), "the positions' budget is the largest power of two whose one-byte rows fit the body");
}
