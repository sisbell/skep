use skep_address::subtree_of;
use skep_identity::CredentialKind;

use skep_engine::types::t_enroll;

use super::*;
use crate::auth::policy::addr_of;

/// An in-memory engine built through M10 alone, its board unclaimed, with
/// two bootstrap-delegated accounts — the MAKER `1.0.1` (principal 900) and
/// ANOTHER `1.0.2` (901) — each holding its born-published home, and the
/// maker a private draft beside it; the exec closure every cell below writes
/// through. The shape the supersession cell builds, lifted out so the fence
/// cells and the correspondence cell build theirs the same way.
struct TwoAccounts {
    engine: skep_engine::Engine,
    febe: skep_febe::OperationSurface<skep_engine::World>,
    maker: (PrincipalId, skep_febe::SessionId),
    other: (PrincipalId, skep_febe::SessionId),
    home: String,
    other_home: String,
    draft: String,
}

impl TwoAccounts {
    fn open() -> TwoAccounts {
        use serde_json::json;
        use skep_febe::OperationSurface;
        use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};

        let engine = skep_engine::Engine::open(KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(0),
        })
        .expect("in-memory genesis cannot fail");
        let febe = OperationSurface::new(Box::new(engine.stores()), std::num::NonZeroUsize::MIN);
        let (maker_id, other_id) = (PrincipalId(900), PrincipalId(901));
        let boot = febe.bootstrap_session();
        let delegate = |prefix: &str, id: PrincipalId| json!({"op": "delegate", "new_prefix": prefix, "new_id": id.0});
        exec(&febe, boot, delegate("1.0.1", maker_id));
        exec(&febe, boot, delegate("1.0.2", other_id));
        let (maker, other) = (febe.open_session(maker_id), febe.open_session(other_id));
        let mint = |sid, account: &str| exec(&febe, sid, json!({"op": "create_new_document", "account": account})).to_string();
        let (home, other_home) = (mint(maker, "1.0.1"), mint(other, "1.0.2"));
        let draft = mint(maker, "1.0.1");
        TwoAccounts { engine, febe, maker: (maker_id, maker), other: (other_id, other), home, other_home, draft }
    }

    /// Claims the board for the maker through M10 alone.
    ///
    /// The ceremony's last three steps: the genesis atom into the maker's
    /// home, its enroll link and the claim (as `commits::feed::attest`'s
    /// tests claim their boards).
    ///
    /// # Panics
    ///
    /// Panics where a step is refused or the board does not read claimed.
    fn claim(&self) {
        use serde_json::json;
        use skep_engine::types::t_claim;
        use skep_identity::{encode_enroll, Enrollment};
        use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

        let (_, maker) = self.maker;
        let key = |n: u8| {
            HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[n; 32])
                .expect("tag 1")
                .public_key()
                .clone()
        };
        let genesis = encode_enroll(&[
            Enrollment::new(key(1), true, None).expect("no label"),
            Enrollment::new(key(2), false, None).expect("no label"),
        ]);
        let home = self.home.as_str();
        let atom = exec(
            &self.febe,
            maker,
            json!({"op": "insert", "doc": home, "at": {"subspace": "1", "ordinal": "1"},
                   "values": [{"atom": genesis}], "deposit": t_enroll().to_string(),
                   "as_of": self.febe.log_position().0}),
        )
        .to_string();
        let link = |from: &str, to: &[&str], ty: &Address| {
            json!({"op": "make_link", "home": home, "from": {"addrs": [from]},
                   "to": {"addrs": to}, "ty": {"addrs": [ty.to_string()]}})
        };
        exec(&self.febe, maker, link(&atom, &["1.0.1"], t_enroll()));
        exec(&self.febe, maker, link("1.0.1", &[], t_claim()));
        assert!(
            self.engine.kernel().snapshot().world().identity().claimant().is_some(),
            "the premise: claimed"
        );
    }
}

/// THE PRICE AHEAD OF THE LOCK (the link-sets design §5.7, W8 (1)): the
/// producer answers the four terms where a publication's in-lock reads are
/// priced past `MAX_PUBLICATION_READS`, and nothing at the budget. The
/// draft term: the maker's draft fragmented into seventeen runs by
/// seventeen inserts at its first position — each value's identity above
/// the last's, so no run merges — and a shot of 4096 runs over it, a kept
/// place carried so the re-window reads the draft, prices at 17 × 4096,
/// past the budget's 16 × 4096; the same shot off a sixteen-run draft is at
/// the budget and admitted, and the seventeen-run shot with NO place carried
/// reads no draft and is admitted too. The home term: one link deposited in
/// the maker's home makes it the one link-holding home, and a read-with
/// list one entry past the budget is refused on it where the shot names no
/// draft. The other's account prices no homes of the maker's, and an op
/// that is no publish is nothing's.
#[test]
fn a_publications_reads_priced_past_the_budget_are_refused_ahead_of_the_lock() {
    use serde_json::json;
    use skep_address::Nat;
    use skep_arrangement::{HasM5, VPos};
    use skep_febe::{EndArg, LinkEntry, MemberSpan, NamedAddress, PublishDeposits, PublishTarget, Run, Shot, ShotRun};
    use skep_kernel::MAX_TXN_BYTES;
    use skep_links::{stored_tumbler_bytes, KEPT_PLACE_BYTES, MAX_PUBLICATION_READS, PLACED_RUN_BYTES, READ_WITH_BYTES, SHOT_BYTES};

    use crate::auth::policy::{publication_read_refusal, PublicationReadRefusal};

    let board = TwoAccounts::open();
    let (maker_id, maker) = board.maker;
    let draft = crate::codec::wire_address(&board.draft).expect("the draft's address");
    let home = crate::codec::wire_address(&board.home).expect("the home's address");
    let fragment = |count: usize| {
        for _ in 0..count {
            exec(&board.febe, maker, json!({"op": "insert", "doc": board.draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["a"], "as_of": board.febe.log_position().0}));
        }
    };
    let shot = |draft: Option<Address>, runs: usize| Shot {
        base: None,
        draft,
        also: vec![],
        keep_base: false,
        runs: vec![ShotRun { origin: home.clone(), run: Run::new(addr_of(&[1, 0, 1, 0, 1, 0, 1, 1]), Nat::from(1u32)).expect("a run") }; runs],
    };
    let publish_at = |shot: Shot, places: Vec<Option<VPos>>, read_with: usize| Op::Publish {
        target: PublishTarget::Document(home.clone()),
        shot,
        places,
        also_places: Vec::new(),
        deposits: PublishDeposits { claim: false, links: Vec::new(), retract: Vec::new(), read_with: vec![home.clone(); read_with], supersede: Vec::new(), originals: Vec::new(), base_runs: Vec::new() },
    };
    // A drafted shot carries one kept place — beside its first run, a stray
    // place — so the re-window reads the draft; a draftless one none.
    let publish = |shot: Shot, read_with: usize| {
        let places = if shot.draft.is_some() { vec![Some(VPos::content(Nat::from(1u32)))] } else { Vec::new() };
        publish_at(shot, places, read_with)
    };
    // The draft term, at the budget and one run past it.
    fragment(16);
    let snap = board.engine.kernel().snapshot();
    assert_eq!(snap.world().m5().content_run_count(&draft), 16, "sixteen inserts at the front: sixteen runs");
    assert_eq!(publication_read_refusal(snap.world(), &publish(shot(Some(draft.clone()), 4096), 0), maker_id), None, "16 × 4096 is the budget");
    fragment(1);
    let snap = board.engine.kernel().snapshot();
    // The staged bytes beside the reads: the shot, the rendering draft's
    // address in its slot, 4096 by-reference placements and the one stray
    // place's stab (no record: one piece), inside the transaction budget.
    let staged = SHOT_BYTES + stored_tumbler_bytes(draft.tumbler()) + 4096 * PLACED_RUN_BYTES + KEPT_PLACE_BYTES;
    assert_eq!(
        publication_read_refusal(snap.world(), &publish(shot(Some(draft.clone()), 4096), 0), maker_id),
        Some(PublicationReadRefusal { homes: 0, entries: 0, draft_runs: 17, runs: 4096, total: 17 * 4096, budget: MAX_PUBLICATION_READS, staged_bytes: staged, byte_budget: MAX_TXN_BYTES }),
        "17 × 4096 is past it: every term named"
    );
    let unplaced = publish_at(shot(Some(draft.clone()), 4096), Vec::new(), 0);
    assert_eq!(publication_read_refusal(snap.world(), &unplaced, maker_id), None, "no place carried: the re-window reads no draft, and the draft term is nothing");
    // The home term: one link-holding home, a list one entry past the budget.
    exec(&board.febe, maker, json!({"op": "make_link", "home": board.home, "from": {"addrs": []}, "to": {"addrs": []}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}}));
    let snap = board.engine.kernel().snapshot();
    let over = publish(shot(None, 0), MAX_PUBLICATION_READS + 1);
    let staged = SHOT_BYTES + (MAX_PUBLICATION_READS as u64 + 1) * READ_WITH_BYTES;
    assert!(staged <= MAX_TXN_BYTES, "the read-withs stage inside the transaction budget: {staged}");
    assert_eq!(
        publication_read_refusal(snap.world(), &over, maker_id),
        Some(PublicationReadRefusal { homes: 1, entries: MAX_PUBLICATION_READS + 1, draft_runs: 0, runs: 0, total: MAX_PUBLICATION_READS + 1, budget: MAX_PUBLICATION_READS, staged_bytes: staged, byte_budget: MAX_TXN_BYTES }),
        "one home times one entry past the budget"
    );
    assert_eq!(publication_read_refusal(snap.world(), &publish(shot(None, 0), MAX_PUBLICATION_READS), maker_id), None, "at the budget");
    assert_eq!(publication_read_refusal(snap.world(), &over, board.other.0), None, "the other holds no link-holding home");
    assert_eq!(publication_read_refusal(snap.world(), &Op::Fork { published: None }, maker_id), None, "no publish, no price");
    // THE FIFTH TERM (lane F4): the staged bytes past the transaction budget
    // with the reads inside theirs — a hundred `links` entries whose `from`
    // names the member's 4096 positions over a 4096-run shot, each resolving
    // to up to 4096 stored spans — refused with the bytes named; one such
    // entry is inside both budgets.
    let wide = |count: usize| Op::Publish {
        target: PublishTarget::Document(home.clone()),
        shot: shot(None, 4096),
        places: Vec::new(),
        also_places: Vec::new(),
        deposits: PublishDeposits {
            claim: false,
            links: (0..count)
                .map(|_| LinkEntry {
                    home: NamedAddress::Member,
                    from: EndArg::Member(vec![MemberSpan { ordinal: 1, width: 4096 }]),
                    to: EndArg::Addrs(Vec::new()),
                    ty: EndArg::Addrs(vec![NamedAddress::Address(addr_of(&[1, 1, 0, 1, 0, 1, 0, 3, 13]))]),
                    old: None,
                })
                .collect(),
            retract: Vec::new(),
            read_with: Vec::new(),
            supersede: Vec::new(),
            originals: Vec::new(),
            base_runs: Vec::new(),
        },
    };
    assert_eq!(publication_read_refusal(snap.world(), &wide(1), maker_id), None, "one wide entry is inside both budgets");
    let refusal = publication_read_refusal(snap.world(), &wide(100), maker_id).expect("a hundred are past the transaction budget");
    assert!(refusal.bytes_over() && !refusal.reads_over(), "the bytes, not the reads: {refusal:?}");
    assert_eq!((refusal.homes, refusal.entries, refusal.draft_runs, refusal.runs, refusal.byte_budget), (1, 100, 0, 4096, MAX_TXN_BYTES));
    assert!(refusal.staged_bytes > MAX_TXN_BYTES && refusal.staged_bytes < 2 * MAX_TXN_BYTES, "{}", refusal.staged_bytes);
}

/// Executes `frame` through M10 as `sid`, answering the ack's address.
///
/// # Panics
///
/// Panics where the frame does not parse or the surface answers anything but
/// an `ack_addr`.
fn exec(febe: &skep_febe::OperationSurface<skep_engine::World>, sid: skep_febe::SessionId, frame: serde_json::Value) -> Address {
    use skep_febe::{Codec, Response};

    use crate::codec::JsonCodec;

    let req = JsonCodec.parse(frame.to_string().as_bytes()).unwrap_or_else(|e| panic!("{frame}: {:?}", e.detail));
    match febe.execute(sid, req) {
        Response::AckAddr { addr, .. } => addr,
        other => panic!("{frame}: {}", String::from_utf8_lossy(&JsonCodec.marshal(&other))),
    }
}

/// THE BASE AHEAD OF THE LOCK (§5.1's key (iii) as E4 2.1 re-says it): the
/// maker's draft `abc` published as its home's first member, a publication
/// off that member whose `links` entry names an original has the member's
/// runs over its positions `1 ..= base_extent` set on its deposits — cut
/// where the extent stops inside a run — and one naming no original, or
/// standing off the bare document, carries none.
#[test]
fn a_publications_base_runs_are_set_ahead_of_the_lock_where_an_entry_names_an_original() {
    use serde_json::json;
    use skep_address::Nat;
    use skep_arrangement::{Base, HasM5};
    use skep_febe::{EndArg, LinkEntry, NamedAddress, PublishDeposits, PublishTarget, Run, Shot};

    use crate::auth::policy::publication_base;

    let board = TwoAccounts::open();
    let (_, maker) = board.maker;
    exec(&board.febe, maker, json!({"op": "insert", "doc": board.draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["abc"], "as_of": board.febe.log_position().0}));
    let draft_word = format!("{}.0.1.1", board.draft);
    let member = exec(&board.febe, maker, json!({"op": "publish", "doc": board.home, "draft": board.draft, "runs": [{"origin": board.draft, "i_start": draft_word, "width": "3"}]}));
    let home = crate::codec::wire_address(&board.home).expect("the home's address");
    let publish = |base: &Address, extent: u32, old: Option<Address>| Op::Publish {
        target: PublishTarget::Document(home.clone()),
        shot: Shot { base: Some(Base { member: base.clone(), extent: Nat::from(extent) }), draft: None, also: Vec::new(), keep_base: false, runs: Vec::new() },
        places: Vec::new(),
        also_places: Vec::new(),
        deposits: PublishDeposits {
            links: vec![LinkEntry { home: NamedAddress::Member, from: EndArg::Addrs(Vec::new()), to: EndArg::Addrs(Vec::new()), ty: EndArg::Addrs(vec![NamedAddress::Address(home.clone())]), old }],
            ..PublishDeposits::default()
        },
    };
    let snap = board.engine.kernel().snapshot();
    let based = |mut op: Op| -> Vec<Run> {
        publication_base(snap.world(), &mut op);
        let Op::Publish { deposits, .. } = op else { unreachable!("a publish") };
        deposits.base_runs
    };
    let runs: Vec<Run> = snap.world().m5().content_runs(&member).cloned().collect();
    assert_eq!(runs.len(), 1, "the premise: the member's one run of three");
    let original = Some(addr_of(&[1, 0, 1, 0, 64, 0, 2, 1]));
    assert_eq!(based(publish(&member, 3, original.clone())), runs, "the member's positions 1..3");
    assert_eq!(based(publish(&member, 2, original.clone())), vec![Run::new(runs[0].i_start().clone(), Nat::from(2u32)).expect("a run")], "cut where the extent stops");
    assert!(based(publish(&member, 3, None)).is_empty(), "no entry names an original: no read");
    assert!(based(publish(&home, 3, original)).is_empty(), "the bare document keys nothing");
}

/// Checks the sole-writer fence's correspondence half (the link-sets design
/// §5.7, the `replaces` fence's twin).
///
/// Over an unclaimed board, where ownership alone decides the producer: a
/// `make_link`, an `emit` and an `edit_link` successor typed the class by
/// the home's owner answer `correspondence_not_standalone`; from another
/// account they answer nothing — the destination's `not_owner` is
/// `execute`'s, downstream, the ordering pin; the parent `counterpart`
/// `3.102`, alone or beside the subtype it covers, is no class and answers
/// nothing; a `Resolve` and an I-span slot name content and answer nothing;
/// and the `replaces` half keeps its own token through the one producer.
#[test]
fn the_sole_writer_fence_refuses_the_correspondence_class_to_the_owner_alone() {
    use skep_engine::types::{t_correspondence, t_replaces};
    use skep_febe::SuccessorSpec;

    use crate::auth::CredentialLock;

    let board = TwoAccounts::open();
    let snap = board.engine.kernel().snapshot();
    let world = snap.world();
    let lock = CredentialLock::new();
    let home = crate::codec::wire_address(&board.home).expect("the home's address");
    let draft = crate::codec::wire_address(&board.draft).expect("the draft's address");
    let other_home = crate::codec::wire_address(&board.other_home).expect("the other home's address");
    let parent = addr_of(&[1, 1, 0, 1, 0, 1, 0, 3, 102]);
    let fence = |op: &Op, principal: PrincipalId| sole_writer_refusal(&lock.read(), world, op, principal);
    let make_link = |home: &Address, ty: SlotArg| Op::MakeLink {
        home: home.clone(),
        from: SlotArg::Addrs(Vec::new()),
        to: SlotArg::Addrs(Vec::new()),
        ty,
        replaces: None,
    };
    let emit = |home: &Address, ty: &Address| Op::Emit { home: home.clone(), ty: enc([ty]), from: home.clone(), to: Vec::new() };
    let edit_link = |home: &Address, ty: SlotArg| Op::EditLink {
        original: home.clone(),
        successor: SuccessorSpec { from: Vec::new().into(), to: Vec::new().into(), ty },
        d_s: home.clone(),
        d_a: home.clone(),
    };
    let addrs = |ty: &Address| SlotArg::Addrs(vec![ty.clone()]);
    let (maker, other) = (board.maker.0, board.other.0);
    let token = Some(CredentialRefusal::CorrespondenceNotStandalone);

    // The owner, at each door, in the published home and in the draft alike.
    for home in [&home, &draft] {
        assert_eq!(fence(&make_link(home, addrs(t_correspondence())), maker), token, "make_link into {home}");
        assert_eq!(fence(&emit(home, t_correspondence()), maker), token, "emit into {home}");
        assert_eq!(fence(&edit_link(home, addrs(t_correspondence())), maker), token, "edit_link into {home}");
        // Beside a subtype of its own: one coverage class, the fence's.
        let beside = SlotArg::Addrs(vec![t_correspondence().clone(), addr_of(&[1, 1, 0, 1, 0, 1, 0, 3, 102, 1, 1])]);
        assert_eq!(fence(&make_link(home, beside), maker), token, "the class beside its own subtype");
    }
    // Another account: nothing here — `not_owner` is `execute`'s, downstream.
    assert_eq!(fence(&make_link(&home, addrs(t_correspondence())), other), None);
    assert_eq!(fence(&emit(&home, t_correspondence()), other), None);
    assert_eq!(fence(&edit_link(&home, addrs(t_correspondence())), other), None);
    // …and the owner of one home of an edit's two is no owner of both.
    let straddling = Op::EditLink {
        original: home.clone(),
        successor: SuccessorSpec { from: Vec::new().into(), to: Vec::new().into(), ty: addrs(t_correspondence()) },
        d_s: home.clone(),
        d_a: other_home.clone(),
    };
    assert_eq!(fence(&straddling, maker), None, "an edit naming another's home: `not_owner` downstream");
    // The parent is no class, alone or covering its subtype.
    assert_eq!(fence(&make_link(&home, addrs(&parent)), maker), None, "the parent counterpart");
    assert_eq!(fence(&emit(&home, &parent), maker), None);
    let covering = SlotArg::Addrs(vec![parent.clone(), t_correspondence().clone()]);
    assert_eq!(fence(&make_link(&home, covering), maker), None, "the parent covers the subtype: counterpart's class");
    // The content forms name no class.
    assert_eq!(fence(&make_link(&home, SlotArg::Resolve(Vec::new())), maker), None);
    assert_eq!(fence(&make_link(&home, SlotArg::Spans(vec![subtree_of(t_correspondence().tumbler())])), maker), None);
    // The `replaces` half, through the one producer.
    assert_eq!(fence(&make_link(&home, addrs(t_replaces())), maker), Some(CredentialRefusal::ReplacesNotStandalone));
    assert_eq!(fence(&make_link(&home, addrs(t_replaces())), other), None);
    assert_eq!(CredentialRefusal::CorrespondenceNotStandalone.token(), "correspondence_not_standalone");
    assert_eq!(CredentialRefusal::CorrespondenceNotStandalone.disposition(), skep_febe::Disposition::Permanent);
}

/// Checks the correspondence class's `nullify` cell (PUB-6.64's member; the
/// link-sets design §5.7).
///
/// The class has no writer until the publish shot's lane lands — every door
/// refuses it — so the one link of the class here is STAGED DIRECTLY into
/// the kernel, as a replayed journal frame reaches M7's fold: an M7 record
/// decoded from its own serde shape, with none of M7's write gates between,
/// at the address M3 mints for the maker's draft. The board is CLAIMED
/// through M10 (the ceremony, no head), so entitlement decides the answer:
/// the maker's `nullify` of the record, homed in its draft, answers
/// `nullify_audit_view`; another account's answers nothing — `not_owner`
/// downstream, the ordering pin; and a link typed the parent `counterpart`
/// `3.102`, deposited through `make_link` as any client may, is an ordinary
/// link whose owner's retraction this producer admits.
#[test]
fn a_correspondence_records_nullify_is_refused_to_its_owner_and_falls_through_for_a_stranger() {
    use serde_json::json;
    use skep_engine::types::t_correspondence;
    use skep_links::LinkRec;

    use crate::auth::CredentialLock;

    let board = TwoAccounts::open();
    let (maker_id, maker) = board.maker;
    let (other_id, _) = board.other;
    board.claim();

    // The parent-typed link, through the door every client has.
    let draft = board.draft.as_str();
    let counterpart = exec(
        &board.febe,
        maker,
        json!({"op": "make_link", "home": draft, "from": {"addrs": []}, "to": {"addrs": []},
               "ty": {"addrs": ["1.1.0.1.0.1.0.3.102"]}}),
    );
    // The correspondence record, staged directly: M3's mint for the draft's
    // link subspace, then M7's deposit record decoded from its serde shape —
    // `LinkRec` being `#[non_exhaustive]`, no crate but M7 builds one by
    // literal.
    let draft_addr = crate::codec::wire_address(draft).expect("the draft's address");
    let run = addr_of(&[1, 0, 1, 0, 65, 0, 1, 1]);
    let member = addr_of(&[1, 0, 1, 0, 1, 1, 0, 1, 1]);
    let value = Link::triple(enc([&run]), enc([&member]), enc([t_correspondence()]));
    let (record, _) = board
        .engine
        .kernel()
        .transact(&[], |stg| {
            let (addr, m3rec) = stg.working().m3().mint_link(&draft_addr).expect("a registered draft mints a link");
            stg.push(skep_engine::Record::Namespace(m3rec));
            let raw = json!({"Deposit": {
                "addr": serde_json::to_value(addr.tumbler()).expect("a tumbler serializes"),
                "value": serde_json::to_value(&value).expect("a link serializes"),
            }});
            let rec: LinkRec = serde_json::from_value(raw).expect("M7's record decodes from its own serde shape");
            stg.push(skep_engine::Record::Links(rec));
            Ok::<Address, ()>(addr)
        })
        .expect("the staged deposit commits");

    let snap = board.engine.kernel().snapshot();
    let world = snap.world();
    assert_eq!(world.links().readlink(&record).map(|l| l.type_slot().clone()), Some(enc([t_correspondence()])), "the record stands, typed the class");
    let lock = CredentialLock::new();
    let class_of = |target: &Address, caller: PrincipalId| {
        let op = Op::Nullify { home: draft_addr.clone(), target: target.clone() };
        nullify_refusal(&lock.read(), world, &op, caller)
    };
    assert_eq!(class_of(&record, maker_id), Some(CredentialRefusal::NullifyAuditView), "the owner: PUB-6.64's cell");
    assert_eq!(class_of(&record, other_id), None, "a stranger: nothing here, `not_owner` downstream");
    assert_eq!(class_of(&counterpart, maker_id), None, "the parent counterpart: an ordinary link, its retraction admitted");
    // THE RIDER's CLASS CELL (the link-sets design §5.7 (vi′)): a publication
    // whose `originals` names the record — behind whatever claim the owner
    // may have asserted onto a copy, which the store's plan alone would
    // admit — is refused by the same producer at the entry's index in the
    // rider, `audit_view`, so the record stays active; the counterpart
    // passes, and a stranger's request answers nothing here. The `retract`
    // list is judged first: an entry of each refused names the `retract`
    // list's.
    use crate::auth::policy::{retract_class_refusal, RetractClassRefusal, RetractList};
    use skep_arrangement::Shot;
    use skep_links::{OriginalEntry, PublishDeposits, PublishTarget};
    let publish = |retract: Vec<Address>, originals: Vec<Address>| Op::Publish {
        target: PublishTarget::Document(addr_of(&[1, 0, 1, 0, 1])),
        shot: Shot { base: None, draft: None, also: vec![], keep_base: false, runs: vec![] },
        places: vec![],
        also_places: vec![],
        deposits: PublishDeposits {
            retract,
            originals: originals.into_iter().map(|old| OriginalEntry { old, rest: vec![] }).collect(),
            ..PublishDeposits::default()
        },
    };
    let rider = |caller: PrincipalId, originals: Vec<Address>| retract_class_refusal(&lock.read(), world, &publish(vec![], originals), caller);
    assert_eq!(
        rider(maker_id, vec![counterpart.clone(), record.clone()]),
        Some(RetractClassRefusal { list: RetractList::Originals, index: 1, cause: "audit_view" }),
        "the record named in the rider: refused at its entry, the counterpart passing"
    );
    assert_eq!(rider(other_id, vec![record.clone()]), None, "a stranger's rider: nothing here");
    assert_eq!(
        retract_class_refusal(&lock.read(), world, &publish(vec![record.clone()], vec![record.clone()]), maker_id),
        Some(RetractClassRefusal { list: RetractList::Retract, index: 0, cause: "audit_view" }),
        "the retract list is judged ahead of the rider"
    );
    assert!(world.links().is_active(&record), "the record stands: nothing here writes");
}

/// Checks that PUB-2.15's projection is address arithmetic and total.
///
/// A version member answers its document, a document answers itself, a
/// member of a member peels to the same document — and off the document
/// tier the arithmetic changes nothing (an account has no document field;
/// an element's field is its document's own). The projection the gate
/// reads is M5's, so this pins the one spelling the daemon shares with the
/// write path.
#[test]
fn a_version_member_projects_to_its_document() {
    let doc = addr_of(&[1, 0, 1, 0, 1]);
    assert_eq!(trunk_of(&doc), doc, "a document is its own trunk");
    assert_eq!(trunk_of(&addr_of(&[1, 0, 1, 0, 1, 1])), doc, "a version");
    assert_eq!(trunk_of(&addr_of(&[1, 0, 1, 0, 1, 1, 2])), doc, "a version of a version");
    let acct = addr_of(&[1, 0, 1]);
    assert_eq!(trunk_of(&acct), acct);
    let element = addr_of(&[1, 0, 1, 0, 1, 0, 1, 1]);
    assert_eq!(trunk_of(&element), element);
}

/// Checks the write path's input as wired.
///
/// Every pinned class address classifies to its own arm, the credential
/// kinds answer through the same input as `kind_of` does, the edition
/// class is *no* class (PUB-6.32 — its owner's retraction is admitted),
/// and a content span is nothing. The wiring itself — the `LazyLock`
/// constructing without the prefix-free assertion firing — is what the
/// first call proves.
#[test]
fn the_write_path_input_recognizes_every_pinned_class() {
    let types = write_types();
    let unit = |a: &Address| vec![subtree_of(a.tumbler())];
    assert_eq!(
        types.target_class(&unit(t_enroll())),
        Some(TargetClass::Credential(CredentialKind::Enroll))
    );
    assert_eq!(types.target_class(&unit(t_grant())), Some(TargetClass::Grant));
    for (class, addr) in [
        (AuditClass::SuccessorOf, t_successor_of()),
        (AuditClass::DelegatorEndorsement, t_endorse()),
        (AuditClass::ConsumptionMarker, t_consumption_marker()),
        (AuditClass::JournalDesignation, t_journal_designation()),
        (AuditClass::RailRecord, t_rail_record()),
        (AuditClass::StewardClassification, t_steward_classification()),
        (AuditClass::Replaces, t_replaces()),
        (AuditClass::Binding, t_binding()),
        (AuditClass::TakedownRecord, t_takedown()),
        (AuditClass::PolicyLink, t_policy_link()),
        (AuditClass::Supersession, &supersedes_type()),
        (AuditClass::Correspondence, t_correspondence()),
    ] {
        assert_eq!(
            types.target_class(&unit(addr)),
            Some(TargetClass::AuditView(class)),
            "{} is {class:?}",
            addr.tumbler()
        );
    }
    // The correspondence class is a subtype row under counterpart `3.102`
    // (the link-sets design §5.7): the parent is no class — an ordinary type
    // a picker lists, its owner's retraction admitted.
    assert_eq!(types.target_class(&unit(&addr_of(&[1, 1, 0, 1, 0, 1, 0, 3, 102]))), None);
    // The supersession class's address is M7's reserved ghost tumbler,
    // read from M7 and spelled here only to pin the reading: a stored
    // claim's type slot is exactly that class.
    assert_eq!(supersedes_type(), addr_of(&[1, 1, 0, 1, 0, 1, 0, 1, 4]));
    let claim = skep_links::supersession_claim(
        &addr_of(&[1, 0, 1, 0, 1, 0, 2, 1]),
        &addr_of(&[1, 0, 1, 0, 1, 0, 2, 2]),
    );
    assert_eq!(
        types.target_class(claim.type_slot()),
        Some(TargetClass::AuditView(AuditClass::Supersession))
    );
    // The registry's subtype rows are their kinds' members by prefix
    // (REG-1.21); the endpoint is no class at all (REG-1.11, REG-1.46).
    for (class, addr) in [
        (AuditClass::TakedownRecord, skep_engine::types::t_takedown_lifted()),
        (AuditClass::PolicyLink, skep_engine::types::t_disavowal()),
        (AuditClass::PolicyLink, skep_engine::types::t_succession_policy()),
    ] {
        assert_eq!(types.target_class(&unit(addr)), Some(TargetClass::AuditView(class)));
    }
    assert_eq!(types.target_class(&unit(skep_engine::types::t_endpoint())), None);
    // The edition class (3.14) is read under the active view: no class.
    assert_eq!(types.target_class(&unit(skep_engine::types::t_edition())), None);
    // A content I-span names nothing here either.
    let content = subtree_of(addr_of(&[1, 0, 1, 0, 1, 0, 1, 1]).tumbler());
    assert_eq!(types.target_class(&[content]), None);
    // A subtype by prefix is its class's member (L10): `endorse.trust`.
    let trust = addr_of(&[1, 1, 0, 1, 0, 1, 0, 3, 42, 2]);
    assert_eq!(
        types.target_class(&unit(&trust)),
        Some(TargetClass::AuditView(AuditClass::DelegatorEndorsement))
    );
}

/// Checks the supersession claim's two keys (PUB-6.64; skep #677).
///
/// The board is built through M10 alone and left unclaimed, where
/// [`nullify_refusal`] answers a class's token to every caller, so the
/// class decision is read bare. A claim in its maker's private notes is a
/// member where its `new` is homed in a published document and its `old`
/// is the maker's own: an ordinary link in the maker's account, or a
/// credential whose subject is the maker's account wherever it is homed —
/// the genesis a first rotation's trail names, in another account's doc 1.
/// The same claim over another account's ordinary link is an ordinary
/// link, and so is one over a credential naming another account, in the
/// maker's own home as anywhere, and one whose `new` is private. The keys
/// are facts of the claim: the maker and another account asking get one
/// answer.
#[test]
fn a_supersession_claim_is_a_member_only_over_its_makers_own_old() {
    use serde_json::json;

    use crate::auth::CredentialLock;

    let board = TwoAccounts::open();
    let (engine, febe) = (&board.engine, &board.febe);
    let exec = |sid, frame: serde_json::Value| -> Address { exec(febe, sid, frame) };
    let (maker_id, maker) = board.maker;
    let (other_id, other) = board.other;
    // Each account's home, born published; the maker's private notes.
    let (home, other_home, notes) = (board.home.clone(), board.other_home.clone(), board.draft.clone());
    let link = |sid, doc: &str, n: u32| -> String {
        exec(
            sid,
            json!({"op": "make_link", "home": doc, "from": {"addrs": []},
                   "to": {"addrs": []}, "ty": {"addrs": [format!("{doc}.0.3.6.{n}")]}}),
        )
        .to_string()
    };
    // An enroll-typed link naming `subject`: the class is its type slot's,
    // so the record atom a deposit's `from` names is left out.
    let credential = |sid, doc: &str, subject: &str| -> String {
        exec(
            sid,
            json!({"op": "make_link", "home": doc, "from": {"addrs": []},
                   "to": {"addrs": [subject]}, "ty": {"addrs": [t_enroll().to_string()]}}),
        )
        .to_string()
    };
    let own_old = link(maker, &notes, 1);
    let published_new = link(maker, &home, 2);
    let private_new = link(maker, &notes, 3);
    let foreign_old = link(other, &other_home, 4);
    // The maker's genesis as its registrar would home it, in another
    // account's doc 1; a credential the maker filed for another account in
    // its own; one naming the maker in its own.
    let makers_genesis = credential(other, &other_home, "1.0.1");
    let others_credential = credential(maker, &home, "1.0.2");
    let makers_credential = credential(maker, &home, "1.0.1");
    let claim = |old: &str, new: &str| {
        exec(maker, json!({"op": "assert_sup", "home": notes, "old": old, "new": new}))
    };
    let own = claim(&own_old, &published_new);
    let over_another = claim(&foreign_old, &published_new);
    let private = claim(&own_old, &private_new);
    let over_makers_genesis = claim(&makers_genesis, &published_new);
    let over_others_credential = claim(&others_credential, &published_new);
    let over_makers_credential = claim(&makers_credential, &published_new);

    let snap = engine.kernel().snapshot();
    let world = snap.world();
    assert!(world.identity().claimant().is_none(), "the premise: unclaimed, every caller told");
    let notes = crate::codec::wire_address(&notes).expect("the notes' address");
    let lock = CredentialLock::new();
    for caller in [maker_id, other_id] {
        let class_of = |target: &Address| {
            let op = Op::Nullify { home: notes.clone(), target: target.clone() };
            nullify_refusal(&lock.read(), world, &op, caller)
        };
        let member = |why: &str| format!("{caller:?}: {why}, a published `new`: a member");
        let audit_view = Some(CredentialRefusal::NullifyAuditView);
        assert_eq!(class_of(&own), audit_view, "{}", member("the maker's own `old`"));
        assert_eq!(
            class_of(&over_makers_genesis),
            audit_view,
            "{}",
            member("a credential naming the maker, homed in another's doc 1")
        );
        assert_eq!(
            class_of(&over_makers_credential),
            audit_view,
            "{}",
            member("a credential naming the maker, homed in its own")
        );
        let ordinary = |why: &str| format!("{caller:?}: {why}: an ordinary link");
        assert_eq!(class_of(&over_another), None, "{}", ordinary("another's `old`"));
        assert_eq!(class_of(&private), None, "{}", ordinary("a private `new`"));
        assert_eq!(
            class_of(&over_others_credential),
            None,
            "{}",
            ordinary("a credential naming another account, homed in the maker's own")
        );
    }
}

/// Three accounts for the well-known mint's cells, the third holding nothing.
///
/// [`TwoAccounts`]' board with a third bootstrap-delegated account `1.0.3`,
/// principal 902's, which holds no document: the answer is the board, that
/// account and its principal.
fn a_board_with_a_homeless_account() -> (TwoAccounts, Address, PrincipalId) {
    let board = TwoAccounts::open();
    let homeless_id = PrincipalId(902);
    let boot = board.febe.bootstrap_session();
    let homeless = exec(
        &board.febe,
        boot,
        serde_json::json!({"op": "delegate", "new_prefix": "1.0.3", "new_id": homeless_id.0}),
    );
    (board, homeless, homeless_id)
}

/// Checks the well-known creation's door on an unclaimed board (the mailbox
/// design §2, §3).
///
/// At every slot alike — the mailbox's, the bio's, the link page's and the
/// policy document's. Through the whole admission, on a board where the
/// pre-claim gate answers
/// `claim_first` to every write it does not know: a mint naming the system
/// account answers `system_account_no_well_known`, permanent, whoever names
/// it — an account holder, the owner of an account with no document, the
/// system principal itself; the owner of the account that holds no document,
/// naming it, answers `mint_home_first`; and the mint slot answers nothing
/// to the maker naming its own account, which holds its home, or to a
/// stranger naming the empty account, so each meets the gate's `claim_first`
/// — the stranger told nothing of the account, whom M10's store answers
/// `not_owner` with nothing committed. The producer alone answers nothing
/// either for the address of no registered account, asked by the principal
/// that owns the space it names, or for any other op.
#[test]
fn the_well_known_mints_door_answers_its_two_tokens_ahead_of_the_pre_claim_gate() {
    use skep_febe::{Disposition, RejectCode, Request, Response};
    use skep_namespace::{WellKnownSlot, SYSTEM_PRINCIPAL};

    use crate::auth::CredentialLock;

    let (board, homeless, homeless_id) = a_board_with_a_homeless_account();
    let snap = board.engine.kernel().snapshot();
    let world = snap.world();
    assert!(world.identity().claimant().is_none(), "the premise: unclaimed");
    assert!(
        world.m3().is_registered_account(&homeless) && !world.m3().has_documents(&homeless),
        "the premise: registered, and holding no document"
    );
    let lock = CredentialLock::new();
    let (maker, other) = (board.maker.0, board.other.0);
    let own = addr_of(&[1, 0, 1]);
    let no_well_known = CredentialRefusal::SystemAccountNoWellKnown;
    assert_eq!(no_well_known.token(), "system_account_no_well_known");
    assert_eq!(no_well_known.disposition(), Disposition::Permanent);
    let unregistered = addr_of(&[1, 0, 9]);
    assert!(
        world.m3().is_effective_owner(BOOTSTRAP_PRINCIPAL, &unregistered),
        "the premise: the bootstrap principal owns the space"
    );
    for slot in WellKnownSlot::ALL {
        let mint = |account: &Address| Op::CreateWellKnownDocument { account: account.clone(), slot };
        let admission = |account: &Address, caller: PrincipalId| {
            plain_admission(&lock.read(), world, &mint(account), caller, None, None)
        };
        let door = |account: &Address, caller: PrincipalId| {
            well_known_mint_refusal(&lock.read(), world, &mint(account), caller)
        };

        // The system account: its token, whoever names it.
        for caller in [maker, other, homeless_id, SYSTEM_PRINCIPAL, BOOTSTRAP_PRINCIPAL] {
            assert_eq!(
                admission(&system_account(), caller),
                Err(no_well_known.clone()),
                "{slot:?}: {caller:?} naming the system account"
            );
        }
        // An account with no document: its owner is told to mint the home
        // first.
        assert_eq!(
            admission(&homeless, homeless_id),
            Err(CredentialRefusal::MintHomeFirst),
            "{slot:?}: the owner of an account holding no document"
        );
        // An account holding its home: the mint slot passes, and the
        // pre-claim gate's wildcard answers.
        assert_eq!(door(&own, maker), None, "{slot:?}: the owner of an account holding its home");
        assert_eq!(
            admission(&own, maker),
            Err(CredentialRefusal::ClaimFirst),
            "{slot:?}: an unclaimed board admits no well-known creation"
        );
        // A stranger naming the empty account: nothing here, so the answer
        // is the one a stranger naming a full account meets — and
        // `not_owner` is the store's.
        for stranger in [maker, other] {
            assert_eq!(
                door(&homeless, stranger),
                None,
                "{slot:?}: {stranger:?} naming another's empty account"
            );
            assert_eq!(
                admission(&homeless, stranger),
                admission(&own, other),
                "{slot:?}: {stranger:?}: the answer tells nothing of the account"
            );
        }
        let before = board.febe.log_position();
        match board.febe.execute(board.other.1, Request::from(mint(&homeless))) {
            Response::Rejected(rej) => assert_eq!(rej.code, RejectCode::NotOwner, "{slot:?}: {rej:?}"),
            other => panic!("{slot:?}: a stranger's creation is refused: {other:?}"),
        }
        assert_eq!(board.febe.log_position(), before, "the refusal commits nothing");
        // The address of no registered account: the store's
        // `not_an_account`, never `mint_home_first`.
        assert_eq!(
            door(&unregistered, BOOTSTRAP_PRINCIPAL),
            None,
            "{slot:?}: an unregistered account"
        );
    }
    // Every other op is another producer's.
    let fork = Op::Fork { published: None };
    assert_eq!(
        well_known_mint_refusal(&lock.read(), world, &fork, homeless_id),
        None,
        "a fork is mint-first's"
    );
}

/// Checks the well-known creation's door on a claimed board (the mailbox
/// design §2, §3; PUB-6.43).
///
/// The board claimed by the maker through M10. At every slot the system
/// account's token answers as on the unclaimed board, whoever names it, and
/// the owner of the account holding no document answers `mint_home_first`.
/// Where the mint slot answers nothing the board-state pair reads the slot's
/// own state. The mailbox is private, so the publish-class gate stands aside:
/// a bare session's creation is admitted with nothing for its marker slot, as
/// a `stage` is, and a signed session's too, an `attest` it presents dropped
/// unverified — M10 then mints the mailbox at slot 2. The bio, the link page
/// and the policy document are created published, so their creation is
/// publish-class for the account's owner: a bare session answers
/// `signed_session_required`, and a signed one reaches the write-path check,
/// which on this board, where no head is written, answers
/// `attestation_invalid:board_unavailable` ahead of asking for the member. A
/// stranger naming another's account is told nothing here at any slot, and
/// M10's store answers `not_owner`.
#[test]
fn a_claimed_board_reads_the_slots_own_state_and_keeps_the_two_tokens_at_every_slot() {
    use skep_febe::{RejectCode, Request, Response};
    use skep_identity::Fingerprint;
    use skep_kernel::Attestation;
    use skep_namespace::{mailbox_address, WellKnownSlot, SYSTEM_PRINCIPAL};

    use crate::auth::policy::AttestFault;
    use crate::auth::CredentialLock;

    let (board, homeless, homeless_id) = a_board_with_a_homeless_account();
    board.claim();
    let snap = board.engine.kernel().snapshot();
    let world = snap.world();
    let lock = CredentialLock::new();
    let (maker, other) = (board.maker.0, board.other.0);
    let own = addr_of(&[1, 0, 1]);
    // A signed session's two marks, as the gate reads them: the key that
    // opened it, by fingerprint, and the member a frame presented.
    let key = Fingerprint::parse_hex(&"07".repeat(32)).expect("a fingerprint's hex");
    let presented = || Attestation::new(1, vec![0xA5; 8]).expect("a tag over a blob");

    for slot in WellKnownSlot::ALL {
        let mint = |account: &Address| Op::CreateWellKnownDocument { account: account.clone(), slot };
        let admission = |account: &Address, caller: PrincipalId| {
            plain_admission(&lock.read(), world, &mint(account), caller, None, None)
        };
        let signed = |account: &Address, caller: PrincipalId, attest: Option<Attestation>| {
            plain_admission(&lock.read(), world, &mint(account), caller, Some(&key), attest)
        };

        for caller in [maker, other, homeless_id, SYSTEM_PRINCIPAL] {
            assert_eq!(
                admission(&system_account(), caller),
                Err(CredentialRefusal::SystemAccountNoWellKnown),
                "{slot:?}: {caller:?} naming the system account"
            );
            assert_eq!(
                signed(&system_account(), caller, Some(presented())),
                Err(CredentialRefusal::SystemAccountNoWellKnown),
                "{slot:?}: {caller:?} naming the system account, signed"
            );
        }
        assert_eq!(
            admission(&homeless, homeless_id),
            Err(CredentialRefusal::MintHomeFirst),
            "{slot:?}: the owner of an account holding no document"
        );
        assert_eq!(
            signed(&homeless, homeless_id, Some(presented())),
            Err(CredentialRefusal::MintHomeFirst),
            "{slot:?}: the same owner in a signed session: the home first, whatever it signs"
        );
        if slot.born_published() {
            assert_eq!(
                admission(&own, maker),
                Err(CredentialRefusal::SignedSessionRequired),
                "{slot:?}: the owner, bare: a published creation is publish-class"
            );
            for attest in [None, Some(presented())] {
                assert_eq!(
                    signed(&own, maker, attest),
                    Err(CredentialRefusal::AttestationInvalid(AttestFault::BoardUnavailable)),
                    "{slot:?}: the owner, signed: the write-path check is reached"
                );
            }
        } else {
            assert_eq!(
                admission(&own, maker),
                Ok(None),
                "{slot:?}: the owner, bare: admitted, its marker slot empty"
            );
            for attest in [None, Some(presented())] {
                assert_eq!(
                    signed(&own, maker, attest),
                    Ok(None),
                    "{slot:?}: the owner, signed: admitted, an `attest` dropped unverified"
                );
            }
        }
        for attest in [None, Some(presented())] {
            assert_eq!(admission(&homeless, other), Ok(None), "{slot:?}: a stranger, bare");
            assert_eq!(
                signed(&homeless, other, attest),
                Ok(None),
                "{slot:?}: a stranger: nothing here, `not_owner` downstream"
            );
        }
        match board.febe.execute(board.other.1, Request::from(mint(&homeless))) {
            Response::Rejected(rej) => assert_eq!(rej.code, RejectCode::NotOwner, "{slot:?}: {rej:?}"),
            other => panic!("{slot:?}: a stranger's creation is refused: {other:?}"),
        }
    }

    let mailbox = Op::CreateWellKnownDocument { account: own.clone(), slot: WellKnownSlot::Mailbox };
    match board.febe.execute(board.maker.1, Request::from(mailbox)) {
        Response::AckAddr { addr, .. } => {
            assert_eq!(Some(addr), mailbox_address(&own), "the mailbox, at slot 2")
        }
        other => panic!("the owner's mint is acked: {other:?}"),
    }
}

/// Checks the registrar's gate on `register_node` (REG-2.1).
///
/// Through the whole admission, on [`TwoAccounts`]' board. Unclaimed, the
/// pre-claim gate answers `claim_first` to every caller, bare and signed.
/// Claimed by the maker, with a keyless account delegated beneath the
/// maker's: the maker's own principal is admitted in a signed session under
/// each key of its set, the anchor and the device key alike, with nothing
/// for the marker slot and a presented `attest` dropped; a bare session
/// answers `signed_session_required` whatever its principal, the maker's
/// own included; and a signed session of any other principal answers
/// `not_registrar`, permanent — the other account's, and the two the
/// maker's own keys open, the bootstrap principal's and the keyless
/// sub-account's, under a key of the claimant's set as under any other. A
/// bare `delegate` from the bootstrap principal beside them stays outside
/// the gate.
#[test]
fn register_node_is_admitted_to_the_registrars_signed_session_alone() {
    use skep_febe::Disposition;

    use crate::auth::CredentialLock;

    let board = TwoAccounts::open();
    let lock = CredentialLock::new();
    let (maker, other) = (board.maker.0, board.other.0);
    let node = Op::RegisterNode { addr: addr_of(&[1, 9]).tumbler().clone() };
    let foreign = Fingerprint::parse_hex(&"ab".repeat(32)).expect("a fingerprint");

    // Unclaimed: the board has no registrar, so no session admits a node.
    {
        let snap = board.engine.kernel().snapshot();
        let world = snap.world();
        assert!(world.identity().claimant().is_none(), "the premise: unclaimed");
        for caller in [maker, other, BOOTSTRAP_PRINCIPAL] {
            for signer in [None, Some(&foreign)] {
                assert_eq!(
                    plain_admission(&lock.read(), world, &node, caller, signer, None),
                    Err(CredentialRefusal::ClaimFirst),
                    "unclaimed: {caller:?}, signed: {}",
                    signer.is_some()
                );
            }
        }
    }

    board.claim();
    let sub_id = PrincipalId(903);
    let sub = exec(
        &board.febe,
        board.maker.1,
        serde_json::json!({"op": "delegate", "new_prefix": "1.0.1.1", "new_id": sub_id.0}),
    );
    let snap = board.engine.kernel().snapshot();
    let world = snap.world();
    let claimant = world.identity().claimant().expect("the premise: claimed").clone();
    assert_eq!(
        world.m3().principal_prefix(maker),
        Some(&claimant),
        "the premise: the maker's account is the claimant"
    );
    assert!(
        world.identity().key_set(&sub).is_empty(),
        "the premise: the account beneath the claimant's holds no key of its own"
    );
    let keys: Vec<(Fingerprint, bool)> =
        world.identity().key_set(&claimant).enrolled().map(|(fp, e)| (*fp, e.anchor)).collect();
    assert_eq!(
        (keys.len(), keys.iter().filter(|(_, anchor)| *anchor).count()),
        (2, 1),
        "the premise: the claimant's set holds an anchor and a device key"
    );
    let admission = |caller: PrincipalId, signer: Option<&Fingerprint>| {
        plain_admission(&lock.read(), world, &node, caller, signer, None)
    };

    // The registrar: the claimant's own principal, under each key of its set.
    for (fp, anchor) in &keys {
        assert_eq!(
            admission(maker, Some(fp)),
            Ok(None),
            "the registrar, signed by its {} key",
            if *anchor { "anchor" } else { "device" }
        );
    }
    // An `attest` presented beside the op is dropped, never verified.
    let presented = Attestation::new(1, vec![0xAB; 8]).expect("a slot value");
    assert_eq!(
        plain_admission(&lock.read(), world, &node, maker, Some(&keys[0].0), Some(presented)),
        Ok(None),
        "the registrar's `register_node` fills no marker slot"
    );

    // A bare session, whatever its principal.
    for caller in [maker, other, sub_id, BOOTSTRAP_PRINCIPAL] {
        assert_eq!(
            admission(caller, None),
            Err(CredentialRefusal::SignedSessionRequired),
            "bare: {caller:?}"
        );
    }

    // A signed session of any principal but the registrar's, under a key of
    // the claimant's set — which opens the bootstrap principal and the
    // keyless sub-account — as under any other.
    let not_registrar = CredentialRefusal::NotRegistrar;
    for caller in [other, sub_id, BOOTSTRAP_PRINCIPAL] {
        for fp in keys.iter().map(|(fp, _)| fp).chain([&foreign]) {
            assert_eq!(
                admission(caller, Some(fp)),
                Err(not_registrar.clone()),
                "signed, not the registrar: {caller:?}"
            );
        }
    }
    assert_eq!(
        (not_registrar.token().as_str(), not_registrar.disposition()),
        ("not_registrar", Disposition::Permanent)
    );

    // `delegate` from the bootstrap principal stays outside the gate.
    let delegate = Op::Delegate {
        new_prefix: addr_of(&[1, 0, 3]).tumbler().clone(),
        new_id: PrincipalId(904),
    };
    assert_eq!(
        plain_admission(&lock.read(), world, &delegate, BOOTSTRAP_PRINCIPAL, None, None),
        Ok(None),
        "a bare `delegate` from the bootstrap principal is admitted"
    );
}
