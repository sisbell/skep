//! Genesis: the initial world seeds each store per its own design, and the
//! registry built from the compiled format constants — there is no genesis
//! configuration — is ONE process constant, which M7's slice and the engine
//! handle each read rather than hold and M9's catalog projects. The five
//! reserved type addresses are in-docuverse ghost tumblers, and the property
//! the abolished 9-space bought by unreachability is re-proven here through
//! the real ops: the allocator never issues them.

use crate::common;

use common::*;
use skep_address::Address;
use skep_arrangement::AsOf;
use skep_arrangement::{deposit_class_types, Caller, Deposit, HasM5};
use skep_content::{HasContent, Val};
use skep_engine::types::{
    pins_outside_the_registry, t_binding, t_disavowal, t_endpoint, t_expulsion_ground,
    t_policy_link, t_policy_link_own, t_succession_ground, t_succession_policy, t_successor_of,
    t_takedown, t_takedown_base, t_takedown_lifted,
};
use skep_engine::{Engine, Seq, World};
use skep_febe::{Disposition, Op, OperationSurface, RejectCode, Request, Response, SessionId};
use skep_links::{
    coverage_class, edition_type, read_with_type, HasLinks, ReservedAddrs, ShippedType, View,
};
use skep_namespace::{
    ghost_home_document, ghost_position, head_document, staging_draft, system_account, system_node,
    time_document, HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL, GHOST_POSITIONS, SYSTEM_PRINCIPAL,
};
use skep_retrieval::Spec;
use tempfile::tempdir;

/// M7's own list of the five — read rather than restated, so a walk here
/// cannot come to cover four classes out of five.
const SHIPPED: [ShippedType; 5] = ShippedType::ALL;

/// Genesis seeds M3's baptismal roots and its system account seed (PUB-6.65)
/// — four empty documents, three born published and one, the staging draft,
/// born unpublished — and leaves M4/M5/M7's stores empty. So Σ₀ holds one
/// draft and no link, and every derived structure the engine seeds agrees
/// with a rebuild over it: the exception set holds that one draft, withheld
/// from every reader class but its owner's, and the check this ends on is the
/// standing one `World::genesis` names, run over bare Σ₀.
#[test]
fn genesis_seeds_each_store_per_its_design() {
    let engine = mem_engine();
    let snap = engine.kernel().snapshot();
    let world = snap.world();

    // M3: node [1] registered, owned by the bootstrap principal.
    assert_eq!(world.m3().entity_level(&node1()), Some(skep_address::Level::Node));
    assert_eq!(world.m3().effective_owner(&node1()), Some(BOOTSTRAP_PRINCIPAL));

    // M3's system account seed (PUB-6.65): four documents, all empty, the
    // staging draft alone born unpublished. The bit is read off M3, and then
    // off `World::published`, which answers off the exception set: an empty
    // set would answer `true` for the draft whatever M3 holds.
    let seeded = [
        (ghost_home_document(), true),
        (head_document(), true),
        (staging_draft(), false),
        (time_document(), true),
    ];
    for (doc, published) in &seeded {
        assert!(world.m3().is_registered_document(doc), "{doc} is seeded");
        assert_eq!(world.m3().published(doc), *published, "{doc}: the bit it was born with (M3's)");
        assert_eq!(world.published(doc), *published, "{doc}: the exception set agrees with M3");
        assert_eq!(world.m5().content_count(doc), nat(0), "{doc} is born empty");
    }
    assert_eq!(
        world.m3().documents().len(),
        seeded.len(),
        "the four seeded documents and no other"
    );

    // The exception set holds the one draft, owned by the system account.
    let drafts: Vec<(Address, Address)> =
        world.drafts().map(|d| (d.document.clone(), d.owner_account.clone())).collect();
    assert_eq!(
        drafts,
        vec![(staging_draft(), system_account())],
        "Σ₀'s exception set is the staging draft alone, under its owner account"
    );

    // Every reader class but the draft's own owner is refused it: the guest;
    // a principal seated nowhere; principal 0, whose node-tier seat reads no
    // draft by subtree; and the rule engine's fires, which read at guest
    // class. The system principal reads it, as its publish shots must.
    let draft = staging_draft();
    assert!(!world.readable(None, &draft), "the guest is refused the staging draft");
    assert!(
        !world.readable(Some(PrincipalId(77)), &draft),
        "a principal seated nowhere is refused"
    );
    assert!(!world.readable(Some(BOOTSTRAP_PRINCIPAL), &draft), "principal 0 is refused");
    assert!(!World::visible_to(Caller::System)(world, &draft), "a rule fire is refused");
    assert!(world.readable(Some(SYSTEM_PRINCIPAL), &draft), "the system principal reads its draft");
    for (doc, _) in seeded.iter().filter(|(_, published)| *published) {
        assert!(world.readable(None, doc), "{doc} is born published, so the guest reads it");
    }

    // M4: the permascroll starts empty.
    assert!(world.content().is_empty());

    // M5: no arrangements (any document reads as absent-empty).
    assert_eq!(world.m5().content_count(&node1()), nat(0));

    // M7: no links; the whole audit slice is empty.
    assert!(world.links().match_links(&[], View::Audit).is_empty());

    engine
        .check_hints()
        .expect("Σ₀ carries its own derived state: a rebuild over the seed agrees");
}

/// The staging draft is withheld in a world held in memory, on the two
/// reads that take a document, at every reader class but its owner's. An
/// in-memory world is installed as built and never rebuilt, so what holds the
/// draft back here is the exception set `World::genesis` seeds, and nothing
/// else: with that set empty the draft would read published to every class.
/// The classes are the guest; a principal seated at an account of its own; a
/// principal seated nowhere; and principal 0, seated at node `[1]`. The
/// system principal owns the draft and reads it.
#[test]
fn the_staging_draft_is_withheld_from_every_class_but_its_owner_in_memory() {
    let engine = mem_engine();
    let febe: OperationSurface<World> =
        OperationSurface::new(Box::new(engine.stores()), std::num::NonZeroUsize::MIN);
    let boot = febe.bootstrap_session();
    let next_prefix = Request::from(Op::NextAccountPrefix { parent: node1() });
    let prefix = match febe.execute(boot, next_prefix) {
        Response::MaybeAddr { addr: Some(a), .. } => a,
        other => panic!("expected the next account prefix, got {other:?}"),
    };
    match febe.execute(
        boot,
        Request::from(Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: USER }),
    ) {
        Response::AckAddr { .. } => {}
        other => panic!("expected the delegation's ack, got {other:?}"),
    }
    let draft = staging_draft();
    let retrieve_v = |session: SessionId| {
        febe.execute(
            session,
            Request::from(Op::RetrieveV {
                specs: vec![Spec { doc: draft.clone(), span: vspan(1, 1, 1) }],
            }),
        )
    };
    let doc_metadata = |session: SessionId| {
        febe.execute(session, Request::from(Op::DocMetadata { doc: draft.clone() }))
    };
    let assert_withheld = |resp: Response, read: &str, class: &str| match resp {
        Response::Rejected(rej) => {
            assert_eq!(rej.code, RejectCode::Withheld, "{read} at {class}: {rej:?}");
            assert_eq!(rej.disposition, Disposition::Reorder, "{read} at {class}: {rej:?}");
            assert_eq!(
                rej.site.as_ref().and_then(|s| s.addr.as_ref()),
                Some(&draft),
                "{read} at {class}: {rej:?}"
            );
            assert!(rej.detail.is_none(), "{read} at {class}: withheld carries no detail: {rej:?}");
        }
        other => panic!("{read} at {class}: expected withheld, got {other:?}"),
    };

    let classes = [
        (SessionId::GUEST, "the guest"),
        (febe.open_session(USER), "a principal seated at its own account"),
        (febe.open_session(PrincipalId(77)), "a principal seated nowhere"),
        (boot, "principal 0"),
    ];
    for (session, class) in classes {
        assert_withheld(retrieve_v(session), "retrieve_v", class);
        assert_withheld(doc_metadata(session), "doc_metadata", class);
    }

    // The owner's class: the draft answers, empty and unpublished, entered
    // at the genesis coordinate.
    let system = febe.open_session(SYSTEM_PRINCIPAL);
    match retrieve_v(system) {
        Response::Delivery { items, .. } => {
            assert!(delivered_bytes(&items).is_empty(), "the draft is born empty: {items:?}");
        }
        other => panic!("the system principal was refused its own draft: {other:?}"),
    }
    match doc_metadata(system) {
        Response::DocMetadata { doc, published, owner, at, .. } => {
            assert_eq!(doc, draft);
            assert!(!published, "the staging draft is born unpublished");
            assert_eq!(owner, Some(system_account()));
            assert_eq!(at, Some(Seq(0)), "minted at the genesis coordinate");
        }
        other => panic!("the system principal was refused its own draft's metadata: {other:?}"),
    }
}

/// The staging draft stands in a journalled world before anything is
/// written: an engine over a directory with no daemon above it, so no write
/// of the system account's has run. A journalled open rebuilds the exception
/// set from the namespace it loaded, so what holds the draft here is the
/// namespace's own seed record — registered, unpublished, owned by the
/// system account — and a reopen reads the same. It is the journalled cell
/// that reads the genesis state alone: a daemon's board has the system
/// account's own writes above genesis by the time a test reads it.
#[test]
fn a_journalled_board_no_seed_has_written_holds_the_staging_draft_withheld() {
    let dir = tempdir().expect("tempdir");
    let draft = staging_draft();
    for open in ["the first open", "a reopen"] {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("open");
        assert_eq!(engine.kernel().current_seq(), Seq(0), "{open}: nothing has been written");
        let snap = engine.kernel().snapshot();
        let world = snap.world();
        assert!(world.m3().is_registered_document(&draft), "{open}: the draft is registered");
        assert!(!world.m3().published(&draft), "{open}: its bit is unset (M3's)");
        assert_eq!(world.m3().minted_at(&draft), Some(Seq(0)), "{open}: at the genesis coordinate");
        let drafts: Vec<(Address, Address)> =
            world.drafts().map(|d| (d.document.clone(), d.owner_account.clone())).collect();
        assert_eq!(
            drafts,
            vec![(draft.clone(), system_account())],
            "{open}: the rebuilt exception set is the staging draft alone"
        );
        assert!(!world.readable(None, &draft), "{open}: the guest is refused it");
        assert!(
            !world.readable(Some(BOOTSTRAP_PRINCIPAL), &draft),
            "{open}: principal 0 is refused it"
        );
        assert!(world.readable(Some(SYSTEM_PRINCIPAL), &draft), "{open}: its owner reads it");
        let guest = engine.world_dump_visible_to(None).into_string();
        assert!(
            guest.contains("\"publication\": []"),
            "{open}: the guest's dump lists no draft:\n{guest}"
        );
        let whole = engine.world_dump().into_string();
        let listed = format!("\"publication\": [{}]", quoted(&draft));
        assert!(whole.contains(&listed), "{open}: the unfiltered dump lists it:\n{whole}");
        engine.check_hints().expect("the rebuilt hints agree with a rebuild");
    }
}

/// Genesis is a compiled constant: two constructions are byte-identical
/// through M2's own checkpoint encoding — the determinism that used to be a
/// caller contract over a passed configuration is now a fact with no inputs.
#[test]
fn two_geneses_are_byte_identical() {
    let a = bincode::serialize(&World::genesis()).expect("a world serializes");
    let b = bincode::serialize(&World::genesis()).expect("a world serializes");
    assert_eq!(a, b, "genesis must be one value, byte for byte");
}

/// The genesis seam: ONE registry serves every shipped class. The engine's
/// accessor and a world's own slice both read `skep_links::registry()`, a
/// process constant built from the compiled format constants and held by
/// neither of them — so there is no second instance for a comparison to
/// catch, and their agreement is definitional rather than checkable.
///
/// What remains checkable is COVERAGE: a shipped class the registry does not
/// register has no `Registration`, and the write gates and folds keyed on its
/// coverage class would find none. The two reads are named side by side so
/// that an accessor which stopped forwarding to the constant fails here
/// rather than at a write gate.
#[test]
fn the_one_registry_registers_every_shipped_class() {
    let engine = mem_engine();
    let snap = engine.kernel().snapshot();
    let links = snap.world().links();

    for ty in SHIPPED {
        let ours = engine.registry().reserved_type(ty);
        assert!(
            engine.registry().registration(&coverage_class(ours)).is_some(),
            "shipped class {ty:?} must be registered"
        );
        assert_eq!(ours, links.reserved_type(ty), "shipped class {ty:?}");
    }
}

/// The third consumer: M9's catalog is a pure projection of that same
/// registry (assembly is infallible now — nothing is twice-passed), and the
/// empty rule registry is vacuously quiescent.
#[test]
fn coordinator_projects_the_one_registry() {
    let engine = mem_engine();
    let coord = engine.coordinator();

    for ty in SHIPPED {
        assert_eq!(
            coord.reserved_type(ty),
            engine.registry().reserved_type(ty),
            "coordinator catalog and engine registry disagree on {ty:?}"
        );
    }

    let snap = engine.kernel().snapshot();
    assert!(coord.quiescent(&snap), "an empty rule registry is quiescent");
}

/// The five reserved addresses are format state — the owner-pinned ghost
/// tumblers (2026-08-26): content positions 1–5 of doc 1 of account 1 of the
/// registry node 1.1, in the ruling's assignment order. Pinned as literal
/// text rather than re-derived from the constructor that makes them — that
/// constructor is the thing that could change — and format-frozen the day
/// this merged: an edit silently mis-dispatches every journal in existence.
#[test]
fn the_format_pins_its_five_reserved_addresses() {
    let reserved = ReservedAddrs::format();
    assert_eq!(reserved.pred_def.to_string(), "1.1.0.1.0.1.0.1.1");
    assert_eq!(reserved.pred_stable.to_string(), "1.1.0.1.0.1.0.1.2");
    assert_eq!(reserved.retired.to_string(), "1.1.0.1.0.1.0.1.3");
    assert_eq!(reserved.supersedes.to_string(), "1.1.0.1.0.1.0.1.4");
    assert_eq!(reserved.retraction.to_string(), "1.1.0.1.0.1.0.1.5");
    // The engine's registry serves exactly these, so the dispatch keys and
    // the pinned literals are one set.
    let engine = mem_engine();
    for (ty, addr) in [
        (ShippedType::PredDef, &reserved.pred_def),
        (ShippedType::PredStable, &reserved.pred_stable),
        (ShippedType::Retired, &reserved.retired),
        (ShippedType::Supersedes, &reserved.supersedes),
        (ShippedType::Retraction, &reserved.retraction),
    ] {
        assert_eq!(engine.registry().reserved_type(ty), &skep_links::enc(std::slice::from_ref(addr)));
    }
}

/// REG-1.24, REG-1.32 — THE TWELVE ROWS ARE PRESENT at every board as the
/// ledger's pins, at the addresses commons-map pins, each the one row
/// `skep-registry`'s table holds: five kinds at `3.55`–`3.59`, seven subtype
/// rows under their kinds. A commons row is a compiled address and never a
/// record, so genesis seeds nothing at any of them — nothing is allocated
/// at a row on a fresh board, and the ghost document is born empty as the
/// cell above shows; `successor-of`, the engine's own pin, is held equal to
/// the table's `3.59`.
#[test]
fn the_registrys_twelve_rows_are_the_ledgers_pins_at_the_maps_addresses() {
    type Reader = fn() -> &'static Address;
    let readers: [(Reader, &str); 12] = [
        (t_binding, "55"),
        (t_endpoint, "56"),
        (t_takedown, "57"),
        (t_takedown_base, "57.1"),
        (t_takedown_lifted, "57.2"),
        (t_policy_link, "58"),
        (t_policy_link_own, "58.1"),
        (t_disavowal, "58.2"),
        (t_expulsion_ground, "58.3"),
        (t_succession_ground, "58.4"),
        (t_succession_policy, "58.5"),
        (t_successor_of, "59"),
    ];
    let engine = mem_engine();
    let snap = engine.kernel().snapshot();
    let m3 = snap.world().m3();
    for ((read, tail), row) in readers.iter().zip(skep_registry::rows()) {
        let pin = read();
        assert_eq!(pin.tumbler().to_string(), format!("1.1.0.1.0.1.0.3.{tail}"));
        assert_eq!(pin, &row.address, "the ledger's reader is the table's row");
        assert!(!m3.is_allocated(pin), "{pin}: a commons row is a pin, never an allocation");
    }
    assert_eq!(t_successor_of(), skep_registry::t_successor_of());
}

/// REG-1.30 to REG-1.32 — THE SEEDING CHECK over what the engine sees: the
/// registry's rows against the ledger's pins outside the registry and M5's
/// deposit-class set, with the set's two registry members set aside — they
/// are the rows spelled a second time, held equal above, and no foreign row.
/// The three arms pass over this domain; each arm's refusal is proved on a
/// list the registry crate's own suite builds, and the daemon's check runs
/// over the build's whole commons table less the registry's rows, a domain
/// its own suite holds every one of these pins to be an entry of.
#[test]
fn the_seeding_check_passes_over_what_the_engine_sees() {
    let domain: Vec<&Address> = pins_outside_the_registry()
        .into_iter()
        .chain(deposit_class_types().iter().filter(|ty| skep_registry::row_at(ty).is_none()))
        .collect();
    assert_eq!(domain.len(), 11 + 2, "eleven pins and the two credential members of M5's set");
    assert_eq!(skep_registry::seeding_check(skep_registry::rows(), domain), Ok(()));
}

/// M7's two spellings of the commons values a publication's deposits are
/// typed by (the link-sets design §5.7; lane S3) — the read-with type its
/// `read_with` entries deposit and the edition-claim type its `claim`
/// writes — are the ledger's own pins, as its correspondence type is held
/// to `t_correspondence` beside them: the link store sits below the engine
/// and spells the two addresses itself, and this holds the two spellings
/// equal where both are in view, so neither can drift from the ledger.
#[test]
fn the_link_stores_read_with_and_edition_types_are_the_ledgers_pins() {
    assert_eq!(read_with_type(), skep_engine::types::t_read_with(), "the read-with type, `3.71`");
    assert_eq!(edition_type(), skep_engine::types::t_edition(), "the edition-claim type, `3.14`");
}

/// Non-reissue end to end, through the assembled engine — the load-bearing
/// clause of the ghost-tumbler ruling (1c): dispatch is by number, so a
/// fresh mint landing on the `retraction` value would be catastrophic. The
/// ghost region is REACHABLE territory (that is what the old 9-space test
/// proved could never happen by unreachability): the ghost home document is
/// real, and since PUB-6.65 its whole lineage is genesis's — the registry
/// node, the system account at ordinal 1 and its doc-1 are seeded at exactly
/// the ordinals the ceremony's delegate and doc-1 mint used to land on — and
/// the doc's content frontier provably starts past the region, so INSERT's
/// content lands from position 6 and nothing exists at any ghost tumbler,
/// before or after.
#[test]
fn no_reserved_address_is_ever_minted_and_the_ceremony_is_not_renumbered() {
    let engine = mem_engine();
    let reserved = ReservedAddrs::format();

    // The lineage is seeded at its ordinary ordinals — the pin renumbers
    // nothing — and its document is born EMPTY: nothing at the five, anywhere.
    let doc1 = ghost_home_document();
    {
        let snap = engine.kernel().snapshot();
        let m3 = snap.world().m3();
        assert!(m3.is_allocated(&system_node()), "the registry node 1.1 is seeded");
        assert!(
            m3.is_registered_account(&system_account()),
            "the system account sits at account ordinal 1 under it"
        );
        assert_eq!(system_account(), addr(&[1, 1, 0, 1]));
        assert!(m3.is_registered_document(&doc1), "its doc-1 IS the ghost home document");
        for addr in [
            &reserved.pred_def,
            &reserved.pred_stable,
            &reserved.retired,
            &reserved.supersedes,
            &reserved.retraction,
        ] {
            assert!(!m3.is_allocated(addr), "{addr} allocated at genesis");
        }
    }

    // INSERT drives the content chain: the permascroll writes land from
    // position GHOST_POSITIONS + 1, and keep going contiguously. Doc-1 is
    // born published, so the write is what the ceremony's own record atom
    // is — a deposit DECLARED under ENROLL's type, the genesis enrollment's
    // class (PUB-2.11, PUB-2.64), at its fresh positions (PUB-2.59,
    // PUB-2.63) — written as the account's own principal, the system's.
    let (start, _) = engine
        .vstream()
        .insert(
            Caller::Principal(SYSTEM_PRINCIPAL),
            &doc1,
            vp(1, 1),
            vec![Val::new(vec![b'a']), Val::new(vec![b'b'])],
            Deposit::Declared(deposit_class_types()[0].clone()),
            AsOf::Typed(engine.kernel().current_seq()),
        )
        .expect("insert into the ghost doc succeeds");
    assert_eq!(
        start,
        addr(&[1, 1, 0, 1, 0, 1, 0, 1, GHOST_POSITIONS + 1]),
        "the first content mint lands past the ghost region"
    );

    let snap = engine.kernel().snapshot();
    for x in 1..=GHOST_POSITIONS {
        assert!(
            !snap.world().m3().is_allocated(&ghost_position(x)),
            "ghost {x} must stay unallocated with the chain past it"
        );
    }
    assert!(snap.world().m3().is_allocated(&start));
}
