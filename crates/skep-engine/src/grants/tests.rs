use skep_arrangement::Caller;
use skep_kernel::WorldState;
use skep_links::SlotArg;
use skep_namespace::PrincipalId;

use crate::testkit::{
    a_published_home_and_a_private_draft, addr, delegated_account, element, mem_engine, USER,
};
use crate::Engine;

use super::*;

/// Deposit a record of the class in `home`, as [`USER`], with `from` its
/// one `from` address and an EMPTY `to`. Returns the record's address.
fn record(engine: &Engine, home: &Address, from: &Address) -> Address {
    let caller = Caller::Principal(USER);
    engine
        .linkstore(&World::visible_to(caller))
        .makelink(
            caller,
            home,
            SlotArg::Addrs(vec![from.clone()]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![t_grant().clone()]),
        )
        .expect("the record deposits into the issuer's own doc 1")
        .0
}

/// THE EARLIER-RECORD SET, held on its own. Every record the set sends to
/// NEITHER KIND sits at a link address, which the ladder refuses as well,
/// so no answer of the predicate can tell a fold that kept the set from
/// one that leaned on the ladder — and the promise the set carries must
/// not rest on that overlap ([`classify`]). So the set is asked directly,
/// beside the operative set it parts from: the grant is operative until
/// its revocation and stays in the earlier-record set after it; that set
/// keeps the revocation and a record of neither kind too, none of them
/// operative; it answers for their own home alone; and the seed rebuilds
/// it whole, since nothing journals it.
///
/// The predicate watches only one direction of [`Grants::is_operative`]:
/// answering `false` of a live grant would turn every revocation into a
/// record of neither kind, and the suite's revocation tests would fail.
/// The other direction no answer can show — a record naming one that is
/// no operative grant withdraws nothing whichever arm it is sent to, so a
/// `true` there moves no state — and this test is what holds it.
#[test]
fn the_earlier_record_set_keeps_what_the_operative_set_lets_go() {
    let (engine, home, draft) = a_published_home_and_a_private_draft();
    let grant = record(&engine, &home, &draft);
    {
        let snap = engine.kernel().snapshot();
        let grants = &snap.world().grants;
        assert!(grants.is_operative(&grant), "admitted, the grant is operative");
        assert!(grants.holds_earlier(&grant, &home), "…and an earlier record of its home");
    }
    let revocation = record(&engine, &home, &grant);
    let neither = record(&engine, &home, &addr(&[1])); // the node stands on neither rung

    let snap = engine.kernel().snapshot();
    let world = snap.world();
    assert!(
        world.grants.operative_records.is_empty(),
        "the premise: the operative set has let the revoked grant go, and held nothing else"
    );
    let members = [
        ("the withdrawn grant", &grant),
        ("the revocation", &revocation),
        ("the record of neither kind", &neither),
    ];
    for (what, member) in members {
        assert!(world.grants.holds_earlier(member, &home), "{what} is an earlier record");
        assert!(!world.grants.is_operative(member), "{what} is no operative grant");
        assert!(!world.grants.holds_earlier(member, &draft), "{what}: of its own home alone");
    }
    assert!(
        !world.grants.holds_earlier(&element(&home, 2, 99), &home),
        "an address of this home that no record occupies is no member"
    );
    let seeded = seed(&world.namespace, &world.links, &world.drafts);
    assert_eq!(
        seeded.earlier_records, world.grants.earlier_records,
        "the seed rebuilds the set the fold kept"
    );
    assert_eq!(seeded.earlier_records.len(), members.len(), "…one member per admitted record");
}

/// …and [`classify`] CONSULTS the earlier-record set AHEAD of the ladder,
/// which no state the store can reach will show: every record of the class
/// sits at a link address, and the ladder refuses those on its own. So the
/// set here is SYNTHETIC — it holds a DOCUMENT address, as though a record
/// of the class sat on a rung — which is the one shape where the two tests
/// part. The ladder admits that `from`; the earlier-record test, speaking
/// first, sends the record naming it to NEITHER KIND. A classification
/// that dropped the consultation, or ran it after the ladder's arm,
/// answers a fresh grant here. That is the precedence PUB-5.15's second
/// promise rests on, pinned where a ladder that gained a rung would
/// otherwise be the first thing to test it.
#[test]
fn the_earlier_record_test_speaks_before_the_ladder() {
    let (engine, home, _) = a_published_home_and_a_private_draft();
    let naming_the_home = record(&engine, &home, &home);
    let snap = engine.kernel().snapshot();
    let link = snap.world().links.readlink(&naming_the_home).expect("the record is resident");

    assert!(
        matches!(classify(&Grants::new(), &home, link), Kind::Grant { .. }),
        "the premise: asked alone, the ladder admits a `from` at a document"
    );
    let mut synthetic = Grants::new();
    synthetic.keep_earlier(home.clone());
    assert!(
        synthetic.holds_earlier(&home, &home),
        "the synthetic member answers for its own home"
    );
    assert!(
        matches!(classify(&synthetic, &home, link), Kind::Neither),
        "a `from` naming an earlier record that is no operative grant reached the grant arm"
    );
}

/// One step of SplitMix64: the pinned generator the history law below
/// draws from, so every run visits the same histories.
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A draw in `0..n`.
fn below(rng: &mut u64, n: usize) -> usize {
    (splitmix(rng) % n as u64) as usize
}

/// PUB-7.7 for the grant fold as the LAW it states: after EVERY deposit of
/// EVERY history, a rebuild from authoritative state seeds the fold the
/// history built — all FOUR structures compared directly, so every prefix
/// stands in for a restart. `check_hints` compares the operative records
/// alone: the dump renders none of the other three, which `check_hints_of`
/// names, arguing that the two indexes cannot diverge, and the restart
/// tests hold that argument at chosen histories. These are generated from
/// a pinned seed over two issuers depositing into a published doc 1, a
/// published edition that is not doc 1, and a private draft — naming
/// documents, accounts, the node and earlier records of any home, one
/// `from` address or two, to no grantee, one or two — with retractions of
/// the issuer's own records mixed in.
#[test]
fn a_rebuilt_grant_fold_equals_the_live_one_after_every_deposit_of_a_generated_history() {
    let mut rng = 0x6A47_5EED_u64;
    let (mut saw_universal, mut saw_named, mut saw_spent, mut saw_malformed) =
        (false, false, false, false);
    for history in 0..32 {
        let engine = mem_engine();
        let bystander = delegated_account(&engine, PrincipalId(9));
        let issuers: Vec<(PrincipalId, Address, [Address; 3])> = [USER, PrincipalId(8)]
            .into_iter()
            .map(|p| {
                let account = delegated_account(&engine, p);
                let mint = |published| {
                    engine
                        .namespace()
                        .create_new_document(p, &account, published)
                        .expect("the owner mints")
                        .0
                };
                // Doc 1 (the published home), an edition, then a draft.
                let homes = [mint(None), mint(Some(true)), mint(None)];
                (p, account, homes)
            })
            .collect();
        let accounts: Vec<Address> =
            issuers.iter().map(|(_, account, _)| account.clone()).chain([bystander]).collect();
        let prefixes: Vec<Address> = issuers
            .iter()
            .flat_map(|(_, account, homes)| std::iter::once(account).chain(homes))
            .cloned()
            .chain([addr(&[1])])
            .collect();
        let mut records: Vec<Address> = Vec::new();
        for step in 0..12 {
            let (issuer, _, homes) = &issuers[below(&mut rng, issuers.len())];
            let caller = Caller::Principal(*issuer);
            let visibility = World::visible_to(caller);
            let writer = engine.linkstore(&visibility);
            let own: Vec<&Address> = records
                .iter()
                .filter(|r| document_of(r).is_some_and(|home| homes.contains(&home)))
                .collect();
            if !own.is_empty() && below(&mut rng, 10) == 0 {
                let target = own[below(&mut rng, own.len())];
                let home = document_of(target).expect("a record has a home");
                writer
                    .nullify(caller, &home, target)
                    .expect("an issuer retracts its own record");
            } else {
                let home = &homes[[0, 0, 1, 2][below(&mut rng, 4)]];
                let width = if below(&mut rng, 8) == 0 { 2 } else { 1 };
                let from: Vec<Address> = (0..width)
                    .map(|_| {
                        if !records.is_empty() && below(&mut rng, 2) == 0 {
                            records[below(&mut rng, records.len())].clone()
                        } else {
                            prefixes[below(&mut rng, prefixes.len())].clone()
                        }
                    })
                    .collect();
                let to: Vec<Address> = match below(&mut rng, 6) {
                    0 | 1 => Vec::new(),
                    5 => vec![accounts[0].clone(), accounts[2].clone()],
                    _ => vec![accounts[below(&mut rng, accounts.len())].clone()],
                };
                let (record, _) = writer
                    .makelink(
                        caller,
                        home,
                        SlotArg::Addrs(from),
                        SlotArg::Addrs(to),
                        SlotArg::Addrs(vec![t_grant().clone()]),
                    )
                    .expect("an issuer deposits into its own document");
                records.push(record);
            }
            let world = engine.kernel().snapshot().world().clone();
            let live = &world.grants;
            let rebuilt = world.clone().rebuild_derived().grants;
            let at = format!("history {history}, step {step}");
            assert_eq!(
                rebuilt.operative_records, live.operative_records,
                "{at}: the operative set"
            );
            assert_eq!(
                rebuilt.earlier_records, live.earlier_records,
                "{at}: the earlier-record set"
            );
            assert_eq!(rebuilt.by_grantee, live.by_grantee, "{at}: the principal-exact index");
            assert_eq!(rebuilt.universal, live.universal, "{at}: the any-principal index");
            saw_universal |= !live.universal.is_empty();
            saw_named |= !live.by_grantee.is_empty();
            saw_spent |= live.earlier_records.len() > live.operative_records.len();
            saw_malformed |= live.earlier_records.iter().any(|r| {
                let link = world.links.readlink(r).expect("an earlier record is resident");
                link.from_slot().single_denoted().is_none()
            });
        }
    }
    assert!(
        saw_universal && saw_named && saw_spent && saw_malformed,
        "the histories must admit an any-principal grant ({saw_universal}), a named one \
         ({saw_named}), a record that is no operative grant ({saw_spent}) and one whose `from` \
         denotes no single address ({saw_malformed}), or the comparisons compared empty sets"
    );
}
