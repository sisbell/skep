use skep_arrangement::Caller;
use skep_kernel::WorldState;
use skep_links::{Endset, SlotArg};
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
/// history built — all SIX structures compared directly, so every prefix
/// stands in for a restart. `check_hints` compares the operative records
/// alone: the dump renders none of the other five, which `check_hints_of`
/// names, arguing that the two indexes cannot diverge, and the restart
/// tests hold that argument at chosen histories. These are generated from
/// a pinned seed over two issuers depositing into a published doc 1, a
/// published edition that is not doc 1, and a private draft — naming
/// documents, accounts, the node and earlier records of any home, one
/// `from` address or two, to no grantee, one or two — with retractions of
/// the issuer's own records mixed in, and RE-SHARES: a record deposited with
/// its `replaces` member (PUB-5.15 (iv)), over the key of a grant an earlier
/// record revoked and naming that revocation — or a stale one, or a grant —
/// so the fourth outcome honors some and refuses others.
#[test]
fn a_rebuilt_grant_fold_equals_the_live_one_after_every_deposit_of_a_generated_history() {
    let mut rng = 0x6A47_5EED_u64;
    let (mut saw_universal, mut saw_named, mut saw_spent, mut saw_malformed) =
        (false, false, false, false);
    let (mut saw_re_share_honored, mut saw_re_share_refused, mut saw_withdrawn_member) =
        (false, false, false);
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
            let world = engine.kernel().snapshot().world().clone();
            let in_own_home =
                |a: &Address| document_of(a).is_some_and(|home| homes.contains(&home));
            let own: Vec<Address> = records.iter().filter(|r| in_own_home(r)).cloned().collect();
            // This issuer's STANDING grants and its keys' CURRENT revocations,
            // read off the live fold and SORTED, so the pinned seed still
            // visits the same histories: what the revoking and re-sharing
            // steps below aim at, so that keys are withdrawn and re-shared
            // rather than only ever granted.
            let mut standing: Vec<Address> =
                world.grants.operative_records.keys().filter(|a| in_own_home(a)).cloned().collect();
            standing.sort();
            let mut current: Vec<Address> = world
                .grants
                .populations
                .values()
                .filter_map(OrdMap::get_max)
                .filter(|(addr, member)| *member == Member::Revocation && in_own_home(addr))
                .map(|(addr, _)| addr.clone())
                .collect();
            current.sort();
            let slots_of = |a: &Address| {
                let link = world.links.readlink(a).expect("an earlier record is resident");
                let names = |e: &Endset| -> Vec<Address> {
                    e.addrs()
                        .map(|t| validate(t.clone()).expect("a slot names T4-valid addresses"))
                        .collect()
                };
                (names(link.from_slot()), names(link.to_slot()))
            };
            match below(&mut rng, 20) {
                0 | 1 if !own.is_empty() => {
                    let target = &own[below(&mut rng, own.len())];
                    let home = document_of(target).expect("a record has a home");
                    writer
                        .nullify(caller, &home, target)
                        .expect("an issuer retracts its own record");
                }
                2..=5 if !standing.is_empty() => {
                    // A REVOCATION of one of this issuer's standing grants.
                    let grant = &standing[below(&mut rng, standing.len())];
                    let home = document_of(grant).expect("a record has a home");
                    let (record, _) = writer
                        .makelink(
                            caller,
                            &home,
                            SlotArg::Addrs(vec![grant.clone()]),
                            SlotArg::Addrs(vec![]),
                            SlotArg::Addrs(vec![t_grant().clone()]),
                        )
                        .expect("an issuer revokes its own grant");
                    records.push(record);
                }
                6..=9 if !own.is_empty() => {
                    // A RE-SHARE: half the time naming a revocation that is its
                    // key's CURRENT state, over the key of the grant it
                    // withdrew; else naming any record of its own — a stale
                    // revocation, a grant, a record of neither kind — over the
                    // key of the grant it names, or its own slots.
                    let named = if !current.is_empty() && below(&mut rng, 2) == 0 {
                        current[below(&mut rng, current.len())].clone()
                    } else {
                        own[below(&mut rng, own.len())].clone()
                    };
                    let (from, to) = match slots_of(&named).0.as_slice() {
                        [revoked] if records.contains(revoked) => slots_of(revoked),
                        _ => slots_of(&named),
                    };
                    let home = document_of(&named).expect("a record has a home");
                    let (record, _) = writer
                        .makelink_replacing(
                            caller,
                            &home,
                            SlotArg::Addrs(from),
                            SlotArg::Addrs(to),
                            SlotArg::Addrs(vec![t_grant().clone()]),
                            &named,
                        )
                        .expect("an issuer re-shares into its own document");
                    let snap = engine.kernel().snapshot();
                    match snap.world().grants.operative_records.get(&record) {
                        Some(grant) => {
                            saw_re_share_honored |= grant.replaces.as_ref() == Some(&named);
                        }
                        None => saw_re_share_refused = true,
                    }
                    records.push(record);
                }
                _ => {
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
            assert_eq!(rebuilt.populations, live.populations, "{at}: the per-key population");
            assert_eq!(rebuilt.unpaired, live.unpaired, "{at}: the unpaired would-be grants");
            saw_withdrawn_member |= live
                .populations
                .values()
                .any(|population| population.values().any(|m| *m == Member::Revocation));
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
    assert!(
        saw_re_share_honored && saw_re_share_refused && saw_withdrawn_member,
        "the histories must honor a re-share ({saw_re_share_honored}), refuse one \
         ({saw_re_share_refused}) and keep a withdrawn key's revocation in its population \
         ({saw_withdrawn_member}), or the fourth outcome's two halves compared nothing"
    );
}

/// [`record`] WITH its `replaces` member — a re-share as its one writer
/// deposits it, the record and then its `replaces` link naming `replaces`, in
/// one transaction. Returns the record's address.
fn re_share(engine: &Engine, home: &Address, from: &Address, replaces: &Address) -> Address {
    let caller = Caller::Principal(USER);
    engine
        .linkstore(&World::visible_to(caller))
        .makelink_replacing(
            caller,
            home,
            SlotArg::Addrs(vec![from.clone()]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![t_grant().clone()]),
            replaces,
        )
        .expect("the re-share deposits into the issuer's own doc 1")
        .0
}

/// THE PAIR READ, held on its own (PUB-5.15: "a grant's `replaces` is the
/// `to` of the `replaces` link homed with that grant whose `from` is that
/// grant, deposited in the grant's own transaction, and is read from nowhere
/// else"). The class's one writer puts every pair at its record's next
/// address and the open writes are fenced, so no store the writes can reach
/// holds a `replaces` link anywhere else — which is why the pair step is
/// asked directly here, over the live fold, with links no write could
/// deposit: one homed in ANOTHER document, one in the record's home at
/// another address, one at the record's next address naming another
/// record, one whose `to` names two states. None re-decides the record: the
/// bare re-grant, which names the EMPTY state over a withdrawn key, stays of
/// neither kind — the one malformed `to` included, which spends the record's
/// pair on nothing. Only the link at the record's next address, naming it
/// and one state — the key's current revocation — honors it.
#[test]
fn the_pair_is_the_replaces_link_at_the_record_s_next_address_and_no_other() {
    let (engine, home, draft) = a_published_home_and_a_private_draft();
    let grant = record(&engine, &home, &draft);
    let revocation = record(&engine, &home, &grant);
    let bare = record(&engine, &home, &draft);
    let snap = engine.kernel().snapshot();
    let live = &snap.world().grants;
    assert!(!live.is_operative(&bare), "the premise: the bare re-grant names a stale EMPTY state");
    assert_eq!(live.unpaired.get(&home).map(|u| &u.record), Some(&bare), "…and awaits its pair");

    let next = checked_inc(&bare, 0).expect("the record's next address");
    let pair = |from: &Address, to: &[&Address]| {
        Link::triple(
            skep_links::enc([from]),
            skep_links::enc(to.iter().copied()),
            skep_links::enc([t_replaces()]),
        )
    };
    let refused: [(&str, Address, Link); 4] = [
        ("homed in another document", element(&draft, 2, 1), pair(&bare, &[&revocation])),
        (
            "at another address of the home",
            checked_inc(&next, 0).expect("T4"),
            pair(&bare, &[&revocation]),
        ),
        ("naming another record", next.clone(), pair(&grant, &[&revocation])),
        ("naming two states", next.clone(), pair(&bare, &[&revocation, &grant])),
    ];
    for (what, addr, link) in refused {
        let mut grants = live.clone();
        grants.take_pair(&addr, &link);
        assert!(!grants.is_operative(&bare), "a replaces link {what} honored the record");
        assert_eq!(grants.populations, live.populations, "{what}: the key's population moved");
    }
    let mut grants = live.clone();
    grants.take_pair(&next, &pair(&bare, &[&revocation]));
    assert_eq!(
        grants.operative_records.get(&bare).and_then(|g| g.replaces.as_ref()),
        Some(&revocation),
        "the pair at the record's next address, naming the current revocation, honors it"
    );
    assert!(grants.unpaired.is_empty(), "…and is spent");
}

/// THE MEASUREMENT (r265-S1, owner-ruled 2026-09-28: "accept, add the
/// measurement to the code lane"; PUB-7.59, PUB-7.66, PUB-7.67 — "the cost
/// is UNMEASURED and is the code lane's to measure"): a board with N
/// RE-SHARES of ONE key — a first share, then N rounds of a revocation and a
/// re-share naming it — at N = 10, 100 and 1,000, reporting the key's
/// population; the SEED's time over the board (the grant fold's share of the
/// board-open walk and of every reconstruction) and the whole derived
/// rebuild's; the FOLD's own step for the last re-share — the record's turn
/// and its pair's, over the fold as it stood before them — which reads one
/// key's latest member and so should not grow with N; and, beside the fold,
/// the whole live commit of the first and the last re-share with the issuer
/// doc 1's count of link-subspace RUNS — which stays ONE now the pair link
/// is seated beside its record (it was one run per re-share while the link
/// was born unseated, and the commit grew with it).
/// Printed and asserted on nothing but the population's size and the
/// verdicts — no threshold: the numbers are the report's.
#[test]
fn the_measurement_n_re_shares_of_one_key() {
    use std::time::{Duration, Instant};
    for n in [10usize, 100, 1_000] {
        let (engine, home, draft) = a_published_home_and_a_private_draft();
        let mut current = record(&engine, &home, &draft);
        let (mut first_commit, mut last_commit) = (Duration::ZERO, Duration::ZERO);
        let mut before_last = engine.kernel().snapshot().world().clone();
        for round in 0..n {
            let revocation = record(&engine, &home, &current);
            if round + 1 == n {
                before_last = engine.kernel().snapshot().world().clone();
            }
            let started = Instant::now();
            current = re_share(&engine, &home, &draft, &revocation);
            let took = started.elapsed();
            if round == 0 {
                first_commit = took;
            }
            last_commit = took;
        }
        let world = engine.kernel().snapshot().world().clone();
        let key =
            world.grants.operative_records.get(&current).expect("the last re-share stands").key();
        let population = world.grants.populations.get(&key).map_or(0, OrdMap::len);
        assert_eq!(population, 2 * n + 1, "every grant honored and every revocation, kept");
        assert_eq!(world.grants.operative_records.len(), 1, "one standing grant for the one key");
        let median = |f: &dyn Fn() -> Duration| {
            let mut runs: Vec<Duration> = (0..5).map(|_| f()).collect();
            runs.sort();
            runs[2]
        };
        let seed_time = median(&|| {
            let started = Instant::now();
            let seeded = seed(&world.namespace, &world.links, &world.drafts);
            let took = started.elapsed();
            assert_eq!(seeded.populations, world.grants.populations, "the seed agrees");
            took
        });
        let rebuild_time = median(&|| {
            let copy = world.clone();
            let started = Instant::now();
            let rebuilt = copy.rebuild_derived();
            let took = started.elapsed();
            drop(rebuilt);
            took
        });
        // The fold's own two steps for the last re-share, over the fold as it
        // stood before them: the record's turn, then its pair's.
        let value = world.links.readlink(&current).expect("the last re-share is resident");
        let pair_addr = checked_inc(&current, 0).expect("the pair's address");
        let pair = world.links.readlink(&pair_addr).expect("the last re-share's pair");
        let fold_time = median(&|| {
            let prev = before_last.grants.clone();
            let started = Instant::now();
            let mut next =
                fold_one(prev, &before_last.namespace, &before_last.drafts, current.clone(), value);
            next.take_pair(&pair_addr, pair);
            let took = started.elapsed();
            assert!(next.is_operative(&current), "the fold's step honors the last re-share");
            took
        });
        let runs = world.arrangement.link_runs(&home).count();
        eprintln!(
            "REPLAY-FIX MEASUREMENT N={n}: key population {population} records ({} grant-class \
             links, {n} replaces links); seed {seed_time:?}; whole derived rebuild \
             {rebuild_time:?}; fold step for the last re-share {fold_time:?}; live re-share \
             commit first {first_commit:?}, last {last_commit:?}; doc 1 link-subspace runs {runs}",
            2 * n + 1,
        );
    }
}
