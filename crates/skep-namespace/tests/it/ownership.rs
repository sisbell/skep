//! §C ownership: containment is not authorization, ω is the longest covering
//! prefix, a registered document is owned at its own account and found there
//! by one lookup, the principal registry answers in both directions and
//! enumerates every seat, ω's work follows the registry and not the probe,
//! and the seats ω refuses or names.

use crate::common::*;
use crate::heap::heap_bytes;

use skep_address::{same_account, validate, Address, Level, Tumbler};
use skep_namespace::{
    first_document_address, prefix_contains, system_account, CreateDocumentError, HasM3, M3Rec,
    M3State, Namespace, PrincipalId, BOOTSTRAP_PRINCIPAL, SYSTEM_PRINCIPAL,
};

#[test]
fn containment_is_not_authorization() {
    let (k, acct, doc) = kernel_with_account_and_doc();
    let snap = k.snapshot();
    let m3 = snap.world().m3();

    // O1: bare containment is true for SEVERAL principals at once — π₀'s
    // prefix [1] contains the delegated account and its documents…
    assert!(prefix_contains(&a(&[1]), &acct));
    assert!(prefix_contains(&a(&[1]), &doc));
    assert!(prefix_contains(&acct, &doc));
    assert!(prefix_contains(&acct, &acct)); // ≼ admits equality
    assert!(!prefix_contains(&acct, &a(&[1])));
    // …so only ω (longest-prefix match) arbitrates: the delegate owns its
    // subtree, π₀ keeps what no deeper seat covers (O2/O3, the
    // ownership-divergence discipline).
    assert_eq!(m3.effective_owner(&doc), Some(ID1));
    assert_eq!(m3.effective_owner(&acct), Some(ID1));
    assert_eq!(m3.effective_owner(&a(&[1])), Some(BOOTSTRAP_PRINCIPAL));
    // ω is a pure prefix query — valid even for not-yet-allocated addresses.
    assert_eq!(
        m3.effective_owner(&a(&[1, 0, 2])),
        Some(BOOTSTRAP_PRINCIPAL)
    );
    assert_eq!(m3.effective_owner(&a(&[1, 0, 1, 0, 9, 0, 1, 5])), Some(ID1));
    // Uncovered (a foreign node's subtree): None.
    assert!(m3.effective_owner(&a(&[2])).is_none());
    assert!(m3.effective_owner(&a(&[2, 0, 1])).is_none());

    // The authorization predicate agrees with ω everywhere, and is where the
    // divergence bites: π₀ CONTAINS the account but is not its ω, so
    // containment says yes exactly where authorization says no.
    assert!(m3.is_effective_owner(ID1, &doc));
    assert!(m3.is_effective_owner(ID1, &acct));
    assert!(prefix_contains(&a(&[1]), &acct));
    assert!(!m3.is_effective_owner(BOOTSTRAP_PRINCIPAL, &acct));
    assert!(m3.is_effective_owner(BOOTSTRAP_PRINCIPAL, &a(&[1])));
    // An unknown id owns nothing; an uncovered address has no owner at all,
    // and absent-ω is not-owner rather than a pass.
    assert!(!m3.is_effective_owner(UNKNOWN_ID, &doc));
    assert!(!m3.is_effective_owner(ID1, &a(&[2, 0, 1])));
    assert!(!m3.is_effective_owner(BOOTSTRAP_PRINCIPAL, &a(&[2, 0, 1])));
}

#[test]
fn omega_is_the_longest_covering_prefix_at_every_depth() {
    // §5 / O2/O3: ω is the LONGEST principal prefix, and is_effective_owner
    // agrees with it everywhere. Checked against an independent oracle — the
    // linear scan keeping the longest match, which the design names as the
    // reference — over a GENERATED family of probes, so no chosen point
    // decides it and a candidate walk that truncates at depth is caught.
    let seeded = World {
        m3: M3State::genesis()
            .apply_m3(&alloc(&[1, 0, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1]),
                id: ID1,
            })
            .apply_m3(&alloc(&[1, 0, 1, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1, 1]),
                id: ID2,
            })
            .apply_m3(&alloc(&[1, 0, 1, 1, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1, 1, 1]),
                id: PrincipalId(3),
            })
            .apply_m3(&alloc(&[1, 0, 2]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 2]),
                id: PrincipalId(4),
            })
            // [1,0,3] stays allocated and principal-less, so the probe at it
            // keeps its meaning: an uncovered sibling resolving to π₀.
            .apply_m3(&alloc(&[1, 0, 3]))
            // An INVERTED pair: the shallower principal carries the HIGHER id,
            // so "longest prefix" and "highest id" disagree here and nowhere
            // else in the suite. Ids are opaque and assigned by M10 — nothing
            // makes them monotone in depth, and ω must not read them as
            // ordering.
            .apply_m3(&alloc(&[1, 0, 4]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 4]),
                id: PrincipalId(50),
            })
            .apply_m3(&alloc(&[1, 0, 4, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 4, 1]),
                id: PrincipalId(5),
            }),
    };
    let pi = [
        (a(&[1]), BOOTSTRAP_PRINCIPAL),
        (a(&[1, 0, 1]), ID1),
        (a(&[1, 0, 1, 1]), ID2),
        (a(&[1, 0, 1, 1, 1]), PrincipalId(3)),
        (a(&[1, 0, 2]), PrincipalId(4)),
        (a(&[1, 0, 4]), PrincipalId(50)),
        (a(&[1, 0, 4, 1]), PrincipalId(5)),
    ];
    // Independent oracle: reconstruct the probe's OWN node/account-tier
    // prefixes, longest first, and take the first that names a principal.
    // That is the other derivation of ω — deliberately not the
    // implementation's, which walks Π and keeps the longest cover — so the two
    // can only agree by both being right.
    let oracle = |probe: &Address| -> Option<PrincipalId> {
        (1..=probe.tumbler().len()).rev().find_map(|plen| {
            let p =
                validate(Tumbler::new(probe.tumbler().iter().take(plen).cloned()).ok()?).ok()?;
            if !matches!(p.level(), Level::Node | Level::Account) {
                return None;
            }
            pi.iter().find(|(q, _)| *q == p).map(|(_, id)| *id)
        })
    };
    let m3 = seeded.m3;

    // The family: every prefix of a deep address, each of those with its
    // last component bumped (an uncovered sibling), and a foreign node's
    // subtree.
    let deep = [1u32, 0, 1, 1, 1, 0, 1, 0, 1, 1];
    let mut probes = vec![
        a(&[2]),
        a(&[2, 0, 1]),
        a(&[1, 0, 3]),
        a(&[1, 0, 1, 2, 0, 1]),
        // The inverted pair, and what sits under and beside it: at [1,0,4,1]
        // and below, ω is the DEEPER seat (id 5) and not the higher id (50).
        a(&[1, 0, 4]),
        a(&[1, 0, 4, 1]),
        a(&[1, 0, 4, 1, 1]),
        a(&[1, 0, 4, 2]),
    ];
    for len in 1..=deep.len() {
        if let Ok(p) = validate(t(&deep[..len])) {
            probes.push(p);
        }
        let mut bumped = deep[..len].to_vec();
        if let Some(last) = bumped.last_mut() {
            *last += 1;
        }
        if let Ok(p) = validate(t(&bumped)) {
            probes.push(p);
        }
    }
    assert!(
        probes.len() > 12,
        "the generated family is the point of this test"
    );

    let mut ids: Vec<PrincipalId> = pi.iter().map(|(_, id)| *id).collect();
    ids.push(UNKNOWN_ID);
    for probe in &probes {
        assert_eq!(
            m3.effective_owner(probe),
            oracle(probe),
            "ω disagrees at {probe:?}"
        );
        // The other projection of the same walk: the seat, not the id.
        assert_eq!(
            m3.effective_owner_prefix(probe),
            oracle(probe).and_then(|id| pi.iter().find(|(_, i)| *i == id).map(|(p, _)| p)),
            "ω's prefix disagrees at {probe:?}"
        );
        for id in &ids {
            assert_eq!(
                m3.is_effective_owner(*id, probe),
                oracle(probe) == Some(*id),
                "is_effective_owner({id:?}, {probe:?}) disagrees with ω"
            );
        }
    }
}

#[test]
fn every_registered_document_is_owned_at_its_own_account() {
    // §5: a registered document is owned at its OWN account, `acct(d)` —
    // never `None`, never the node above it, never an ancestor account — on
    // every state M3's ops produce. ASN-0042's O6 promises only containment,
    // `pfx(ω(d)) ≼ acct(d)`; M3 makes it equality because every document is
    // minted under a registered account (P8; a version under a registered
    // document) and every registered account holds its own seat (`delegate`).
    // That account is the document's OWNER ACCOUNT (PUB-7.5, PUB-8.12), which
    // `account_seat` reads by one lookup, so ω and that read are both walked
    // over EVERY document `documents` enumerates — on a fold-produced slice,
    // every registered document: genesis's two under the system account, and
    // under one account a document, a fork, a version and a version of that
    // version, beside a document under the account's sub-account — the one
    // shape where an ancestor account's seat covers the document too.
    let (k, _acct, doc) = kernel_with_account_and_doc();
    let ns = Namespace::new(&k);
    let (sub_acct, _) = ns
        .delegate(ID1, t(&[1, 0, 1, 1]), ID2)
        .expect("sub-delegate");
    // The sub-account's document comes off the mint itself — as M5's
    // cross-owner VERSION mints one — so a wrong ω is reported by the walk
    // below, not refused by an ω gate in the fixture.
    let sub_doc = commit_mint(&k, M3State::document_lock_key(&sub_acct), |m3| {
        m3.mint_document(&sub_acct, false)
    });
    let (forked, _) = ns.fork(ID1, None).expect("a fork into the account");
    let v1 = commit_mint(&k, M3State::version_lock_key(&doc), |m3| {
        m3.mint_version(&doc, true)
    });
    let v2 = commit_mint(&k, M3State::version_lock_key(&v1), |m3| {
        m3.mint_version(&v1, true)
    });
    let m3 = k.snapshot().world().m3().clone();

    let mut walked = Vec::new();
    for (d, _) in m3.documents() {
        let owner = m3
            .effective_owner_prefix(d)
            .unwrap_or_else(|| panic!("{d:?} is registered and owned by no seat"));
        // `same_account` (T6(b)) holds of an account-tier owner exactly when
        // the owner IS `acct(d)`.
        assert_eq!(owner.level(), Level::Account, "{d:?} is owned at {owner:?}");
        assert!(
            same_account(owner, d),
            "{d:?} is owned at {owner:?}, not at its own account"
        );
        // …and the owner-account read answers that same seat, by one lookup.
        assert_eq!(
            m3.account_seat(d).map(|(seat, _)| seat),
            Some(owner),
            "{d:?}: the owner-account read disagrees with ω"
        );
        walked.push(d.clone());
    }
    // The walk reached every shape built above; genesis's two are the seed's,
    // pinned in `genesis.rs`.
    for built in [&doc, &sub_doc, &forked, &v1, &v2] {
        assert!(walked.contains(built), "the walk missed {built:?}");
    }
}

#[test]
fn the_account_seat_is_omega_by_one_lookup_and_never_climbs() {
    // §5: `account_seat` is ω by ONE point lookup wherever the probe's own
    // account holds a seat — on every state M3's ops produce, every registered
    // document and every registered account — and `None` wherever ω climbs
    // past that account. It is THE read of a registered document's OWNER
    // ACCOUNT, per request or once per entry of a walk over the store (the
    // engine's draft memo and grant admission, rebuilt at every load and
    // every historical reconstruction), so agreement is checked over every
    // document, every seat, and every seated account's doc-1 slot — the
    // first address past that seat in key order — with Π grown past one
    // 64-key B-tree leaf, so the lookup descends through an internal node and
    // some seat is that node's separator key: the shape a neighbour search
    // that ignores the separator answers wrongly. The two shapes where ω
    // climbs — to an ancestor ACCOUNT, which a tier check on ω's answer
    // passes, and to the NODE — are built through the fold, the only way to
    // reach a registered document whose own account holds no seat. The cost
    // is pinned in heap bytes: one copy of the account, nothing past it and
    // nothing beside it — never a walk of Π.
    let (k, acct, doc) = kernel_with_account_and_doc();
    let ns = Namespace::new(&k);
    // Seventy sub-accounts, each seated for its own principal: with genesis's
    // two seats and the account's own, Π holds 73 and spans two B-tree levels.
    let mut sub_accts = Vec::new();
    for i in 0..70u64 {
        let sub_peek = k
            .snapshot()
            .world()
            .m3()
            .next_account_prefix(&acct)
            .expect("the account has a delegable slot");
        let (sub_acct, _) = ns
            .delegate(ID1, sub_peek.into(), PrincipalId(100 + i))
            .expect("sub-delegate");
        sub_accts.push(sub_acct);
    }
    let last_sub_acct = sub_accts.last().expect("seventy sub-accounts").clone();
    let (last_doc, _) = ns
        .create_new_document(PrincipalId(169), &last_sub_acct, None)
        .expect("the last sub-account's doc 1");
    let v1 = commit_mint(&k, M3State::version_lock_key(&doc), |m3| {
        m3.mint_version(&doc, true)
    });
    let element = commit_mint(&k, M3State::content_lock_key(&last_doc), |m3| {
        m3.mint_content(&last_doc)
    });
    let m3 = k.snapshot().world().m3().clone();

    // Agreement: every document the walk yields — genesis's two included —
    // every seated account and its doc-1 slot, and an element.
    let mut probes: Vec<Address> = m3.documents().map(|(d, _)| d.clone()).collect();
    for built in [&doc, &v1, &last_doc] {
        assert!(probes.contains(built), "the walk reaches {built:?}");
    }
    let mut accounts = vec![acct.clone(), system_account()];
    accounts.extend(sub_accts);
    for account in &accounts {
        probes.push(first_document_address(account).expect("an account anchors a document chain"));
    }
    probes.extend(accounts);
    probes.push(element);
    for probe in &probes {
        let seat = m3.account_seat(probe);
        assert!(seat.is_some(), "{probe:?}: its own account is seated");
        assert_eq!(seat, m3.effective_owner_pair(probe), "{probe:?}");
    }

    // Where ω climbs past the probe's own account, this answers nobody. To an
    // ancestor ACCOUNT — account-tier, so a tier check on ω's answer passes
    // it, and a memo of it would admit every principal seated under the
    // ancestor, the owner's siblings included, to the document:
    let to_an_account = M3State::genesis()
        .apply_m3(&alloc(&[1, 0, 1]))
        .apply_m3(&M3Rec::RegisterPrincipal {
            prefix: a(&[1, 0, 1]),
            id: ID1,
        })
        .apply_m3(&alloc(&[1, 0, 1, 1]))
        .apply_m3(&alloc(&[1, 0, 1, 1, 0, 1]));
    let sub_doc = a(&[1, 0, 1, 1, 0, 1]);
    assert!(to_an_account.is_registered_document(&sub_doc));
    assert_eq!(
        to_an_account.effective_owner_prefix(&sub_doc),
        Some(&a(&[1, 0, 1]))
    );
    assert_eq!(to_an_account.account_seat(&sub_doc), None);
    // …and to the NODE.
    let to_the_node = M3State::genesis()
        .apply_m3(&alloc(&[1, 0, 1]))
        .apply_m3(&alloc(&[1, 0, 1, 0, 1]));
    let acct_doc = a(&[1, 0, 1, 0, 1]);
    assert!(to_the_node.is_registered_document(&acct_doc));
    assert_eq!(
        to_the_node.effective_owner_prefix(&acct_doc),
        Some(&a(&[1]))
    );
    assert_eq!(to_the_node.account_seat(&acct_doc), None);
    // A node address has no account to look up, seated or not.
    assert_eq!(m3.effective_owner(&a(&[1])), Some(BOOTSTRAP_PRINCIPAL));
    assert_eq!(m3.account_seat(&a(&[1])), None);

    // The cost is the ACCOUNT's copy and nothing past it: probes under one
    // seated account, element fields from one component to fifty thousand,
    // ask the heap for one byte count.
    let under = |depth: usize| {
        let mut comps = vec![1u32, 0, 1, 0, 1, 0, 1];
        comps.extend(std::iter::repeat_n(1u32, depth - 1));
        a(&comps)
    };
    let shallow = under(1);
    let (seat, shallow_bytes) = heap_bytes(|| m3.account_seat(&shallow));
    assert_eq!(seat, Some((&acct, ID1)));
    for depth in [10, 1_000, 50_000] {
        let deep = under(depth);
        let (seat, bytes) = heap_bytes(|| m3.account_seat(&deep));
        assert_eq!(seat, Some((&acct, ID1)), "{depth} element-field components");
        assert_eq!(
            bytes, shallow_bytes,
            "a copy past the account at {depth} components"
        );
    }

    // …and nothing BESIDE that copy: ONE point lookup, never a walk of Π. A
    // walk asks the heap for its iterator's path through the tree and the
    // lookup asks for nothing, so the read's whole heap use is what M1's two
    // constructors ask to rebuild the account from its own components — and
    // at a node, which has no account to rebuild, nothing at all. A body
    // spelled as ω narrowed to the probe's own account gives every answer
    // above, agreement and climbs alike, at one cost per depth, and walks Π
    // on every call: the engine's draft memo and grant admission would cost
    // Θ(entries · |Π|) again at every load and every historical read.
    let (_, one_copy_bytes) = heap_bytes(|| {
        validate(Tumbler::new(acct.tumbler().iter().cloned()).expect("an account is nonempty"))
            .expect("an account rebuilt from its own components is T4-valid")
    });
    assert_eq!(
        shallow_bytes, one_copy_bytes,
        "the read asked the heap for more than one copy of its account: it walked Π"
    );
    let node = a(&[1]);
    let (seat, node_bytes) = heap_bytes(|| m3.account_seat(&node));
    assert_eq!(seat, None);
    assert_eq!(
        node_bytes, 0,
        "at a node, which has no account to rebuild, the read asked the heap for bytes: it walked Π"
    );
}

#[test]
fn the_principal_registry_answers_one_prefix_per_principal_in_both_directions() {
    // §5: a principal's prefix is the principal registry's KEY and is filed
    // nowhere else, so the prefix it is seated at — what ω arbitrates by —
    // and the prefix it is reported at — what `principal_prefix` answers, and
    // what `fork` then creates a document under — are one value.
    // id → prefix → ω → id is therefore the identity on Π. A registry that
    // filed the prefix twice could disagree with itself, and would fail OPEN:
    // a document minted under the wrong account.
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("account under the bootstrap node");
    ns.delegate(ID1, t(&[1, 0, 1, 1]), ID2)
        .expect("sub-account under ID1's account");
    ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 2]), PrincipalId(3))
        .expect("a sibling account");
    let m3 = k.snapshot().world().m3().clone();

    let seated = [
        (BOOTSTRAP_PRINCIPAL, a(&[1])),
        (ID1, a(&[1, 0, 1])),
        (ID2, a(&[1, 0, 1, 1])),
        (PrincipalId(3), a(&[1, 0, 2])),
    ];
    // The round trip holds on the live slice and, unchanged, on one restored
    // from its checkpoint bytes — the door a disagreement between a seated
    // and a reported prefix could otherwise arrive through.
    let bytes = bincode::serialize(&m3).expect("serialize M3State");
    let restored: M3State = bincode::deserialize(&bytes).expect("deserialize M3State");
    for state in [&m3, &restored] {
        for (id, prefix) in &seated {
            assert_eq!(state.principal_prefix(*id), Some(prefix));
            // …and ω at that very prefix names the principal back.
            assert_eq!(state.effective_owner(prefix), Some(*id));
            assert!(state.is_effective_owner(*id, prefix));
            // The seat ω names IS the seat the registry keys it by.
            assert_eq!(state.effective_owner_prefix(prefix), Some(prefix));
        }
        // An unknown id names no prefix, and no address answers it as ω.
        assert!(state.principal_prefix(UNKNOWN_ID).is_none());
        for (_, prefix) in &seated {
            assert!(!state.is_effective_owner(UNKNOWN_ID, prefix));
        }
    }
}

#[test]
fn the_principal_registry_enumerates_every_seat_in_address_order() {
    // §5: Π's walk is every seat, verbatim, in address order — π₀'s node-tier
    // seat, the system account genesis seats, each delegation's — including a
    // seat beneath a node `register_node` admitted, which no walk of account
    // frontiers from the genesis seats reaches. One delegation is one new
    // entry, so the walk of the world after a commit, less the walk of the
    // world before it, names the seat that commit made: the comparison a
    // caller holding neither an address nor an id makes.
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("an account under the bootstrap node");
    ns.register_node(t(&[1, 7])).expect("a provisioned node");
    let before = k.snapshot().world().m3().clone();
    let (provisioned, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 7, 0, 1]), ID2)
        .expect("an account under the provisioned node");
    let after = k.snapshot().world().m3().clone();

    let (root, system) = (a(&[1]), system_account());
    assert_eq!(
        after.principals().collect::<Vec<_>>(),
        vec![
            (&root, BOOTSTRAP_PRINCIPAL),
            (&acct, ID1),
            (&system, SYSTEM_PRINCIPAL),
            (&provisioned, ID2),
        ],
        "every seat, in address order"
    );
    assert_eq!(after.principals().len(), 4);
    assert_eq!(after.principals().next_back(), Some((&provisioned, ID2)));
    // The commit's one new seat: the walk after it, less the walk before —
    // taken in ONE pass over the two in step, as `principals`' card says a
    // comparison of two walks is; the earlier walk is a subsequence of the
    // later.
    let mut earlier = before.principals().peekable();
    let seated: Vec<_> = after
        .principals()
        .filter(|seat| earlier.next_if_eq(seat).is_none())
        .collect();
    assert!(
        earlier.next().is_none(),
        "every seat of the earlier walk is in the later one"
    );
    assert_eq!(seated, vec![(&provisioned, ID2)]);
}

#[test]
fn omega_resolves_by_the_registry_not_by_the_probes_depth() {
    // §5 cost discipline: ω's work is sized by Π, never by the address the
    // caller hands in. T4 constrains an address's zero pattern, NOT its
    // component count, so a ~100 KB dotted-decimal request can carry a
    // 50_000-component account-tier probe — and every prefix of it past the
    // separator is itself account-tier, so a per-candidate prefix walk has no
    // short-circuit and rebuilds ~1.25e9 components for this one call, while
    // `create_new_document` and `delegate` hold the global principals key
    // across exactly this read. Asking the heap for exactly the bytes a
    // three-component probe asks for is the refusal, and it is COUNTED, not
    // timed: a wall-clock bound is a flake and a slow test is no failure, so
    // a probe rebuilt per candidate, or copied even once, is a different
    // number at four components, before any deep probe runs. Corpus seed for
    // the fuzzing tier.
    // Π = { [1]→π₀, [1,0,1]→ID1, [1,1,0,1]→SYSTEM_PRINCIPAL }
    let (k, _acct, _doc) = kernel_with_account_and_doc();
    let snap = k.snapshot();
    let m3 = snap.world().m3();

    // The walk's own heap bytes at three components, then at depths
    // generated past it, before any deep probe runs.
    let probe = |len: usize| {
        let mut comps = vec![1u32, 0];
        comps.extend(std::iter::repeat_n(1u32, len - 2));
        a(&comps)
    };
    let shallow = probe(3);
    let (owner, shallow_bytes) = heap_bytes(|| m3.effective_owner(&shallow));
    assert_eq!(owner, Some(ID1));
    for len in [4, 10, 100, 1_000] {
        let deeper = probe(len);
        let (owner, bytes) = heap_bytes(|| m3.effective_owner(&deeper));
        assert_eq!(owner, Some(ID1), "ω at {len} components");
        assert_eq!(
            bytes, shallow_bytes,
            "ω's heap bytes at {len} components against 3"
        );
        let (owns, bytes) = heap_bytes(|| m3.is_effective_owner(ID1, &deeper));
        assert!(owns, "the authorization predicate at {len} components");
        assert_eq!(
            bytes, shallow_bytes,
            "the authorization predicate's heap bytes at {len} components against 3"
        );
    }

    let mut deep = vec![1u32, 0];
    deep.extend(std::iter::repeat_n(1u32, 49_998));
    let deep = a(&deep);
    assert_eq!(deep.level(), Level::Account); // every prefix past [1,0] is a candidate
    let (owner, bytes) = heap_bytes(|| m3.effective_owner(&deep));
    assert_eq!(owner, Some(ID1));
    assert_eq!(
        bytes, shallow_bytes,
        "ω's heap bytes at fifty thousand components against 3"
    );
    assert!(m3.is_effective_owner(ID1, &deep));
    assert!(!m3.is_effective_owner(BOOTSTRAP_PRINCIPAL, &deep));

    // Equally deep, under no principal at all: None, at the same cost.
    let mut foreign = vec![2u32, 0];
    foreign.extend(std::iter::repeat_n(1u32, 49_998));
    assert!(m3.effective_owner(&a(&foreign)).is_none());

    // Mid-depth, same registry, same answer — a walk that truncates anywhere
    // between three components and fifty thousand has no threshold to hide at.
    let mid = a(&[1, 0, 1, 1, 1, 1, 1, 1, 1, 1]);
    assert_eq!(m3.effective_owner(&mid), Some(ID1));
    assert!(m3.is_effective_owner(ID1, &mid));
}

#[test]
fn omega_refuses_a_principal_seated_below_the_account_tier() {
    // §5 / O1a: Π is node/account tier only, and ω is the ONE reader that
    // refuses a below-tier entry — because ω is the one reader whose answer to
    // one would be a PASS. The seat is unreachable through `delegate` (its
    // hoisted NotAccountTier gate) and representable in a corrupted checkpoint
    // (`M3State` decodes by bare derive), so the fold is how a test reaches it.
    // Below the account tier are TWO tiers, and each is seated here — a
    // document and an element beneath it — because a filter that refused one
    // of them would pass a test that seats only the other.
    let doc = a(&[1, 0, 1, 0, 1]);
    let element = a(&[1, 0, 1, 0, 1, 0, 1, 1]);
    let seeded = World {
        m3: M3State::genesis()
            .apply_m3(&alloc(&[1, 0, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1]),
                id: ID1,
            })
            .apply_m3(&alloc(&[1, 0, 1, 0, 1]))
            // A DOCUMENT-tier seat — below O1a's bound.
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: doc.clone(),
                id: ID2,
            })
            // …and an ELEMENT-tier seat beneath it, the bound's other side.
            .apply_m3(&alloc(&[1, 0, 1, 0, 1, 0, 1, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: element.clone(),
                id: PrincipalId(3),
            }),
    };
    let k = mem_kernel(seeded);
    let snap = k.snapshot();
    let m3 = snap.world().m3();

    // ω skips both and keeps the longest ADMISSIBLE cover — the account above
    // — so a below-tier seat shadows no one, at its own address or beneath
    // it. Both projections refuse them, because they share the walk that
    // filters.
    assert_eq!(m3.effective_owner(&doc), Some(ID1));
    assert_eq!(m3.effective_owner_prefix(&doc), Some(&a(&[1, 0, 1])));
    assert!(!m3.is_effective_owner(ID2, &doc));
    assert_eq!(m3.effective_owner(&element), Some(ID1));
    assert_eq!(m3.effective_owner_prefix(&element), Some(&a(&[1, 0, 1])));
    assert!(!m3.is_effective_owner(ID2, &element));
    assert!(!m3.is_effective_owner(PrincipalId(3), &element));

    // The registry's verbatim readers report both seats, as their docs say —
    // by id and in the walk of every seat…
    assert_eq!(m3.principal_prefix(ID2), Some(&doc));
    assert_eq!(m3.principal_prefix(PrincipalId(3)), Some(&element));
    assert!(m3.principals().any(|seat| seat == (&doc, ID2)));
    assert!(m3
        .principals()
        .any(|seat| seat == (&element, PrincipalId(3))));
    // …and the ω-gated op is what refuses it. Without the filter this call
    // passes authorization and refuses structurally instead — the right
    // outcome for the wrong reason, and the wrong one for M5, which asks ω
    // about elements.
    assert_eq!(
        rejected(Namespace::new(&k).create_new_document(ID2, &doc, None)),
        CreateDocumentError::NotOwner
    );
}

#[test]
fn omega_names_the_seat_it_matched_when_two_principals_carry_one_id() {
    // §5: `effective_owner_prefix` exists because the composition a caller
    // would otherwise write — `principal_prefix(effective_owner(a))` — is the
    // same answer ONLY while Π is id-injective, a PRODUCER invariant
    // (`delegate`'s DuplicateId gate) that `apply_m3` does not re-check. Two
    // carriers of one id is unreachable through the ops and representable in
    // a corrupted checkpoint, so the fold is how a test reaches it — and it is
    // the one input at which the two projections can come apart.
    let deep_seat = a(&[1, 0, 1, 1]);
    let seeded = World {
        m3: M3State::genesis()
            .apply_m3(&alloc(&[1, 0, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1]),
                id: ID1,
            })
            .apply_m3(&alloc(&[1, 0, 1, 1]))
            // The SAME id, seated again deeper — id-injectivity broken.
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: deep_seat.clone(),
                id: ID1,
            }),
    };
    let m3 = seeded.m3;

    // ω matches ONE entry, and both projections come off it: at the seat and
    // beneath it, the seat reported is the seat matched — the DEEPER one,
    // which is not what `principal_prefix(ID1)` answers here.
    for probe in [deep_seat.clone(), a(&[1, 0, 1, 1, 0, 1])] {
        assert_eq!(m3.effective_owner(&probe), Some(ID1), "ω's id at {probe:?}");
        assert_eq!(
            m3.effective_owner_prefix(&probe),
            Some(&deep_seat),
            "ω's seat at {probe:?} is not the entry it matched"
        );
        assert!(m3.is_effective_owner(ID1, &probe));
    }
}
