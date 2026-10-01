use super::*;

use crate::ghost::{ghost_position, GHOST_POSITIONS};
use crate::ns::{account_ns, content_ns, document_ns, link_ns, ns_lock_key, version_ns};
use skep_address::parent;

fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
}

fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("T4-valid")
}

/// §1/§8: for every chain family, the key derived from a MINTED address
/// (the child side, which `apply_m3` uses to advance the frontier) is
/// byte-identical to the key its caller locks and its mint reads (the
/// anchor side). A divergence would under-serialize a namespace and
/// REUSE an address. Checked at two ordinals per chain, because every
/// member of a chain must derive the same key or the frontier forks.
#[test]
fn each_chains_minted_addresses_advance_the_key_their_mint_read() {
    let node = a(&[1]);
    let acct = a(&[1, 0, 1]);
    let doc = a(&[1, 0, 1, 0, 1]);
    for (family, anchor_key, members) in [
        (
            "content",
            content_ns(&doc),
            [a(&[1, 0, 1, 0, 1, 0, 1, 1]), a(&[1, 0, 1, 0, 1, 0, 1, 2])],
        ),
        (
            "link",
            link_ns(&doc),
            [a(&[1, 0, 1, 0, 1, 0, 2, 1]), a(&[1, 0, 1, 0, 1, 0, 2, 2])],
        ),
        (
            "version",
            version_ns(&doc),
            [a(&[1, 0, 1, 0, 1, 1]), a(&[1, 0, 1, 0, 1, 2])],
        ),
        (
            "document",
            document_ns(&acct),
            [a(&[1, 0, 1, 0, 1]), a(&[1, 0, 1, 0, 2])],
        ),
        (
            "account under a node",
            account_ns(&node),
            [a(&[1, 0, 1]), a(&[1, 0, 2])],
        ),
        (
            "sub-account under an account",
            account_ns(&acct),
            [a(&[1, 0, 1, 1]), a(&[1, 0, 1, 2])],
        ),
    ] {
        for member in &members {
            let child_key = namespace_of(member).expect("minted addresses have a parent");
            assert_eq!(
                child_key, anchor_key,
                "{family}: the fold's key for {member:?} is not the mint's key"
            );
            assert_eq!(
                ns_lock_key(&child_key),
                ns_lock_key(&anchor_key),
                "{family}: lock bytes differ from frontier bytes for {member:?}"
            );
        }
    }
    // The key constructors are that same encoding, so a caller's key
    // and the frontier its mint reads are one value — the account
    // chain included, whose lock `delegate` takes and whose frontier
    // `mint_account` reads.
    assert_eq!(
        M3State::content_lock_key(&doc),
        ns_lock_key(&content_ns(&doc))
    );
    assert_eq!(M3State::link_lock_key(&doc), ns_lock_key(&link_ns(&doc)));
    assert_eq!(
        M3State::version_lock_key(&doc),
        ns_lock_key(&version_ns(&doc))
    );
    assert_eq!(
        M3State::document_lock_key(&acct),
        ns_lock_key(&document_ns(&acct))
    );
    assert_eq!(
        M3State::account_lock_key(&node),
        ns_lock_key(&account_ns(&node))
    );
    assert_eq!(
        M3State::account_lock_key(&acct),
        ns_lock_key(&account_ns(&acct))
    );
}

#[test]
fn lock_keys_distinguish_every_chain_and_key_domain() {
    let acct = a(&[1, 0, 1]);
    let doc = a(&[1, 0, 1, 0, 1]);
    // The three g=1 chains under ONE document — content (b_C(d),1), link
    // (b_L(d),1), version (d,1) — plus the document chain and the two
    // registry keys: all pairwise distinct (B7/B8; §1/§8 — an alias would
    // under-serialize a namespace and reuse an address).
    let keys = [
        M3State::content_lock_key(&doc),
        M3State::link_lock_key(&doc),
        M3State::version_lock_key(&doc),
        M3State::document_lock_key(&acct),
        M3State::principals_lock_key(),
        M3State::nodes_lock_key(),
    ];
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j], "lock keys {i} and {j} alias");
        }
    }
    // g distinguishes the two chains anchored at the SAME tumbler: an
    // account's version-style (A,1) sub-account chain vs its (A,2) document
    // chain (ASN-0123 separation falls out of the key).
    assert_ne!(
        M3State::version_lock_key(&acct),
        M3State::document_lock_key(&acct)
    );
    // Distinct homes get distinct keys.
    assert_ne!(
        M3State::content_lock_key(&doc),
        M3State::content_lock_key(&a(&[1, 0, 1, 0, 2]))
    );
}

/// §1: [`M3State::effective_frontier`] takes a MAX, not a fallback — so a
/// stored frontier BELOW the floor cannot drag a mint back into the ghost
/// region. Only corruption or a foreign producer regresses a frontier, and
/// the fold's contiguity guard is a `debug_assert` and absent in release,
/// so the `max` is what carries non-reissue there. Built by hand rather
/// than folded, because folding the regressing record is what that assert
/// stops.
#[test]
fn the_ghost_floor_holds_against_a_regressed_frontier() {
    let ghost_ns = content_ns(&ghost_home_doc());
    let mut s = M3State::genesis();
    s.frontiers.insert(ghost_ns.clone(), Nat::from(2u32));

    // The mint still lands past the region, not at the stored value + 1.
    let next = s
        .next_in(&ghost_ns)
        .expect("a Document's content base is T4");
    assert_eq!(
        *ordinal(next.tumbler()),
        Nat::from(GHOST_POSITIONS + 1),
        "a regressed frontier moved a mint into the ghost region"
    );
    // …and membership excludes all five however the frontier reads, since
    // it compares against the floor and not against the stored count.
    for ordinal in 1..=GHOST_POSITIONS {
        assert!(
            !s.is_allocated(&ghost_position(ordinal)),
            "ghost {ordinal} became a member"
        );
    }
}

/// §1: a stored ZERO is an empty chain at both frontier-end reads — the
/// reading [`M3State::has_documents`] and [`M3State::latest_version`] each
/// state, and which neither can reach through M3's own ops, since
/// [`M3State::apply_m3`] inserts only `effective_frontier + 1`, and genesis's
/// seed is itself folded through it. A checkpoint is bytes and `NsKeyShadow`
/// screens the KEY, not the count, so this is the shape those two guards exist
/// for; it is built by hand for the reason the ghost test above is.
///
/// The guards fail in opposite ways. Without [`M3State::latest_version`]'s,
/// [`nth_in`] computes `0 − 1` on a `Nat` and the read PANICS — on the
/// path M5's trunk head and every daemon read of that document take.
/// Without [`M3State::has_documents`]', an empty account reads as
/// non-empty and the create path mints its doc 1 PRIVATE against PUB-8.21.
#[test]
fn a_zero_frontier_is_an_empty_chain_at_both_reads() {
    let acct = a(&[1, 0, 1]);
    let doc = a(&[1, 0, 1, 0, 1]);
    let mut s = M3State::genesis()
        .apply_m3(&M3Rec::Allocate {
            addr: acct.clone(),
            published: false,
        })
        .apply_m3(&M3Rec::Allocate {
            addr: doc.clone(),
            published: true,
        });
    // The ordinary readings first, so a guard that answers `false`/`None`
    // unconditionally is not what turns this test green.
    assert!(s.has_documents(&acct));
    assert_eq!(s.latest_version(&doc), None); // the key is ABSENT, not zero

    // Now write both chains down as EMPTY — a stored zero.
    s.frontiers.insert(document_ns(&acct), Nat::zero());
    s.frontiers.insert(version_ns(&doc), Nat::zero());

    assert!(
        !s.has_documents(&acct),
        "a zero count read as a document: PUB-8.21 would mint doc 1 private"
    );
    assert_eq!(
        s.latest_version(&doc),
        None,
        "a zero count read as a member"
    );
    // …and a written-down empty chain mints and enumerates exactly like
    // one that was never written down: c₁ is still next, and no member.
    assert_eq!(
        s.next_in(&version_ns(&doc))
            .expect("k = 1 passes TA5a on every anchor"),
        a(&[1, 0, 1, 0, 1, 1])
    );
    assert!(!s.is_allocated(&a(&[1, 0, 1, 0, 1, 1])));
}

/// PUB-1.9: a document's bit is written ONCE. A second `Allocate` naming a
/// registered document is outside [`M3State::apply_m3`]'s totality domain
/// and the contiguity `debug_assert` is what refuses it — but that assert
/// is absent in RELEASE, and no record door can carry the fact (whether an
/// address is already registered is a claim about the registry, which a
/// decoder holding one frame cannot settle). So the insert itself is
/// write-once, and this is the shape that reaches it in a debug run: a
/// stored ZERO makes the re-staged record CONTIGUOUS, so the assert passes
/// and the publication insert is reached on both build profiles.
#[test]
fn a_replayed_allocate_never_moves_a_documents_bit() {
    let acct = a(&[1, 0, 1]);
    let doc = a(&[1, 0, 1, 0, 1]);
    let minted = M3State::genesis()
        .apply_m3(&M3Rec::Allocate {
            addr: acct.clone(),
            published: false,
        })
        .apply_m3(&M3Rec::Allocate {
            addr: doc.clone(),
            published: false,
        });
    assert!(!minted.published(&doc), "minted private");

    let mut regressed = minted.clone();
    regressed.frontiers.insert(document_ns(&acct), Nat::zero());
    let replayed = regressed.apply_m3(&M3Rec::Allocate {
        addr: doc.clone(),
        published: true,
    });

    assert!(replayed.is_registered_document(&doc));
    assert!(
        !replayed.published(&doc),
        "a second Allocate flipped a private document public: the bit is written once (PUB-1.9)"
    );
}

/// [`M3State::latest_version`] reads the CHAIN and not the registry: it
/// answers for a document-tier address "registered or not", and PUB-6.37's
/// gate stays the caller's ([`M3State::is_registered_document`]), exactly
/// as it does on [`M3State::published`]. The discriminating shape is a
/// version chain holding a member under a document that was never minted;
/// every other fixture in the crate hands this read a registered document,
/// so a registration gate added here would pass them all.
#[test]
fn latest_version_reads_the_chain_not_the_registry() {
    let orphan = a(&[1, 0, 1, 0, 9]);
    let member = a(&[1, 0, 1, 0, 9, 1]);
    let s = M3State::genesis().apply_m3(&M3Rec::Allocate {
        addr: member.clone(),
        published: false,
    });
    assert!(
        !s.is_registered_document(&orphan),
        "the source was never minted"
    );
    assert_eq!(s.latest_version(&orphan), Some(member));
}

/// §6 (iv): the single probe answers "does a registered principal sit
/// STRICTLY under `p`?" — checked over the shape family one probe can
/// meet, because only ONE key is ever examined, so a wrong range bound or
/// a dropped containment test still answers correctly at a chosen point.
/// Π holds the seats each row names plus genesis's two: `[1]`, an ANCESTOR
/// of `p` that sorts before it, so no row's answer may come from it; and the
/// system account `1.1.0.1`, which sorts AFTER `p` — so in the
/// empty-subtree row the probe meets that seat, a successor that is no
/// descendant, and no row ever hands it an empty block. The assertion after
/// the loop is that block: a `p` past every seat, where the probe finds no
/// key at all.
///
/// The last two rows are the PRECONDITION `p ∉ Π` made executable: once
/// `p` is itself a principal the block of keys ≥ `p` opens with `p`, so
/// the probe answers false whether or not a principal sits beneath. That
/// is why [`crate::Namespace::delegate`] PINS (i) and (ii) ahead of (iv),
/// and a probe made correct for `p ∈ Π` makes the last row wrong and that
/// pinning revisable — one edit, both consequences.
#[test]
fn the_top_down_probe_sees_strict_descendants_and_nothing_else() {
    let p = a(&[1, 0, 1]);
    for (shape, seats, expected) in [
        ("an empty subtree", vec![], false),
        ("a strict child", vec![vec![1, 0, 1, 1]], true),
        (
            "a deep strict descendant only",
            vec![vec![1, 0, 1, 1, 1]],
            true,
        ),
        (
            "a successor that is no descendant",
            vec![vec![1, 0, 2]],
            false,
        ),
        ("p itself, with nothing beneath", vec![vec![1, 0, 1]], false),
        (
            "p itself, with a child beneath — the precondition's blind spot",
            vec![vec![1, 0, 1], vec![1, 0, 1, 1]],
            false,
        ),
    ] {
        let state =
            seats
                .iter()
                .enumerate()
                .fold(M3State::genesis(), |state, (nth, prefix)| {
                    state.apply_m3(&M3Rec::RegisterPrincipal {
                        prefix: a(prefix),
                        id: PrincipalId(nth as u64 + 1),
                    })
                });
        assert_eq!(
            state.has_principal_strictly_under(&p),
            expected,
            "{shape}: the top-down probe disagrees"
        );
    }
    // The probe's other arm: no key ≥ `p` at all. Both of genesis's seats
    // sort before `[1, 2, 0, 1]`, so the block is empty and nothing sits
    // under it.
    assert!(
        !M3State::genesis().has_principal_strictly_under(&a(&[1, 2, 0, 1])),
        "past every seat the block is empty"
    );
}

/// The [`M3RecShadow`] door tests `#a ≥ 2`; [`M3State::apply_m3`]'s
/// `expect` needs `parent(a).is_some()`. Two spellings of one fact, sound
/// only while M1's `parent` is `None` at exactly one component — a
/// property M3 asserts in prose and cannot enforce. Pinned here so a
/// change in M1 reddens this suite instead of panicking the applier at
/// every replay from then on.
#[test]
fn the_allocate_door_admits_exactly_what_the_fold_can_key() {
    for comps in [
        vec![1u32],
        vec![7],
        vec![1, 1],
        vec![1, 7],
        vec![2, 3],
        vec![1, 0, 1],
        vec![1, 0, 1, 1],
        vec![1, 0, 1, 0, 1],
        vec![1, 0, 1, 0, 1, 1],
        vec![1, 0, 1, 0, 1, 0, 1],
        vec![1, 0, 1, 0, 1, 0, 2],
        vec![1, 0, 1, 0, 1, 0, 1, 1],
        vec![1, 0, 1, 0, 1, 0, 2, 9],
    ] {
        let addr = a(&comps);
        let door_admits = addr.tumbler().len() >= 2;
        assert_eq!(
            parent(&addr).is_some(),
            door_admits,
            "{comps:?}: the door's length test and M1's `parent` disagree"
        );
        assert_eq!(
            namespace_of(&addr).is_some(),
            door_admits,
            "{comps:?}: the fold's key derivation disagrees with the door"
        );
    }
}

/// AUTH-6.37's optional accessor: [`M3State::effective_owner_pair`] is ω
/// UNPROJECTED — the two projections' answers, as ONE entry, at every
/// probe — and its `None` is theirs. The probes are the read's own cells:
/// a seat answers ITSELF (`prefix == a`; these seats are folded without
/// their allocations, so this pins ω's walk, and the account-tier
/// equivalence of seat and allocation is
/// `an_account_is_allocated_iff_a_principal_is_seated_at_it`'s); an
/// unallocated first child `inc(X, 1)` answers the seat ABOVE it, never
/// none under the node; a sub-account outranks its parent by length; and
/// an address no registered prefix contains has neither half.
#[test]
fn the_pair_accessor_is_omega_unprojected() {
    let (x, x_id) = (a(&[1, 0, 1]), PrincipalId(7));
    let (sub, sub_id) = (a(&[1, 0, 1, 2]), PrincipalId(9));
    let s = M3State::genesis()
        .apply_m3(&M3Rec::RegisterPrincipal { prefix: x.clone(), id: x_id })
        .apply_m3(&M3Rec::RegisterPrincipal { prefix: sub.clone(), id: sub_id });

    let node = a(&[1]);
    for (probe, expect) in [
        // A seat of its own: the prefix IS the address asked.
        (x.clone(), Some((&x, x_id))),
        (sub.clone(), Some((&sub, sub_id))),
        (node.clone(), Some((&node, BOOTSTRAP_PRINCIPAL))),
        // Unallocated `inc(X, 1)`: X's own seat, the nearest above it.
        (a(&[1, 0, 1, 1]), Some((&x, x_id))),
        // Beneath a sub-account: the LONGEST containing prefix wins.
        (a(&[1, 0, 1, 2, 0, 4]), Some((&sub, sub_id))),
        // A document of X's, and an unregistered sibling account under
        // the node alone.
        (a(&[1, 0, 1, 0, 3]), Some((&x, x_id))),
        (a(&[1, 0, 2]), Some((&node, BOOTSTRAP_PRINCIPAL))),
        // Under no registered prefix: both halves absent, TOGETHER.
        (a(&[2]), None),
        (a(&[2, 0, 7]), None),
    ] {
        let pair = s.effective_owner_pair(&probe);
        assert_eq!(pair, expect, "ω's pair at {probe:?}");
        assert_eq!(
            pair.map(|(prefix, _)| prefix),
            s.effective_owner_prefix(&probe),
            "the pair's prefix is the prefix projection at {probe:?}"
        );
        assert_eq!(
            pair.map(|(_, id)| id),
            s.effective_owner(&probe),
            "the pair's principal is the id projection at {probe:?}"
        );
    }
}
