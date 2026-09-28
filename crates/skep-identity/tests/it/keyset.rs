//! The key-set semantics (AUTH-1.30–1.31; I3, I4 and I9's conformance arms):
//! what a `KeySet` answers — membership NOW and the anchor flag, both maps in
//! FINGERPRINT ORDER, and the keyed rows in address order (AUTH-2.59) — and
//! what each post leaves in it: the holder enrollment's filter (AUTH-2.69),
//! the order an effect carries its entries in (AUTH-2.52), a retirement's move
//! with its flag (AUTH-2.74), and the records that change nothing or would
//! empty the set. The fold's refusal order is `fold.rs`'s, these sets'
//! checkpoint bytes `checkpoint.rs`'s.

use crate::common;

use std::collections::BTreeMap;

use common::*;
use skep_identity::{Effect, Enrolled, IdentityState};

/// AUTH-1.31 — `contains` and `is_anchor` report membership NOW and the flag
/// the key entered under; a seeded account's set is non-empty.
#[test]
fn enrolled_reads_report_membership_and_the_anchor_flag() {
    let mut fx = Fixture::new();
    let st = seeded(&mut fx);
    let set = st.key_set(&addr(ACCT_A));
    assert!(!set.is_empty());
    assert!(set.contains(&fp(1)) && set.is_anchor(&fp(1)));
    assert!(set.contains(&fp(2)) && !set.is_anchor(&fp(2)));
}

/// AUTH-1.31 — `enrolled()` answers FINGERPRINT ORDER — ascending by the
/// digest bytes, `Fingerprint`'s card — not the order the record listed the
/// keys in (the ordering the realm genesis-set framing reuses, AUTH-2.119).
/// The expectation is computed from the BYTES, never from `Fingerprint`'s own
/// `Ord`, so a representation whose derived order is not byte order goes red
/// here instead of agreeing with itself; eight keys, listed in DESCENDING byte
/// order, so a set iterating in record order answers the exact reverse.
#[test]
fn enrolled_iterates_in_fingerprint_order_not_record_order() {
    let mut fx = Fixture::new();
    let mut ascending: Vec<u8> = (1..=8).collect();
    ascending.sort_by_key(|&i| *fp(i).as_bytes());
    let record: Vec<(u8, bool)> = ascending.iter().rev().map(|&i| (i, false)).collect();
    let st = seed_own(&mut fx, &IdentityState::genesis(), ACCT_A, &record);

    let got: Vec<_> = st
        .key_set(&addr(ACCT_A))
        .enrolled()
        .map(|(f, _)| *f)
        .collect();
    let want: Vec<_> = ascending.iter().map(|&i| fp(i)).collect();
    assert_eq!(got, want);
}

/// AUTH-1.31 — `retired()` answers FINGERPRINT ORDER, whatever order the
/// retirement record named the fingerprints in; the expectation computed from
/// the bytes, as above.
#[test]
fn retired_iterates_in_fingerprint_order() {
    let mut fx = Fixture::new();
    let mut ascending: Vec<u8> = (1..=8).collect();
    ascending.sort_by_key(|&i| *fp(i).as_bytes());
    // A ninth key stays enrolled, so retiring these eight is not
    // `would_empty` (I3).
    let seeding: Vec<(u8, bool)> = (1..=9).map(|i| (i, false)).collect();
    let st = seed_own(&mut fx, &IdentityState::genesis(), ACCT_A, &seeding);
    let named: Vec<u8> = ascending.iter().rev().copied().collect();
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&named));
    let (st, v) = fx.step(&st, &dep);
    assert_honored(&v);

    let got: Vec<_> = st
        .key_set(&addr(ACCT_A))
        .retired()
        .map(|(f, _)| *f)
        .collect();
    let want: Vec<_> = ascending.iter().map(|&i| fp(i)).collect();
    assert_eq!(got, want);
}

/// AUTH-2.59 — `keyed_accounts()` answers ADDRESS order, not the order the
/// accounts were seeded in: the enumeration the spec builds `/dump`'s identity
/// section from, a section no dump renders as built.
#[test]
fn keyed_accounts_iterates_in_address_order() {
    let mut fx = Fixture::new();
    let st = IdentityState::genesis();
    // Seeded high address first, so insertion order is the reverse of the
    // claim.
    let st = seed_own(&mut fx, &st, ACCT_B, &[(8, true)]);
    let st = seed_own(&mut fx, &st, ACCT_A, &[(7, true)]);
    let st = seed_own(&mut fx, &st, CLAIMANT, &[(9, true)]);

    let got: Vec<_> = st.keyed_accounts().map(|(a, _)| a.clone()).collect();
    let mut want = vec![addr(ACCT_B), addr(ACCT_A), addr(CLAIMANT)];
    want.sort();
    assert_eq!(got, want);
}

/// I9's conformance arm (AUTH-2.104) — re-listing an enrolled non-anchor key
/// under the `anchor` flag answers `nothing_changed` and the flag stays
/// `false`: a fingerprint's flag is fixed by the record that FIRST enrolls
/// it, for the fingerprint's lifetime.
#[test]
fn re_listing_an_enrolled_key_under_the_anchor_flag_changes_nothing() {
    let mut fx = Fixture::new();
    let st = seeded(&mut fx);
    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &enroll_payload(&[(2, true)]));
    let (next, v) = fx.step(&st, &dep);
    assert_detail(&v, "nothing_changed");
    assert_eq!(next, st);
    assert!(!next.key_set(&addr(ACCT_A)).is_anchor(&fp(2)));
}

/// AUTH-2.69 — the holder post: `added` is exactly the entries whose
/// fingerprints are neither ENROLLED nor RETIRED, whatever flag the entry
/// carries (I4 AUTH-2.98, I9 AUTH-2.104), and the filtered entries do NOT ride
/// in on the new key's coat-tails.
/// `re_listing_an_enrolled_key_under_the_anchor_flag_changes_nothing` and
/// `a_retired_fingerprint_never_re_enrolls` pin records where EVERY entry is
/// filtered out — which an `added` computed as "all the entries, if any entry
/// is new" also satisfies; this mixed record is what tells them apart.
/// `an_effect_carries_its_entries_in_record_order` states the ORDER `added`
/// carries; this one states which entries reach it at all.
#[test]
fn a_holder_enrollment_adds_only_the_entries_that_are_neither_enrolled_nor_retired() {
    let mut fx = Fixture::new();
    // enrolled = {fp(1): anchor}, retired = {fp(2): non-anchor}.
    let st = seeded_then_retired(&mut fx);
    // Entry 1 re-lists the ENROLLED key under the OPPOSITE flag; entry 2 the
    // RETIRED one; entry 3 is new, and an anchor.
    let dep = fx.enroll_dep(
        &doc1(ACCT_A),
        ACCT_A,
        &enroll_payload(&[(1, false), (2, true), (3, true)]),
    );
    let (next, v) = fx.step(&st, &dep);
    match assert_honored(&v) {
        Effect::Enroll { account, added } => {
            assert_eq!(*account, addr(ACCT_A));
            assert_eq!(
                *added,
                vec![Enrolled {
                    key: key(3),
                    anchor: true
                }],
                "only the new entry is added, with the flag that entry carries"
            );
        }
        other => panic!("expected an enroll effect, got {other:?}"),
    }
    let set = next.key_set(&addr(ACCT_A));
    assert!(set.contains(&fp(3)), "the new key is enrolled");
    assert!(set.is_anchor(&fp(3)), "under the flag its entry carried");
    assert!(
        set.is_anchor(&fp(1)),
        "I9: the re-listed key keeps its FIRST flag"
    );
    assert!(
        !set.contains(&fp(2)),
        "I4: the retired key does not re-enter"
    );
}

/// AUTH-2.52 — `Effect`'s POSTCONDITION: `keys`, `added` and `removed` are in
/// the RECORD's own ENTRY ORDER, and the two filtered arms carry the
/// SUBSEQUENCE of it their filter admits. Every record below lists its entries
/// in DESCENDING fingerprint order — the order the crate answers everywhere
/// else (`enrolled()`, `retired()`, the duplicate scan's ordered set), and the
/// one a second implementation reaches for first — so an effect collected in
/// fingerprint order answers the exact REVERSE of each claim here, and one
/// collected as "every entry" fails the two subsequence rows.
///
/// The order is promised because the effect is READ: skepd's key-decodability
/// courtesy walks a bounded PREFIX of `keys`/`added`, so which refusal token an
/// over-cap record earns depends on it, and `classify` is a mirror's ORACLE
/// (AUTH-2.57) whose answers are compared under `Effect`'s `PartialEq`. The
/// corpus's other `Effect::Enroll` and `Effect::Retire` assertions carry ONE
/// entry each, which no order can tell apart.
#[test]
fn an_effect_carries_its_entries_in_record_order() {
    let mut fx = Fixture::new();
    let row = |i: u8, anchor: bool| Enrolled { key: key(i), anchor };
    // Descending fingerprint order: the reverse of every other read's answer.
    let descending = |indices: &[u8]| -> Vec<u8> {
        let mut v = indices.to_vec();
        v.sort_by_key(|&i| fp(i));
        v.reverse();
        v
    };

    // GENESIS — EVERY entry, in record order, each under its own flag.
    let seeding: Vec<(u8, bool)> = descending(&[1, 2, 3, 4])
        .into_iter()
        .map(|i| (i, i % 2 == 0))
        .collect();
    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &enroll_payload(&seeding));
    let (st, v) = fx.step(&IdentityState::genesis(), &dep);
    match assert_honored(&v) {
        Effect::Genesis { keys, .. } => assert_eq!(
            *keys,
            seeding.iter().map(|&(i, a)| row(i, a)).collect::<Vec<_>>(),
            "genesis keys are every entry, in record order"
        ),
        other => panic!("expected a genesis effect, got {other:?}"),
    }

    // ENROLL — the SUBSEQUENCE the filter admits: an already-enrolled key sits
    // in the MIDDLE, so `added` is a proper subsequence of the record.
    let fresh = descending(&[5, 6, 7]);
    let listed = vec![
        (fresh[0], false),
        (1, true), // enrolled already (I4, I9): filtered out
        (fresh[1], false),
        (fresh[2], false),
    ];
    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &enroll_payload(&listed));
    let (st, v) = fx.step(&st, &dep);
    match assert_honored(&v) {
        Effect::Enroll { added, .. } => assert_eq!(
            *added,
            fresh.iter().map(|&i| row(i, false)).collect::<Vec<_>>(),
            "added is the record's order, the filtered entry skipped"
        ),
        other => panic!("expected an enroll effect, got {other:?}"),
    }

    // RETIRE — the same over `F ∩ enrolled`: a fingerprint enrolled nowhere
    // sits in the middle, and four of the seven keys stay enrolled (I3).
    let retiring = descending(&[2, 3, 5]);
    let named = vec![retiring[0], 9, retiring[1], retiring[2]];
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&named));
    let (_, v) = fx.step(&st, &dep);
    match assert_honored(&v) {
        Effect::Retire { removed, .. } => assert_eq!(
            *removed,
            retiring.iter().map(|&i| fp(i)).collect::<Vec<_>>(),
            "removed is the record's order, the stranger skipped"
        ),
        other => panic!("expected a retire effect, got {other:?}"),
    }
}

/// AUTH-2.74 — an honored retirement names the removed fingerprints in its
/// effect, and the key leaves `enrolled` for `retired`.
#[test]
fn retiring_an_enrolled_key_names_it_in_the_effect_and_removes_it() {
    let mut fx = Fixture::new();
    let st = seeded(&mut fx);
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[2]));
    let (next, v) = fx.step(&st, &dep);
    match assert_honored(&v) {
        Effect::Retire { account, removed } => {
            assert_eq!(*account, addr(ACCT_A));
            assert_eq!(*removed, vec![fp(2)]);
        }
        other => panic!("expected a retire effect, got {other:?}"),
    }
    let set = next.key_set(&addr(ACCT_A));
    assert!(!set.contains(&fp(2)));
    assert!(!set.is_anchor(&fp(2)));
    assert_eq!(set.retired().count(), 1);
}

/// AUTH-1.31/AUTH-1.30 — `is_anchor` answers NOW and `retired()` the key's
/// lifetime, and the two disagree for exactly one key: a retired ANCHOR key.
/// `retiring_an_enrolled_key_names_it_in_the_effect_and_removes_it` reads
/// `is_anchor` of a key that was never an anchor, so an `is_anchor` that also
/// consulted the retired map passes it — and fails here.
#[test]
fn a_retired_anchor_key_is_no_longer_an_anchor() {
    let mut fx = Fixture::new();
    let st = seeded(&mut fx); // fp(1) anchor, fp(2) non-anchor
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[1]));
    let (st, v) = fx.step(&st, &dep);
    assert_honored(&v); // anchor-blind (AUTH-2.75): the only anchor may retire
    let set = st.key_set(&addr(ACCT_A));
    assert!(!set.contains(&fp(1)), "retired: no longer enrolled");
    assert!(!set.is_anchor(&fp(1)), "is_anchor answers NOW");
    assert_eq!(
        set.retired()
            .find(|(f, _)| **f == fp(1))
            .map(|(_, anchor)| anchor),
        Some(true),
        "the retired row still says it WAS an anchor"
    );
}

/// AUTH-1.30 — each retired row carries the flag its key was ENROLLED under,
/// both ways: an anchor key stays an anchor in the retired map, a non-anchor
/// key stays a non-anchor. The lifetime claim is what makes "was that an
/// ANCHOR key" a head read.
#[test]
fn retired_row_carries_the_flag_the_key_was_enrolled_under() {
    let mut fx = Fixture::new();
    let st = seed_own(
        &mut fx,
        &IdentityState::genesis(),
        ACCT_A,
        &[(1, true), (2, false), (3, false)],
    );
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[1, 2]));
    let (st, v) = fx.step(&st, &dep);
    assert_honored(&v);

    let set = st.key_set(&addr(ACCT_A));
    let flags: BTreeMap<_, _> = set.retired().collect();
    assert_eq!(
        flags.get(&fp(1)),
        Some(&true),
        "the anchor key's flag survives retirement"
    );
    assert_eq!(
        flags.get(&fp(2)),
        Some(&false),
        "the non-anchor key's flag survives retirement"
    );
}

/// AUTH-2.74 — retiring an already-retired fingerprint touches nothing:
/// `removed = F ∩ enrolled = ∅`, so the record is `nothing_changed`.
#[test]
fn retiring_an_already_retired_key_changes_nothing() {
    let mut fx = Fixture::new();
    let st = seeded_then_retired(&mut fx);
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[2]));
    let (next, v) = fx.step(&st, &dep);
    assert_detail(&v, "nothing_changed");
    assert_eq!(next, st);
}

/// I4 (AUTH-2.98) — a retired fingerprint never re-enters its account's set:
/// the re-enrollment entry is outside `added` whatever flag it carries.
#[test]
fn a_retired_fingerprint_never_re_enrolls() {
    let mut fx = Fixture::new();
    let st = seeded_then_retired(&mut fx);
    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &enroll_payload(&[(2, true)]));
    let (next, v) = fx.step(&st, &dep);
    assert_detail(&v, "nothing_changed");
    assert_eq!(next, st);
}

/// I3 (AUTH-2.97) — a retirement naming the WHOLE enrolled set is inert
/// whole: `would_empty`, so non-emptiness stays monotone.
#[test]
fn retiring_the_whole_enrolled_set_is_would_empty() {
    let mut fx = Fixture::new();
    let st = seeded_then_retired(&mut fx);
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[1]));
    let (next, v) = fx.step(&st, &dep);
    assert_detail(&v, "would_empty");
    assert_eq!(next, st);
}

/// I3 (AUTH-2.97) — the whole-set test is SET EQUALITY, never a size
/// coincidence: a retirement naming every enrolled fingerprint AND a
/// fingerprint that is enrolled nowhere is still `would_empty`. `removed` is
/// `F ∩ enrolled` (AUTH-2.74), so the stranger is filtered out and the two
/// sizes agree. A `removed` that carried the stranger — or a `WouldEmpty`
/// test read off the RECORD's length — honors this record, empties the
/// account's set, and voids I3 and AUTH-1.36. Every other retirement vector
/// names only fingerprints the account has held, so this is the one that
/// tells the intersection from the record.
#[test]
fn retiring_the_whole_set_plus_a_stranger_is_still_would_empty() {
    let mut fx = Fixture::new();
    // enrolled = {fp(1), fp(2)}; key 5 is enrolled nowhere on this board.
    let st = seeded(&mut fx);
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[1, 2, 5]));
    let (next, v) = fx.step(&st, &dep);
    assert_detail(&v, "would_empty");
    assert_eq!(next, st);
    assert!(
        !next.key_set(&addr(ACCT_A)).is_empty(),
        "I3: an account's set never re-empties"
    );
}
