use super::*;
use crate::key::{ALG_MLDSA65_ED25519, MLDSA65_KEY_LEN};
use skep_address::{validate, Nat, Tumbler};

fn addr(comps: &[u32]) -> Address {
    validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")).expect("T4-valid")
}

/// A tag-1 key whose Ed25519 half is the byte `i` throughout — a distinct
/// key per `i`, decoded by nothing here (AUTH-1.4).
fn key(i: u8) -> PublicKey {
    PublicKey::from_halves(ALG_MLDSA65_ED25519, &[0; MLDSA65_KEY_LEN], &[i; 32]).expect("the tag-1 row's widths")
}

fn admission(i: u8, anchor: bool, since: Option<u64>, until: Until) -> Admission {
    let key = key(i);
    Admission { fingerprint: Fingerprint::of(&key), key, anchor, label: None, since, until }
}

/// A table holding, per `(account, admissions)`, the admissions as given.
fn table(rows: &[(&[u32], Vec<Admission>)]) -> FilteredTable {
    let mut t = FilteredTable::new(None);
    for (account, admissions) in rows {
        t.tables.insert(addr(account), admissions.clone());
    }
    t
}

fn fingerprints(set: Option<Vec<Enrolled>>) -> Option<Vec<Fingerprint>> {
    set.map(|set| set.iter().map(|e| Fingerprint::of(&e.key)).collect())
}

/// The doc-1 arithmetic the home pin compares against (AUTH-2.126,
/// AUTH-2.127): `A·0·1`, at a nested account under its own prefix.
#[test]
fn the_home_pin_compares_against_the_accounts_first_document() {
    assert_eq!(doc_1(&addr(&[1, 0, 5])), Some(addr(&[1, 0, 5, 0, 1])));
    assert_eq!(doc_1(&addr(&[1, 0, 3, 2])), Some(addr(&[1, 0, 3, 2, 0, 1])));
}

/// AS OF A POSITION (the design record §4.5's clause (b); P12): an admission
/// is in the set at a position past its own and at the position of the
/// record that retires it — a rotation's retire-old is signed by the key it
/// retires — and out of it one past; a position-free admission is in at
/// every position, a position-free retirement out at every one.
#[test]
fn an_admission_stands_from_past_its_record_through_the_record_that_retires_it() {
    let t = table(&[(
        &[1, 0, 5],
        vec![
            admission(1, true, Some(4), Until::Enrolled),
            admission(2, false, Some(4), Until::RetiredAt(9)),
            admission(3, false, None, Until::Enrolled),
            admission(4, false, None, Until::RetiredPositionFree),
        ],
    )]);
    let account = addr(&[1, 0, 5]);
    let at = |position: u64| -> Vec<u8> {
        t.as_of(&account, position).map(|a| a.key.ed25519_half()[0]).collect()
    };
    assert_eq!(at(4), [3], "at its own position a record's keys are not yet in");
    assert_eq!(at(5), [1, 2, 3]);
    assert_eq!(at(9), [1, 2, 3], "in at the position of the record that retires it");
    assert_eq!(at(10), [1, 3]);
    let now: Vec<u8> = t.current(&account).map(|a| a.key.ed25519_half()[0]).collect();
    assert_eq!(now, [1, 3]);
}

/// THE WALK (AUTH-4.30 (i)): an account's own set where it holds a key,
/// whatever the account above holds; where it is empty, the nearest keyed
/// account above it; the empty set itself where the walk reaches the node;
/// and `None` — never an empty set, never the account above — where a
/// table on the walk is undeterminable at the position asked, which a gap
/// at the position itself is not.
#[test]
fn the_walk_opens_an_empty_account_through_the_account_above_and_stops_at_a_gap() {
    let mut t = table(&[
        (&[1, 0, 2], vec![admission(2, true, Some(1), Until::Enrolled)]),
        (&[1, 0, 8], vec![admission(8, true, Some(1), Until::Enrolled)]),
        (&[1, 0, 8, 1], vec![admission(9, false, Some(2), Until::Enrolled)]),
    ]);
    let fp = |i: u8| Fingerprint::of(&key(i));
    assert_eq!(fingerprints(t.opening_now(&addr(&[1, 0, 2, 3]))), Some(vec![fp(2)]), "empty: the account above");
    assert_eq!(fingerprints(t.opening_now(&addr(&[1, 0, 8, 1]))), Some(vec![fp(9)]), "its own keys");
    assert_eq!(fingerprints(t.opening_now(&addr(&[1, 0, 7]))), Some(vec![]), "the node: the empty set itself");
    assert_eq!(fingerprints(t.opening_at(&addr(&[1, 0, 8, 1]), 2)), Some(vec![fp(8)]), "as of 2 its own set is empty");
    t.missing(&addr(&[1, 0, 2, 3]), 6);
    assert_eq!(t.opening_now(&addr(&[1, 0, 2, 3])), None, "a gap on the account itself");
    assert_eq!(fingerprints(t.opening_at(&addr(&[1, 0, 2, 3]), 6)), Some(vec![fp(2)]), "determinable as of the gap's own position");
    assert_eq!(t.opening_at(&addr(&[1, 0, 2, 3]), 7), None, "and not past it");
    t.missing(&addr(&[1, 0, 6]), 3);
    assert_eq!(t.opening_now(&addr(&[1, 0, 6, 1])), None, "a gap on the account above an empty one");
    t.missing(&addr(&[1, 0, 6]), 1);
    assert_eq!(t.missing.get(&addr(&[1, 0, 6])), Some(&1), "the earliest gap stands");
}

/// THE GENESIS REGISTRY by address arithmetic (AUTH-2.62): the parent
/// account for an account beneath one; none for the first child of a
/// bootstrap-tier account, the agent space (RES-80, AUTH-5.87); and, for a
/// bootstrap-tier account, the claimant from the claim's position on and
/// the account's own space before it, or with no claim held.
#[test]
fn the_genesis_registry_is_the_parent_the_claimant_or_the_accounts_own_space() {
    /// An enrollment of `subject` at `position`, every other member a stand-in.
    fn record<'a>(home: &'a Address, subject: &'a Address, position: Option<u64>) -> CredentialRecord<'a> {
        CredentialRecord {
            kind: RecordKind::Enroll,
            link: home,
            home,
            home_account: home,
            subject,
            ty: home,
            sigless: b"{}",
            sig: None,
            enrolled: &[],
            retired: &[],
            position,
        }
    }
    let home = addr(&[1, 0, 1, 0, 1]);
    let claimed = FilteredTable::new(Some((2, addr(&[1, 0, 1]))));
    let unclaimed = FilteredTable::new(None);
    let registry = |t: &FilteredTable, subject: &[u32], position: Option<u64>| t.genesis_registry(&record(&home, &addr(subject), position));
    assert_eq!(registry(&claimed, &[1, 0, 3, 2], Some(9)), Some(addr(&[1, 0, 3])), "the parent account");
    assert_eq!(registry(&claimed, &[1, 0, 3, 1], Some(9)), None, "a bootstrap-tier account's agent space");
    assert_eq!(registry(&claimed, &[1, 0, 3, 2, 1], Some(9)), Some(addr(&[1, 0, 3, 2])), "a nested account's first child is its own");
    assert_eq!(registry(&claimed, &[1, 0, 3, 2, 1, 4], Some(9)), Some(addr(&[1, 0, 3, 2, 1])));
    assert_eq!(registry(&claimed, &[1, 0, 5], Some(9)), Some(addr(&[1, 0, 1])), "the claimant above the claim");
    assert_eq!(registry(&claimed, &[1, 0, 5], Some(2)), Some(addr(&[1, 0, 5])), "its own space at the claim");
    assert_eq!(registry(&claimed, &[1, 0, 5], None), Some(addr(&[1, 0, 1])), "position-free: the claimant");
    assert_eq!(registry(&unclaimed, &[1, 0, 5], Some(9)), Some(addr(&[1, 0, 5])), "no claim held: its own space");
}

/// AUTH-3.21's GRADE off these tables: a top-level account's genesis enters
/// no cone (device grade); a handoff is anchor-grade iff the giver's set
/// holds an anchor; a hire — a child of the giver's agent space — and a
/// spawn — the giver itself an agent — are device-grade whatever the sets
/// above hold; and a gap on the way is no grade at all.
#[test]
fn the_genesis_grade_reads_the_givers_table_and_the_two_device_grade_cones() {
    let mut t = table(&[
        (&[1, 0, 3], vec![admission(1, true, Some(1), Until::Enrolled)]),
        (&[1, 0, 3, 1, 7], vec![admission(2, true, Some(3), Until::Enrolled)]),
        (&[1, 0, 4], vec![admission(3, false, Some(1), Until::Enrolled)]),
    ]);
    let grade = |t: &FilteredTable, subject: &[u32]| t.genesis_grade(&addr(subject)).ok();
    assert_eq!(grade(&t, &[1, 0, 9]), Some(false), "a top-level account's genesis");
    assert_eq!(grade(&t, &[1, 0, 3, 2]), Some(true), "a handoff from a giver holding an anchor");
    assert_eq!(grade(&t, &[1, 0, 4, 2]), Some(false), "a handoff from a giver holding none");
    assert_eq!(grade(&t, &[1, 0, 3, 1, 5]), Some(false), "a hire beneath the giver's agent space");
    assert_eq!(grade(&t, &[1, 0, 3, 1, 7, 2]), Some(false), "a spawn beneath an agent");
    t.missing(&addr(&[1, 0, 3, 2]), 5);
    assert_eq!(grade(&t, &[1, 0, 3, 2, 4]), None, "a gap on the way up");
}
