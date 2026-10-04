use skep_identity::Fingerprint;

use super::*;
use crate::parse_address;

fn a(s: &str) -> Address {
    parse_address(s).unwrap()
}

fn signed() -> Verdict {
    Verdict::Signed(Fingerprint::parse_hex(&"ab".repeat(32)).unwrap())
}

fn binding(at: u64, link: &str, prefix: &str, account: Option<&str>, replaces: Option<&str>) -> Judged<BindingRecord> {
    Judged {
        position: at,
        link: a(link),
        home: a("1.0.1.0.1"),
        record: BindingRecord {
            prefix: a(prefix),
            account: account.map(a),
            replaces: replaces.map(a),
            honored: false,
        },
        verdict: signed(),
    }
}

fn endpoint(at: u64, link: &str, home: &str, replaces: Option<&str>) -> Judged<EndpointRecord> {
    Judged {
        position: at,
        link: a(link),
        home: a(home),
        record: EndpointRecord { origins: vec![format!("https://{at}.example")], replaces: replaces.map(a), honored: false, nullified: false },
        verdict: signed(),
    }
}

/// THE REPLAY MATRIX at the binding walk (REG-2.9, REG-2.10, REG-2.24):
/// the allocation; a double allocation inert; a same-account binding
/// naming a stale state inert; the restoration naming the current state
/// honored; a retirement honored; a first binding carrying `replaces`
/// inert; a retraction clearing nothing; and a prefix whose one binding
/// is inert, with no standing, the parent of no depth address
/// (REG-3.82).
#[test]
fn the_binding_walk_honors_by_the_replay_clause() {
    let mut ledger = Ledger::default();
    let l = |n: u32| format!("1.0.1.0.1.0.2.{n}");
    assert!(ledger.fold_binding(binding(10, &l(1), "1.5", Some("1.0.2"), None)), "the allocation");
    assert!(!ledger.fold_binding(binding(11, &l(2), "1.5", Some("1.0.3"), None)), "a double allocation is inert");
    assert!(!ledger.fold_binding(binding(12, &l(3), "1.5", Some("1.0.3"), Some(&l(1)))), "a different account is inert even naming the current state");
    assert!(!ledger.fold_binding(binding(13, &l(4), "1.5", Some("1.0.2"), Some(&l(2)))), "a stale state is inert");
    assert!(ledger.fold_binding(binding(14, &l(5), "1.5", Some("1.0.2"), Some(&l(1)))), "the restoration naming the current state is honored");
    assert!(!ledger.fold_binding(binding(15, &l(6), "1.5", Some("1.0.2"), Some(&l(1)))), "the second record naming one predecessor is inert");
    assert!(ledger.fold_binding(binding(16, &l(7), "1.5", None, Some(&l(5)))), "a retirement naming the current state is honored");
    assert!(ledger.fold_binding(binding(17, &l(8), "1.5", Some("1.0.2"), Some(&l(7)))), "a restoration after the retirement");
    assert!(!ledger.fold_binding(binding(18, &l(9), "1.6", Some("1.0.4"), Some(&l(1)))), "a first binding naming a state is inert: the empty state is current");
    assert!(ledger.fold_binding(binding(19, &l(10), "1.6", Some("1.0.4"), None)));
    assert!(!ledger.fold_binding(binding(20, &l(11), "1.7", Some("1.0.5"), Some(&l(1)))), "1.7's one binding is inert");
    let s = ledger.standing(&a("1.5")).expect("bound");
    assert_eq!(s.current.link, a(&l(8)));
    assert_eq!(s.history.len(), 8);
    assert_eq!(s.history.iter().filter(|b| b.record.honored).count(), 4);
    assert!(!ledger.nullify(&a(&l(8))), "a retraction of a binding clears nothing");
    assert_eq!(ledger.standing(&a("1.5")).unwrap().current.link, a(&l(8)));
    assert_eq!(ledger.standing(&a("1.7")), None, "an inert binding alone is no standing");
    assert_eq!(ledger.standing(&a("1.8")), None);
    assert_eq!(ledger.parent_prefix(&a("1.5.3")), Some(a("1.5")));
    assert_eq!(ledger.parent_prefix(&a("1.5")), None, "a proper prefix alone");
    assert_eq!(ledger.parent_prefix(&a("1.7.1")), None, "a prefix with no standing is no parent");
    assert_eq!(ledger.parent_prefix(&a("1.8.1")), None);
    assert_eq!(ledger.counts().honored_bindings, 5);
}

/// THE REPLAY CLAUSE AS A LAW (REG-2.9, REG-2.10, REG-2.24), over every
/// sequence of one to four bindings at one prefix — each naming one of
/// two accounts or none, and replacing nothing, a link outside the
/// sequence, or any binding before it: an inert binding moves no state;
/// the prefix stands exactly where a binding was honored; the first
/// honored binding replaces nothing, each later one replaces the one
/// honored before it and names the first's account or none — so a held
/// prefix is never bound to another account, an inert binding written
/// before the allocation included; the history is every binding in
/// journal order, each marked as the walk took it; and a retraction of
/// any of them clears nothing.
#[test]
fn the_replay_clause_holds_over_every_short_sequence() {
    let p = a("1.5");
    let l = |i: usize| format!("1.0.1.0.1.0.2.{}", i + 1);
    let accounts = [Some("1.0.2"), Some("1.0.3"), None];
    // Binding i: an account, and the link it replaces, if any.
    type Sequence = Vec<(Option<&'static str>, Option<String>)>;
    let mut all: Vec<Sequence> = Vec::new();
    let mut shorter: Vec<Sequence> = vec![Vec::new()];
    for i in 0..4 {
        let replaced: Vec<Option<String>> =
            [None, Some("1.0.1.0.1.0.2.99".to_string())].into_iter().chain((0..i).map(|j| Some(l(j)))).collect();
        let mut longer = Vec::new();
        for seq in &shorter {
            for account in accounts {
                for replaces in &replaced {
                    let mut next = seq.clone();
                    next.push((account, replaces.clone()));
                    longer.push(next);
                }
            }
        }
        all.extend(longer.iter().cloned());
        shorter = longer;
    }
    assert_eq!(all.len(), 6 + 54 + 648 + 9_720, "every sequence of one to four");
    for seq in &all {
        let mut ledger = Ledger::default();
        let mut honored = Vec::new();
        for (i, (account, replaces)) in seq.iter().enumerate() {
            let before = ledger.standing(&p).map(|s| s.current);
            if ledger.fold_binding(binding(i as u64 + 1, &l(i), "1.5", *account, replaces.as_deref())) {
                honored.push(i);
            } else {
                assert_eq!(ledger.standing(&p).map(|s| s.current), before, "an inert binding moves no state: {seq:?} at {i}");
            }
        }
        let Some(standing) = ledger.standing(&p) else {
            assert!(honored.is_empty(), "a binding honored and no standing: {seq:?}");
            continue;
        };
        assert!(!honored.is_empty(), "a standing and no binding honored: {seq:?}");
        let allocated = seq[honored[0]].0;
        assert_eq!(seq[honored[0]].1, None, "the allocation replaces nothing: {seq:?}");
        for pair in honored.windows(2) {
            assert_eq!(seq[pair[1]].1, Some(l(pair[0])), "each replaces the one honored before it: {seq:?}");
        }
        for &h in &honored {
            assert!(seq[h].0.is_none() || seq[h].0 == allocated, "bound to another account: {seq:?}");
        }
        assert_eq!(standing.current.link, a(&l(*honored.last().expect("one honored"))), "{seq:?}");
        let walked: Vec<(Address, bool)> = standing.history.iter().map(|b| (b.link.clone(), b.record.honored)).collect();
        let written: Vec<(Address, bool)> = (0..seq.len()).map(|i| (a(&l(i)), honored.contains(&i))).collect();
        assert_eq!(walked, written, "the history is every binding in journal order: {seq:?}");
        for i in 0..seq.len() {
            assert!(!ledger.nullify(&a(&l(i))), "a retraction of a binding clears nothing: {seq:?}");
        }
        assert_eq!(ledger.standing(&p), Some(standing), "{seq:?}");
    }
}

/// THE PARENT PREFIX (REG-3.82) is the LONGEST proper prefix with a
/// standing, compared by component and never by text.
#[test]
fn the_parent_prefix_is_the_longest_proper_prefix_with_a_standing() {
    let mut ledger = Ledger::default();
    assert!(ledger.fold_binding(binding(10, "1.0.1.0.1.0.2.1", "1.5.3", Some("1.0.3"), None)));
    assert!(ledger.fold_binding(binding(11, "1.0.1.0.1.0.2.2", "1.5", Some("1.0.2"), None)));
    assert_eq!(ledger.parent_prefix(&a("1.5.3.7")), Some(a("1.5.3")), "the longer of two");
    assert_eq!(ledger.parent_prefix(&a("1.5.4")), Some(a("1.5")));
    assert_eq!(ledger.parent_prefix(&a("1.55")), None, "a prefix by component, never by text");
}

/// THE ENDPOINT'S CURRENCY (REG-1.10, REG-1.11): the first deposit, a
/// second naming it current, a third naming the first inert, the
/// nullified second leaving the view and the first standing, and the
/// org's next deposit naming the nullified one honored.
#[test]
fn the_current_endpoint_is_the_latest_honored_deposit_on_the_active_view() {
    let mut ledger = Ledger::default();
    let home = "1.0.2.0.1";
    let l = |n: u32| format!("1.0.2.0.1.0.2.{n}");
    assert!(ledger.fold_endpoint(endpoint(20, &l(1), home, None)));
    assert!(ledger.fold_endpoint(endpoint(21, &l(2), home, Some(&l(1)))));
    assert!(!ledger.fold_endpoint(endpoint(22, &l(3), home, Some(&l(1)))), "a stale state is inert");
    assert!(!ledger.fold_endpoint(endpoint(23, &l(4), home, None)), "a first-form deposit where one has stood is inert");
    assert_eq!(ledger.current_endpoint(&a(home)).map(|d| d.position), Some(21));
    assert!(ledger.nullify(&a(&l(2))), "the org's own nullify is effective");
    assert_eq!(ledger.current_endpoint(&a(home)).map(|d| d.position), Some(20), "the one before it stands");
    assert!(ledger.fold_endpoint(endpoint(24, &l(5), home, Some(&l(2)))), "the next deposit names the nullified one");
    assert_eq!(ledger.current_endpoint(&a(home)).map(|d| d.position), Some(24));
    assert!(ledger.nullify(&a(&l(5))) && ledger.nullify(&a(&l(1))));
    assert_eq!(ledger.current_endpoint(&a(home)), None, "every honored deposit nullified");
    assert!(ledger.any_honored_endpoint(&a(home)));
    assert!(!ledger.nullify(&a("1.0.9.0.1.0.2.1")), "a link the ledger does not hold");
    assert_eq!(ledger.counts().honored_endpoints, 3);
}

/// A DEPOSIT HANDED TWICE is retracted where it stood: its second fold is
/// inert beside the first, and the `nullify` takes the honored one off the
/// active view — never the inert copy, leaving the deposit standing.
#[test]
fn a_deposit_handed_twice_is_retracted_where_it_stood() {
    let mut ledger = Ledger::default();
    let (home, link) = ("1.0.2.0.1", "1.0.2.0.1.0.2.1");
    assert!(ledger.fold_endpoint(endpoint(20, link, home, None)));
    assert!(!ledger.fold_endpoint(endpoint(21, link, home, None)), "handed again: inert beside the first");
    assert!(ledger.nullify(&a(link)));
    assert_eq!(ledger.current_endpoint(&a(home)), None, "the deposit that stood is off the view");
}

/// THE INDEX is the ledger behind the gate: what the gate passes folds
/// by the ledger's rule, and what it keeps out is read back in journal
/// order and counted by cause beside the ledger's counts — each verdict
/// but SIGNED counted as itself, never as another.
#[test]
fn the_index_counts_what_the_gate_kept_out_beside_the_ledger() {
    let mut index = Index::default();
    assert!(index.fold_binding(binding(10, "1.0.1.0.1.0.2.1", "1.5", Some("1.0.2"), None)));
    let out = |at: u64, cause| Suppressed { position: at, link: a(&format!("1.0.1.0.1.0.2.{at}")), kind: BodyKind::Binding, cause };
    index.suppress(out(11, Cause::Verdict(Verdict::Unsigned)));
    index.suppress(out(12, Cause::Verdict(Verdict::UndeterminableHere)));
    index.suppress(out(13, Cause::Verdict(Verdict::Disavowed)));
    index.suppress(out(14, Cause::Verdict(Verdict::BeforeAttestation)));
    index.suppress(out(15, Cause::Malformed(skep_registry::Refusal::NotCanonical)));
    assert_eq!(index.suppressed().iter().map(|s| s.position).collect::<Vec<_>>(), [11, 12, 13, 14, 15]);
    let c = index.counts();
    assert_eq!((c.prefixes, c.bindings, c.honored_bindings), (1, 1, 1));
    assert_eq!((c.suppressed_unsigned, c.suppressed_undeterminable, c.suppressed_malformed), (1, 1, 1));
    assert_eq!((c.suppressed_disavowed, c.suppressed_before_attestation), (1, 1), "a verdict counted as itself");
    assert!(index.standing(&a("1.5")).is_some());
}
