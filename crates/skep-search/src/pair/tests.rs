use super::*;
use crate::header::{ChainAt, Grant, GrantKind};
use crate::hit::Rung;
use crate::unit::{Class, Item, UnitKey};
use crate::Chain;
use skep_address::{validate, Address, Nat, Tumbler};

fn addr(comps: &[u32]) -> Address {
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
    validate(t).expect("a T4-valid address")
}

fn unit(class: Class, kind: Kind, doc: &[u32]) -> Unit {
    Unit::new(
        UnitKey::new(addr(doc)),
        None,
        kind,
        class,
        1,
        vec![Item::Text { start: 1, bytes: b"words".to_vec() }],
    )
    .expect("one extent")
}

fn range(under: Option<&[u32]>, grant: Option<(GrantKind, &[u32])>) -> RangeRecord {
    RangeRecord {
        under: under.map(addr),
        held: ChainAt { position: 1, chain: Chain::from_bytes([0; 32]) },
        refusals: Vec::new(),
        bare_rows: 0,
        grant: grant.map(|(kind, issuer)| Grant { kind, issuer: addr(issuer) }),
    }
}

/// §3.2 `QueryOpts { limit (default 50), offset }`.
#[test]
fn the_default_opts_list_fifty_rows_from_the_start() {
    assert_eq!(QueryOpts::default(), QueryOpts { offset: 0, limit: 50 });
    assert_eq!(DEFAULT_LIMIT, 50);
}

/// §1.4, §5.2 the pair by role: the guest form holds the published index
/// alone; a session's holds both, in role order.
#[test]
fn the_pair_is_passed_by_role() {
    let published = Index::new(Class::Guest);
    let supplement = Index::new(Class::Principal(3));
    let guest = Pair::guest(&published);
    assert!(guest.supplement.is_none() && guest.ranges.is_empty() && guest.honored.is_empty());
    assert_eq!(guest.indexes().count(), 1);
    let ranges = [range(Some(&[1, 0, 3]), None)];
    let session = Pair::session(&published, &supplement, &ranges, &[]);
    assert_eq!(
        session.indexes().map(Index::class).collect::<Vec<_>>(),
        [Class::Guest, Class::Principal(3)]
    );
    assert_eq!(session.ranges.len(), 1);
}

/// §3.1 STANDING from the member of the pair: the published member's edition
/// is `Public`; a draft is never `Public`.
#[test]
fn a_published_edition_is_public_and_a_draft_never_is() {
    let published = Index::new(Class::Guest);
    let pair = Pair::guest(&published);
    assert_eq!(
        pair.standing(Role::Published, &unit(Class::Guest, Kind::Edition, &[1, 0, 1, 0, 1])),
        Standing::Public
    );
    assert_eq!(
        pair.standing(Role::Published, &unit(Class::Guest, Kind::Draft, &[1, 0, 1, 0, 1])),
        Standing::YoursToRead
    );
    assert_eq!(
        pair.standing(Role::Supplement, &unit(Class::Principal(3), Kind::Draft, &[1, 0, 1, 0, 1])),
        Standing::YoursToRead,
        "no range covers it: not held"
    );
}

/// §3.1 `Held` by prefix arithmetic over the pair's inputs: a draft under a
/// granted range the honored set no longer admits is `Held` with the grant's
/// kind and issuer and the range's own rung; under the subtree's range —
/// the principal's own or an ancestor's, which carries no grant — it is
/// `YoursToRead`; so is one a second honored grant covers; of several
/// departed grants the narrowest prefix's cell is carried.
#[test]
fn held_is_composed_from_the_departed_ranges_record_and_never_under_an_admitting_prefix() {
    let published = Index::new(Class::Guest);
    let supplement = Index::new(Class::Principal(3));
    let draft = |doc: &[u32]| unit(Class::Principal(3), Kind::Draft, doc);
    let issuer_a = [1, 0, 2];
    let issuer_b = [1, 0, 4];
    let ranges = [
        range(Some(&[1, 0, 3]), None), // the principal's own subtree
        range(Some(&[1, 0, 2, 0, 4]), Some((GrantKind::Named, &issuer_a))), // a document grant, departed
        range(Some(&[1, 0, 4]), Some((GrantKind::AnyPrincipal, &issuer_b))), // an account grant, departed
        range(Some(&[1, 0, 4, 0, 7]), Some((GrantKind::Named, &issuer_a))), // a narrower document grant under it, departed
        range(Some(&[1, 0, 5]), Some((GrantKind::Named, &issuer_b))), // an account grant, still honored
    ];
    let honored = [Prefix::new(addr(&[1, 0, 5]))];
    let pair = Pair::session(&published, &supplement, &ranges, &honored);
    let standing = |doc: &[u32]| pair.standing(Role::Supplement, &draft(doc));

    assert_eq!(standing(&[1, 0, 3, 0, 1]), Standing::YoursToRead, "the principal's own draft");
    assert_eq!(
        standing(&[1, 0, 2, 0, 4]),
        Standing::Held { kind: GrantKind::Named, rung: Rung::Document, issuer: addr(&issuer_a) },
        "the departed document grant's cell and issuer"
    );
    assert_eq!(
        standing(&[1, 0, 4, 0, 2]),
        Standing::Held {
            kind: GrantKind::AnyPrincipal,
            rung: Rung::Account,
            issuer: addr(&issuer_b)
        },
        "the departed account grant's cell"
    );
    assert_eq!(
        standing(&[1, 0, 4, 0, 7]),
        Standing::Held { kind: GrantKind::Named, rung: Rung::Document, issuer: addr(&issuer_a) },
        "of several departed grants the narrowest prefix's"
    );
    assert_eq!(standing(&[1, 0, 5, 0, 1]), Standing::YoursToRead, "an honored grant admits it");
    assert_eq!(standing(&[1, 0, 9, 0, 1]), Standing::YoursToRead, "no range covers it");

    // A second honored grant covering a departed range's document admits it.
    let honored_too = [Prefix::new(addr(&[1, 0, 5])), Prefix::new(addr(&[1, 0, 2, 0, 4]))];
    let pair = Pair::session(&published, &supplement, &ranges, &honored_too);
    assert_eq!(pair.standing(Role::Supplement, &draft(&[1, 0, 2, 0, 4])), Standing::YoursToRead);

    // An ancestor's range, which carries no grant, admits a draft under it
    // whatever departed grant covers it too.
    let with_ancestor = [
        range(Some(&[1, 0, 4]), None),
        range(Some(&[1, 0, 4, 0, 7]), Some((GrantKind::Named, &issuer_a))),
    ];
    let pair = Pair::session(&published, &supplement, &with_ancestor, &[]);
    assert_eq!(pair.standing(Role::Supplement, &draft(&[1, 0, 4, 0, 7])), Standing::YoursToRead);
}
