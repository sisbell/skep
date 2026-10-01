//! The publication bit (owner rulings D1/D2, 2026-09-05; PUB-7.8, PUB-7.10,
//! PUB-8.18, PUB-8.21): resolved by the op that creates, stamped verbatim by
//! the mint, written once, enumerated in address order, and recovered by
//! checkpoint and replay.

use crate::common::*;

use serde::Serialize;
use skep_address::{Address, Tumbler};
use skep_kernel::Kernel;
use skep_namespace::{
    first_document_address, ghost_home_document, head_document, HasM3, M3Rec, M3State, Namespace,
    PrincipalId, BOOTSTRAP_PRINCIPAL, SYSTEM_PRINCIPAL,
};
use tempfile::tempdir;

/// Create a document through the op and read its bit back off the committed
/// slice — the observable of the CREATE path's resolution, since the bit the
/// op resolved is the bit the record journals and the fold writes, and
/// nothing else ever writes one.
fn create_and_read(
    ns: &Namespace<'_, World>,
    k: &Kernel<World>,
    caller: PrincipalId,
    acct: &Address,
    flag: Option<bool>,
) -> (Address, bool) {
    let (d, _) = ns
        .create_new_document(caller, acct, flag)
        .expect("the owner creates a document");
    let published = k.snapshot().world().m3().published(&d);
    (d, published)
}

/// PUB-8.21, the create-path default, resolved by `create_new_document` and
/// never by the mint: a FLAGLESS first mint into an empty account is honored
/// born PUBLISHED (PUB-1.17: the home) — the Allocate the mint stamps carries
/// `true`, the fold's map holds `true`, and `published` answers `true`.
#[test]
fn a_flagless_first_create_is_born_published() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("delegate");
    // The account is empty: the slot its chain opens at holds nothing.
    let slot = first_document_address(&acct).expect("an account anchors a document chain");
    let before_create = k.snapshot().world().m3().clone();
    assert!(!before_create.is_registered_document(&slot));

    let (d1, published) = create_and_read(&ns, &k, ID1, &acct, None);
    assert_eq!(d1, slot);
    assert!(
        published,
        "the flagless first mint is doc 1, born published"
    );

    // The record half, pure, on the pre-create slice: the op resolved `true`
    // and the mint stamps exactly what it is handed, so the Allocate that
    // registered doc 1 carries `true` — whole value…
    let (addr, rec) = before_create
        .mint_document(&acct, true)
        .expect("the empty account mints");
    assert_eq!(addr, slot);
    assert_eq!(
        rec,
        M3Rec::Allocate {
            addr: slot.clone(),
            published: true,
        }
    );
    // …and folding that one record is the whole of what the op committed:
    // the map is written by the fold, in the same step as the registration.
    assert_eq!(before_create.apply_m3(&rec), *k.snapshot().world().m3());
    assert!(before_create.apply_m3(&rec).published(&slot));
}

/// PUB-8.21's other arm at the engine: an EXPLICIT `false` first mint is NOT
/// refused here — it mints PRIVATE, honored as sent. The refusal (PUB-8.20)
/// is the daemon's door (owner ruling D2c), and no `MintError` names it.
/// An explicit `true` on an empty account is `true`.
#[test]
fn an_explicit_first_create_flag_is_honored_as_sent_and_never_refused_here() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct1, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("delegate ID1");
    let (acct2, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 2]), ID2)
        .expect("delegate ID2");

    let (acct1_d1, published) = create_and_read(&ns, &k, ID1, &acct1, Some(false));
    assert_eq!(acct1_d1, first_document_address(&acct1).expect("slot"));
    assert!(
        !published,
        "an explicit false mints private — no refusal, no override"
    );
    assert!(k.snapshot().world().m3().is_registered_document(&acct1_d1));

    let (acct2_d1, published) = create_and_read(&ns, &k, ID2, &acct2, Some(true));
    assert_eq!(acct2_d1, first_document_address(&acct2).expect("slot"));
    assert!(published);
}

/// PUB-1.1 at the engine: once the account has a document, a flagless mint is
/// PRIVATE, and an explicit flag is honored as sent — `Some(true)` publishes,
/// `Some(false)` does not. Doc 1's own bit stands through all of it.
#[test]
fn a_create_into_a_non_empty_account_is_private_unless_flagged() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("delegate");
    let (d1, published) = create_and_read(&ns, &k, ID1, &acct, None);
    assert!(published);

    let (d2, published) = create_and_read(&ns, &k, ID1, &acct, None);
    assert_eq!(d2, a(&[1, 0, 1, 0, 2]));
    assert!(!published, "flagless into a non-empty account is private");
    let (d3, published) = create_and_read(&ns, &k, ID1, &acct, Some(true));
    assert_eq!(d3, a(&[1, 0, 1, 0, 3]));
    assert!(published);
    let (d4, published) = create_and_read(&ns, &k, ID1, &acct, Some(false));
    assert_eq!(d4, a(&[1, 0, 1, 0, 4]));
    assert!(!published);

    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.published(&d1), "doc 1's bit is untouched by later mints");
    assert!(!m3.published(&d2) && m3.published(&d3) && !m3.published(&d4));
}

/// PUB-8.18: `mint_version` stamps exactly the bit passed — the composite's
/// resolution, never the mint's. A version of a PRIVATE source passed
/// `false` reads `false`; the same source passed `true` reads `true`; the
/// source's own bit is untouched either way (a version is its own member —
/// projecting it to its document ahead of a gate, PUB-2.15, is the caller's).
#[test]
fn mint_version_stamps_exactly_the_bit_passed() {
    let (k, acct, _doc) = kernel_with_account_and_doc();
    let ns = Namespace::new(&k);
    // A PRIVATE source: the account's second document, flagless.
    let (src, published) = create_and_read(&ns, &k, ID1, &acct, None);
    assert!(!published);

    let v1 = commit_mint(&k, M3State::version_lock_key(&src), |m3| {
        m3.mint_version(&src, false)
    });
    let v2 = commit_mint(&k, M3State::version_lock_key(&src), |m3| {
        m3.mint_version(&src, true)
    });
    assert_eq!(v1, a(&[1, 0, 1, 0, 2, 1]));
    assert_eq!(v2, a(&[1, 0, 1, 0, 2, 2]));
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_registered_document(&v1) && m3.is_registered_document(&v2));
    assert!(!m3.published(&v1), "passed false, reads false");
    assert!(
        m3.published(&v2),
        "passed true, reads true — the composite's choice"
    );
    assert!(
        !m3.published(&src),
        "the source's own bit is not the version's"
    );

    // The record carries the bit verbatim, whole value, in both directions.
    for bit in [false, true] {
        let (next, rec) = m3.mint_version(&src, bit).expect("peek");
        assert_eq!(
            rec,
            M3Rec::Allocate {
                addr: next,
                published: bit,
            }
        );
    }
}

/// The RIDER on PUB-8.21: the empty-account default is the CREATE path's
/// alone. `mint_document` into an EMPTY account — the cross-owner `version`
/// path, which passes the bit its composite inherited from the source
/// (PUB-8.17) — stamps what it is handed: `false` mints the account's first
/// document PRIVATE, the born-published default NOT applied.
#[test]
fn mint_document_applies_no_default_into_an_empty_account() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("delegate");
    let slot = first_document_address(&acct).expect("slot");
    assert!(!k.snapshot().world().m3().is_registered_document(&slot));

    let first = commit_mint(&k, M3State::document_lock_key(&acct), |m3| {
        m3.mint_document(&acct, false)
    });
    assert_eq!(first, slot, "the account's FIRST document");
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_registered_document(&first));
    assert!(
        !m3.published(&first),
        "the create-path default must not be applied by the mint"
    );
    // …and the mint stamps `true` the same way, into a now non-empty
    // account: it stamps, it never resolves.
    let second = commit_mint(&k, M3State::document_lock_key(&acct), |m3| {
        m3.mint_document(&acct, true)
    });
    assert_eq!(second, a(&[1, 0, 1, 0, 2]));
    assert!(k.snapshot().world().m3().published(&second));
}

/// The bit is folded for a DOCUMENT-tier Allocate and read for no other: an
/// account's or an element's record carries the non-document `false` as an
/// absence, and the map gains no entry for it.
#[test]
fn only_a_document_allocate_writes_the_publication_map() {
    let s = M3State::genesis()
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1]),
            published: true, // an account: outside the axis, not read
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 1]),
            published: true,
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 1, 0, 1, 1]),
            published: true, // an element: outside the axis, not read
        });
    assert!(s.published(&a(&[1, 0, 1, 0, 1])));
    assert!(!s.published(&a(&[1, 0, 1])));
    assert!(!s.published(&a(&[1, 0, 1, 0, 1, 0, 1, 1])));
    // A version is a document, and its Allocate is folded like any other's.
    let s = s.apply_m3(&M3Rec::Allocate {
        addr: a(&[1, 0, 1, 0, 1, 1]),
        published: false,
    });
    assert!(s.is_registered_document(&a(&[1, 0, 1, 0, 1, 1])));
    assert!(!s.published(&a(&[1, 0, 1, 0, 1, 1])));
    // The enumeration is the registered documents and nothing else — the
    // account and the element are absent — in address order: the two minted
    // here, then genesis's two born-published seeds under the system account
    // (PUB-6.65: `1.1.0.1.0.1` and `H`), which sort above everything under
    // `1.0.1`.
    let (doc, version) = (a(&[1, 0, 1, 0, 1]), a(&[1, 0, 1, 0, 1, 1]));
    let (seed_1, seed_h) = (ghost_home_document(), head_document());
    assert_eq!(
        s.documents().collect::<Vec<_>>(),
        vec![
            (&doc, true),
            (&version, false),
            (&seed_1, true),
            (&seed_h, true)
        ]
    );
    // The walk is exact-size and double-ended, as a map walk is in std: the
    // count is answered without walking, and the back of the walk is the
    // ADDRESS-greatest entry — the seeded `H`, which is not the newest (the
    // version was minted last; `the_publication_walk_is_in_address_order_not_mint_order`
    // is the shape that tells the two apart among minted documents).
    assert_eq!(s.documents().len(), 4);
    assert_eq!(s.documents().next_back(), Some((&seed_h, true)));
}

/// The walk is in ADDRESS order, which is not mint order: a version of doc 1
/// sorts BETWEEN doc 1 and doc 2, whichever was minted first. The two agree on
/// every other fixture in this file — each mints one chain in ascending
/// ordinals — so this is the shape that tells them apart, and it is the shape
/// the engine's dump renders (two boards with one history must render one byte
/// string). It also fixes what `.next_back()` gives: the ADDRESS-greatest
/// entry, which is NOT the newest document. Genesis is never empty since
/// PUB-6.65's seed — the system account's doc 1 and `H`, born published — so
/// every walk here ends with those two, above everything minted under `1.0.1`.
#[test]
fn the_publication_walk_is_in_address_order_not_mint_order() {
    let (d1, d2, v1) = (
        a(&[1, 0, 1, 0, 1]),
        a(&[1, 0, 1, 0, 2]),
        a(&[1, 0, 1, 0, 1, 1]),
    );
    let (seed_1, seed_h) = (ghost_home_document(), head_document());
    // The seed alone, one minted, many — the walk's three sizes, in mint order
    // d1, d2, v1.
    let s = M3State::genesis();
    assert_eq!(
        s.documents().collect::<Vec<_>>(),
        vec![(&seed_1, true), (&seed_h, true)]
    );
    let s = s.apply_m3(&alloc(&[1, 0, 1])).apply_m3(&M3Rec::Allocate {
        addr: d1.clone(),
        published: true,
    });
    assert_eq!(
        s.documents().collect::<Vec<_>>(),
        vec![(&d1, true), (&seed_1, true), (&seed_h, true)]
    );
    let s = s
        .apply_m3(&M3Rec::Allocate {
            addr: d2.clone(),
            published: false,
        })
        .apply_m3(&M3Rec::Allocate {
            addr: v1.clone(),
            published: true,
        });

    // Address order — d1, then d1's version, then d2, then the seed — not the
    // mint order (seed), d1, d2, v1.
    assert_eq!(
        s.documents().collect::<Vec<_>>(),
        vec![
            (&d1, true),
            (&v1, true),
            (&d2, false),
            (&seed_1, true),
            (&seed_h, true)
        ]
    );
    assert_eq!(s.documents().len(), 5);
    // So the back of the walk is the address-greatest entry and not the
    // newest: v1 was minted last, and the seeded `H` — older than all three —
    // is what `.next_back()` answers; among the minted three, d2 is the
    // greatest and v1 sorts below it.
    assert_eq!(s.documents().next_back(), Some((&seed_h, true)));
    assert_eq!(s.documents().nth_back(2), Some((&d2, false)));
}

/// PUB-1.9/PUB-1.68, and PUB-7.7's fold half: no public function changes a
/// document's bit after its mint — every op the crate has runs after the
/// mints and none moves one — and the map is ordinary recoverable state:
/// restored from the checkpoint and advanced by replaying the
/// post-checkpoint Allocates, it reproduces the live map exactly.
#[test]
fn the_bit_is_immutable_and_recovers_by_checkpoint_and_replay() {
    let dir = tempdir().expect("tempdir");
    let (expected, live) = {
        let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("open");
        let ns = Namespace::new(&k);
        let (acct, _) = ns
            .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
            .expect("delegate");
        let (d1, _) = ns.create_new_document(ID1, &acct, None).expect("doc 1");
        let (draft, _) = ns.create_new_document(ID1, &acct, None).expect("draft");
        let (published_doc, _) = ns
            .create_new_document(ID1, &acct, Some(true))
            .expect("published");
        // Checkpoint here: those three are restored FROM the checkpoint; the
        // rest ride post-checkpoint replay.
        k.checkpoint().expect("checkpoint");
        let v_private = commit_mint(&k, M3State::version_lock_key(&published_doc), |m3| {
            m3.mint_version(&published_doc, false)
        });
        let v_published = commit_mint(&k, M3State::version_lock_key(&draft), |m3| {
            m3.mint_version(&draft, true)
        });
        let (forked, _) = ns.fork(ID1, None).expect("fork"); // flagless, non-empty: private
        let expected = vec![
            (d1, true),
            (draft, false),
            (published_doc, true),
            (v_private, false),
            (v_published, true),
            (forked, false),
        ];
        let bits =
            |m3: &M3State| -> Vec<bool> { expected.iter().map(|(d, _)| m3.published(d)).collect() };
        let after_mints = bits(k.snapshot().world().m3());
        assert_eq!(
            after_mints,
            expected.iter().map(|(_, b)| *b).collect::<Vec<_>>()
        );

        // Every op the crate has, after the mints: none moves a bit. Doc 1
        // is the home the content and link mints take — the document an
        // element is minted under — and its bit stands through both.
        ns.register_node(t(&[1, 7])).expect("register node");
        ns.delegate(ID1, t(&[1, 0, 1, 1]), ID2)
            .expect("sub-delegate");
        let d1 = &expected[0].0;
        commit_mint(&k, M3State::content_lock_key(d1), |m3| m3.mint_content(d1));
        commit_mint(&k, M3State::link_lock_key(d1), |m3| m3.mint_link(d1));
        ns.create_new_document(ID1, &acct, Some(true))
            .expect("another document");
        ns.fork(ID1, None).expect("another fork");
        assert_eq!(bits(k.snapshot().world().m3()), after_mints);
        let live = k.snapshot().world().m3().clone();
        (expected, live)
    };

    let k2 = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("reopen");
    let recovered = k2.snapshot().world().m3().clone();
    assert_eq!(recovered, live);
    for (doc, bit) in &expected {
        assert!(recovered.is_registered_document(doc));
        assert_eq!(
            recovered.published(doc),
            *bit,
            "{doc:?} recovered with the wrong bit"
        );
    }
}

/// PUB-7.8: the bit is NON-OPTIONAL at rest. A journal record and a
/// checkpoint written in the pre-publication shape — the old bytes, built by
/// hand — FAIL TO DECODE; neither resolves to `false`, and a checkpoint never
/// resolves to everything-published (PUB-1.2: no grandfather clause). The
/// premise is pinned first: the current shape IS the old bytes followed by
/// the bit — the field is appended — so the hand-built shapes are the old
/// ones and not a strawman.
#[test]
fn a_record_or_checkpoint_without_the_bit_fails_to_decode() {
    // The journal record, pre-publication shape: an Allocate is its address.
    #[derive(Serialize)]
    enum OldM3Rec {
        Allocate { addr: Tumbler },
    }
    let doc = a(&[1, 0, 1, 0, 1]);
    let old = bincode::serialize(&OldM3Rec::Allocate {
        addr: t(&[1, 0, 1, 0, 1]),
    })
    .expect("serialize the old shape");
    for bit in [false, true] {
        let new = bincode::serialize(&M3Rec::Allocate {
            addr: doc.clone(),
            published: bit,
        })
        .expect("serialize the current shape");
        assert_eq!(
            new,
            [old.as_slice(), &[u8::from(bit)][..]].concat(),
            "the current record shape is the old bytes plus the bit"
        );
    }
    assert!(
        bincode::deserialize::<M3Rec>(&old).is_err(),
        "a pre-publication Allocate decoded — it must fail, never default"
    );

    // The checkpointed slice: the frontier map, the node set, the principal
    // map, and then the publication map — the field the bit appended. Genesis
    // is no longer empty (PUB-6.65's seed: system node 1.1, the system account
    // 1.1.0.1, its doc 1 and `H` born published), so the three trailing fields
    // are hand-built from the seed's public pins — a `Vec` of pairs encodes
    // exactly as the maps do — and pinned as the slice's suffix; the frontier
    // map's key is the crate's own type, so its bytes lead the slice as the
    // encoding writes them, ahead of the three. The old shape is then the
    // slice short of the appended map, and it must not decode.
    let new = bincode::serialize(&M3State::genesis()).expect("serialize genesis");
    let nodes = bincode::serialize(&vec![t(&[1]), t(&[1, 1])]).expect("the node set");
    let principals = bincode::serialize(&vec![
        (t(&[1]), BOOTSTRAP_PRINCIPAL),
        (t(&[1, 1, 0, 1]), SYSTEM_PRINCIPAL),
    ])
    .expect("the principal map");
    let publication = bincode::serialize(&vec![
        (t(&[1, 1, 0, 1, 0, 1]), true),
        (t(&[1, 1, 0, 1, 0, 2]), true),
    ])
    .expect("the publication map");
    assert!(
        new.ends_with(
            &[
                nodes.as_slice(),
                principals.as_slice(),
                publication.as_slice()
            ]
            .concat()
        ),
        "the current checkpoint shape ends with the seed's nodes, principals and publication map"
    );
    let old = &new[..new.len() - publication.len()];
    assert!(
        bincode::deserialize::<M3State>(old).is_err(),
        "a pre-publication checkpoint decoded — it must fail, never read as everything-published"
    );
}

/// PUB-6.37: registration precedes publication. `published` is defined for a
/// REGISTERED document and callers gate on `is_registered_document` first;
/// an address that was never minted — the chain's next slot, a deeper
/// never-minted document — is answered by the registration check, which is
/// false there, and `published` on it is outside the contract. A document
/// becomes registered and gains its bit in the ONE step that mints it.
#[test]
fn registration_precedes_publication() {
    let (k, acct, doc) = kernel_with_account_and_doc();
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_registered_document(&doc) && m3.published(&doc));
    for never_minted in [
        a(&[1, 0, 1, 0, 2]),    // the chain's next slot
        a(&[1, 0, 1, 0, 9]),    // deeper on the chain
        a(&[1, 0, 1, 0, 1, 1]), // doc 1's version chain, never opened
        a(&[1, 0, 2, 0, 1]),    // under an account that does not exist
    ] {
        assert!(
            !m3.is_registered_document(&never_minted),
            "{never_minted:?} reads as registered"
        );
    }
    // The next slot is registered — and carries its bit — after the one
    // record that mints it, and not before.
    let d2 = commit_mint(&k, M3State::document_lock_key(&acct), |m3| {
        m3.mint_document(&acct, true)
    });
    assert_eq!(d2, a(&[1, 0, 1, 0, 2]));
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_registered_document(&d2));
    assert!(m3.published(&d2));
}
