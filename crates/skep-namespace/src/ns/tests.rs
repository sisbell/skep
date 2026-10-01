use super::*;

use crate::M3State;
use skep_address::ordinal;

fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
}

fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("T4-valid")
}

/// Every T4-valid address of `1..=max_len` components drawn from {0, 1, 2}:
/// every tier, every field length the total allows, both subspaces, every
/// separator position — enumerated, so no shape is one a human chose.
fn every_address_up_to(max_len: u32) -> Vec<Address> {
    (1..=max_len)
        .flat_map(|len| {
            (0..3u32.pow(len)).filter_map(move |code| {
                let comps: Vec<u32> = (0..len).map(|i| code / 3u32.pow(i) % 3).collect();
                validate(t(&comps)).ok()
            })
        })
        .collect()
}

/// §1: a frontier key re-enters memory through its own door. `first_in`
/// re-`validate`s a key's anchor with an `expect`, and `Tumbler`
/// admits any nonempty component sequence — `[1, 0]` decodes and is not
/// T4-valid — so without the door a checkpoint could seat a key that is
/// a panic waiting for the first reader to dereference it. Refused while
/// it is still bytes, at no cost to the encoding.
#[test]
fn a_frontier_key_re_enters_through_its_t4_door() {
    #[derive(Serialize)]
    struct RawNsKey {
        parent: Tumbler,
        g: u8,
    }

    let good = NsKey {
        parent: t(&[1, 0, 1]),
        g: Generator::NextField,
    };
    let bytes = bincode::serialize(&good).expect("serialize the key");
    assert_eq!(
        bincode::deserialize::<NsKey>(&bytes).expect("a well-formed key round-trips"),
        good
    );
    // The door changes nothing at rest: the key's bytes are still the
    // struct's own, anchor tumbler then generator numeral.
    assert_eq!(
        bytes,
        bincode::serialize(&RawNsKey {
            parent: t(&[1, 0, 1]),
            g: 2
        })
        .expect("serialize the raw shape"),
    );

    // Anchors no `*_ns` constructor could have produced: a trailing
    // separator and a doubled one, both nonempty tumblers, neither T4.
    for bogus in [vec![1u32, 0], vec![1, 0, 0, 1]] {
        let frame = bincode::serialize(&RawNsKey {
            parent: t(&bogus),
            g: 1,
        })
        .expect("serialize the raw shape");
        assert!(
            bincode::deserialize::<NsKey>(&frame).is_err(),
            "{bogus:?} decoded as a namespace anchor"
        );
    }
}

/// The half of `first_in`'s anchor precondition the key's at-rest door
/// (`t4_anchor`) does not carry — a next-field generator over an
/// Element-level anchor — is left out because it FAILS SOFT, the door's doc
/// says: M1's TA5a gate refuses `k = 2` at that tier and `first_in` answers
/// `GateViolation` as a value. That is the door's reason for its scope. No
/// mint ever asks: each builds its key fresh, and each mint's gate refuses
/// the one argument that could build this one
/// (`mint_preconditions_reject_structurally`) — so it is reached here, on a
/// key the door admits.
#[test]
fn a_next_field_key_over_an_element_anchor_fails_soft() {
    let key = NsKey {
        parent: t(&[1, 0, 1, 0, 1, 0, 1, 1]),
        g: Generator::NextField,
    };
    assert!(
        is_t4_valid(&key.parent),
        "the T4 half holds: only the pair is wrong"
    );
    // The door admits the pair: refusing it is not the door's work.
    let bytes = bincode::serialize(&key).expect("serialize the key");
    assert_eq!(
        bincode::deserialize::<NsKey>(&bytes).expect("the door admits the pair"),
        key
    );
    // …and both chain-member reads answer the refusal as a value.
    assert_eq!(first_in(&key), Err(GateViolation));
    assert_eq!(nth_in(&key, &Nat::from(3u32)), Err(GateViolation));
}

/// The generator IS ASN-0040's baptismal depth `d ∈ {1, 2}`: it is the
/// numeral wherever bytes are written — the checkpointed frontier key and
/// `ns_lock_key`'s trailing byte — and no third value survives the way back
/// in, so the `k` `first_in` hands M1 is one its TA5a gate admits by shape.
#[test]
fn generator_is_its_numeral_and_admits_no_third_value() {
    for (g, n) in [(Generator::SameField, 1u8), (Generator::NextField, 2u8)] {
        assert_eq!(u8::from(g), n);
        assert_eq!(g.inc_k(), n as usize);
        assert_eq!(Generator::try_from(n), Ok(g));
        assert_eq!(
            bincode::serialize(&g).expect("serialize the generator"),
            bincode::serialize(&n).expect("serialize the numeral"),
        );
    }
    for bogus in [0u8, 3, 7, 255] {
        assert!(Generator::try_from(bogus).is_err());
        assert!(bincode::deserialize::<Generator>(&[bogus]).is_err());
    }
}

/// The chain-family rule at the tier pairs the `*_ns` family is built at:
/// an anchor and child at the SAME tier extend the anchor's own field, a
/// child one tier down opens the next one. This is what puts the document
/// chain `(A, 2)` and the version chain `(d, 1)` on separate frontiers
/// (ASN-0123 VD), so the two keys anchored at one account differ.
#[test]
fn the_chain_family_rule_separates_document_from_version() {
    assert_eq!(
        generator(Level::Element, Level::Element),
        Generator::SameField
    );
    assert_eq!(
        generator(Level::Document, Level::Document),
        Generator::SameField
    );
    assert_eq!(
        generator(Level::Account, Level::Document),
        Generator::NextField
    );
    assert_eq!(generator(Level::Node, Level::Account), Generator::NextField);
    assert_eq!(
        generator(Level::Account, Level::Account),
        Generator::SameField
    );

    // The fixed families carry what the rule yields, and the two chains
    // anchored at one account are distinct keys.
    let acct = a(&[1, 0, 1]);
    assert_eq!(version_ns(&acct).g, Generator::SameField);
    assert_eq!(document_ns(&acct).g, Generator::NextField);
    assert_ne!(version_ns(&acct), document_ns(&acct));
    assert_eq!(account_ns(&acct).g, Generator::SameField);

    let doc = a(&[1, 0, 1, 0, 1]);
    assert_eq!(content_ns(&doc).g, Generator::SameField);
    assert_eq!(link_ns(&doc).g, Generator::SameField);
    // The child-side derivation agrees with the anchor-side one: the
    // account peeked under a node sits in the very key `account_ns`
    // builds there.
    let node = a(&[1]);
    assert_eq!(account_ns(&node).g, Generator::NextField);
    assert_eq!(namespace_of(&acct), Some(account_ns(&node)));
}

/// §2's membership-correctness invariant, stated as a law — "for T4-valid
/// `a`, `a` is exactly `c_{ordinal(a)}` of its decomposed `(parent, g)`
/// namespace" — held over every address `every_address_up_to(8)` yields, with
/// the fact `Allocate`'s door rests on beside it:
///
/// * a namespace exists iff the address has two or more components — the
///   door's `#a ≥ 2`, M1's `parent` and `namespace_of` agree everywhere;
/// * address → key → address: `a` is the member its own key names at its own
///   ordinal — what makes membership exact, since a key naming another member
///   at `a`'s ordinal would make `a` read allocated once that member was
///   minted;
/// * key → address → key: every member of that chain, at small ordinals and
///   past a machine word, derives the same key and carries its ordinal —
///   "every member of a chain must derive the same key or the frontier forks"
///   (§1/§8).
///
/// `each_chains_minted_addresses_advance_the_key_their_mint_read` pins six
/// mint families at ordinals 1 and 2; this reaches what it does not — a node
/// under a node; a subspace base under its document, whose key would be the
/// document's VERSION chain if the chain-family rule ever read
/// `(Document, Element)` as same-field; multi-component fields at every tier.
#[test]
fn every_address_is_the_member_its_own_key_names() {
    let family = every_address_up_to(8);
    assert!(
        family.len() > 2_000,
        "the generated family is the point of this test"
    );
    let ordinals = [
        Nat::from(1u32),
        Nat::from(2u32),
        Nat::from(255u32),
        Nat::from(256u32),
        Nat::from(1u64 << 32),
        Nat::from(u64::MAX) + 2u32,
    ];
    for addr in &family {
        let extends_a_parent = addr.tumbler().len() >= 2;
        assert_eq!(
            parent(addr).is_some(),
            extends_a_parent,
            "{addr:?}: M1's `parent`"
        );
        assert_eq!(
            namespace_of(addr).is_some(),
            extends_a_parent,
            "{addr:?}: `namespace_of`"
        );
        let Some(key) = namespace_of(addr) else {
            continue;
        };
        assert_eq!(
            nth_in(&key, ordinal(addr.tumbler())),
            Ok(addr.clone()),
            "{addr:?} is not the member its own key names"
        );
        for n in &ordinals {
            let member = nth_in(&key, n)
                .expect("a NextField key comes of a peeled separator: its anchor is not Element");
            assert_eq!(
                namespace_of(&member),
                Some(key.clone()),
                "{member:?} forks {key:?}"
            );
            assert_eq!(
                ordinal(member.tumbler()),
                n,
                "{member:?} is not member {n} of {key:?}"
            );
        }
    }
}

/// The `NsKey → LockKey` map is INJECTIVE (§1) — distinct namespaces,
/// distinct locks — and functional, on EVERY pair a key can be built from,
/// T4-valid anchor or not. A law, so a generated family: every anchor of one
/// to three components over an alphabet of magnitudes whose encodings run
/// together when spliced — zero, one and two, the byte boundaries
/// 255/256/257 and 65_535/65_536, both sides of the 32-bit and of the 64-bit
/// limb boundary, and 2⁶⁴ + 1 — crossed with both generators, beside the
/// chains' own longer anchors. Without the per-component length, `[1, 256]`
/// and `[257, 0]` encode alike; spliced by machine word instead of by byte,
/// `[2⁶⁴, 0]` and `[0, 2⁶⁴]` do.
#[test]
fn the_lock_key_encoding_is_injective_over_a_generated_family() {
    let alphabet: Vec<Nat> = [
        0u64,
        1,
        2,
        255,
        256,
        257,
        65_535,
        65_536,
        u64::from(u32::MAX),
        1 << 32,
        u64::MAX,
    ]
    .into_iter()
    .map(Nat::from)
    .chain([Nat::from(u64::MAX) + 1u32, Nat::from(u64::MAX) + 2u32])
    .collect();
    let mut anchors: Vec<Vec<Nat>> = Vec::new();
    let mut layer: Vec<Vec<Nat>> = vec![Vec::new()];
    for _ in 1..=3 {
        layer = layer
            .iter()
            .flat_map(|shorter| {
                alphabet.iter().map(move |c| {
                    let mut longer = shorter.clone();
                    longer.push(c.clone());
                    longer
                })
            })
            .collect();
        anchors.extend(layer.iter().cloned());
    }
    // The chains' own anchors past three components, up to the element tier.
    for comps in [
        vec![1u32, 0, 1, 1],
        vec![1, 0, 1, 0, 1],
        vec![1, 0, 1, 0, 1, 0, 1],
        vec![1, 0, 1, 0, 1, 0, 2],
        vec![1, 0, 1, 0, 1, 0, 1, 1],
    ] {
        anchors.push(comps.into_iter().map(Nat::from).collect());
    }
    let mut locks = std::collections::BTreeMap::new();
    for anchor in &anchors {
        for g in [Generator::SameField, Generator::NextField] {
            let key = NsKey {
                parent: Tumbler::new(anchor.iter().cloned()).expect("nonempty"),
                g,
            };
            let lock = ns_lock_key(&key);
            // Functional: the same key encodes to the same bytes every time.
            assert_eq!(ns_lock_key(&key), lock);
            if let Some(other) = locks.insert(lock, key.clone()) {
                panic!("distinct namespaces share a lock: {other:?} and {key:?}");
            }
        }
    }
    assert!(
        locks.len() > 4_000,
        "the generated family is the point of this test"
    );
}

/// What a key owes is injectivity, and it owes it on every anchor — a
/// lock key is compared, never dereferenced. `content_ns`/`link_ns` on an
/// element build `e ++ [0, 1]` and `e ++ [0, 2]`, four separators apiece
/// and so outside T4, which is exactly the shape `first_in`'s precondition
/// excludes and no mint can reach: both go through
/// `is_registered_document`, which admits only a Document. The keys are
/// still deterministic and still distinct, which is the whole of what
/// [`M3State::content_lock_key`] and [`M3State::link_lock_key`] promise.
///
/// That the mints really do refuse an element — the half this test
/// argues rather than runs — is executed by the integration suite's
/// `mint_preconditions_reject_structurally`, which hands every mint an
/// allocated element and a node.
#[test]
fn a_lock_key_is_injective_even_on_an_anchor_no_mint_could_reach() {
    let element = a(&[1, 0, 1, 0, 1, 0, 1, 1]);
    assert_eq!(element.level(), Level::Element);

    let (content, link) = (content_ns(&element), link_ns(&element));
    assert!(!is_t4_valid(&content.parent), "the anchor is outside T4");
    assert!(!is_t4_valid(&link.parent), "the anchor is outside T4");

    // Deterministic, and the two subspaces stay apart — the properties
    // the public constructors exist to provide.
    assert_eq!(
        M3State::content_lock_key(&element),
        M3State::content_lock_key(&element)
    );
    assert_ne!(
        M3State::content_lock_key(&element),
        M3State::link_lock_key(&element)
    );
    // …and neither collides with the key of the document that homes it.
    let doc = a(&[1, 0, 1, 0, 1]);
    assert_ne!(
        M3State::content_lock_key(&element),
        M3State::content_lock_key(&doc)
    );
}
