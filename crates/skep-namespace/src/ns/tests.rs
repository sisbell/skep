use super::*;

use crate::M3State;

fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
}

fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("T4-valid")
}

/// §1: a frontier key re-enters memory through its own door. `next_in`
/// re-`validate`s a loaded key's anchor with an `expect`, and `Tumbler`
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

/// The generator IS ASN-0040's `d ∈ {1, 2}`: it is the numeral wherever
/// bytes are written — the checkpointed frontier key and `ns_lock_key`'s
/// trailing byte — and no third value survives the way back in, so the
/// `k` `next_in` hands M1 is one its TA5a gate admits by shape.
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
    let acct = validate(Tumbler::new([1u32, 0, 1].map(Nat::from)).expect("nonempty"))
        .expect("T4-valid account");
    assert_eq!(version_ns(&acct).g, Generator::SameField);
    assert_eq!(document_ns(&acct).g, Generator::NextField);
    assert_ne!(version_ns(&acct), document_ns(&acct));
    assert_eq!(account_ns(&acct).g, Generator::SameField);

    let doc = validate(Tumbler::new([1u32, 0, 1, 0, 1].map(Nat::from)).expect("nonempty"))
        .expect("T4-valid document");
    assert_eq!(content_ns(&doc).g, Generator::SameField);
    assert_eq!(link_ns(&doc).g, Generator::SameField);
    // The child-side derivation agrees with the anchor-side one: the
    // account peeked under a node sits in the very key `account_ns`
    // builds there.
    let node = validate(Tumbler::new([Nat::from(1u32)]).expect("nonempty")).expect("T4-valid");
    assert_eq!(account_ns(&node).g, Generator::NextField);
    assert_eq!(namespace_of(&acct), Some(account_ns(&node)));
}

/// The `NsKey → LockKey` map is INJECTIVE (§1) — distinct namespaces,
/// distinct locks — and functional. Over a family crossed with both
/// generators, including the pair that makes the per-component length
/// delimiter load-bearing: without it `[1, 256]` and `[257, 0]` encode
/// alike.
#[test]
fn the_lock_key_encoding_is_injective_over_a_generated_family() {
    let parents: Vec<Tumbler> = [
        vec![1u32],
        vec![1, 1],
        vec![2],
        vec![1, 2],
        vec![1, 256],
        vec![257, 0],
        vec![1, 0, 1],
        vec![1, 0, 1, 1],
        vec![1, 0, 1, 0, 1],
        vec![1, 0, 1, 0, 1, 0, 1],
        vec![1, 0, 1, 0, 1, 0, 2],
        vec![1, 0, 1, 0, 1, 0, 1, 1],
    ]
    .into_iter()
    .map(|c| Tumbler::new(c.into_iter().map(Nat::from)).expect("nonempty"))
    .collect();
    let mut keys = Vec::new();
    for parent in &parents {
        for g in [Generator::SameField, Generator::NextField] {
            let key = NsKey {
                parent: parent.clone(),
                g,
            };
            let encoded = ns_lock_key(&key);
            // Functional: the same key encodes to the same bytes every
            // time.
            assert_eq!(ns_lock_key(&key), encoded);
            keys.push((key, encoded));
        }
    }
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(
                keys[i].1, keys[j].1,
                "distinct namespaces share a lock: {:?} and {:?}",
                keys[i].0, keys[j].0
            );
        }
    }
}

/// What a key owes is injectivity, and it owes it on every anchor — a
/// lock key is compared, never dereferenced. `content_ns`/`link_ns` on an
/// element build `e ++ [0, 1]` and `e ++ [0, 2]`, four separators apiece
/// and so outside T4, which is exactly the shape `next_in`'s precondition
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
