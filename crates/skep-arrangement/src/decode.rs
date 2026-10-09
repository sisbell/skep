//! The slice's collections decoded entry by entry ([`entry_by_entry`],
//! [`element_by_element`]): an `im::OrdMap` or `im::Vector` read one entry at
//! a time, reserving nothing from the count its bytes declare.
//!
//! M2 decodes [`M5State`](crate::M5State) from a checkpoint body, bytes it
//! does not trust (its HOSTILE-INPUT OBLIGATION on `WorldState`): the header's
//! checksum and hash prove the bytes are the ones that were written, and
//! nothing about whether decoding them is safe, and its load refuses a body
//! that will not decode and falls back to an older base. `im`'s own visitors
//! reserve room for the count a collection's bytes declare before they have
//! read one entry, and M2's codec reads that count as a bare `u64` bounded by
//! nothing. So a count the body does not carry — a writer/reader skew reading
//! another field's bytes as this length, or a crafted file — makes that
//! reservation panic past `isize::MAX` bytes and, short of it, abort the
//! process on a count the allocator cannot grant: where the load must refuse,
//! the process dies, and dies again at every open of that checkpoint.
//! Inserting each entry as it arrives reserves nothing the bytes have not
//! carried, so a short body runs out of input and the decode refuses it. M4's
//! content map decodes the same way, for the same reason.
//!
//! The decode is otherwise `im`'s own. The bytes are the ones `im`'s
//! `Serialize` writes — a count, then the entries in order — so the encoding
//! is untouched; each entry is decoded by its own `Deserialize`, door and all
//! (a key re-enters M1's `Address` door, a run [`Run::new`](crate::Run::new),
//! a span T12); a map's later entry under a repeated key replaces the
//! earlier, as `im`'s insert-in-order does; and nothing `im`'s visitor admits
//! is refused. What bounds the loop is the ELEMENT: each must consume at least
//! one byte, so a count larger than the entries that follow costs at most one
//! pass over the body. Every element the slice holds does — an address, a
//! run, a span, a natural and the shot terms each open with a count of their
//! own — and an element that decoded from zero bytes would turn a lying count
//! into an unbounded loop (M2's obligation states that hazard on `Record`).
//!
//! Every collection the slice decodes comes through here: `M5State`'s three
//! maps, each run-list behind `RunListShadow`, and R's map and each
//! document's spans behind `ProvenanceShadow`.
//! `the_slice_decodes_or_refuses_whatever_count_its_bytes_declare`
//! (`state/tests.rs`) writes `u64::MAX` over every eight bytes of a slice
//! holding all of them, so a collection decoded by `im`'s own visitor — a
//! field added without its door — fails there.

use std::fmt;
use std::marker::PhantomData;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

/// An `im::OrdMap`, decoded one entry at a time — the door every map the
/// slice holds decodes through, named in its field's
/// `#[serde(deserialize_with = …)]`. Reserves nothing; each key and value is
/// decoded by its own `Deserialize`, and a repeated key keeps the later value.
pub(crate) fn entry_by_entry<'de, D, K, V>(deserializer: D) -> Result<im::OrdMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord + Clone,
    V: Deserialize<'de> + Clone,
{
    struct Entries<K, V>(PhantomData<(K, V)>);

    impl<'de, K, V> Visitor<'de> for Entries<K, V>
    where
        K: Deserialize<'de> + Ord + Clone,
        V: Deserialize<'de> + Clone,
    {
        type Value = im::OrdMap<K, V>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> Result<Self::Value, A::Error> {
            let mut map = im::OrdMap::new();
            while let Some((key, value)) = entries.next_entry()? {
                map.insert(key, value);
            }
            Ok(map)
        }
    }

    deserializer.deserialize_map(Entries(PhantomData))
}

/// An `im::Vector`, decoded one element at a time, in order — the door every
/// vector the slice holds decodes through, as [`entry_by_entry`] is every
/// map's. Reserves nothing; each element is decoded by its own `Deserialize`.
pub(crate) fn element_by_element<'de, D, A>(deserializer: D) -> Result<im::Vector<A>, D::Error>
where
    D: Deserializer<'de>,
    A: Deserialize<'de> + Clone,
{
    struct Elements<A>(PhantomData<A>);

    impl<'de, A: Deserialize<'de> + Clone> Visitor<'de> for Elements<A> {
        type Value = im::Vector<A>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a sequence")
        }

        fn visit_seq<S: SeqAccess<'de>>(self, mut elements: S) -> Result<Self::Value, S::Error> {
            let mut vector = im::Vector::new();
            while let Some(element) = elements.next_element()? {
                vector.push_back(element);
            }
            Ok(vector)
        }
    }

    deserializer.deserialize_seq(Elements(PhantomData))
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    /// A map and a vector behind the two doors, as the slice's types hold
    /// them, each written by `im`'s own `Serialize`.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Held {
        #[serde(deserialize_with = "entry_by_entry")]
        map: im::OrdMap<u32, u64>,
        #[serde(deserialize_with = "element_by_element")]
        vector: im::Vector<u64>,
    }

    /// `bytes` decoded as a `Held`, the panic caught: `None` where the decode
    /// panicked — as a reservation sized by a count the bytes do not carry
    /// does once it passes `isize::MAX` bytes.
    fn decoded(bytes: &[u8]) -> Option<bincode::Result<Held>> {
        std::panic::catch_unwind(|| bincode::deserialize::<Held>(bytes)).ok()
    }

    #[test]
    fn each_door_decodes_what_im_writes_and_refuses_a_count_its_bytes_do_not_carry() {
        // The doors are `im`'s decode without the reservation: what `im`'s
        // `Serialize` writes comes back as the collections that wrote it; a
        // map naming one key twice keeps the later value, as `im`'s own
        // visitor does; and a count of `u64::MAX` at either door is refused
        // where the input runs out, never reserved for. A count is eight
        // bytes, as M2's codec writes it: the map's opens the body, and the
        // vector's follows the map's three entries of twelve bytes each.
        let held = Held {
            map: im::OrdMap::from(vec![(3u32, 30u64), (1, 10), (2, 20)]),
            vector: im::Vector::from(vec![7, 8, 9]),
        };
        let bytes = bincode::serialize(&held).expect("the collections serialize");
        assert_eq!(
            decoded(&bytes).expect("no panic").expect("they decode"),
            held
        );
        // A map's bytes are its pairs' bytes: one naming key 1 twice.
        let mut repeated =
            bincode::serialize(&vec![(1u32, 10u64), (1, 11)]).expect("the pairs serialize");
        repeated.extend(bincode::serialize(&held.vector).expect("the vector serializes"));
        let later = decoded(&repeated)
            .expect("no panic")
            .expect("a repeated key decodes");
        assert_eq!(later.map, im::OrdMap::unit(1, 11), "the later value stands");
        let vector_count = 8 + 3 * (4 + 8);
        assert_eq!(
            bytes[vector_count..vector_count + 8],
            3u64.to_le_bytes(),
            "the premise: the vector's count follows the map's entries"
        );
        for (door, at) in [("the map's", 0), ("the vector's", vector_count)] {
            let mut lying = bytes.clone();
            lying[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            let refused = decoded(&lying).unwrap_or_else(|| {
                panic!(
                    "{door} count of u64::MAX panicked the decode: a reservation sized by a \
                     count the bytes do not carry"
                )
            });
            assert!(refused.is_err(), "{door} count of u64::MAX decoded");
        }
    }
}
