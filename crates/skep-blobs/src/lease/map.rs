//! The lease map: the leases held, and each principal's keys beside them.
//!
//! The leases are keyed `(designation, hex, principal)`, the hash first and
//! ordered, so the leases on one hash are one range of the map. Beside them,
//! the index by principal holds each principal's keys of the map, spelled as
//! the map spells them: a principal's read — the daemon's, once per 64 KiB
//! chunk of an upload as it re-checks the own scope (M-I6 (e)) — borrows each
//! of its keys for one lookup and allocates nothing, so it costs that
//! principal's own leases and never every lease held. The two are private to
//! this file and change together — by [`LeaseMap::insert`] and
//! [`LeaseMap::retain`], and nowhere else — so the index holds the map's keys
//! and no others, and no principal stays in it holding no lease: its size is
//! the map's, bounded as the map is by the horizon. Its price is memory: each
//! lease's three strings are held three times — in the map's key, in the
//! lease, and in the index's copy of the key — linear in the leases held.

use std::collections::{BTreeMap, BTreeSet};

use super::Lease;

/// A lease's key in the map: its designation, its hex and its principal.
pub(super) type Key = (String, String, String);

/// The leases held, by hash first and by principal.
pub(super) struct LeaseMap {
    /// Every lease by its key, the hash first: the compacted log's order.
    by_hash: BTreeMap<Key, Lease>,
    /// Each principal's keys of `by_hash`, spelled as `by_hash` spells them.
    by_principal: BTreeMap<String, BTreeSet<Key>>,
}

impl LeaseMap {
    /// Returns a map over `by_hash`, its index built from the keys.
    pub(super) fn new(by_hash: BTreeMap<Key, Lease>) -> LeaseMap {
        let mut by_principal: BTreeMap<String, BTreeSet<Key>> = BTreeMap::new();
        for key in by_hash.keys() {
            by_principal.entry(key.2.clone()).or_default().insert(key.clone());
        }
        LeaseMap { by_hash, by_principal }
    }

    /// Returns every lease by its key, the hash first.
    ///
    /// The view is read-only: every change goes through [`LeaseMap::insert`]
    /// or [`LeaseMap::retain`].
    pub(super) fn by_hash(&self) -> &BTreeMap<Key, Lease> {
        &self.by_hash
    }

    /// Returns the principal's leases, in designation and then hex order.
    ///
    /// Each is one lookup of a key the index holds, so the read costs the
    /// principal's own leases and never every lease held; a principal holding
    /// none costs one lookup.
    pub(super) fn of(&self, principal: &str) -> impl Iterator<Item = &Lease> + '_ {
        self.by_principal.get(principal).into_iter().flatten().filter_map(|key| self.by_hash.get(key))
    }

    /// Holds `lease` as its principal's current lease on its hash.
    ///
    /// It replaces the one before under the same key, whatever either's
    /// expiry.
    pub(super) fn insert(&mut self, lease: Lease) {
        let key = (lease.designation.clone(), lease.hex.clone(), lease.principal.clone());
        self.by_principal.entry(lease.principal.clone()).or_default().insert(key.clone());
        self.by_hash.insert(key, lease);
    }

    /// Drops every lease `keep` refuses, and answers how many.
    ///
    /// Each key goes from the index with its lease, and a principal left
    /// holding none goes from it with its last.
    pub(super) fn retain(&mut self, mut keep: impl FnMut(&Lease) -> bool) -> usize {
        let held = self.by_hash.len();
        let by_principal = &mut self.by_principal;
        self.by_hash.retain(|key, lease| {
            if keep(lease) {
                return true;
            }
            if let Some(keys) = by_principal.get_mut(&key.2) {
                keys.remove(key);
                if keys.is_empty() {
                    by_principal.remove(&key.2);
                }
            }
            false
        });
        held - self.by_hash.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a lease of `principal` on `<designation>/<hex>`.
    ///
    /// It is three bytes, live until `expires`.
    fn lease(principal: &str, designation: &str, hex: &str, expires: u64) -> Lease {
        Lease {
            principal: principal.to_string(),
            designation: designation.to_string(),
            hex: hex.to_string(),
            size: 3,
            expires,
        }
    }

    /// Asserts the map's invariant, the module's card.
    ///
    /// The index holds the map's keys and no others, each under its own
    /// principal, and no principal stands in it holding no lease.
    fn assert_the_index_is_the_maps_keys(map: &LeaseMap) {
        let indexed: BTreeSet<&Key> = map.by_principal.values().flatten().collect();
        let held: BTreeSet<&Key> = map.by_hash.keys().collect();
        assert_eq!(indexed, held, "the index holds the map's keys and no others");
        for (principal, keys) in &map.by_principal {
            assert!(!keys.is_empty(), "{principal} stands in the index holding no lease");
            assert!(keys.iter().all(|key| &key.2 == principal), "{principal}'s keys are its own");
        }
    }

    /// Returns the principal's leases as [`LeaseMap::of`] answers them.
    ///
    /// Each is named by its designation and hex.
    fn held_by(map: &LeaseMap, principal: &str) -> Vec<(String, String)> {
        map.of(principal).map(|l| (l.designation.clone(), l.hex.clone())).collect()
    }

    /// Checks that every change keeps the index to the map's keys.
    ///
    /// The changes are the map's making over two principals, one holding three
    /// leases; a lease inserted; a re-PUT of a held key, which replaces its
    /// lease and indexes it once; and a retain that drops one principal's
    /// every lease, answering the count it dropped, its principal gone from
    /// the index rather than left holding none. Between them a principal's
    /// leases come in designation and then hex order, whatever order they
    /// were held in, and a principal holding none answers none.
    #[test]
    fn the_index_holds_the_maps_keys_and_no_others() {
        let mut by_hash = BTreeMap::new();
        for l in [
            lease("a", "blake3", "cd", 10),
            lease("a", "blake3", "ab", 20),
            lease("a", "aaa", "ff", 30),
            lease("b", "blake3", "cd", 10),
        ] {
            by_hash.insert((l.designation.clone(), l.hex.clone(), l.principal.clone()), l);
        }
        let mut map = LeaseMap::new(by_hash);
        assert_the_index_is_the_maps_keys(&map);
        let pairs = |list: &[(&str, &str)]| -> Vec<(String, String)> {
            list.iter().map(|(d, h)| (d.to_string(), h.to_string())).collect()
        };
        assert_eq!(held_by(&map, "a"), pairs(&[("aaa", "ff"), ("blake3", "ab"), ("blake3", "cd")]));
        assert_eq!(held_by(&map, "b"), pairs(&[("blake3", "cd")]));
        assert_eq!(held_by(&map, "c"), pairs(&[]), "a principal holding none");

        map.insert(lease("c", "blake3", "ee", 40));
        assert_the_index_is_the_maps_keys(&map);
        assert_eq!(held_by(&map, "c"), pairs(&[("blake3", "ee")]));

        map.insert(lease("a", "blake3", "ab", 99));
        assert_the_index_is_the_maps_keys(&map);
        assert_eq!(map.by_hash.len(), 5, "a re-PUT replaces its lease");
        assert_eq!(map.by_principal["a"].len(), 3, "and is indexed once");
        let expiries: Vec<u64> = map.of("a").map(|l| l.expires).collect();
        assert_eq!(expiries, [30, 99, 10], "the latest lease stands");

        assert_eq!(map.retain(|l| l.principal != "a"), 3, "a's every lease dropped");
        assert_the_index_is_the_maps_keys(&map);
        assert!(!map.by_principal.contains_key("a"), "a gone from the index, not left holding none");
        assert_eq!(held_by(&map, "a"), pairs(&[]));
        assert_eq!(held_by(&map, "b"), pairs(&[("blake3", "cd")]), "b's lease on the same hash stands");
        assert_eq!(map.retain(|_| true), 0, "a retain that keeps all drops none");
        assert_the_index_is_the_maps_keys(&map);
    }
}
