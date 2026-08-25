//! The key set — AUTH-1.29–1.37 (with AUTH-1.57).

use im::OrdMap;
use serde::{Deserialize, Serialize};

use crate::key::Fingerprint;
use crate::key::PublicKey;

/// AUTH-1.29 — one enrolled key: the public key and its anchor flag. The
/// same shape `Effect::Genesis`/`Effect::Enroll` name (AUTH-2.52).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrolled {
    /// The enrolled public key.
    pub key: PublicKey,
    /// The anchor flag the key entered under (AUTH-1.26; immutable per key
    /// per set — I9, AUTH-2.104).
    pub anchor: bool,
}

/// AUTH-1.29 — one account's key set: the enrolled map and the retired map,
/// both private. Standing invariants (each re-checked ONLY at the two
/// deserialization boundaries AUTH-1.33 names — a transferred slice-carrying
/// checkpoint, a checkpoint restored from backup — a bootstrap-side
/// obligation of the engine/mirror, on no fold path, with AUTH-1.34's
/// refuse-the-slice disposition):
///
/// * AUTH-1.32 — for every `(fp, e)` in `enrolled`,
///   `fp == Fingerprint::of(&e.key)`: the map key is an index over the
///   value, never a second authority (`apply` establishes it by
///   construction, AUTH-2.53);
/// * AUTH-1.35 — `enrolled ∩ retired = ∅` (AUTH-1.37);
/// * AUTH-1.36/AUTH-1.57 (RES-13) — `retired ≠ ∅ ⇒ enrolled ≠ ∅`, so
///   `is_empty()` implies `retired = ∅` and no genesis can re-enroll a
///   retired fingerprint (the genesis arm posts `enrolled = K` WITHOUT
///   consulting `retired`, AUTH-2.70).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySet {
    enrolled: OrdMap<Fingerprint, Enrolled>,
    retired: OrdMap<Fingerprint, bool /* anchor */>,
}

impl KeySet {
    /// AUTH-1.31 — ⇔ no enrolled key.
    pub fn is_empty(&self) -> bool {
        self.enrolled.is_empty()
    }

    /// AUTH-1.31 — ⇔ `fp` is enrolled NOW.
    pub fn contains(&self, fp: &Fingerprint) -> bool {
        self.enrolled.contains_key(fp)
    }

    /// AUTH-1.31 — ⇔ enrolled NOW with the anchor flag.
    pub fn is_anchor(&self, fp: &Fingerprint) -> bool {
        self.enrolled.get(fp).is_some_and(|e| e.anchor)
    }

    /// AUTH-1.31 — the enrolled keys, iterated in fingerprint order (the
    /// ordering the realm genesis-set framing reuses — AUTH-2.119, RES-1).
    pub fn enrolled(&self) -> impl Iterator<Item = (&Fingerprint, &Enrolled)> {
        self.enrolled.iter()
    }

    /// AUTH-1.31 — the retired fingerprints in fingerprint order, each
    /// yielding the anchor flag it was ENROLLED under (AUTH-1.30: the flag
    /// is for the fingerprint's lifetime, retirement included, so "was that
    /// a senior key" is a head read).
    pub fn retired(&self) -> impl Iterator<Item = (&Fingerprint, bool)> {
        self.retired.iter().map(|(fp, anchor)| (fp, *anchor))
    }

    /// ⇔ `fp` is retired — the point form of what [`retired`] discloses in
    /// bulk. Crate-private because AUTH-1.29 fixes the public surface; the
    /// enrollment arm's `k ∉ retired` (AUTH-2.69) is its one caller.
    ///
    /// [`retired`]: KeySet::retired
    pub(crate) fn retired_contains(&self, fp: &Fingerprint) -> bool {
        self.retired.contains_key(fp)
    }

    /// How many keys are enrolled NOW. Crate-private for the same reason; the
    /// retirement arm's whole-set test (AUTH-2.74) is its one caller, sound
    /// there because that arm filtered its `removed` from `enrolled` and
    /// AUTH-2.15 left the record's fingerprints duplicate-free.
    pub(crate) fn enrolled_len(&self) -> usize {
        self.enrolled.len()
    }

    /// Enrol one key, the map key derived via `Fingerprint::of` on the key
    /// inserted — establishing AUTH-1.32 by construction (AUTH-2.53).
    /// Crate-private: only `apply` posts.
    pub(crate) fn insert_enrolled(&mut self, e: Enrolled) {
        self.enrolled.insert(Fingerprint::of(&e.key), e);
    }

    /// Move one enrolled fingerprint to `retired`, carrying the flag it was
    /// enrolled under (AUTH-1.30, AUTH-2.74's post); a fingerprint that is
    /// not enrolled moves nothing, so the act is total and decides nothing
    /// (AUTH-2.53). Crate-private: only `apply` posts, and `classify`
    /// guarantees the membership.
    pub(crate) fn move_to_retired(&mut self, fp: &Fingerprint) {
        if let Some(e) = self.enrolled.remove(fp) {
            self.retired.insert(*fp, e.anchor);
        }
    }
}
