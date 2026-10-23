//! The key set — AUTH-1.29–1.37 (with AUTH-1.57).

use im::OrdMap;
use serde::{Deserialize, Serialize};

use crate::key::Fingerprint;
use crate::key::PublicKey;

/// One enrolled key, the public key and its anchor flag (AUTH-1.29).
///
/// It is the shape `Effect::Genesis` and `Effect::Enroll` name (AUTH-2.52).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrolled {
    /// The enrolled public key.
    pub key: PublicKey,
    /// The anchor flag the key entered under (AUTH-1.26).
    ///
    /// It is immutable per key per set (I9, AUTH-2.104).
    pub anchor: bool,
}

/// One account's key set, the enrolled map and the retired map (AUTH-1.29).
///
/// Both maps are private. AUTH-1.33 owes a re-check of each standing
/// invariant below at two deserialization boundaries alone — a transferred
/// slice-carrying checkpoint, a checkpoint restored from backup — as a
/// bootstrap-side obligation of the engine or a mirror, on no fold path, with
/// AUTH-1.34's refuse-the-slice disposition; neither this crate nor the
/// engine's load makes it. The standing invariants:
///
/// * AUTH-1.32 — for every `(fp, e)` in `enrolled`,
///   `fp == Fingerprint::of(&e.key)`: the map key is an index over the
///   value, never a second authority (`apply` establishes it by
///   construction, AUTH-2.53);
/// * AUTH-1.35 — `enrolled ∩ retired = ∅` (AUTH-1.37);
/// * AUTH-1.36/AUTH-1.57 (RES-13) — `retired ≠ ∅ ⇒ enrolled ≠ ∅`, so
///   `is_empty()` implies `retired = ∅` and no genesis can re-enroll a
///   retired fingerprint (the genesis arm posts `enrolled = K` without
///   consulting `retired`, AUTH-2.70).
///
/// On the write path the three are held by different means: AUTH-1.32 by
/// construction here (the enrolling mutator derives the map key from the
/// value it inserts), and AUTH-1.35 and AUTH-1.36 as preconditions on the
/// two crate-private mutators, discharged by the posting arms — re-checked
/// nowhere on this side, so a new posting arm inherits them and must
/// discharge them itself. The enrolling mutator's precondition is one fact
/// this set answers about its own two maps, `admits`: a fingerprint it has
/// never held, enrolled or retired. That one fact holds AUTH-1.35 and I9's
/// per-set flag alike (AUTH-2.104, which [`Enrolled::anchor`] states), since
/// the enrolling mutator replaces an enrolled row, flag and all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySet {
    enrolled: OrdMap<Fingerprint, Enrolled>,
    retired: OrdMap<Fingerprint, bool /* anchor */>,
}

impl KeySet {
    /// Returns whether no key is enrolled (AUTH-1.31).
    pub fn is_empty(&self) -> bool {
        self.enrolled.is_empty()
    }

    /// Returns whether `fp` is enrolled now (AUTH-1.31).
    pub fn contains(&self, fp: &Fingerprint) -> bool {
        self.enrolled.contains_key(fp)
    }

    /// Returns whether `fp` is enrolled now with the anchor flag (AUTH-1.31).
    pub fn is_anchor(&self, fp: &Fingerprint) -> bool {
        self.enrolled.get(fp).is_some_and(|e| e.anchor)
    }

    /// Returns the enrolled keys in fingerprint order (AUTH-1.31).
    ///
    /// The order is ascending by the digest bytes ([`Fingerprint`]'s card),
    /// the ordering the realm genesis-set framing reuses (AUTH-2.119, RES-1).
    pub fn enrolled(&self) -> impl Iterator<Item = (&Fingerprint, &Enrolled)> {
        self.enrolled.iter()
    }

    /// Returns the retired fingerprints in fingerprint order (AUTH-1.31).
    ///
    /// The order is [`Fingerprint`]'s card's. Each fingerprint yields the
    /// anchor flag it was enrolled under (AUTH-1.30: the flag is for the
    /// fingerprint's lifetime, retirement included, so "was that an anchor
    /// key" is a head read).
    pub fn retired(&self) -> impl Iterator<Item = (&Fingerprint, bool)> {
        self.retired.iter().map(|(fp, anchor)| (fp, *anchor))
    }

    /// Returns whether `fp` is in neither map, enrolled or retired.
    ///
    /// Since nothing ever leaves `retired` and a fingerprint leaves `enrolled`
    /// only for `retired`, a fingerprint in neither — not enrolled now, and
    /// not retired — is one this set has never held. Those are exactly the
    /// fingerprints an enrollment may add (AUTH-2.69's
    /// `k ∉ enrolled ∧ k ∉ retired`), and so [`insert_enrolled`]'s
    /// precondition, held as one fact about this set: a retired fingerprint
    /// never re-enters (AUTH-1.35, I4 AUTH-2.98) and an enrolled one is never
    /// posted over (I9, AUTH-2.104). A question about the whole set, not an
    /// operation on one of its maps. Crate-private because AUTH-1.29 fixes the
    /// public surface; the holder arm's filter is its one caller.
    ///
    /// [`insert_enrolled`]: KeySet::insert_enrolled
    pub(crate) fn admits(&self, fp: &Fingerprint) -> bool {
        !self.enrolled.contains_key(fp) && !self.retired.contains_key(fp)
    }

    /// Returns how many keys are enrolled now.
    ///
    /// Crate-private for the same reason; the retirement arm's whole-set test
    /// (AUTH-2.74) is its one caller, sound there because that arm filtered
    /// its `removed` from `enrolled` and AUTH-2.15 left the record's
    /// fingerprints duplicate-free.
    pub(crate) fn enrolled_len(&self) -> usize {
        self.enrolled.len()
    }

    /// Enrolls one key, deriving the map key with `Fingerprint::of`.
    ///
    /// That derivation establishes AUTH-1.32 by construction (AUTH-2.53).
    /// Crate-private: only `apply` posts.
    ///
    /// **Precondition.** The set [`admits`] `Fingerprint::of(&e.key)` at the
    /// moment of each insert. This routine consults neither map, and an insert
    /// over an enrolled fingerprint replaces its row, flag and all. Broken on
    /// the retired half, AUTH-1.35 (`enrolled ∩ retired = ∅`) and with it I4
    /// (AUTH-2.98) are void, nothing ever removing from `retired`; broken on
    /// the enrolled half, I9 (AUTH-2.104: a fingerprint's flag is fixed in its
    /// set by the record that first enrolled it, as [`Enrolled::anchor`]
    /// states) is void — a post that names one fingerprint twice included, its
    /// second insert finding the first. Nothing here re-checks it. Both
    /// posting arms discharge it, each over a record whose entries are
    /// duplicate-free ([`parse_enroll`]'s postcondition, AUTH-2.15), so no
    /// insert finds an earlier one of its own post: the holder arm posts only
    /// entries the set [`admits`] before the post (AUTH-2.69), and the genesis
    /// arm posts into an empty set, which AUTH-1.36 makes admit every
    /// fingerprint (`enrolled = ∅ ⇒ retired = ∅`, AUTH-2.70).
    ///
    /// [`admits`]: KeySet::admits
    /// [`parse_enroll`]: crate::parse_enroll
    pub(crate) fn insert_enrolled(&mut self, e: Enrolled) {
        self.enrolled.insert(Fingerprint::of(&e.key), e);
    }

    /// Moves one enrolled fingerprint to `retired`, with its enrolled flag.
    ///
    /// The flag is the one it was enrolled under (AUTH-1.30, AUTH-2.74's
    /// post); a fingerprint that is not enrolled moves nothing, so the act is
    /// total and decides nothing (AUTH-2.53). Crate-private: only `apply`
    /// posts, and `classify` guarantees the membership.
    ///
    /// **Precondition.** The fingerprints moved in one post do not exhaust
    /// `enrolled`. This routine does not consult the set's size, so
    /// AUTH-1.36 (`retired ≠ ∅ ⇒ enrolled ≠ ∅`) and with it I3 (AUTH-2.97)
    /// are the caller's to preserve. The retirement arm discharges it with
    /// its `WouldEmpty` test (AUTH-2.74).
    pub(crate) fn move_to_retired(&mut self, fp: &Fingerprint) {
        if let Some(e) = self.enrolled.remove(fp) {
            self.retired.insert(*fp, e.anchor);
        }
    }
}
