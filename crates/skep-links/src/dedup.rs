//! §3 — the idempotence identity: [`DedupKey`], which knows what dedup class
//! a link value lands in and how that class serializes into M2's opaque
//! `LockKey`.

use skep_kernel::{LockKey, Space};

use crate::endset::{coverage_class, CoverageClass, Link};

/// The idempotence identity `I0 = (cov(F), cov(G))` within a type class
/// (ASN-0128 I0/I1) — the dedup hint key, the in-txn check's lookup and,
/// serialized, the `LockKey`'s payload. Crate-internal: it never crosses a
/// seam (the interface exposes only the opaque `LockKey` bytes).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct DedupKey {
    pub(crate) ty: CoverageClass,
    pub(crate) from: CoverageClass,
    pub(crate) to: CoverageClass,
}

impl DedupKey {
    /// I0 of a link value — the ONE derivation. The pre-transact lock, the
    /// in-txn incumbent lookup and the hint fold all state the identity
    /// through this constructor, so the section M2 serializes is BY
    /// CONSTRUCTION the section the check reads and the fold indexes.
    pub(crate) fn of(value: &Link) -> DedupKey {
        DedupKey {
            ty: coverage_class(value.type_slot()),
            from: coverage_class(value.from_slot()),
            to: coverage_class(value.to_slot()),
        }
    }

    /// The idem⊤ key as M2's opaque `LockKey`: the `Space::CoverageClass` tag
    /// byte, then the three classes as length-prefixed minimal antichains.
    /// Same I0-class ⇒ same bytes ⇒ M2 serializes the check-and-deposit
    /// (I1a/I4); different class ⇒ no contention. Partitioned BY CLASS, never
    /// by home (§3).
    pub(crate) fn lock_key(&self) -> LockKey {
        let mut buf = Vec::new();
        push_class(&mut buf, &self.ty);
        push_class(&mut buf, &self.from);
        push_class(&mut buf, &self.to);
        LockKey::new(Space::CoverageClass, &buf)
    }
}

/// One class as the lock's payload: the ≼-minimal denoted antichain, length-
/// prefixed. The format serializes DENOTED CLASSES ONLY, and an extent class
/// reaching it FAIL-STOPS rather than being skipped — a skipped slot would
/// collapse two distinct I0 identities onto one section, silently voiding the
/// check-and-deposit serialization (I1a/I4) the section exists to provide.
///
/// What keeps an extent class out is the construction of the three ops that
/// take a section — `emit`, `nullify` and `assert_sup` build F and G through
/// `enc` and validate `ty` address-denoting — asserted at
/// `deposit_lock_set`, which is where the decision to take one is made. It is
/// NOT the registered-idem⊤ test beside that assertion, which reads the type
/// slot alone: the open surface does deposit extent-classed F and G into
/// registered idem⊤ classes, and the hint fold keys those values as it keys
/// any other, so extent-classed dedup keys are live in the hint map. They
/// take no lock section, MAKELINK facing no dedup check at all (§3).
fn push_class(buf: &mut Vec<u8>, class: &CoverageClass) {
    let Some(denoted) = class.denoted() else {
        unreachable!(
            "the I0 lock format serializes denoted classes only; an extent-classed slot is \
             refused at the section decision, never skipped here (§3)"
        )
    };
    buf.extend_from_slice(&(denoted.len() as u64).to_be_bytes());
    for t in denoted.iter() {
        buf.extend_from_slice(&(t.len() as u64).to_be_bytes());
        for component in t {
            let bytes = component.to_bytes_be();
            buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            buf.extend_from_slice(&bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use skep_address::{validate, Address, Nat, Span, Tumbler};

    use super::*;
    use crate::endset::{enc, Endset};

    fn addr(comps: &[u32]) -> Address {
        validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty"))
            .expect("T4-valid")
    }

    fn link<'a>(
        from: impl IntoIterator<Item = &'a Address>,
        to: impl IntoIterator<Item = &'a Address>,
        ty: impl IntoIterator<Item = &'a Address>,
    ) -> Link {
        Link::triple(enc(from), enc(to), enc(ty))
    }

    #[test]
    fn key_is_the_coverage_identity_and_the_lock_section_follows_it() {
        let a = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
        let b = addr(&[1, 0, 1, 0, 1, 0, 1, 2]);
        let ty = addr(&[1, 1, 0, 1, 0, 1, 0, 1, 1]); // pred_def's ghost tumbler
        // Span ORDER is decomposition, never identity: two structurally
        // distinct values of one coverage are one I0 class, and — because
        // the lock is derived from the key — one M2 section.
        let ab = link([&a], [&a, &b], [&ty]);
        let ba = link([&a], [&b, &a], [&ty]);
        assert_ne!(ab, ba);
        assert_eq!(DedupKey::of(&ab), DedupKey::of(&ba));
        assert_eq!(DedupKey::of(&ab).lock_key(), DedupKey::of(&ba).lock_key());

        // A distinct class contends with neither.
        let other = link([&b], [&a, &b], [&ty]);
        assert_ne!(DedupKey::of(&ab), DedupKey::of(&other));
        assert_ne!(DedupKey::of(&ab).lock_key(), DedupKey::of(&other).lock_key());

        // The three slots are distinguishable positions of the key, not a
        // bag: swapping F and G is a different section.
        let swapped = link([&a, &b], [&a], [&ty]);
        assert_ne!(DedupKey::of(&ab).lock_key(), DedupKey::of(&swapped).lock_key());
    }

    /// The I0 lock format serializes denoted classes only, and an extent class
    /// reaching it FAIL-STOPS. The tempting repair — skipping such a slot, or
    /// dropping the section — is what this refuses: an extent-classed key is
    /// a live entry in the dedup HINT map (the open surface deposits
    /// extent-classed F and G into registered idem⊤ classes), so a skip would
    /// collapse two distinct I0 identities onto one section and silently void
    /// the check-and-deposit serialization the section exists to provide.
    #[test]
    #[should_panic(expected = "denoted classes only")]
    fn a_lock_key_over_an_extent_classed_slot_fail_stops() {
        let ty = addr(&[1, 1, 0, 1, 0, 1, 0, 1, 1]); // pred_def — registered idem⊤
        let extent = Endset::from_spans([Span::from_endpoints(
            addr(&[1, 0, 1, 0, 1, 0, 1, 1]).tumbler().clone(),
            addr(&[1, 0, 1, 0, 1, 0, 1, 4]).tumbler(),
        )
        .expect("a content extent")]);
        let value = Link::triple(extent, Endset::empty(), enc([&ty]));
        assert!(
            DedupKey::of(&value).from.denoted().is_none(),
            "the F slot really is extent-classed, so the key reaches the format constraint"
        );
        let _ = DedupKey::of(&value).lock_key();
    }
}
