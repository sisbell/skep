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
        let mut bytes = Vec::new();
        push_class(&mut bytes, &self.ty);
        push_class(&mut bytes, &self.from);
        push_class(&mut bytes, &self.to);
        LockKey::new(Space::CoverageClass, &bytes)
    }
}

fn push_class(buf: &mut Vec<u8>, class: &CoverageClass) {
    match class {
        CoverageClass::Addrs(set) => {
            buf.extend_from_slice(&(set.len() as u64).to_be_bytes());
            for t in set.iter() {
                buf.extend_from_slice(&(t.len() as u64).to_be_bytes());
                for c in t {
                    let comp = c.to_bytes_be();
                    buf.extend_from_slice(&(comp.len() as u64).to_be_bytes());
                    buf.extend_from_slice(&comp);
                }
            }
        }
        CoverageClass::Extents(_) => unreachable!(
            "no Extents class is ever serialized into a LockKey: every idem⊤ dedup key is \
             validated address-denoting before the lock is built (§Core data model)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::slice;

    use skep_address::{validate, Address, Nat, Tumbler};

    use super::*;
    use crate::endset::enc;

    fn addr(comps: &[u32]) -> Address {
        validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty"))
            .expect("T4-valid")
    }

    fn link(from: &[Address], to: &[Address], ty: &[Address]) -> Link {
        Link::new([enc(from), enc(to), enc(ty)]).expect("arity 3")
    }

    #[test]
    fn key_is_the_coverage_identity_and_the_lock_section_follows_it() {
        let a = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
        let b = addr(&[1, 0, 1, 0, 1, 0, 1, 2]);
        let ty = addr(&[9, 0, 9, 0, 9, 0, 9, 1]);
        // Span ORDER is decomposition, never identity: two structurally
        // distinct values of one coverage are one I0 class, and — because
        // the lock is derived from the key — one M2 section.
        let ab = link(slice::from_ref(&a), &[a.clone(), b.clone()], slice::from_ref(&ty));
        let ba = link(slice::from_ref(&a), &[b.clone(), a.clone()], slice::from_ref(&ty));
        assert_ne!(ab, ba);
        assert_eq!(DedupKey::of(&ab), DedupKey::of(&ba));
        assert_eq!(DedupKey::of(&ab).lock_key(), DedupKey::of(&ba).lock_key());

        // A distinct class contends with neither.
        let other = link(slice::from_ref(&b), &[a.clone(), b.clone()], slice::from_ref(&ty));
        assert_ne!(DedupKey::of(&ab), DedupKey::of(&other));
        assert_ne!(DedupKey::of(&ab).lock_key(), DedupKey::of(&other).lock_key());

        // The three slots are distinguishable positions of the key, not a
        // bag: swapping F and G is a different section.
        let swapped = link(&[a.clone(), b.clone()], slice::from_ref(&a), slice::from_ref(&ty));
        assert_ne!(DedupKey::of(&ab).lock_key(), DedupKey::of(&swapped).lock_key());
    }
}
