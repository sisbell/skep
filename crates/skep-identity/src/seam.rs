//! The fold seam — AUTH-2.29–2.35, AUTH-2.126.
//!
//! The seam answers FOUR FACTS across two traits and owns no algorithm
//! (AUTH-2.31). The crate stays generic over the world-fact abstraction —
//! it never names a concrete `World` (composition contract); the engine
//! implements [`Values`] and [`FoldCtx`] for its assembled world, a mirror
//! for its projection.

use skep_address::{checked_inc, parent, Address, Level, Tumbler};

/// AUTH-2.29 — the seam's one genuinely world-side fact (M4 `value_at`):
/// the VALUE at one I-address AS OF THE CTX'S POSITION — never at-head
/// (AUTH-2.5: a value read answered at head MUST NOT be used to fold);
/// `None` means the home never minted that address.
///
/// AUTH-2.30 — the key is `&Tumbler`, the walk's own output and M4's own
/// key, so NO fallible per-position `validate` lift exists on the payload
/// path: a span start's validity and position-hood are checked ONCE per
/// span, ahead of the walk (AUTH-2.38).
pub trait Values {
    /// The value at `at`, as of the ctx's position; `None` iff never minted.
    ///
    /// AUTH-1.22 — every `Some` answer carries AT LEAST ONE BYTE, and that is
    /// the implementor's obligation rather than a nicety: the payload read's
    /// reach walk (AUTH-2.42) is bounded by the byte cap alone (AUTH-2.43),
    /// because a span whose width acts above the element level covers every
    /// ordinal above its start. A ctx that can answer `Some(&[])` at a covered
    /// position leaves that walk unbounded and MUST NOT be used to fold until
    /// a second bound on per-record span/position work exists. `record_bytes`
    /// debug-asserts the premise at the one call that rests on it.
    fn value_at(&self, at: &Tumbler) -> Option<&[u8]>;
}

/// AUTH-2.31 — the fold's world seam, over [`Values`].
pub trait FoldCtx: Values {
    /// AUTH-2.32 — ω(a), UNPROJECTED: one longest-prefix resolution over the
    /// principal registry (M3 `effective_owner`, AUTH-2.108); `None` iff `a`
    /// is unowned.
    fn owner_of(&self, a: &Address) -> Option<Owner>;

    /// AUTH-2.33 — M3 `entity_level(a) == Some(Account)`.
    fn is_account(&self, a: &Address) -> bool;

    /// AUTH-2.34 — the document's BIRTH state: publication is at birth and no
    /// document ever transitions, so the answer is CONSTANT over every
    /// record's life. v1 wires it constant `true` (AUTH-2.117) and the fold
    /// asks anyway (AUTH-2.102, I7); a mirror derives it as the guest
    /// visibility class (AUTH-2.123). NOT an I2 frozen constant (AUTH-2.90).
    fn is_published(&self, doc: &Address) -> bool;
}

/// AUTH-2.31/AUTH-2.32 — an ω answer: the owning principal's prefix, and
/// whether that principal is the bootstrap principal.
/// `is_bootstrap` is `id == BOOTSTRAP_PRINCIPAL`, compared inside the ctx
/// implementor where the principal ids live — never inside `skep-identity`
/// (AUTH-2.32, AUTH-2.108).
#[derive(Debug, Clone)]
pub struct Owner {
    /// The owning principal's prefix.
    pub prefix: Address,
    /// Whether the owner is the bootstrap principal.
    pub is_bootstrap: bool,
}

/// AUTH-2.35 — the crate's own ω projection (never re-implemented outside
/// it): the account a document belongs to, `ctx.owner_of(doc)?.prefix`. A
/// non-folding reader takes `owner_of(doc)?.prefix` itself.
pub(crate) fn document_account(ctx: &impl FoldCtx, doc: &Address) -> Option<Address> {
    ctx.owner_of(doc).map(|owner| owner.prefix)
}

/// AUTH-2.35 — the delegator classification `delegator(ctx, a)` projects to.
pub(crate) enum Delegator {
    /// The parent's owner is the bootstrap principal — the bootstrap-delegated
    /// tier: every account one separator deep, on every board (AUTH-2.65).
    Bootstrap,
    /// The parent's owner is an account principal (an account delegated
    /// BENEATH an account); carries that owner's prefix.
    Account(Address),
}

/// AUTH-2.35 — the crate's second ω projection (crate-private): M1
/// `parent(a)` then `owner_of` mapped — `Bootstrap` iff that owner is the
/// bootstrap principal, `Account(prefix)` otherwise, `None` iff the account
/// has no parent or the parent is unowned (unreachable in practice for an
/// address M3 admits as an account, merely total here — AUTH-2.106).
pub(crate) fn delegator(ctx: &impl FoldCtx, a: &Address) -> Option<Delegator> {
    let p = parent(a)?;
    let owner = ctx.owner_of(&p)?;
    Some(if owner.is_bootstrap {
        Delegator::Bootstrap
    } else {
        Delegator::Account(owner.prefix)
    })
}

/// AUTH-2.126 (RES-17) — THE DOC-1 ADDRESS: the address of `a`'s FIRST
/// document, computed FROM THE ACCOUNT ADDRESS ALONE as address arithmetic —
/// `inc(a, 2)` = `a·0·1` under AUTH-2.109's pinned M3 expectation (verified
/// against M1's `inc`: `k = 2` appends one zero then a `1`) — with NO query
/// and NO new seam method; [`FoldCtx`] still answers AUTH-2.31's four facts.
/// The home pin (AUTH-2.127) compares credential homes against this address.
pub(crate) fn doc_1_of(a: &Address) -> Address {
    match checked_inc(a, 2) {
        Ok(doc) => doc,
        Err(_) => {
            // The TA5a gate refuses k = 2 only for an Element-level operand;
            // no conforming ω answers an element-level principal prefix
            // (M3 registers principals at node/account prefixes). Total,
            // never a panic (AUTH-2.57): the returned prefix is document-of
            // nothing, so every home comparison against it refuses.
            debug_assert!(
                a.level() != Level::Element,
                "doc_1_of on an element-level prefix — no conforming ctx answers one"
            );
            a.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::doc_1_of;
    use skep_address::{validate, Nat, Tumbler};

    fn addr(comps: &[u32]) -> skep_address::Address {
        validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty"))
            .expect("T4-valid")
    }

    /// AUTH-2.126/AUTH-2.109 — the doc-1 form is `A·0·1` (`inc(A, 2)`).
    #[test]
    fn doc_1_is_account_dot_0_dot_1() {
        assert!(doc_1_of(&addr(&[1, 1, 0, 5])) == addr(&[1, 1, 0, 5, 0, 1]));
        // A nested account's first document sits under the nested prefix.
        assert!(doc_1_of(&addr(&[1, 1, 0, 3, 1])) == addr(&[1, 1, 0, 3, 1, 0, 1]));
        // A node-level prefix (the bootstrap owner's) still answers totally.
        assert!(doc_1_of(&addr(&[1, 1])) == addr(&[1, 1, 0, 1]));
    }
}
