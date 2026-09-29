//! The fold seam — AUTH-2.29–2.34.
//!
//! The seam answers FOUR FACTS across two traits and owns no algorithm
//! (AUTH-2.31). The crate stays generic over the world-fact abstraction —
//! it never names a concrete `World` (composition contract); the fold's host
//! implements [`Values`] and [`FoldCtx`] for its assembled world — the
//! engine in AUTH-2.79's cast, skepd's `WorldCtx` as built (the crate-level
//! composition note) — and a mirror for its projection. A host holding its
//! world behind a reference or a box — `&dyn FoldCtx`, `Box<dyn FoldCtx>` —
//! writes no impl of its own: both traits forward through `&T` and `Box<T>`,
//! as std's own traits do. What the fold derives from those facts — its ω
//! projections (AUTH-2.35) and the doc-1 address (AUTH-2.126) — is the fold's
//! own, private to `state.rs`.

use skep_address::{Address, Tumbler};

/// AUTH-2.29 — the seam's one genuinely world-side fact (M4 `value_at`):
/// the VALUE at one I-address AS OF THE CTX'S COMMIT — the point in the
/// record stream the ctx answers as of, which for the fold is the deposit's
/// own commit — never at-head (AUTH-2.5: a value read answered at head MUST
/// NOT be used to fold); `None` means the home had not minted that address
/// AS OF THAT COMMIT — not that it never will. The two facts an implementor
/// must not fuse: `at` is a POSITION (an element address, AUTH-2.40), the
/// commit is a point in the STREAM. Bare, "position" in this crate is only
/// ever the former; the one journal index the crate holds, the
/// [`BoardTerm`](crate::BoardTerm)'s, is spelled `log_position`.
///
/// AUTH-2.30 — the key is `&Tumbler`, the walk's own output and M4's own
/// key, so NO fallible per-position `validate` lift exists on the payload
/// path: a span start's validity and position-hood are checked ONCE per
/// span, ahead of the walk (AUTH-2.38).
pub trait Values {
    /// The value at `at`, as of the ctx's commit; `None` iff the home had
    /// not minted `at` as of that commit.
    ///
    /// AUTH-1.22 — every `Some` answer carries AT LEAST ONE BYTE, and that is
    /// the implementor's obligation rather than a nicety: the payload read's
    /// reach walk (AUTH-2.42) is bounded by the byte cap (AUTH-2.43) only
    /// while it holds, because a span whose width acts above the element
    /// level covers every ordinal above its start.
    ///
    /// A ctx that answers `Some(&[])` at a covered position is NOT one this
    /// crate folds under, and what the crate does about it splits by BUILD.
    /// In DEBUG, `record_bytes` debug-asserts the premise at the one call that
    /// rests on it, so it IS a detector — of every violation the walk REACHES,
    /// a SINGLE zero-byte answer among non-empty ones as much as a ctx that
    /// answers `Some(&[])` everywhere — naming it at its first occurrence, and
    /// the record does not fold. It detects nothing the walk never asks: a
    /// position past an earlier refusal is never read. In RELEASE nothing is
    /// named. The one mechanism that still bears on the violation there is the
    /// per-record position budget, and it is NOT a detector: it bounds the
    /// WORST case, where every covered position answers `Some(&[])` and
    /// nothing else would end the walk (it ends at `TooLarge`, in bounded
    /// work), and `TooLarge` is the verdict an honest over-cap record earns
    /// too, so no caller can read a broken premise off it. A SINGLE zero-byte
    /// answer among non-empty ones reaches nothing at all in release: it
    /// appends nothing, the walk ends where it always would, and the record
    /// reads, parses and FOLDS with nothing reporting that the premise was
    /// broken. Discharging AUTH-1.22 is the implementor's, in full.
    fn value_at(&self, at: &Tumbler) -> Option<&[u8]>;
}

/// AUTH-2.31 — the fold's world seam, over [`Values`] and on the SAME ctx:
/// every fact below is answered AS OF THE CTX'S COMMIT, as `value_at` is —
/// for the fold, the deposit's own commit, the point
/// [`IdentityState`](crate::IdentityState)'s I2 statement (AUTH-2.90) rests
/// on. AUTH-2.29 calls `value_at` the seam's one genuinely world-side fact:
/// its one read of the CONTENT store, not its one time-bound answer. Of the
/// three below, two cannot tell the commit from the head for anything the
/// fold asks: ω of a registered home or of a registered principal's parent —
/// fixed once that home or principal is registered, M3 registering a
/// principal before anything beneath it and none at a document — and a
/// registered document's birth state (AUTH-2.34). [`FoldCtx::is_account`]
/// can: the fold asks it of the address an enroll/retire `to` names, an
/// endset names addresses verbatim (M7 deposits a ghost name as readily as a
/// minted one), and that address may become an account only after the
/// deposit commits. Answered at head, such a deposit — `malformed_shape` at
/// its commit — can fold honored, and the table is then the head's, not the
/// stream's.
pub trait FoldCtx: Values {
    /// AUTH-2.32 — ω(a), UNPROJECTED: one longest-prefix resolution over the
    /// principal registry (M3 `effective_owner`, AUTH-2.108); `None` iff `a`
    /// is unowned.
    ///
    /// The prefix answered is a PRINCIPAL prefix — the address M3 registered
    /// the principal at, node- or account-level — never a document- or
    /// element-level address. This crate takes doc-1 arithmetic on it
    /// (`inc(prefix, 2)`, AUTH-2.126/AUTH-2.109) for the home pin, and a
    /// prefix at any other level answers an address that is document-of
    /// nothing: under such a ctx NO credential deposit can pass the home pin
    /// at all, so an otherwise-conforming one refuses `not_doc_one` —
    /// silently, and in release. The crate's `doc_1_of` debug-asserts only
    /// the element-level half, the half that trips M1's TA5a gate; a
    /// document-level prefix passes that gate, is monitored nowhere, and is
    /// the implementor's alone.
    fn owner_of(&self, a: &Address) -> Option<Owner>;

    /// AUTH-2.33 — M3 `is_registered_account(a)`, AS OF THE CTX'S COMMIT: of
    /// this trait's three facts, the one an at-head answer moves (the trait's
    /// card).
    fn is_account(&self, a: &Address) -> bool;

    /// AUTH-2.34 — the document's BIRTH state: publication is at birth and no
    /// document ever transitions (PUB-1.9, the bit a document is born with),
    /// so the answer is CONSTANT over every record's life. The origin answers
    /// it off the EXCEPTION SET — `doc ∉ exception_set`, the engine's derived
    /// membership index over M3's per-document publication bit, journaled on
    /// the minting record (PUB-7.5; owner ruling D1, 2026-09-05: one
    /// publication definition) — where v1 wired it constant `true`
    /// (AUTH-2.117); the fold asks it either way (AUTH-2.102, I7), and a
    /// mirror derives it as the guest visibility class (AUTH-2.123). NOT an
    /// I2 frozen constant (AUTH-2.90).
    ///
    /// Its domain is REGISTERED documents — a birth state is a fact about a
    /// born document — and the fold asks it of a deposit's `home` alone, which
    /// [`LinkDeposit`](crate::LinkDeposit) requires to be one. Outside that
    /// domain no answer is specified (the origin's set answers `true` there,
    /// fail-open), and the fold cannot screen such an address out for the
    /// implementor: ω's answer at item 2 does not imply registration.
    fn is_published(&self, doc: &Address) -> bool;
}

/// AUTH-2.31/AUTH-2.32 — an ω answer: the owning principal's prefix, and
/// whether that principal is the bootstrap principal.
/// `is_bootstrap` is `id == BOOTSTRAP_PRINCIPAL`, compared inside the ctx
/// implementor where the principal ids live — never inside `skep-identity`
/// (AUTH-2.32, AUTH-2.108).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    /// The owning principal's prefix.
    pub prefix: Address,
    /// Whether the owner is the bootstrap principal.
    pub is_bootstrap: bool,
}

/// [`Values`] through a reference — the forwarding impl std gives its own
/// object-safe traits (`Display for &T`, `Read for &mut R`). An
/// `impl Values` parameter is a generic with an implicit `Sized` bound, so
/// `dyn Values` itself never satisfies one: this and the `Box` impl below are
/// what let a host holding its world as `&dyn Values` or `Box<dyn Values>` —
/// and, with [`FoldCtx`]'s pair below, as a `dyn FoldCtx` — hand it to
/// [`record_bytes`](crate::record_bytes) and the fold. The orphan rule leaves
/// such a host no impl of its own to write.
impl<T: Values + ?Sized> Values for &T {
    fn value_at(&self, at: &Tumbler) -> Option<&[u8]> {
        (**self).value_at(at)
    }
}

/// [`Values`] through a box, as through a reference above.
impl<T: Values + ?Sized> Values for Box<T> {
    fn value_at(&self, at: &Tumbler) -> Option<&[u8]> {
        (**self).value_at(at)
    }
}

/// [`FoldCtx`] through a reference, as [`Values`] above: every fact is the
/// held ctx's own, answered as of that ctx's commit.
impl<T: FoldCtx + ?Sized> FoldCtx for &T {
    fn owner_of(&self, a: &Address) -> Option<Owner> {
        (**self).owner_of(a)
    }

    fn is_account(&self, a: &Address) -> bool {
        (**self).is_account(a)
    }

    fn is_published(&self, doc: &Address) -> bool {
        (**self).is_published(doc)
    }
}

/// [`FoldCtx`] through a box, as through a reference above.
impl<T: FoldCtx + ?Sized> FoldCtx for Box<T> {
    fn owner_of(&self, a: &Address) -> Option<Owner> {
        (**self).owner_of(a)
    }

    fn is_account(&self, a: &Address) -> bool {
        (**self).is_account(a)
    }

    fn is_published(&self, doc: &Address) -> bool {
        (**self).is_published(doc)
    }
}
