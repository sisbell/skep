//! §Internal design — the home projection and the home rule: the one place a
//! link's HOME is computed — `home(a)`, M1's `document_of` (EL8b) — and the
//! one place the caller's DOCUMENT predicate is asked about it. Every read
//! that answers for a reader asks through [`home_readable`]; asked of a link
//! directly, the predicate admits every link, which is why the composition
//! has an address of its own.

use skep_address::{document_of, Address};

/// `home(a)`: the origin Document of a link address — M1's `document_of`
/// projection (EL8b), spelled once so the descriptor family's home filter and
/// the lineage read-out attribute a link the same way.
pub(crate) fn home_of(a: &Address) -> Address {
    document_of(a).expect("a link address has zeros = 3, so its origin Document exists")
}

/// THE HOME RULE (PUB-6.13): may the reader read `a`'s home? The home
/// projection composed with the caller's predicate, in one place, because
/// `readable` answers about a DOCUMENT and every question the rule answers
/// here is asked about a LINK. Asked directly of the link it would answer
/// TRUE: an element address is absent from the publication index exactly as
/// a published document is, so the rule would admit every link. That is why
/// the composition is an element and not an idiom.
///
/// Total on every address, because the pointwise pair asks it of a
/// caller's `a` before anything establishes that `a` is a link: an address
/// with no document field — a node or an account — lives under no home and
/// has nothing to withhold, so the rule admits it and the store's own answer
/// about it stands. Every link has a home, so on a result set this is
/// exactly `readable(home(a))`.
pub(crate) fn home_readable(readable: &dyn Fn(&Address) -> bool, a: &Address) -> bool {
    document_of(a).is_none_or(|home| readable(&home))
}
