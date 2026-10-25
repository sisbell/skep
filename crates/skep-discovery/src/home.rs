//! §Internal design — the home projection and the home rule: the one place a
//! link's HOME is computed — `home(a)`, M1's `document_of` (EL8b) — and the
//! one place the caller's DOCUMENT predicate is asked about it. Every read
//! that answers for a reader asks through [`home_readable`], at a link's
//! identity, or through [`home_admitted`], of a home the descriptor's `home`
//! slot names ahead of that home's links; asked of a link directly, the
//! predicate admits every link, which is why the composition has an address
//! of its own.

use skep_address::{document_of, Address};

/// `home(a)`: the origin Document of `a` — M1's `document_of` projection
/// (EL8b), spelled once so every read attributes an address to the same home.
/// `None` for an address with no document field — a node or an account —
/// which lives under no home.
///
/// Every LINK has a home, so on a key of the link store this is always
/// `Some`; the partiality stays in the type all the same, because the
/// pointwise pair hands the home rule a CALLER's address before anything
/// establishes that it is a link, and a projection that assumed one would
/// fault on the first node or account address a request names. So no read
/// reaches a home that is not there: each caller states, where it asks, what
/// an absent home means to it.
pub(crate) fn home_of(a: &Address) -> Option<Address> {
    document_of(a)
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
    home_of(a).is_none_or(|home| readable(&home))
}

/// THE HOME RULE ASKED OF A HOME (PUB-6.13, at the grain PUB-7.18 pins): may
/// the reader read `home` — a document the descriptor's `home` slot covers
/// and the store says holds links — asked ONCE, ahead of that home's links?
/// The predicate's own question, so no projection composes with it: the one
/// place it is asked of a document that is not a link's home read off the
/// link.
///
/// Where [`home_readable`] runs at a link's identity, after every other
/// filter, this runs before the home's links are read at all, so an
/// unreadable home's whole candidate list is dropped on one test and never
/// walked per link — which is what keeps the answer's timing from counting
/// the links of a home the reader may not read, and what asks the predicate
/// once per distinct home rather than once per candidate. Every home the
/// store names is a document address, so there is nothing to withhold from
/// the projection and nothing for it to answer: the question is the
/// predicate's, whole.
pub(crate) fn home_admitted(readable: &dyn Fn(&Address) -> bool, home: &Address) -> bool {
    readable(home)
}
