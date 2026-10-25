//! §Internal design — the home projection and the home rule: the one place a
//! link's HOME is computed — `home(a)`, M1's `document_of` (EL8b) — and the
//! one place the caller's DOCUMENT predicate is asked about it. Every read
//! that answers for a reader asks through [`home_admitted`], of a candidate
//! home the link store names ahead of that home's links, or through
//! [`home_readable`], at a link's identity; asked of a link directly, the
//! predicate admits every link, which is why the composition has an address
//! of its own. [`home_behind`] is the one cursor question that reads a home
//! off an address: which homes a window resuming past a cursor may pass
//! unasked.

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
/// exactly `readable(home(a))`. The lineage pair and the pointwise pair ask
/// here, at an identity; every result-set read enumerates homes and asks
/// [`home_admitted`] instead.
pub(crate) fn home_readable(readable: &dyn Fn(&Address) -> bool, a: &Address) -> bool {
    home_of(a).is_none_or(|home| readable(&home))
}

/// THE HOME RULE ASKED OF A HOME (PUB-6.13, at the grain PUB-7.18 pins): may
/// the reader read `home` — a candidate the link store names for the read's
/// query, ahead of that home's links?
///
/// A result-set read enumerates the homes the link store names for its
/// query — a document the home slot covers, a candidate the coverage
/// index's directory names at some slot, a home of the whole store — each
/// once, in address order, and asks here of each AHEAD of that home's
/// links, so an unreadable home's whole candidate list is dropped on one
/// test and never walked per link, and the answer's timing counts the homes
/// a reader may not read and nothing finer. One home is named by several
/// slots, several spans and both sides of one read, and the predicate is
/// asked of it once: the store's walk yields a home once however many
/// ranges reached it, which is what keeps the ask count a count of distinct
/// homes (PUB-7.15, PUB-7.16) and what the contract the crate header states
/// promises its caller. The predicate's own question, so no projection
/// composes with it: every home the store names is a document address, and
/// there is nothing to withhold from the projection and nothing for it to
/// answer.
pub(crate) fn home_admitted(readable: &dyn Fn(&Address) -> bool, home: &Address) -> bool {
    readable(home)
}

/// Returns whether every link homed in `home` sorts at or before `cursor`,
/// so a window resuming strictly past the cursor can pass the home unasked
/// and unstabbed.
///
/// A link's address is `home · 0 · s_L · n`, so the homes' links never
/// interleave and a cursor names the home to resume in: a home below the
/// cursor's own home — `document_of` of a link, a document or an element,
/// the member a version member's link is homed in — holds nothing past the
/// cursor, and the cursor's home itself is cut past the cursor by the
/// window. A cursor with no home, a node or an account, lies above every
/// link of the homes below it in T1 order, so those are behind too. Total
/// on every cursor, as every address is a legal cursor.
pub(crate) fn home_behind(home: &Address, cursor: &Address) -> bool {
    match home_of(cursor) {
        Some(resumes_in) => *home < resumes_in,
        None => *home < *cursor,
    }
}
