//! How an address stands in its document's version chain (PUB round 2,
//! lanes 3.1 and 3.2; owner ruling D2b, 2026-09-05): which DOCUMENT a member
//! belongs to ([`trunk_of`], PUB-2.15), which member HEADS that document's
//! chain ([`trunk_head`], PUB-2.53), and whether that document is PUBLISHED
//! ([`published_target`], PUB-2.11) — and, from those three, which
//! arrangement a READER of an address answers from ([`reading_surface`]) and
//! which one a DECLARED DEPOSIT naming it lands in ([`deposit_surface`]) —
//! and which member OPENS the chain, its birth version ([`birth_version`],
//! PUB-2.34). Pure over M1's address arithmetic and M3's slice: no
//! arrangement is read here, and every chain read the write surface makes
//! asks this file rather than spelling the read itself.
//!
//! The two surfaces are two answers because they differ at exactly one kind
//! of address, a PINNED member — any member other than the trunk head
//! (PUB-2.66's pinned older member; PUB-2.39's "older"). Every version
//! address answers its own member forever (PUB-2.50), the head's included;
//! but a declared deposit naming any member lands on the head, so a pinned
//! member's arrangement never grows, and the head's grows until a later
//! trunk member becomes the head.
//!
//! A LINK deposit — M7's writes into a document's link subspace, gated by
//! the same [`Caller`](crate::Caller) — is outside the version-chain rule
//! (PUB-2.12): it seats into the address it names, and neither surface
//! answers for it.
//!
//! CONTRACT, of two kinds. A read on M3's PUBLICATION bit —
//! [`published_target`], and the two surfaces built on it — REQUIRES the
//! address asked about to be a REGISTERED document or a member of one
//! (PUB-6.37): M3 answers that bit for registered addresses alone, and what
//! it returns for any other is no answer. A read on M3's version FRONTIER
//! alone — [`trunk_head`], [`birth_version`] — is TOTAL, as M3's
//! `latest_version` and `first_version_address` are: `None` off the document
//! tier and for a chain with no member, registered or not. PUB-6.37's
//! polarity is the caller's there, as M3 states it — registration is asked
//! first, so an unregistered address is answered by the registration check
//! and a `None` here says only that the chain is empty.

use skep_address::{validate, Address, Level, Tumbler};
use skep_namespace::{first_version_address, M3State};

/// PUB-2.15 — the TRUNK DOCUMENT of a document: its version components
/// stripped off the document field, so a member `A·0·d·v·w` answers `A·0·d`
/// and a document answers itself. Pure address arithmetic, no read: the
/// answer PUB-2.16's "M1 step on the nested form" (`parent`) reaches when
/// taken once per version component, reached here in ONE truncation. A
/// document's field ends its address, and its version components are every
/// component of that field after the first, so they are cut off together —
/// one pass over the address however deep the chain. The depth is a
/// request's to choose, and M1's step re-derives and re-validates the whole
/// remaining prefix each time it is taken, so taking it once per component
/// would make the projection quadratic in that depth.
///
/// AN ADDRESS THAT IS NOT A DOCUMENT ANSWERS ITSELF — an element, whichever
/// member minted it, and an account alike: there is no document to project.
/// So the projection never turns a non-document into a document: a check
/// made on its answer — does it name a registered document? is it the
/// document that minted these addresses? — refuses an address of the wrong
/// tier rather than answering for the document it lies in. A caller holding
/// an element and wanting that element's trunk asks M1's `document_of`
/// first: `document_of` then `trunk_of` is the composition.
///
/// PUB-8.2's one spelling of the projection: a gate ahead of the store
/// imports it rather than restating it. M1's `document_of` is NOT this
/// projection: it answers the FULL document field, version components
/// included, so a member answers itself there.
pub fn trunk_of(a: &Address) -> Address {
    // A Document's field is its address's last and is nonempty — T4 admits no
    // trailing zero — so its version components number `field.len() - 1` and
    // occupy that many components at the address's end.
    let versions = match (a.level(), a.document_field()) {
        (Level::Document, Some(field)) => field.len() - 1,
        _ => return a.clone(),
    };
    if versions == 0 {
        return a.clone();
    }
    let kept = a.tumbler().len() - versions;
    let trunk = Tumbler::new(a.tumbler().iter().take(kept).cloned())
        .expect("a document keeps its node, account and first document component");
    validate(trunk).expect("a document cut back to its first document component is T4-valid")
}

/// PUB-2.53 — the TRUNK HEAD of the document `doc` belongs to: the latest
/// member of the trunk's own version chain `D.1, D.2, …` anchored at
/// `trunk_of(doc)`, or `None` while that document has no member. THE ONE
/// definition of "the latest version" (PUB-2.49): a daughter chain —
/// `D.2.1, D.2.2, …`, anchored at a member — floats nothing and is never
/// answered here, whichever member `doc` names. M3's `latest_version` is the
/// chain read; the projection to the trunk is [`trunk_of`], so a member, a
/// daughter and the bare document all ask about one chain. The head a shot judges its
/// base against (PUB-2.39) is this one, which is the head every floating
/// reader answers from.
///
/// ASKED BEFORE THE CHAIN MOVES. A composite that extends a chain —
/// `version`'s owned arm, the publish shot — asks this, and the two surfaces
/// built on it, of its working state BEFORE it stages its own
/// `mint_version`: once that record is staged, a trunk member it mints is
/// the head, and the answer would name the member still being built. Both
/// composites ask first, and the suite pins `version`'s order by forking one
/// chain twice (`a_declared_deposit_into_a_published_chain_lands_in_the_head_member_alone`).
///
/// TOTAL: `None` off the document tier and for a chain with no member,
/// registered or not, as M3's `latest_version` answers. PUB-6.37's polarity
/// is the caller's — registration asked first, so an unregistered address is
/// answered by the registration check and a `None` here says only that the
/// chain is empty.
pub fn trunk_head(m3: &M3State, doc: &Address) -> Option<Address> {
    m3.latest_version(&trunk_of(doc))
}

/// PUB-2.34 — the BIRTH VERSION of the document `doc` projects to
/// (PUB-2.15): the member that OPENS its trunk's own version chain, `D.1` —
/// M3's [`first_version_address`] of the trunk — or `None` while that chain
/// has no member. The trunk, each of its members and each daughter answer the
/// one trunk's `D.1`; a daughter chain's own first member (`D.3.1`) is never
/// answered. The projection comes first, and must: M3 opens the chain of
/// whatever it is handed, so a member handed through would answer its own
/// daughter chain's first address — well-formed, minted nowhere, and no
/// error. A chain is anchored at a document alone, so every other tier
/// answers `None`. TOTAL, as [`trunk_head`] is, and PUB-6.37's polarity the
/// caller's here too.
pub fn birth_version(m3: &M3State, doc: &Address) -> Option<Address> {
    trunk_head(m3, doc)?;
    first_version_address(&trunk_of(doc))
}

/// Is `doc` a birth version — [`birth_version`]'s member, asked of the
/// address alone, with no frontier read? The fold's question of the member a
/// minting record names, which that record's own commit mints, so whether it
/// exists is not in doubt. Settled at the first comparison for every address
/// that is no version member, as a cross-owner fork's fresh document is.
pub(crate) fn is_birth_version(doc: &Address) -> bool {
    let trunk = trunk_of(doc);
    trunk != *doc && first_version_address(&trunk).as_ref() == Some(doc)
}

/// PUB-2.11's input, and M5's one publication read: is the DOCUMENT `doc`
/// projects to (PUB-2.15) published — a target the in-place advance refusal
/// applies to? M3's one publication bit ([`M3State::published`], the record
/// its minting `Allocate` journaled), read after [`trunk_of`] — never the
/// member's own bit, which PUB-8.17's inheritance makes agree with its
/// document's today and which the projection keeps from ever deciding a
/// refusal.
///
/// Every publication read M5 makes is this one. It is public so that a door
/// ahead of the store, pre-evaluating the refusal, can ask the rule the store
/// enforces rather than restate it.
///
/// CONTRACT — `doc` is a REGISTERED document or a member of one (PUB-6.37):
/// the read is answered for registered addresses alone. A member's trunk is
/// registered whenever the member is (a member is minted under a registered
/// source, recursively), so the projected read is inside M3's contract too.
/// A caller asks `is_registered_document` first.
pub fn published_target(m3: &M3State, doc: &Address) -> bool {
    m3.published(&trunk_of(doc))
}

/// HEAD-FLOAT — the arrangement a READER of `doc` answers from (PUB-2.49,
/// PUB-2.50, PUB-2.53, PUB-2.66): the ONE place the float is decided. A
/// reader that floats asks it which arrangement to read, then reads that
/// arrangement with reads that answer whatever address they are handed; this
/// read resolves nothing itself. The readers that do not float — M5's own
/// reads on [`M5State`](crate::M5State), [`resolve`](crate::M5State::resolve)
/// among them, and COPY's source spans — answer the address named.
///
/// * A VERSION address answers ITSELF, forever (PUB-2.50).
/// * A BARE document address that is PUBLISHED answers its TRUNK HEAD
///   (PUB-2.53) — and, while it has no member yet, its OWN arrangement: a
///   published document between its mint and its birth version serves what
///   it holds, its declared deposits landing there until a head member exists
///   (PUB-2.66's memberless reading).
/// * A PRIVATE document answers itself: head-float is INERT there. A
///   private document is versionless (PUB-2.9) and so has no member to
///   float to, and the float keys on the document's publication bit
///   ([`published_target`]), so a private document answers its own
///   arrangement even over a member a pre-model state holds under it.
///
/// Pure over M3's slice: one projection, one publication read, one frontier
/// read, asked before the chain moves as [`trunk_head`] states. CONTRACT —
/// `doc` is a REGISTERED document (PUB-6.37): M3's publication read is
/// answered for registered addresses alone, and every reader that floats has
/// already refused an unregistered argument with its own registration code.
pub fn reading_surface(m3: &M3State, doc: &Address) -> Address {
    if trunk_of(doc) != *doc {
        return doc.clone();
    }
    if !published_target(m3, doc) {
        return doc.clone();
    }
    trunk_head(m3, doc).unwrap_or_else(|| doc.clone())
}

/// The arrangement an INSERT naming `doc` places into, which on a published
/// document only a DECLARED deposit reaches (PUB-2.59, PUB-2.65, PUB-2.66):
///
/// * `doc`'s OWN while its document is private — the declaration is inert
///   there, and every insert edits the named arrangement;
/// * the chain's HEAD member's while the document is published and has one —
///   whichever address of the chain `doc` names: the bare document, the head
///   itself, or a pinned member, whose arrangement never grows;
/// * the document's own while it is published and memberless, which is what
///   its readers answer from until a head exists (PUB-2.66's memberless
///   reading).
///
/// It differs from [`reading_surface`] at exactly a PINNED member: a reader
/// of the member answers the member (PUB-2.50), a declared deposit naming it
/// lands on the head. Only the PLACEMENT floats — the atom's identity is
/// minted under the address the caller named, which is `insert`'s business,
/// not this read's. Asked before the chain moves, as [`trunk_head`] states;
/// CONTRACT as [`published_target`] states.
///
/// A caller building a declared deposit asks this for the arrangement whose
/// `n_C + 1` is the one position a published document admits
/// ([`Vstream::insert`](crate::Vstream::insert)). Content only: a link
/// deposit seats into the address it names (PUB-2.12).
pub fn deposit_surface(m3: &M3State, doc: &Address) -> Address {
    if !published_target(m3, doc) {
        return doc.clone();
    }
    trunk_head(m3, doc).unwrap_or_else(|| trunk_of(doc))
}

#[cfg(test)]
mod tests;
