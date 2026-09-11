//! How an address stands in its document's version chain (PUB round 2,
//! lanes 3.1 and 3.2; owner ruling D2b, 2026-09-05): which DOCUMENT a member
//! belongs to ([`trunk_of`], PUB-2.15), which member HEADS that document's
//! chain ([`trunk_head`], PUB-2.53), and whether that document is PUBLISHED
//! ([`published_target`], PUB-2.11) — and, from those three, which
//! arrangement a READER of an address answers from ([`reading_surface`]) and
//! which one a DECLARED DEPOSIT naming it lands in ([`deposit_surface`]).
//! Pure over M1's address arithmetic and M3's slice: no arrangement is read
//! here, and every chain read the write surface makes asks this file rather
//! than spelling the read itself.
//!
//! The two surfaces are two answers because they differ at exactly one kind
//! of address, a PINNED member — any member other than the trunk head
//! (PUB-2.66's pinned older member; the records' "older", PUB-2.39). Every
//! version address answers its own member forever (PUB-2.50), the head's
//! included; but a declared deposit naming any member lands on the head, so
//! a pinned member's arrangement never grows, and the head's grows until a
//! later trunk member becomes the head.
//!
//! A LINK deposit — M7's writes into a document's link subspace, gated by
//! the same [`Caller`](crate::Caller) — is outside the version-chain rule
//! (PUB-2.12): it seats into the address it names, and neither surface
//! answers for it.
//!
//! CONTRACT, for every read here that consults M3 — the address asked about
//! is a REGISTERED document or a member of one (PUB-6.37): M3's publication
//! and frontier reads are answered for registered addresses alone.

use skep_address::{parent, Address, Level};
use skep_namespace::M3State;

/// PUB-2.15 — the TRUNK DOCUMENT of a document: its version components
/// stripped off the document field, one M1 `parent` peel at a time, so a
/// member `A·0·d·v·w` answers `A·0·d` and a document answers itself. Pure
/// address arithmetic (PUB-2.16 — "the M1 step on the nested form"), no read,
/// and terminating because each peel shortens the document field by one.
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
    if a.level() != Level::Document {
        return a.clone();
    }
    let mut trunk = a.clone();
    while trunk.document_field().is_some_and(|field| field.len() > 1) {
        trunk = parent(&trunk)
            .expect("a document field of two or more components peels to one shorter");
    }
    trunk
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
/// CONTRACT — `doc` is a registered document or a member of one (PUB-6.37),
/// as [`published_target`] states.
pub fn trunk_head(m3: &M3State, doc: &Address) -> Option<Address> {
    m3.latest_version(&trunk_of(doc))
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
///   published document between its birth and its first shot serves what it
///   holds, its declared deposits landing there until a head member exists
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
mod tests {
    use super::*;
    use crate::testutil::{a, doc1, pdoc, seeded_m3};
    use skep_namespace::M3Rec;

    /// PUB-2.49/2.50/2.53/2.66 — the float, over every case it decides: a
    /// private document answers itself whether or not a member exists under
    /// it; a published document answers itself while memberless, its trunk
    /// head once one exists, and a version address answers itself forever —
    /// a daughter never floating anything.
    #[test]
    fn a_bare_published_address_floats_to_its_trunk_head_and_nothing_else_moves() {
        let m3 = seeded_m3();
        // Memberless: a published document answers its own arrangement.
        assert_eq!(trunk_head(&m3, &pdoc()), None);
        assert_eq!(reading_surface(&m3, &pdoc()), pdoc());
        // The chain grows two trunk members and a daughter of the first.
        let member1 = a(&[1, 0, 1, 0, 3, 1]);
        let member2 = a(&[1, 0, 1, 0, 3, 2]);
        let daughter = a(&[1, 0, 1, 0, 3, 1, 1]);
        let m3 = m3
            .apply_m3(&M3Rec::Allocate { addr: member1.clone(), published: true })
            .apply_m3(&M3Rec::Allocate { addr: member2.clone(), published: true })
            .apply_m3(&M3Rec::Allocate { addr: daughter.clone(), published: true });
        assert_eq!(trunk_head(&m3, &pdoc()), Some(member2.clone()));
        assert_eq!(reading_surface(&m3, &pdoc()), member2, "the bare address floats to the head");
        // Every version address answers itself, the head included — and
        // asked about the trunk head, a member and a daughter both name the
        // one trunk.
        for member in [&member1, &member2, &daughter] {
            assert_eq!(reading_surface(&m3, member), *member, "a version address answers itself");
            assert_eq!(trunk_head(&m3, member), Some(member2.clone()), "one trunk, whoever asks");
        }
        // Inert on a private document, even one a fixture stamped a member
        // under: the float keys on the publication bit.
        let stamped = m3.apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 1, 1]),
            published: true,
        });
        assert_eq!(trunk_head(&stamped, &doc1()), Some(a(&[1, 0, 1, 0, 1, 1])));
        assert_eq!(reading_surface(&stamped, &doc1()), doc1(), "a private document never floats");
    }

    /// PUB-2.65/2.66 — where a declared deposit lands, over every case it
    /// decides: a memberless edition takes its own deposits; once the chain
    /// has a head, every address of the chain lands there — the bare
    /// document, the head itself, a pinned member and a daughter alike — and a
    /// private document takes its own inserts whatever a fixture stamped under
    /// it. The daughter is also what makes the pinned member a real case: it
    /// gives member1 a chain of its own, whose latest is not the trunk's head.
    #[test]
    fn a_declared_deposit_lands_on_the_head_whichever_chain_address_it_names() {
        let m3 = seeded_m3();
        let edition = pdoc();
        assert_eq!(deposit_surface(&m3, &edition), edition, "memberless: its own arrangement");
        let member1 = a(&[1, 0, 1, 0, 3, 1]);
        let member2 = a(&[1, 0, 1, 0, 3, 2]);
        let daughter = a(&[1, 0, 1, 0, 3, 1, 1]);
        let m3 = m3
            .apply_m3(&M3Rec::Allocate { addr: member1.clone(), published: true })
            .apply_m3(&M3Rec::Allocate { addr: member2.clone(), published: true })
            .apply_m3(&M3Rec::Allocate { addr: daughter.clone(), published: true });
        assert_eq!(m3.latest_version(&member1), Some(daughter.clone()), "member1's own chain");
        for named in [&edition, &member1, &member2, &daughter] {
            assert_eq!(
                deposit_surface(&m3, named),
                member2,
                "{named:?}: a declared deposit lands on the head"
            );
        }
        // The one address the two surfaces answer differently: a pinned
        // member, which its readers answer forever and which never grows.
        assert_eq!(reading_surface(&m3, &member1), member1);
        assert_ne!(deposit_surface(&m3, &member1), reading_surface(&m3, &member1));
        // A private document's declaration is inert: the insert edits the
        // arrangement named, even with a member stamped under it.
        let stamped = m3.apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 1, 1]),
            published: true,
        });
        assert_eq!(deposit_surface(&stamped, &doc1()), doc1());
    }

    /// PUB-2.11/2.15 — the bit that decides every refusal is the DOCUMENT's,
    /// read after the projection: a member stamped with the bit its document
    /// does not carry answers as its document, whichever way the stamp
    /// points. M3's own read answers the stamp, which is why the projection
    /// is this read's to make.
    #[test]
    fn the_publication_read_judges_a_member_as_its_document() {
        let member_of_draft = a(&[1, 0, 1, 0, 1, 1]);
        let member_of_edition = a(&[1, 0, 1, 0, 3, 1]);
        let m3 = seeded_m3()
            .apply_m3(&M3Rec::Allocate { addr: member_of_draft.clone(), published: true })
            .apply_m3(&M3Rec::Allocate { addr: member_of_edition.clone(), published: false });
        assert!(!published_target(&m3, &doc1()));
        assert!(!published_target(&m3, &member_of_draft), "a published-stamped member of a draft");
        assert!(published_target(&m3, &pdoc()));
        assert!(published_target(&m3, &member_of_edition), "a private-stamped member of an edition");
        assert!(m3.published(&member_of_draft), "M3 answers the member's own stamp");
    }

    /// PUB-2.15's projection is address arithmetic and total: a version
    /// member answers its document, a document answers itself, a member of
    /// a member peels to the same document — and off the document tier the
    /// arithmetic changes nothing, an account and an element each answering
    /// itself. The element case is why the projection asks the tier before
    /// it peels: an element MINTED UNDER A MEMBER carries the member's
    /// two-component document field, so peeling it would strip the element's
    /// own components and then the version — answering a document for that
    /// element and the element itself for its sibling under the trunk.
    /// `document_of` first is how a caller asks for an element's trunk, and
    /// it answers the same document for both.
    #[test]
    fn a_version_member_projects_to_its_document() {
        let doc = a(&[1, 0, 1, 0, 1]);
        assert_eq!(trunk_of(&doc), doc, "a document is its own trunk");
        assert_eq!(trunk_of(&a(&[1, 0, 1, 0, 1, 1])), doc, "a version");
        assert_eq!(trunk_of(&a(&[1, 0, 1, 0, 1, 1, 2])), doc, "a version of a version");
        let acct = a(&[1, 0, 1]);
        assert_eq!(trunk_of(&acct), acct);
        let element = a(&[1, 0, 1, 0, 1, 0, 1, 1]);
        assert_eq!(trunk_of(&element), element, "an element of the trunk");
        let member_element = a(&[1, 0, 1, 0, 1, 1, 0, 1, 1]);
        assert_eq!(trunk_of(&member_element), member_element, "an element of a member");
        for e in [&element, &member_element] {
            let document = skep_address::document_of(e).expect("an element lies in a document");
            assert_eq!(trunk_of(&document), doc, "{e:?}: its document's trunk");
        }
    }
}
