//! Classification — the one place the feed asks the world anything: which
//! of an entry's documents are DRAFTS and whose (the head exception set's
//! answer, PUB-7.5), and, for a position whose testimony was lost, which
//! documents the JOURNAL shows the commit touched (PUB-6.45's bare-entry
//! rule). Both answers are immutable facts about a committed position —
//! publication is fixed at mint (PUB-1.9), the owner with it, and the
//! journal does not change — so they are computed once (at commit, or at
//! the open that reconstructs the position) and never re-derived at serve;
//! what the serve path asks per entry is the read predicate alone
//! (`FeedClass::readable`, PUB-7.20).

use std::collections::BTreeSet;
use std::str::FromStr;

use skep_address::{document_of, validate, Address, Nat, Tumbler};
use skep_arrangement::{trunk_of, HasM5};
use skep_engine::World;
use skep_links::{HasLinks, ShippedType, View};

/// One document an entry names, as the feed classified it: the address the
/// record named (a document, or a version member — the address written to,
/// verbatim), and the OWNER ACCOUNT the head exception set fixed for its
/// document at mint (`World::owner_account` of the member's trunk,
/// PUB-2.15) — `Some` iff the document is a DRAFT. A published document
/// carries `None`: it is readable to every class and enters no owner's
/// stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Doc {
    pub addr: Address,
    /// The DRAFT's owner account, or `None` for a published document —
    /// which has an owner this feed never needs. ω is total on a registered
    /// document, so the name says which of the two facts this field is:
    /// asked bare, "the owner" of a published document is an account, and
    /// this answers nothing about it.
    pub draft_owner: Option<Address>,
}

impl Doc {
    /// Whether this document is a draft — the feed's stream-keying and
    /// bitmap test, never its mask (the mask is `readable`'s).
    pub fn is_draft(&self) -> bool {
        self.draft_owner.is_some()
    }
}

/// Classify `addrs` against `world`'s exception set: each address projected
/// to its document (`trunk_of`, PUB-2.15 — a version member reads as its
/// document) and looked up once (PUB-7.5: one hash, no walk). Order is the
/// caller's — the record's own, which rendering preserves.
pub(crate) fn classify(world: &World, addrs: Vec<Address>) -> Vec<Doc> {
    addrs
        .into_iter()
        .map(|addr| {
            let draft_owner = world.owner_account(&trunk_of(&addr)).cloned();
            Doc { addr, draft_owner }
        })
        .collect()
}

/// The dotted-decimal grammar itself: any nonempty component sequence,
/// T4-valid or not, which [`parse_dotted`] refines by M1's validation.
///
/// UNCAPPED, and so not a wire door: the depth and magnitude budgets a
/// client's tumbler meets are [`crate::codec::wire_tumbler`]'s, which is
/// what a frame and a query string both pass through. This grammar reads a
/// FILE.
fn parse_prefix(s: &str) -> Option<Tumbler> {
    let comps = s
        .split('.')
        .map(|c| {
            if c.is_empty() || !c.bytes().all(|b| b.is_ascii_digit()) {
                None
            } else {
                Nat::from_str(c).ok()
            }
        })
        .collect::<Option<Vec<Nat>>>()?;
    Tumbler::new(comps).ok()
}

/// A dotted-decimal address as `commits.log` records it (the wire's own
/// rendering, `Tumbler`'s `Display`), back to an `Address` — [`parse_prefix`]
/// plus M1's T4 validation, so the refinement is one call and not a second
/// copy of the grammar. `None` for anything that is not one — a line this
/// daemon never wrote; the record keeps the string, the feed's
/// classification drops it.
///
/// Uncapped, deliberately: the wire's depth and digit budgets bound what a
/// CLIENT may send, and a name that reached this file is already past them.
pub(crate) fn parse_dotted(s: &str) -> Option<Address> {
    validate(parse_prefix(s)?).ok()
}

/// THE JOURNAL'S CLASSIFICATION of one commit (PUB-6.45): the documents the
/// commit from `before` to `after` touched, as the two worlds show them —
/// read through the engine's public surface alone (the kernel's journal
/// reader stays closed, and the records themselves are reachable by no
/// read the daemon holds). Three witnesses, together EXACT for the mask:
///
/// 1. the DRAFTS the commit minted — every draft of `after` absent from
///    `before` (`create_new_document`/`fork`/`version` resolving private);
/// 2. the LINKS the commit deposited — every link of `after` absent from
///    `before`, each one's HOME, and for a retraction (the shipped `[R]`
///    class) its targets' homes too, which is `nullify`'s own `docs` rule
///    (PUB-6.46); `edit_link`'s two homes fall out as two deposits;
/// 3. the DRAFTS whose arrangement the commit moved — an insert, delete,
///    copy, rearrange or seat into a draft that already existed.
///
/// What it cannot name is a PUBLISHED document an arrangement write or a
/// mint touched (no public read enumerates them) — and it need not: a
/// single-document commit into a published document classifies EMPTY here,
/// and an empty class is served to every class, which is exactly the answer
/// a recorded `[P]` earns (P is readable by all); the two-document ops
/// (`nullify`, `edit_link`) name link homes, which witness 2 enumerates in
/// full. So the mask a bare entry gets from this set equals the mask its
/// lost record would have given it, for every op the wire carries. The
/// record whose mask this reproduces is [`crate::write_path::write_meta`]'s,
/// and the agreement is exactly two inclusions, stated there: every draft
/// that table names appears here, and this answer names nothing it does not.
/// Neither is checkable in the process — the two read different inputs — so
/// a new `Op` the compiler routes through that table reaches this one only
/// if someone brings it, and an op no witness above catches derives an empty
/// class, which is never masked.
///
/// COST: one full-link enumeration per world (`match_links` with no
/// constraint — the whole audit slice), one `readlink` per new link, and,
/// where the arrangement slice moved at all, one run-list comparison per
/// draft the world holds. Paid once per bare boundary at the open that
/// reconstructs it, never at serve.
pub(crate) fn derived_docs(before: &World, after: &World) -> Vec<Address> {
    let mut docs: BTreeSet<Address> = BTreeSet::new();
    // 1. Drafts minted by this commit.
    for draft in after.drafts() {
        if before.owner_account(draft.document).is_none() {
            docs.insert(draft.document.clone());
        }
    }
    // 2. Links deposited by this commit: each one's home, and a retraction's
    //    targets' homes.
    let before_links = before.links().match_links(&[], View::Audit);
    let retraction = after.links().reserved_type(ShippedType::Retraction);
    for link in after.links().match_links(&[], View::Audit).iter() {
        if before_links.contains(link) {
            continue;
        }
        if let Some(home) = document_of(link) {
            docs.insert(home);
        }
        if let Some(value) = after.links().readlink(link) {
            if value.type_slot() == retraction {
                for target in value.to_slot().addrs() {
                    if let Some(home) =
                        validate(target.clone()).ok().and_then(|t| document_of(&t))
                    {
                        docs.insert(home);
                    }
                }
            }
        }
    }
    // 3. Drafts whose arrangement this commit moved. Skipped whole when the
    //    arrangement slice is unchanged (a mint, a delegate, an `emit`).
    if before.m5() != after.m5() {
        for draft in after.drafts() {
            let doc = draft.document;
            if before.owner_account(doc).is_none() {
                continue; // minted by this commit — named by witness 1
            }
            if before.m5().content_runs(doc) != after.m5().content_runs(doc)
                || before.m5().link_runs(doc) != after.m5().link_runs(doc)
            {
                docs.insert(doc.clone());
            }
        }
    }
    docs.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The record's rendering parses back to the address it rendered, and
    /// what is not one is refused rather than guessed.
    #[test]
    fn dotted_decimal_round_trips_and_garbage_is_refused() {
        let a = parse_dotted("1.0.2.0.3").expect("a document address");
        assert_eq!(a.to_string(), "1.0.2.0.3");
        assert!(parse_dotted("1.0").is_none(), "a trailing separator is not an address");
        assert!(parse_dotted("").is_none());
        assert!(parse_dotted("1..2").is_none());
        assert!(parse_dotted("1.x").is_none());
        // A prefix admits what an address refuses: containment is a tumbler
        // question.
        assert_eq!(parse_prefix("1.0").expect("a carrier prefix").to_string(), "1.0");
        assert!(parse_prefix("1.").is_none());
    }
}
