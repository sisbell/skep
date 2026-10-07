//! Classification — the one place the feed asks the world anything: which
//! of an entry's documents are DRAFTS and whose (the head exception set's
//! answer, PUB-7.5), and, for a position whose testimony was lost, which
//! documents the JOURNAL shows the commit touched (PUB-6.45's bare-entry
//! rule) and WHICH OF THE OP'S OWN TERMS it can name — a `delegate`'s pair,
//! a `make_link`'s link, a `publish`'s count and extent, the op itself where
//! the journal's facts name one op alone ([`derived_journal`]; as7-F3,
//! SO-I5 (e)). All three answers are immutable facts about a committed
//! position — publication is fixed at mint (PUB-1.9), the owner with it, and
//! the journal does not change — so they are computed once (at commit, or at
//! the open that reconstructs the position) and never re-derived at serve;
//! what the serve path asks per entry is the read predicate alone
//! (`FeedClass::readable`, PUB-7.20).

use std::collections::BTreeSet;
use std::str::FromStr;

use skep_address::{document_of, ordinal, validate, Address, Nat, Tumbler};
use skep_arrangement::{trunk_of, HasM5};
use skep_engine::World;
use skep_links::{is_replaces_class, HasLinks, ShippedType, View};
use skep_namespace::{system_account, system_node, HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL};

use super::sidecar::{JournalTerms, OpTerms};

/// One document an entry names, as the feed classified it: the address the
/// record named (a document, or a version member — the address written to,
/// verbatim), and the OWNER ACCOUNT the head exception set fixed for its
/// document at mint (`World::owner_account` of the member's trunk,
/// PUB-2.15) — `Some` iff the document is a DRAFT. A published document
/// carries `None`: it is readable to every class and enters no owner's
/// stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Doc {
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
pub(super) fn classify(world: &World, addrs: Vec<Address>) -> Vec<Doc> {
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
pub(super) fn parse_dotted(s: &str) -> Option<Address> {
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
pub(super) fn derived_docs(before: &World, after: &World) -> Vec<Address> {
    derived_docs_over(before, after, &new_links(before, after))
}

/// THE JOURNAL'S WHOLE ANSWER for one bare commit: its documents
/// ([`derived_docs`]) and its terms ([`derived_terms_over`]), the links
/// deposited enumerated ONCE for both — what the reconstruction walk asks
/// per boundary.
pub(super) fn derived_journal(before: &World, after: &World) -> (Vec<Address>, JournalTerms) {
    let links = new_links(before, after);
    (derived_docs_over(before, after, &links), derived_terms_over(before, after, &links))
}

/// The links `after` holds and `before` does not — the ones the commit
/// deposited, in address order: the whole audit slice of each world, as
/// witness 2 of [`derived_docs`] reads it.
fn new_links(before: &World, after: &World) -> Vec<Address> {
    let before_links = before.links().match_links(&[], View::Audit);
    after
        .links()
        .match_links(&[], View::Audit)
        .iter()
        .filter(|link| !before_links.contains(link))
        .cloned()
        .collect()
}

/// [`derived_docs`] over `links` already enumerated.
fn derived_docs_over(before: &World, after: &World, links: &[Address]) -> Vec<Address> {
    let mut docs: BTreeSet<Address> = BTreeSet::new();
    // 1. Drafts minted by this commit.
    for draft in after.drafts() {
        if before.owner_account(draft.document).is_none() {
            docs.insert(draft.document.clone());
        }
    }
    // 2. Links deposited by this commit: each one's home, and a retraction's
    //    targets' homes.
    let retraction = after.links().reserved_type(ShippedType::Retraction);
    for link in links {
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
            if before.m5().content_runs(doc).ne(after.m5().content_runs(doc))
                || before.m5().link_runs(doc).ne(after.m5().link_runs(doc))
            {
                docs.insert(doc.clone());
            }
        }
    }
    docs.into_iter().collect()
}

/// THE JOURNAL'S TERMS for one bare commit (as7-F3; SO-I5 (e): the feed is
/// the mirror's whole input, so a bare `delegate` row that served its pair
/// as `null` left a feed-only mirror's Π short of an account and ω composing
/// the wrong `account`) — the op's own members as the recorded row would
/// have carried them, read off the two worlds through the engine's public
/// surface alone, and the op itself where the facts name one op and no
/// other. One commit is one op, so the three witnesses are exclusive and are
/// read in this order:
///
/// 1. A PRINCIPAL SEATED ([`seated_principal`]) — `delegate` alone seats
///    one (`register_node` registers a node and seats nobody) — so the row
///    is a `delegate`'s, with its pair: `new_prefix` the seat, `new_id` the
///    principal, both as `effective_owner` answers them at `after`.
/// 2. A VERSION MEMBER MINTED ([`minted_member`]) — with M5's placing record
///    for it ([`skep_arrangement::M5State::shot_terms`], D25's (c′)) the row
///    is a `publish`'s, with `placed` and `base_extent` exactly as
///    `doc_metadata` serves them for that member; without one it is a
///    `version`'s, which carries no term.
/// 3. LINKS DEPOSITED — exactly one: a retraction-typed link is `nullify`'s
///    (no op but `nullify` deposits the shipped `[R]` class), carrying no
///    term; any other one link is the `link` the commit minted, the op
///    unnamed — `make_link`, `emit` and `assert_sup` each deposit one and
///    the world does not tell them apart, so a bare row serves `link` where
///    an `emit`'s or an `assert_sup`'s recorded row carried none (r6-2a
///    scoped the member to `make_link`; the journal names the link either
///    way, and lost testimony is never made up for by omission). Exactly
///    two, the second at the next link address and typed `replaces`: a
///    replacing `make_link`'s pair (PUB-5.15 — the class's one writer), the
///    row a `make_link`'s with `link` the record's own. Any other count — an
///    `edit_link`'s successor and claim, nothing at all — answers no term.
///
/// What this cannot name, and says so by `None`: the op of an arrangement
/// write into a published document, of a `create_new_document` or `fork`
/// (one new document, three ops), of a plain `make_link` against an `emit`
/// or `assert_sup`, of an `edit_link`; a `delegate` under a node that
/// `register_node` admitted and that no enumeration from the bootstrap and
/// system nodes reaches (M3 publishes no walk of its principals). Every
/// member a witness rules out is ABSENT on the row, as on the recorded one;
/// every member no witness decides stays `null`.
///
/// COST, beside [`derived_docs`]'s: one walk of the board's principal list
/// at `after` with a frontier read at `before` per account or node, and —
/// where no principal was seated — one pass over M3's registered documents
/// at `after`, versions included, with a registration probe at `before` per
/// document. Paid once per bare boundary at the open that reconstructs it,
/// never at serve. Reached through [`derived_journal`] alone, over the
/// links it enumerated.
fn derived_terms_over(before: &World, after: &World, links: &[Address]) -> JournalTerms {
    if let Some((prefix, id)) = seated_principal(before, after) {
        return JournalTerms {
            op: Some("delegate".into()),
            terms: Some(OpTerms::Delegate { new_prefix: prefix.to_string(), new_id: id.0 }),
        };
    }
    if let Some(member) = minted_member(before, after) {
        return match after.m5().shot_terms(&member) {
            Some(t) if before.m5().shot_terms(&member).is_none() => JournalTerms {
                op: Some("publish".into()),
                terms: Some(OpTerms::Publish {
                    placed: t.placed.to_string(),
                    base_extent: t.base_extent.as_ref().map(ToString::to_string),
                }),
            },
            _ => JournalTerms { op: Some("version".into()), terms: None },
        };
    }
    let typed = |link: &Address, test: &dyn Fn(&skep_links::Endset) -> bool| {
        after.links().readlink(link).is_some_and(|value| test(value.type_slot()))
    };
    match links {
        [link] => {
            let retraction = after.links().reserved_type(ShippedType::Retraction);
            if typed(link, &|ty| ty == retraction) {
                JournalTerms { op: Some("nullify".into()), terms: None }
            } else {
                JournalTerms { op: None, terms: Some(OpTerms::MakeLink { link: link.to_string() }) }
            }
        }
        [record, replaces]
            if is_next_address(record, replaces) && typed(replaces, &is_replaces_class) =>
        {
            JournalTerms {
                op: Some("make_link".into()),
                terms: Some(OpTerms::MakeLink { link: record.to_string() }),
            }
        }
        _ => JournalTerms::default(),
    }
}

/// Is `b` the address right after `a` — the same prefix, the last ordinal
/// one more — the adjacency a replacing `make_link`'s pair is read by
/// (PUB-5.15: the `replaces` link sits at the record's NEXT address).
fn is_next_address(a: &Address, b: &Address) -> bool {
    let (a, b) = (components(a), components(b));
    let Some((a_last, a_prefix)) = a.split_last() else { return false };
    let Some((b_last, b_prefix)) = b.split_last() else { return false };
    a_prefix == b_prefix && a_last.clone() + Nat::from(1u32) == *b_last
}

/// An address's components, owned.
fn components(a: &Address) -> Vec<Nat> {
    a.tumbler().iter().cloned().collect()
}

/// The address `next` names with its last ordinal replaced by `k` — the
/// `k`-th member of the frontier-encoded chain `next` is the next slot of
/// (M3 §1: a chain's realized set is `{c₁..cₘ}`, a gap unrepresentable, so
/// `next = …·(m+1)` names every member below it). `None` where the result is
/// no address, which no chain M3 minted produces.
fn chain_member(next: &Address, k: &Nat) -> Option<Address> {
    let mut comps = components(next);
    *comps.last_mut()? = k.clone();
    validate(Tumbler::new(comps).ok()?).ok()
}

/// The ordinal of the chain's NEXT slot — `m + 1` for a chain of `m`
/// members: the frontier's last component, read by M1's own [`ordinal`].
fn next_ordinal(next: &Address) -> Nat {
    ordinal(next.tumbler()).clone()
}

/// Every member of the chain whose next slot is `next`, ascending.
fn chain_members(next: &Address) -> impl Iterator<Item = Address> + '_ {
    let bound = next_ordinal(next);
    let mut k = Nat::from(1u32);
    std::iter::from_fn(move || {
        if k >= bound {
            return None;
        }
        let member = chain_member(next, &k);
        k += Nat::from(1u32);
        member
    })
}

/// THE PRINCIPAL THE COMMIT SEATED, if one: Π enumerated at `after` off
/// M3's public surface — from the bootstrap node (principal 0's own seat)
/// and the system node, every account chain's members by its frontier
/// (`next_account_prefix`, the next delegable prefix under a node or an
/// account, whose ordinal counts the chain), recursively through the
/// sub-account chains — with each parent's frontier compared against
/// `before`'s: the one parent whose frontier moved seated the chain's newest
/// member, whose pair `effective_owner_pair` answers. `None` where no
/// frontier moved under a parent the walk reaches.
fn seated_principal(before: &World, after: &World) -> Option<(Address, PrincipalId)> {
    let (b, a) = (before.m3(), after.m3());
    let mut parents = walk_roots(after);
    let mut i = 0;
    while i < parents.len() {
        let parent = parents[i].clone();
        i += 1;
        let Some(next) = a.next_account_prefix(&parent) else { continue };
        let moved = b.next_account_prefix(&parent).as_ref() != Some(&next);
        let mut newest = None;
        for member in chain_members(&next) {
            if a.is_registered_account(&member) {
                parents.push(member.clone());
            }
            newest = Some(member);
        }
        if moved {
            let seated = newest?;
            let (prefix, id) = a.effective_owner_pair(&seated)?;
            if *prefix == seated {
                return Some((seated, id));
            }
        }
    }
    None
}

/// THE VERSION MEMBER THE COMMIT MINTED, if one: the document `after`
/// registers and `before` does not that is a MEMBER of a chain — its trunk
/// another document ([`trunk_of`], PUB-2.15) — read off M3's own enumeration
/// of every registered document, versions included and under every node
/// (`M3State::documents`). A minted trunk (`create_new_document`, `fork`, a
/// cross-owner `version`) names no member. Registration is asked of both
/// worlds per entry, as that enumeration's card advises a reader of a
/// checkpoint; an entry the map omits answers `None`, never another member.
fn minted_member(before: &World, after: &World) -> Option<Address> {
    let (b, a) = (before.m3(), after.m3());
    a.documents()
        .map(|(doc, _)| doc)
        .find(|doc| {
            !b.is_registered_document(doc)
                && a.is_registered_document(doc)
                && trunk_of(doc) != **doc
        })
        .cloned()
}

/// Where the principal walk starts: the bootstrap node (principal 0's own
/// seat, `1`), the system node (`1.1`, PUB-6.65) and the system account
/// (`1.1.0.1`) — the seats genesis writes, which no `delegate` row of the
/// feed names.
fn walk_roots(world: &World) -> Vec<Address> {
    let mut roots: Vec<Address> = Vec::new();
    roots.extend(world.m3().principal_prefix(BOOTSTRAP_PRINCIPAL).cloned());
    roots.push(system_node());
    roots.push(system_account());
    roots
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

    /// A VERSION MINTED UNDER A SUB-NODE IS NAMED OFF THE JOURNAL (as7-F3;
    /// SO-I5 (e)): `register_node` admits `1.9001`, an account is delegated
    /// beneath it, and that account versions its own published home. The
    /// commit deposits no link and seats no principal, so its one witness is
    /// the member it minted — which M3's enumeration of registered documents
    /// reaches under any node, where a walk of account frontiers from the
    /// bootstrap and system nodes never would.
    #[test]
    fn a_version_minted_under_a_sub_node_is_named_off_the_journal() {
        use serde_json::json;
        use skep_febe::{Codec, OperationSurface, Response};
        use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};

        use crate::codec::JsonCodec;

        let engine = skep_engine::Engine::open(KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(0),
        })
        .expect("in-memory genesis cannot fail");
        let febe = OperationSurface::new(Box::new(engine.stores()));
        let exec = |sid, frame: serde_json::Value| -> String {
            let req = JsonCodec
                .parse(frame.to_string().as_bytes())
                .unwrap_or_else(|e| panic!("{frame}: {:?}", e.detail));
            match febe.execute(sid, req) {
                Response::AckAddr { addr, .. } => addr.tumbler().to_string(),
                other => panic!("{frame}: {}", String::from_utf8_lossy(&JsonCodec.marshal(&other))),
            }
        };
        let boot = febe.bootstrap_session();
        exec(boot, json!({"op": "register_node", "addr": "1.9001"}));
        exec(boot, json!({"op": "delegate", "new_prefix": "1.9001.0.1", "new_id": 900}));
        let sid = febe.open_session(PrincipalId(900));
        let doc = exec(sid, json!({"op": "create_new_document", "account": "1.9001.0.1"}));
        let before = engine.kernel().snapshot();
        let member = exec(sid, json!({"op": "version", "d_src": doc}));
        let after = engine.kernel().snapshot();
        assert!(member.starts_with(&format!("{doc}.")), "the premise: a member of {doc}, {member}");
        assert_eq!(
            derived_journal(before.world(), after.world()).1,
            JournalTerms { op: Some("version".into()), terms: None },
            "a bare row names the version a sub-node's account minted"
        );
    }
}
