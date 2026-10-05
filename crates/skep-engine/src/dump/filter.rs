//! The per-class POST-FILTER over the dump tree (PUB round 2, lane 3.4 §4) —
//! the reduction that turns the harness-only walk into a reader's dump.
//!
//! [`crate::Engine::world_dump`] and [`crate::Engine::dump_of`] are the
//! HARNESS-ONLY unfiltered walk. The daemon's `/dump` is that walk
//! POST-FILTERED at the request's reader class —
//! [`crate::Engine::dump_of_visible`] over the same threaded predicate every
//! read answers (PUB-6.39) — and this filter runs over the dump TREE before a
//! byte is rendered, so the two are one tree rendered twice and a reader
//! class's dump is byte-identical to the harness-only walk under the total
//! predicate. Determinism holds per reader class (PUB-8.26): the text is a
//! function of the world and the reader class, conditioned on the head's
//! publication state, grant state and the reader's class.
//!
//! What every entry the filter reaches drops and keeps is [`filter_tree`]'s
//! one statement. Three obligations run underneath it and belong to nothing
//! else in the crate:
//!
//! * The PATHS this module walks are string keys, and a path's two halves
//!   have two owners. A LEADING component is the dump's own vocabulary — the
//!   root sections, the hint family names, [`super::shipped_label`]'s
//!   strings. A TRAILING component inside an authoritative slice is that
//!   STORE's own serde field, and a private one: `map` is M4's,
//!   `arrangements` and `provenance` are M5's (its third and fourth,
//!   `birth_extents` and `shot_terms`, are kept whole by name and end no
//!   path), `links` is M7's. So a store
//!   author renaming a field it never published has no reason to look here,
//!   and the rename would leave the filter silently filtering nothing — which
//!   is why every path is asserted to name a place in the tree.
//! * The addresses this module judges are RECOVERED from the text the
//!   builders wrote, in the two FORMS the builders write them in — a store's
//!   own serde form inside an authoritative slice, a dotted string anywhere
//!   the dump's own builders rendered one — because the tree carries
//!   renderings and not the values behind them. That re-entry is through the
//!   types' own doors ([`serde_form_address`], [`dotted_address`]), and what
//!   it cannot recover it DROPS.
//! * Two hint families name something OTHER than the link whose deposit put
//!   it there — a supersession EDGE, a predicate MEMBER — and a link's home
//!   is what governs, so this module RE-DERIVES the link from the type class
//!   it was rendered off ([`sup_edge_claims`], [`member_tuples`]). Each is a
//!   restatement of a rule M7 owns, and the standing obligation on both is to
//!   stay that restatement: one that keyed fewer entries than the
//!   harness-only walk renders would drop, under the TOTAL predicate, what
//!   the harness-only walk wrote, and the identity that makes a reader
//!   class's dump the harness-only walk's own tree would fail. That is why
//!   each is checked against the harness-only walk over a world that has the
//!   entry, and not only against a reader class that reads it. The obligation
//!   binds the other way too, where no identity test can see it: one that
//!   keyed an EXTRA asserting link against an entry the harness-only walk
//!   does render — a retracted claim, a tuple read under another view — keeps
//!   that entry for every reader class that reads the extra link's home,
//!   whatever the operative links assert. That direction is checked against a
//!   reader class, over a world where the extra link is readably homed and
//!   the operative one is not.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use skep_address::{document_of, validate, Address, Nat, Tumbler};
use skep_links::{Endset, LinkState, ShippedType, View};

use crate::canon::{SerdeTree, TreeDe};

use super::{shipped_label, PREDICATE_PROJECTIONS, SLICE_VIEWS};

/// The by-home hint families that have NO TABLE OF THEIR OWN: each is a
/// sequence of dotted LINK addresses, and an entry stays where the reader
/// class reads the document its own address is homed in. That one test is the
/// whole rule here BECAUSE the entry is the link — the thing whose existence
/// the entry discloses is the thing being judged.
///
/// The rule governs more families than this list names, so the list is not
/// the reduction's by-home reach: each shipped class's two slices are link
/// addresses and reduce by the same test, walked off `ShippedType::ALL` and
/// [`SLICE_VIEWS`] because their names are the format's rather than this
/// module's.
///
/// Which families group under which rule is THIS module's knowledge, which is
/// why the list is here; the predicate projections' names are the FORMAT's, so
/// that table is the builder's and is read from there. What the reduction as a
/// whole reaches, and what it therefore leaves whole, is [`filter_tree`]'s
/// statement.
const REDUCED_BY_HOME: [&str; 3] = ["links.audit", "links.active", "links.nullified"];

/// The per-class post-filter over the dump tree — the ONE statement of what
/// the entries it reaches drop and keep, applied before render so the
/// harness-only walk and every reader class's dump are one tree. `readable`
/// is the threaded predicate (PUB-6.39); every address is judged at its
/// DOCUMENT (`document_of`, the address arithmetic the link-address rule
/// uses, PUB-6.6), an address with no document — an account, a node — judged
/// readable.
///
/// * `authoritative.namespace` — KEPT whole. The addresses in it are not
///   secret (PUB-1.13, an address is not), but the slice is M3's WHOLE serde
///   form, and beside the node registry it carries three things: the
///   `publication` map (every registered document with its bit — so a reader
///   class reads the draft MEMBERSHIP of documents it cannot open, and the
///   reduced `publication` section below reduces that SECTION and not what a
///   reader class learns of publication state), the per-namespace frontier
///   COUNTS (so a draft's content and link population is legible without any
///   of its content), and the principal registry. Widening the reduction here
///   would move bytes the crash and wire oracles pin, so what a reader class
///   is owed of this slice is the format owner's question and not this
///   filter's.
/// * `authoritative.content.map` — a CONTENT LINE leaves when its element's
///   document is unreadable.
/// * `authoritative.arrangement.{arrangements, provenance}` — the ENTRIES
///   keyed by an unreadable document leave: its arrangement (M5's
///   per-document arrangement holds content and LINK subspaces alike) and its
///   provenance (keyed by the placing document).
/// * `authoritative.arrangement.birth_extents` — KEPT whole (the owner's
///   ruling, 2026-09-18). Every key M5's fold writes to its birth memo
///   (PUB-3.19) is a VERSION MEMBER — a trunk's opening `D.1` — and every
///   version address that exists names a PUBLISHED state, forever (PUB-2.10;
///   a private document is versionless, PUB-2.9). So no entry is keyed by a
///   document some reader class cannot open, and no reader class is owed
///   less than the whole map; a reduction by the version member's document
///   would have nothing to drop in any world an op builds, which is why
///   `every_reduced_path_actually_reduces` could not hold one. The
///   disposition rests on that key set: a memo keyed by anything but a
///   version member owes a reduction here, and
///   `every_birth_memo_key_is_a_version_member_whose_state_the_guest_reads`
///   holds the key set against a world whose memo has an entry.
/// * `authoritative.arrangement.shot_terms` — KEPT whole, on the birth
///   memo's ground: every key M5's fold writes there is a VERSION MEMBER the
///   shot minted (the signed-ops design record's D25, arm (c′)), so a
///   published state every reader class reads; and what an entry holds — the
///   count the client placed and the base extent its copy took — is what the
///   member's `doc_metadata` serves to every reader who may read the member.
///   The same test holds this key set beside the memo's.
/// * `authoritative.links.links` — a LINK homed in an unreadable document
///   leaves.
/// * `publication` — the SECTION reduced per entry to the readable drafts:
///   EMPTY for the guest, an owner's own drafts for the owner, a grantee's
///   granted one.
/// * `grants` — KEPT whole: a grant is a published document's record, and the
///   addresses it names are not secret (PUB-1.13).
/// * `hints` — every LINK address (the audit/active/nullified slices, the
///   shipped classes' slices, the supersession edges and their successors) by
///   its home; the shipped classes' `key` entries are format constants and
///   stay; `publication.drafts` reduced to the readable drafts, as the
///   section is. Two families are not link addresses and take a second test
///   apiece, because the entry and the deposit that put it there are two
///   things:
///     * The PREDICATE PROJECTIONS ([`PREDICATE_PROJECTIONS`]) are MEMBER
///       addresses — `LinkState::members` denotes the subjects, not the
///       tuples — so an entry stays where the reader class reads the member's
///       own document AND some `pred_def`/`pred_stable` tuple asserting it, at
///       that entry's own view, is readably homed. The REGISTRATION is a fact
///       deposited in that tuple's home, and a link's home governs what a
///       reader class learns of it (PUB-6.13). Either test alone leaks one
///       way: the member's alone puts a draft-homed registration in the
///       guest's dump, the tuple's alone puts a draft's content position there.
///     * A SUPERSESSION EDGE takes a third test beside its two endpoints'
///       homes (lane 4.2, F4; PUB-6.13, PUB-6.22, PUB-6.27): the edge stays
///       only where some operative CLAIM asserting it — the `[K_sup]` link
///       the harness-only walk derived the edge from — is homed in a document
///       the reader class reads. A claim is a link and its home governs, exactly
///       as `in_claims`/`out_claims` filter lineage by the CLAIM's home: a
///       draft-homed `assert_sup` over two public links is invisible to a
///       guest there and leaves the guest's dump here.
///
///   Neither hint's rendered shape is widened — an edge record still carries
///   no claim address and a projection still carries no tuple address — so
///   both re-derivations are read at filter time off `links`, the render's own
///   source, through [`sup_edge_claims`] and [`member_tuples`].
///
/// An entry NO PATH IN THE BODY NAMES is kept whole at every reader class. So
/// the statement above is this reduction's COMPLETENESS as well as its
/// content, and the gap it admits is the one nothing else here catches: a
/// section or a hint family added to the tree and left out of it goes to the
/// guest unreduced, deterministically and with nothing about it looking wrong.
///
/// That statement accounts for ALL FIVE LEVELS of the tree, and
/// `every_entry_at_each_level_of_the_tree_is_reduced_or_kept_by_name` holds it
/// against the builders at each. A level left out of that test is a level
/// where an addition discloses, so the five are named rather than counted:
///
/// * the ROOT's four sections — `publication` and `hints` reduced, `grants`
///   kept whole with the reason given above, and `authoritative` reduced
///   slice by slice at the two levels below;
/// * the AUTHORITATIVE section's four slices, one per store;
/// * inside each of those, that STORE's own serde fields — the level whose
///   names the four paths above end in;
/// * the HINTS section's families, grouped by [`REDUCED_BY_HOME`],
///   [`PREDICATE_PROJECTIONS`] and the three arms of their own; and
/// * the three entries inside a SHIPPED CLASS's own submap
///   (`super::class_tree`'s — two typed slices reduced by home, one
///   format-constant `key` kept).
///
/// The THIRD is the one whose additions are not an engine edit at all, and
/// the reason the level is held here rather than left to the builders: a
/// store growing a serde field on its slice renders whatever that field
/// holds to every reader class, with every path in this body still naming a
/// place of the shape it expects, and — by the module doc's first obligation
/// — with no compiler edge from that store to this file.
///
/// A key that fails to decode is DROPPED (fail-closed): every key here was
/// rendered from an address a moment earlier, so none does, and a filter
/// that met one would rather omit a line than judge it readable. The SHAPE
/// tests run the other way — [`retain_map`], [`retain_seq`] and
/// [`retain_map_of_seqs`] each do nothing where the node at a path is not the
/// shape they expect — so a builder that changed an entry's shape without
/// changing its key leaves the entry whole rather than empty. Both directions
/// are the same fact about this module: it reduces what it recognizes and
/// keeps what it does not.
///
/// The adjacency map has TWO shape levels and so keeps an entry on a HALF
/// applied rule: an unrecognized value survives its key test, which is the
/// one place a kept entry has been judged rather than merely passed over.
/// `every_reduced_path_actually_reduces` asserts that second shape where
/// `reduced_paths` asserts the first.
pub(super) fn filter_tree(
    mut root: SerdeTree,
    readable: &dyn Fn(&Address) -> bool,
    links: &LinkState,
) -> SerdeTree {
    // Every address is judged at its document; an address that HAS no
    // document — an account, a node — is its own answer.
    let document_readable = |a: &Address| document_of(a).is_none_or(|doc| readable(&doc));
    let keep_serde_form =
        |k: &SerdeTree| serde_form_address(k).is_some_and(|a| document_readable(&a));
    let keep_dotted = |s: &SerdeTree| dotted_address(s).is_some_and(|a| document_readable(&a));
    // The operative claims by the edge they assert, read once for the whole
    // tree; an edge some readably-homed claim asserts is a readable edge.
    let claims = sup_edge_claims(links);
    let edge_claimed_readably = |old: &Address, new: &Address| {
        claims
            .get(old.tumbler())
            .and_then(|by_new| by_new.get(new.tumbler()))
            .is_some_and(|asserting| asserting.iter().any(document_readable))
    };

    retain_map(&mut root, &["authoritative", "content", "map"], &keep_serde_form);
    retain_map(&mut root, &["authoritative", "arrangement", "arrangements"], &keep_serde_form);
    retain_map(&mut root, &["authoritative", "arrangement", "provenance"], &keep_serde_form);
    retain_map(&mut root, &["authoritative", "links", "links"], &keep_serde_form);

    retain_seq(&mut root, &["publication"], &keep_dotted);

    for family in REDUCED_BY_HOME {
        retain_seq(&mut root, &["hints", family], &keep_dotted);
    }
    for (family, ty, view) in PREDICATE_PROJECTIONS {
        // A MEMBER, judged at its own document and then at the homes of the
        // tuples asserting it under this entry's own view.
        let asserted_by = member_tuples(links, links.reserved_type(ty), view);
        let keep_member = |item: &SerdeTree| {
            dotted_address(item).is_some_and(|member| {
                document_readable(&member)
                    && asserted_by
                        .get(member.tumbler())
                        .is_some_and(|tuples| tuples.iter().any(document_readable))
            })
        };
        retain_seq(&mut root, &["hints", family], &keep_member);
    }
    for ty in ShippedType::ALL {
        for (label, _) in SLICE_VIEWS {
            retain_seq(&mut root, &["hints", "types", shipped_label(ty), label], &keep_dotted);
        }
    }
    // An EDGE `old → new`: the two endpoints by their own homes, and then by
    // the CLAIM's — the edge stays only where a claim asserting it is homed
    // readably (PUB-6.22).
    retain_map_of_seqs(
        &mut root,
        &["hints", "supersession"],
        &document_readable,
        &|old, new| document_readable(new) && edge_claimed_readably(old, new),
    );
    retain_map(&mut root, &["hints", "publication.drafts"], &keep_dotted);
    root
}

/// The OPERATIVE supersession claims, keyed by the edge each asserts — the
/// denoted OLD endpoint, then the denoted NEW one — for the per-class filter
/// over the dump's `hints.supersession` family.
///
/// NESTED, as M7's own `sup_fwd` hint is and as the fold that builds it is:
/// the caller holds the two endpoints separately, and a probe of a map keyed
/// by a PAIR would have to clone both tumblers to build a key it drops on the
/// next line — once per successor of every rendered edge.
///
/// M7 publishes the edges (`succs`) and not the claims behind them, so the
/// derivation is RESTATED here: one edge per DISTINCT denoted `old` × `new`
/// of every `[K_sup]`-classed tuple, minus the nullified claims. That is
/// `fold_hints`'s supersession arm (the `sup_fwd` build) composed with
/// `succs_operative`'s nullified filter, and the STANDING OBLIGATION on this
/// function is that it stay that composition: an edge the render carries must
/// have at least one claim here, or the filter drops under the total
/// predicate what the harness-only walk rendered, and the identity that makes
/// a reader class's dump the harness-only walk's own tree fails. The test
/// below over a world that HAS an edge is where that agreement is checked,
/// and a change to M7's arm has its counterpart here.
///
/// The NULLIFIED filter is the half of that composition no identity test can
/// hold. A claim kept past its retraction is an EXTRA key, which the total
/// predicate reads like any other, and it keeps for a reader class an edge
/// that only a claim homed where that class cannot read still asserts:
/// `a_retracted_public_claim_does_not_carry_a_draft_s_edge_to_the_guest` is
/// where that direction is checked.
///
/// Both slots are read through `Endset::addrs` UNGUARDED, which is
/// `fold_hints`' own reading and must stay it: that iterator already keeps the
/// unit-depth spans and drops the rest, so an `is_address_denoting` test here
/// would be strictly stronger than the rule being mirrored and would key
/// fewer edges than the harness-only walk renders.
///
/// Nothing in the supersession class can exercise the difference, and the
/// reason is a CLOSURE rather than a coincidence. THREE deposits could put a
/// link in the supersession class, and each is refused or shaped by a door of
/// M7's:
///
/// * `makelink` and `emit` refuse a supersedes-classed type slot outright
///   (`MakeLinkError::SupersessionClass`, `EmitError::SupersessionClass`), so
///   no caller-shaped slot reaches the class through either open surface;
/// * `assert_sup` and `editlink` each build their own CLAIM value,
///   `Link::triple(enc([old]), enc([new]), …)` — one unit-depth span a side,
///   by construction rather than by a check; and
/// * `editlink` additionally deposits a SUCCESSOR that is the caller's own
///   `Link`, so a supersedes-classed one arrives with caller-shaped
///   endpoints. `LinkState::check_sup_schema` is the door that shapes it —
///   `single_denoted` on each endpoint slot — and `editlink` refuses its
///   verdict as `EditLinkError::DcViolation`.
///
/// Those three are what make the cross product below 1 × 1 per claim rather
/// than a product of two slot widths, and
/// `no_door_admits_a_wide_endpoint_into_the_supersession_class` pins all three.
/// The last is the one whose relaxation costs most quietly: M7 admitting a
/// multi-address endpoint would leave this derivation faithful, since it
/// mirrors `fold_hints` whatever a slot holds, and would make the walk
/// quadratic in two slot widths bounded by `skep_links::MAX_SLOT_SPANS`,
/// paid on every filtered dump.
///
/// Read through M7's public surface alone — the class's `type_slice` under
/// the audit view, `is_nullified` and `readlink` per claim — at filter time:
/// the dump is a whole-world render and this is one more whole-class walk;
/// the hint's stored shape is not widened. A claim's home is
/// `document_of(claim)`, the same address arithmetic every other hint entry
/// is judged by.
///
/// `type_slice` carries a stated PRECONDITION on its class — address-denoting
/// or `iextent`-built, else it panics naming it — and this function takes no
/// class from a caller: the one below is `reserved_type(Supersedes)`, M7's
/// own endset, which discharges it.
fn sup_edge_claims(links: &LinkState) -> BTreeMap<Tumbler, BTreeMap<Tumbler, Vec<Address>>> {
    let sup = links.reserved_type(ShippedType::Supersedes);
    let mut by_edge: BTreeMap<Tumbler, BTreeMap<Tumbler, Vec<Address>>> = BTreeMap::new();
    for claim in links.type_slice(sup, View::Audit) {
        if links.is_nullified(&claim) {
            continue; // Df-SUCC: a nullified claim asserts no operative edge
        }
        // RESIDENCY is M7's stated postcondition on `type_slice`, and M7
        // fail-stops on it itself (`LinkState::link_at`). Skipping the claim
        // instead would key fewer edges than the harness-only walk renders,
        // which is the one departure this derivation's standing obligation
        // forbids: under the total predicate the filter would drop what the
        // harness-only walk wrote.
        let link = links
            .readlink(&claim)
            .expect("a type_slice key names a resident link (M7's postcondition)");
        let old_ends: BTreeSet<&Tumbler> = link.from_slot().addrs().collect();
        let new_ends: BTreeSet<&Tumbler> = link.to_slot().addrs().collect();
        for &old in &old_ends {
            let by_new = by_edge.entry(old.clone()).or_default();
            for &new in &new_ends {
                by_new.entry(new.clone()).or_default().push(claim.clone());
            }
        }
    }
    by_edge
}

/// The tuples of class `ty` under `view` that ASSERT each member, keyed by the
/// denoted member — for the per-class filter over the dump's predicate
/// projections ([`PREDICATE_PROJECTIONS`]).
///
/// `LinkState::members` publishes the members and not the tuples behind them,
/// so the derivation is RESTATED here, and the STANDING OBLIGATION is that it
/// stay `members`' own denotation rule: the union of the F-slot's denoted
/// addresses over the class's slice under that view. Two departures from that
/// rule would each break the identity that makes a reader class's dump the
/// harness-only walk's own tree, by keying fewer members than the
/// harness-only walk renders —
///
/// * an `is_address_denoting` guard on the F slot, which is STRICTLY STRONGER
///   than `Endset::addrs`: that iterator already keeps the unit-depth spans
///   and drops the rest, so a mixed slot denotes under `members` and would
///   denote nothing here. What makes that a live risk rather than a nicety is
///   that these classes are NOT closed the way the supersession class is:
///   `makelink` fences the retraction and supersession classes and no others,
///   so a predicate-classed link reaches the slice with a CALLER-SHAPED
///   subject slot — many denoted members, or a shape the managed surface
///   would never build — and this walk must read it exactly as `members`
///   does (`a_mixed_subject_slot_keys_the_member_it_denotes_as_members_does`);
///   and
/// * a view of this function's own choosing. `members` subtracts the filtered
///   roots under `View::Default` alone, and the builder reads `Audit` and
///   `Active`, so each row of [`PREDICATE_PROJECTIONS`] carries the view its own
///   entries were rendered under.
///
/// Keying a member the harness-only walk did NOT render is free: nothing
/// probes it. Keying an extra TUPLE against a member it DID render is not,
/// because one readably-homed tuple keeps the entry — an audit-view tuple
/// keyed for an active-view row keeps a member whose only active registration
/// is a draft's, and the total predicate reads that tuple like any other, so
/// no identity test can tell.
/// `a_projection_entry_is_judged_at_its_own_row_s_view` holds the row's view
/// in both directions.
///
/// Read through M7's public surface alone — the class's `type_slice` and
/// `readlink` per tuple — at filter time, as [`sup_edge_claims`] is. A tuple's
/// home is `document_of(tuple)`, the same address arithmetic every other hint
/// entry is judged by.
///
/// `ty` carries M7's stated precondition — address-denoting or
/// `iextent`-built, else `type_slice` panics naming it — and unlike
/// [`sup_edge_claims`], which reads its own class off the store, this one
/// takes the class from a caller, so the obligation is the CALLER's and
/// belongs here where they can read it. [`filter_tree`] discharges it: it
/// passes `reserved_type` of each row of [`PREDICATE_PROJECTIONS`], and a
/// reserved endset is M7's own.
fn member_tuples(links: &LinkState, ty: &Endset, view: View) -> BTreeMap<Tumbler, Vec<Address>> {
    let mut by_member: BTreeMap<Tumbler, Vec<Address>> = BTreeMap::new();
    for tuple in links.type_slice(ty, view) {
        // RESIDENCY is M7's stated postcondition on `type_slice`, as at
        // `sup_edge_claims`, and skipping the tuple would key fewer members
        // than the harness-only walk renders — the departure the standing
        // obligation above forbids.
        let link = links
            .readlink(&tuple)
            .expect("a type_slice key names a resident link (M7's postcondition)");
        for member in link.from_slot().addrs() {
            by_member.entry(member.clone()).or_default().push(tuple.clone());
        }
    }
    by_member
}

/// The entry at `path` — a chain of string keys through nested maps — if the
/// tree holds one there, borrowed for a reduction to retain in place.
fn at_path_mut<'t>(tree: &'t mut SerdeTree, path: &[&str]) -> Option<&'t mut SerdeTree> {
    let Some((name, rest)) = path.split_first() else {
        return Some(tree);
    };
    let SerdeTree::Map(entries) = tree else {
        return None;
    };
    for (k, v) in entries.iter_mut() {
        if matches!(k, SerdeTree::Str(s) if s.as_str() == *name) {
            return at_path_mut(v, rest);
        }
    }
    None
}

/// Keep the entries of the map at `path` whose KEY `keep` admits.
fn retain_map(tree: &mut SerdeTree, path: &[&str], keep: &dyn Fn(&SerdeTree) -> bool) {
    if let Some(SerdeTree::Map(entries)) = at_path_mut(tree, path) {
        entries.retain(|(k, _)| keep(k));
    }
}

/// Keep the items of the sequence at `path` that `keep` admits.
fn retain_seq(tree: &mut SerdeTree, path: &[&str], keep: &dyn Fn(&SerdeTree) -> bool) {
    if let Some(SerdeTree::Seq(items)) = at_path_mut(tree, path) {
        items.retain(|item| keep(item));
    }
}

/// Keep the PAIRS of the adjacency map at `path` — a map from a dotted key to
/// a sequence of dotted items — that both predicates admit: an entry stays
/// where `keep_key` admits its key, and each of that entry's items stays where
/// `keep_pair` admits it with the key. An entry whose sequence empties LEAVES,
/// because the harness-only walk renders no empty one.
///
/// Both addresses re-enter through [`dotted_address`] here rather than at the
/// caller, so this helper holds the fail-closed key rule itself: what does not
/// decode is dropped, on either side of a pair. The SHAPE direction is its
/// siblings' — a node that is not a map at `path`, or an entry whose value is
/// not a sequence, is left whole rather than emptied.
fn retain_map_of_seqs(
    tree: &mut SerdeTree,
    path: &[&str],
    keep_key: &dyn Fn(&Address) -> bool,
    keep_pair: &dyn Fn(&Address, &Address) -> bool,
) {
    let Some(SerdeTree::Map(entries)) = at_path_mut(tree, path) else {
        return;
    };
    entries.retain_mut(|(key, value)| {
        let Some(key_addr) = dotted_address(key).filter(|a| keep_key(a)) else {
            return false;
        };
        match value {
            SerdeTree::Seq(items) => {
                items.retain(|item| {
                    dotted_address(item).is_some_and(|item_addr| keep_pair(&key_addr, &item_addr))
                });
                !items.is_empty()
            }
            _ => true,
        }
    });
}

/// An address in a STORE's own serde form — a bare tumbler, which is how
/// `Address` serializes and so how the authoritative maps key themselves —
/// back through the type's own door: `Address`'s `Deserialize`, whose
/// `try_from` shadow is `validate`. Read off a map key today, and off
/// whatever node the store wrote it to.
fn serde_form_address(node: &SerdeTree) -> Option<Address> {
    Address::deserialize(TreeDe(node)).ok()
}

/// A dotted-address string — the form the dump's OWN builders render an
/// address in, so the hints' entries and the two sections' — as the address
/// it names. Read off a sequence item and off a map key alike.
fn dotted_address(node: &SerdeTree) -> Option<Address> {
    let SerdeTree::Str(s) = node else {
        return None;
    };
    let comps: Option<Vec<Nat>> = s.split('.').map(|c| c.parse::<Nat>().ok()).collect();
    validate(Tumbler::new(comps?).ok()?).ok()
}

#[cfg(test)]
mod tests;
