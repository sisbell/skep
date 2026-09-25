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
//!   `arrangements` and `provenance` are M5's (its third, `birth_extents`, is
//!   kept whole by name and ends no path), `links` is M7's. So a store
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
            .is_some_and(|asserting| asserting.iter().any(|claim| document_readable(claim)))
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
///   endpoints. `LinkState::conforms_to_sup_schema` is the door that shapes
///   it — `single_denoted` on each endpoint slot — refusing as
///   `EditLinkError::DcViolation`.
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
mod tests {
    use skep_address::parent;
    use skep_arrangement::{trunk_of, Caller, Deposit, Run, Shot, ShotRun, VPos};
    use skep_content::Val;
    use skep_kernel::TxnError;
    use skep_links::{
        enc, EditLinkError, EmitError, Link, MakeLinkError, ReservedAddrs, SlotArg,
    };
    use skep_namespace::PrincipalId;

    use crate::dump::tests::{populated_world, render_of, vspec};
    use crate::dump::{dump, dump_tree, dump_visible, BANNER};
    use crate::testkit::{a_published_home_and_a_private_draft, element, USER};
    use crate::world::World;

    use super::*;

    /// The SHAPE a reduction expects at its path. [`retain_map`] and
    /// [`retain_seq`] do nothing where the node is not theirs, so a builder
    /// that reshaped an entry without renaming it would leave the reduction
    /// filtering nothing — which is why the shape is asserted and not merely
    /// the place.
    #[derive(Debug, PartialEq, Eq)]
    enum Shape {
        Map,
        Seq,
    }

    /// [`populated_world`]'s ONE draft — the document its content, its
    /// arrangement and its link are all homed in, which is what makes a guest
    /// owed nothing of any of them.
    ///
    /// The exception set is HASH-KEYED and its enumeration has no order of
    /// its own, so taking the first entry is deterministic only while there
    /// is one entry to take. A fixture that grew a second document would
    /// leave the three tests below choosing a draft per process — passing or
    /// failing on the hasher's seed, which is worse than either. The count is
    /// asserted here so that growth is an immediate and legible failure
    /// instead.
    fn the_one_draft(world: &World) -> Address {
        let drafts: Vec<&Address> = world.drafts().map(|d| d.document).collect();
        assert_eq!(drafts.len(), 1, "the fixture must hold exactly one draft: {drafts:?}");
        drafts[0].clone()
    }

    /// The dump TREE at `principal`'s reader class — `None` is the guest — as
    /// [`crate::Engine::dump_of_visible`] reduces it, before render.
    fn tree_visible_to(world: &World, principal: Option<PrincipalId>) -> SerdeTree {
        filter_tree(dump_tree(world), &|doc: &Address| world.readable(principal, doc), &world.links)
    }

    /// EVERY path [`filter_tree`] reduces, with the shape its reduction
    /// expects there — built from the filter's own family list, the format's
    /// projection table and the one shipped-class table, so a family added to
    /// any of them is walked by the tests below without an edit here. Every
    /// component of every path is a compiled string: the section, slice and
    /// field names are literals, the family names are the two tables' own, and
    /// [`shipped_label`] answers with the format's.
    fn reduced_paths() -> Vec<(Vec<&'static str>, Shape)> {
        let mut paths = vec![
            (vec!["authoritative", "content", "map"], Shape::Map),
            (vec!["authoritative", "arrangement", "arrangements"], Shape::Map),
            (vec!["authoritative", "arrangement", "provenance"], Shape::Map),
            (vec!["authoritative", "links", "links"], Shape::Map),
            (vec!["publication"], Shape::Seq),
        ];
        for family in REDUCED_BY_HOME {
            paths.push((vec!["hints", family], Shape::Seq));
        }
        for (family, _, _) in PREDICATE_PROJECTIONS {
            paths.push((vec!["hints", family], Shape::Seq));
        }
        for ty in ShippedType::ALL {
            for (label, _) in SLICE_VIEWS {
                paths.push((vec!["hints", "types", shipped_label(ty), label], Shape::Seq));
            }
        }
        paths.push((vec!["hints", "supersession"], Shape::Map));
        paths.push((vec!["hints", "publication.drafts"], Shape::Map));
        paths
    }

    /// The entry at `path`, SHARED: the tests read the trees the reductions
    /// write, and [`at_path_mut`] is the reductions' own walk.
    fn at_path<'t>(tree: &'t SerdeTree, path: &[&str]) -> Option<&'t SerdeTree> {
        let Some((name, rest)) = path.split_first() else {
            return Some(tree);
        };
        let SerdeTree::Map(entries) = tree else {
            return None;
        };
        let (_, next) =
            entries.iter().find(|(k, _)| matches!(k, SerdeTree::Str(s) if s.as_str() == *name))?;
        at_path(next, rest)
    }

    /// The node at `path`, as a shape and a count.
    fn shape_and_len(tree: &SerdeTree, path: &[&str]) -> (Shape, usize) {
        match at_path(tree, path) {
            Some(SerdeTree::Map(entries)) => (Shape::Map, entries.len()),
            Some(SerdeTree::Seq(items)) => (Shape::Seq, items.len()),
            other => panic!("{path:?}: expected a map or a sequence, got {other:?}"),
        }
    }

    /// The v5 root: the two publication-round sections sit beside the
    /// authoritative and hints sections, and every path the filter reduces
    /// names a place in the tree OF THE SHAPE that reduction expects. A slice
    /// renaming its serde field, or a builder reshaping an entry under an
    /// unchanged key, would otherwise leave the filter silently filtering
    /// nothing — which is the one failure a fail-closed key rule cannot catch.
    #[test]
    fn the_v5_root_and_the_filter_s_paths_exist() {
        let (_engine, world) = populated_world();
        let tree = dump_tree(&world);
        for (path, want) in reduced_paths() {
            let (found, _) = shape_and_len(&tree, &path);
            assert_eq!(found, want, "{path:?}: the reduction's shape is not what the builder wrote");
        }
        // …and the slice and the section kept WHOLE — `authoritative.namespace`
        // and `grants` — are places in the tree too, so the statement that
        // names them can be read against something.
        for path in [&["authoritative", "namespace"][..], &["grants"]] {
            assert!(at_path(&tree, path).is_some(), "{path:?} is a place in the v5 tree");
        }
    }

    /// [`filter_tree`]'s statement, held against what the builders write at
    /// each of its five levels — the one test that fails on an entry the
    /// statement does not account for.
    ///
    /// No neighbour sees that failure. The identity tests keep everything by
    /// construction, the guest tests walk a fixed path list a new entry is not
    /// on, and `the_v5_root_and_the_filter_s_paths_exist` asks the question the
    /// other way round: whether every path names a place, not whether every
    /// place has a path. Two levels are beyond a family list besides, each for
    /// its own reason:
    ///
    /// * a SHIPPED CLASS's submap, where the filter reduces two entries per
    ///   shipped class by NAME, so a fourth added beside them goes out whole
    ///   with every path in the filter still naming a place; and
    /// * an AUTHORITATIVE slice's serde fields, where the addition is not an
    ///   engine edit at all. A store growing a field on its slice discloses
    ///   whatever that field holds about a document the reader class cannot
    ///   open, and the store author has no compiler edge to this file.
    ///
    /// What this asks of an addition is a DISPOSITION, which is why the format
    /// tests pinning the rendered text are not a substitute at any level. Those
    /// fire on the new bytes and are answered by updating the expected bytes —
    /// the ordinary move when a format moves on purpose — and the entry ships
    /// unreduced. This one is answered only by reducing the entry or by listing
    /// it among those kept.
    ///
    /// The predicate projections' four names reach both sides of the hints
    /// comparison from `super::PREDICATE_PROJECTIONS`, the builder's own table,
    /// so for that group the assertion is not that two lists agree — they are
    /// one list. What it still catches there is a family written into
    /// `super::hints_tree` beside the table rather than into it.
    ///
    /// Asked of GENESIS, because the tree's keys are FORMAT rather than
    /// content: every builder pushes every key whatever the world holds, so an
    /// empty world carries the whole set and the assertion is over the format
    /// and not over a fixture.
    #[test]
    fn every_entry_at_each_level_of_the_tree_is_reduced_or_kept_by_name() {
        let tree = dump_tree(&World::genesis());
        let keys_at = |tree: &SerdeTree, path: &[&str]| -> BTreeSet<String> {
            match at_path(tree, path) {
                Some(SerdeTree::Map(entries)) => entries
                    .iter()
                    .map(|(k, _)| match k {
                        SerdeTree::Str(s) => s.clone(),
                        other => panic!("{path:?}: the tree's keys are strings, got {other:?}"),
                    })
                    .collect(),
                other => panic!("{path:?}: expected a map, got {other:?}"),
            }
        };

        // The hints section: the by-home families, the by-tuple families, and
        // the three the filter reduces through an arm of their own.
        let families: BTreeSet<String> = REDUCED_BY_HOME
            .iter()
            .copied()
            .chain(PREDICATE_PROJECTIONS.iter().map(|(family, _, _)| *family))
            .chain(["types", "supersession", "publication.drafts"])
            .map(|name| name.to_owned())
            .collect();
        assert_eq!(
            keys_at(&tree, &["hints"]),
            families,
            "a hints family the filter does not name is rendered whole to every reader class"
        );

        // …the root, where each section has a disposition in the filter's one
        // statement: `publication` and `hints` reduced, `grants` kept whole
        // with the reason given, and `authoritative` reduced slice by slice at
        // the two levels below.
        let sections: BTreeSet<String> = ["authoritative", "publication", "grants", "hints"]
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        assert_eq!(
            keys_at(&tree, &[]),
            sections,
            "a root section the filter does not name is rendered whole to every reader class"
        );

        // …the AUTHORITATIVE section's own two levels, which no family list
        // reaches and which a change in ANOTHER CRATE moves. First its four
        // slices, one per store.
        let slices: BTreeSet<String> = ["namespace", "content", "arrangement", "links"]
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        assert_eq!(
            keys_at(&tree, &["authoritative"]),
            slices,
            "an authoritative slice the filter does not name is rendered whole to every \
             reader class"
        );
        // …then, inside each, that store's own serde fields — the level the
        // filter's four authoritative paths END in. A store adding a field to
        // its slice ships it to the guest with every path here still naming a
        // place, and with no compiler edge from that store to this file.
        for (slice, fields) in [
            // M3's four, kept WHOLE with the reason in `filter_tree`'s
            // statement — listed so a fifth is a decision and not a default.
            ("namespace", &["frontiers", "nodes", "principals", "publication"][..]),
            ("content", &["map"]),
            // M5's two keyed fields reduced, and its birth memo kept WHOLE
            // with the reason in `filter_tree`'s statement.
            ("arrangement", &["arrangements", "birth_extents", "provenance"]),
            // M7's skip-serialized hints occupy no bytes and so no key.
            ("links", &["links"]),
        ] {
            let named: BTreeSet<String> = fields.iter().map(|name| (*name).to_owned()).collect();
            assert_eq!(
                keys_at(&tree, &["authoritative", slice]),
                named,
                "{slice}: a serde field the filter does not name is rendered whole to every \
                 reader class"
            );
        }

        // …and INSIDE each shipped class, the level the two family lists above
        // cannot reach: the filter reduces one typed slice per row of
        // `SLICE_VIEWS` and keeps `key` as the format constant it is, so a
        // fourth entry the builder added here would be rendered whole to the
        // guest with every path in the filter still naming a place.
        let class_entries: BTreeSet<String> = SLICE_VIEWS
            .iter()
            .map(|(label, _)| *label)
            .chain(["key"])
            .map(|name| name.to_owned())
            .collect();
        for ty in ShippedType::ALL {
            let label = shipped_label(ty);
            assert_eq!(
                keys_at(&tree, &["hints", "types", label]),
                class_entries,
                "{label}: a shipped-class entry the filter does not name is rendered whole to \
                 every reader class"
            );
        }
    }

    /// Lane 3.4 §4: the per-class filter under the TOTAL predicate is the
    /// identity — every path it walks names a place in the tree, and it
    /// touches nothing else — so the harness-only walk and a reader who may
    /// read everything dump one text. The populated world holds an entry in
    /// every filtered map and sequence family the filter reaches, which is
    /// what makes the equality say something about the paths.
    #[test]
    fn the_filter_under_the_total_predicate_is_the_identity() {
        let (_engine, world) = populated_world();
        assert_eq!(dump_visible(&world, &|_: &Address| true), dump(&world));
        assert!(dump(&world).as_str().starts_with(BANNER), "one banner for both renderings");
    }

    /// …and under the GUEST predicate the draft's content, arrangement and
    /// link leave while the namespace slice and the grants section stay whole
    /// and the publication section empties: the populated world's one
    /// document is a DRAFT, so a guest sees its registration and nothing it
    /// holds. Asked of the TREE, where each place can be named, rather than of
    /// the text.
    #[test]
    fn the_guest_filter_drops_a_draft_s_entries_and_keeps_the_namespace_slice_and_grants_section() {
        let (_engine, world) = populated_world();
        let full = dump_tree(&world);
        let guest = tree_visible_to(&world, None);

        let len_at = |tree: &SerdeTree, path: &[&str]| match at_path(tree, path) {
            Some(SerdeTree::Map(entries)) => entries.len(),
            Some(SerdeTree::Seq(items)) => items.len(),
            other => panic!("{path:?}: expected a map or a sequence, got {other:?}"),
        };
        for path in [
            &["authoritative", "content", "map"][..],
            &["authoritative", "arrangement", "arrangements"],
            &["authoritative", "arrangement", "provenance"],
            &["authoritative", "links", "links"],
            &["publication"],
            &["hints", "links.audit"],
            &["hints", "links.active"],
            &["hints", "publication.drafts"],
        ] {
            assert!(len_at(&full, path) > 0, "{path:?}: the fixture must populate it");
            assert_eq!(len_at(&guest, path), 0, "{path:?}: a guest reads nothing of a draft");
        }
        // The namespace slice is untouched. The `grants` section is kept whole
        // too, but this fixture deposits no grant, so what the loop below
        // compares there is one empty map against another — the integration
        // suite's guest tests are what hold that section's content against a
        // world that has one.
        for path in [&["authoritative", "namespace"][..], &["grants"]] {
            let a = render_of(at_path(&full, path).expect("present"));
            let b = render_of(at_path(&guest, path).expect("present"));
            assert_eq!(a, b, "{path:?} is kept whole");
        }
    }

    /// The premise `authoritative.arrangement.birth_extents`' WHOLE disposition
    /// rests on, held against the memo a world actually carries: every key M5's
    /// fold writes there is a VERSION MEMBER, and every version address names a
    /// PUBLISHED state (PUB-2.10; a private document is versionless, PUB-2.9) —
    /// so the guest, the narrowest reader class, reads every key's document,
    /// and keeping the field whole discloses nothing.
    ///
    /// Nothing else holds the premise, and no other fixture gives the memo an
    /// entry at all: the level test pins the field's NAME, and the identity and
    /// guest tests run over versionless worlds. So a memo M5 widened — noting a
    /// trunk's own birth, a draft's among them — would reach every reader
    /// class's dump with the suite green, and so would a reduction here that
    /// emptied the field. The fixture drives both of M5's arms that write the
    /// memo, and the placement that must not: a placement into a DRAFT, which
    /// notes nothing; an owned VERSION of the published home, whose snapshot
    /// notes the birth member it mints; and a publish SHOT into a published
    /// edition, whose one placement notes the member IT mints — the route the
    /// daemon's head writer takes for every head.
    #[test]
    fn every_birth_memo_key_is_a_version_member_whose_state_the_guest_reads() {
        let (engine, home, draft) = a_published_home_and_a_private_draft();
        let caller = Caller::Principal(USER);
        let (start, _) = engine
            .vstream()
            .insert(
                caller,
                &draft,
                VPos { subspace: Nat::from(1u32), ordinal: Nat::from(1u32) },
                vec![Val::new(vec![b'd'])],
                Deposit::Undeclared,
            )
            .expect("the owner writes its draft");
        let (birth_member, _) = engine
            .vstream()
            .version(USER, &home, None)
            .expect("an owned version of the published home");
        let account = parent(&home).expect("a document's parent is its account");
        let (edition, _) = engine
            .namespace()
            .create_new_document(USER, &account, Some(true))
            .expect("a published edition, memberless");
        let shot = Shot {
            base: None,
            draft: Some(draft.clone()),
            runs: vec![ShotRun {
                origin: draft.clone(),
                run: Run::new(start, Nat::from(1u32)).expect("the draft's one value"),
            }],
        };
        let (shot_member, _) = engine
            .vstream()
            .publish(caller, &edition, shot, &World::visible_to(caller))
            .expect("the birth shot from the draft into the edition");
        let world = engine.kernel().snapshot().world().clone();
        let path = ["authoritative", "arrangement", "birth_extents"];
        let full = dump_tree(&world);
        let keys: Vec<Address> = match at_path(&full, &path) {
            Some(SerdeTree::Map(entries)) => entries
                .iter()
                .map(|(k, _)| {
                    serde_form_address(k).expect("a memo key is an address in M5's serde form")
                })
                .collect(),
            other => panic!("M5's birth memo renders as a map, got {other:?}"),
        };
        for member in [&birth_member, &shot_member] {
            assert!(
                keys.contains(member),
                "the fixture must give the memo its birth member {member}: {keys:?}"
            );
        }
        for key in &keys {
            assert_ne!(
                trunk_of(key),
                *key,
                "birth memo key {key} is no version member: the whole disposition owes a reduction"
            );
            assert!(
                world.readable(None, key),
                "birth memo key {key} names a state the guest cannot read, and the guest's dump \
                 carries it"
            );
        }
        let guest = tree_visible_to(&world, None);
        assert_eq!(
            render_of(at_path(&guest, &path).expect("present")),
            render_of(at_path(&full, &path).expect("present")),
            "the guest's dump carries the memo whole"
        );
        assert_eq!(dump_visible(&world, &|_: &Address| true), dump(&world));
    }

    /// A world holding an entry in EVERY family the reduction reaches, all of
    /// it homed in ONE private draft — so a guest is owed nothing of any of
    /// it, and each path's reduction has something to drop.
    ///
    /// Built on [`populated_world`]'s account, draft, content, arrangement and
    /// link, which cover the authoritative maps and the two publication
    /// families; this adds the link population the shipped classes and the
    /// predicate projections need. The links carry ADDRESS-form slots under
    /// never-minted types in the draft's own subspace 3, so each lands in an
    /// unregistered coverage class and the shipped slices hold exactly the
    /// tuples deposited under them.
    fn every_reduced_family_in_a_draft() -> World {
        let (engine, world) = populated_world();
        let draft = the_one_draft(&world);
        let caller = Caller::Principal(USER);
        let visibility = World::visible_to(caller);
        let writer = engine.linkstore(&visibility);
        let ordinary_link = |n: u32| {
            writer
                .makelink(
                    caller,
                    &draft,
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(vec![element(&draft, 3, n)]),
                )
                .expect("a link in the owner's own draft")
                .0
        };
        // Two endpoints for the supersession claim, and one link to retract.
        let (old, new, retracted) = (ordinary_link(41), ordinary_link(42), ordinary_link(43));
        writer
            .assert_sup(caller, &draft, &old, &new)
            .expect("a supersession claim over two of the draft's links");
        writer.nullify(caller, &draft, &retracted).expect("the owner retracts its own link");
        // One managed tuple per remaining shipped class, over members of the
        // draft — which is what puts the predicate projections in the tree.
        for ty in [ShippedType::Retired, ShippedType::PredDef, ShippedType::PredStable] {
            let class = engine.registry().reserved_type(ty).clone();
            writer
                .emit(caller, &draft, &class, &element(&draft, 1, 9), &[])
                .unwrap_or_else(|e| panic!("a {ty:?} tuple in the owner's own draft: {e:?}"));
        }
        engine.kernel().snapshot().world().clone()
    }

    /// Every path the filter reduces DOES reduce: over a world whose every
    /// reduced family is populated out of one private draft, the unfiltered
    /// walk holds an entry at each and a guest's holds none.
    ///
    /// The one test that walks the reduction's WHOLE surface rather than a
    /// hand-picked slice of it, and the only one that can fail on a path
    /// reducing NOTHING — a family whose arm was never written, a path string
    /// that no longer names a place, a node reshaped under an unchanged key.
    /// Its neighbours cannot: the identity tests keep everything by
    /// construction, and the guest test below fixes on the eight paths its own
    /// fixture populates.
    ///
    /// It cannot fail on an entry judged at the WRONG ADDRESS, and the shape
    /// of this fixture is why: with every deposit and every member inside one
    /// draft, each entry's tests agree whatever they are asked about. That
    /// failure needs an entry whose disclosures STRADDLE the boundary, which
    /// is `a_guest_s_predicate_projections_hold_neither_a_draft_s_tuple_nor_its_member`'s
    /// fixture and not this one. Two failures, two tests.
    ///
    /// The supersession family's SECOND shape level is asserted here too, and
    /// a path list cannot reach it: [`retain_map_of_seqs`] tests the outer map
    /// and then each entry's VALUE, and an entry whose value it does not
    /// recognize is kept on the KEY test ALONE — with the claim's home never
    /// asked. Every other reduction has one shape and `reduced_paths` asserts
    /// it; this is the one with two, and the second is what a reader class's
    /// own edges turn on.
    ///
    /// It is the SHAPE claim that is completed here, not an unwatched
    /// disclosure: reshaping that family reddens
    /// `a_draft_homed_supersession_claim_over_public_links_leaves_the_guest_s_edges`
    /// too, which counts a guest's edges over exactly the world where the
    /// key test passes and the claim's does not. What this adds is the
    /// failure that names the reshaped entry instead of a guest's edge count,
    /// over a fixture that need not straddle the boundary to have one.
    #[test]
    fn every_reduced_path_actually_reduces() {
        let world = every_reduced_family_in_a_draft();
        let full = dump_tree(&world);
        let guest = tree_visible_to(&world, None);
        for (path, want) in reduced_paths() {
            let (shape, len) = shape_and_len(&full, &path);
            assert_eq!(shape, want, "{path:?}: the reduction's shape is not the builder's");
            assert!(len > 0, "{path:?}: the fixture must populate every reduced family");
            assert_eq!(
                shape_and_len(&guest, &path).1,
                0,
                "{path:?}: a guest is owed nothing of a draft, and this path reduces nothing"
            );
        }
        // The one entry whose reduction has a SECOND shape level: an edge's
        // value must be a sequence, or the pair test — and with it the claim's
        // home — never runs on it.
        match at_path(&full, &["hints", "supersession"]) {
            Some(SerdeTree::Map(entries)) => {
                assert!(!entries.is_empty(), "the fixture must render an edge");
                for (old, succs) in entries.iter() {
                    assert!(
                        matches!(succs, SerdeTree::Seq(_)),
                        "hints.supersession {old}: an edge's successors are a sequence, and \
                         a value of any other shape is kept on its KEY alone"
                    );
                }
            }
            other => panic!("hints.supersession is a map, got {other:?}"),
        }
        // …and the reduction is still the identity under the total predicate
        // over this much richer world, which is what the two re-derivations'
        // standing obligations rest on.
        assert_eq!(dump_visible(&world, &|_: &Address| true), dump(&world));
    }

    /// The PREDICATE classes are open where the supersession class is closed:
    /// `makelink` fences the retraction and supersession classes and no
    /// others, so one caller-shaped deposit puts MANY members in a projection
    /// — which is the bound `dump_of_visible`'s cost states for these walks,
    /// and the reason [`member_tuples`] must read a subject slot exactly as
    /// `LinkState::members` does rather than tighten it.
    ///
    /// Every member of the wide tuple is judged by that one tuple's home, so
    /// all of them leave the guest's dump together.
    #[test]
    fn one_open_surface_deposit_puts_many_members_in_a_projection() {
        let (engine, world) = populated_world();
        let draft = the_one_draft(&world);
        let caller = Caller::Principal(USER);
        let visibility = World::visible_to(caller);
        let members: Vec<Address> = (10..26u32).map(|n| element(&draft, 1, n)).collect();
        // ONE link, sixteen denoted members, through the OPEN surface — a
        // shape `emit`'s `enc({from})` could never build.
        engine
            .linkstore(&visibility)
            .makelink(
                caller,
                &draft,
                SlotArg::Addrs(members.clone()),
                SlotArg::Addrs(Vec::new()),
                SlotArg::Addrs(vec![ReservedAddrs::format().pred_def]),
            )
            .expect("a predicate-classed link deposits through the open surface");

        let world = engine.kernel().snapshot().world().clone();
        let full = dump_tree(&world);
        assert_eq!(
            projection(&full, "predicates.defs.audit").len(),
            members.len(),
            "one deposit, one member per denoted address — the walks' real bound"
        );
        let guest = tree_visible_to(&world, None);
        assert!(
            projection(&guest, "predicates.defs.audit").is_empty(),
            "one tuple's home governs every member it denotes"
        );
        // …and the identity holds over the wide slot, which is what a
        // `single_denoted` reading of the subject slot would break; the
        // `is_address_denoting` guard, which an all-unit-depth slot passes, is
        // `a_mixed_subject_slot_keys_the_member_it_denotes_as_members_does`'s.
        assert_eq!(dump_visible(&world, &|_: &Address| true), dump(&world));
    }

    /// …and the SHAPE of an open-surface subject slot, which the wide slot above
    /// cannot reach: its sixteen `Addrs` are all unit-depth, so an
    /// `is_address_denoting` guard on the F slot — the first departure
    /// [`member_tuples`] names — passes it untouched. A MIXED slot is where that
    /// guard parts from `LinkState::members`: `members` denotes its unit-depth
    /// span's address, the guard would key no tuple, and under the total
    /// predicate the filter would drop a member the harness-only walk rendered —
    /// for a slot any client's MAKELINK can deposit.
    #[test]
    fn a_mixed_subject_slot_keys_the_member_it_denotes_as_members_does() {
        let (engine, _home, draft) = a_published_home_and_a_private_draft();
        let caller = Caller::Principal(USER);
        engine
            .vstream()
            .insert(
                caller,
                &draft,
                VPos { subspace: Nat::from(1u32), ordinal: Nat::from(1u32) },
                vec![Val::new(vec![b'x']), Val::new(vec![b'y']), Val::new(vec![b'z'])],
                Deposit::Undeclared,
            )
            .expect("the owner writes its draft");
        // One position, then two: a unit-depth span beside one that is not.
        let (tuple, _) = engine
            .linkstore(&World::visible_to(caller))
            .makelink(
                caller,
                &draft,
                SlotArg::Resolve(vec![vspec(&draft, 1, 1), vspec(&draft, 2, 2)]),
                SlotArg::Addrs(Vec::new()),
                SlotArg::Addrs(vec![ReservedAddrs::format().pred_def]),
            )
            .expect("a predicate-classed link deposits through the open surface");
        let world = engine.kernel().snapshot().world().clone();
        let from = world.links.readlink(&tuple).expect("the tuple is resident").from_slot();
        assert!(
            !from.is_address_denoting() && from.addrs().count() == 1,
            "the fixture must deposit a MIXED subject slot, or the guard and `members` agree: \
             {from:?}"
        );
        assert_eq!(
            projection(&dump_tree(&world), "predicates.defs.audit").len(),
            1,
            "`members` denotes the unit-depth span's one address and nothing of the other span"
        );
        assert_eq!(dump_visible(&world, &|_: &Address| true), dump(&world));
    }

    /// The CLOSURE [`sup_edge_claims`]' unguarded `Endset::addrs` reading
    /// rests on, and with it the 1 × 1 cross product the filter's cost is
    /// stated at — all THREE of its doors, because a slot reaches the class
    /// three ways and the third is not an open surface at all:
    ///
    /// * `makelink` refuses a supersedes-classed type slot;
    /// * `emit` refuses it too; and
    /// * `editlink` deposits a caller-supplied SUCCESSOR beside its own
    ///   claim, so a supersedes-classed successor is a caller-shaped slot
    ///   arriving in the class through the MANAGED surface. M7's
    ///   `conforms_to_sup_schema` is what shapes it, and a two-address
    ///   endpoint is refused there.
    ///
    /// The derivation would still be faithful without any of the three — it
    /// mirrors `fold_hints`' own unguarded read, so the two agree whatever a
    /// slot holds — but the COST would not: a door that admitted a
    /// wide-slotted supersedes-classed deposit would make the walk below a
    /// product of two slot widths per claim, paid on every filtered dump.
    #[test]
    fn no_door_admits_a_wide_endpoint_into_the_supersession_class() {
        let (engine, world) = populated_world();
        let draft = the_one_draft(&world);
        let caller = Caller::Principal(USER);
        let visibility = World::visible_to(caller);
        let writer = engine.linkstore(&visibility);
        let sup = engine.registry().reserved_type(ShippedType::Supersedes).clone();
        let sup_addr = ReservedAddrs::format().supersedes;

        // The OPEN surface, with the class in the type slot: refused, so no
        // caller-shaped slot ever reaches the class.
        assert!(
            matches!(
                writer.makelink(
                    caller,
                    &draft,
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(vec![sup_addr.clone()]),
                ),
                Err(TxnError::Rejected(MakeLinkError::SupersessionClass))
            ),
            "makelink must refuse the supersession class"
        );
        assert!(
            matches!(
                writer.emit(caller, &draft, &sup, &sup_addr, &[]),
                Err(TxnError::Rejected(EmitError::SupersessionClass))
            ),
            "emit must refuse the supersession class"
        );

        // Two ordinary links of the draft, to be the endpoints below.
        let ordinary_link = |n: u32| {
            writer
                .makelink(
                    caller,
                    &draft,
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(vec![element(&draft, 3, n)]),
                )
                .expect("a link in the owner's own draft")
                .0
        };
        let (old, new) = (ordinary_link(41), ordinary_link(42));

        // The THIRD door, and the one no open surface guards: `editlink`
        // deposits the caller's own successor beside its claim, so a
        // supersedes-classed successor carries a CALLER-SHAPED endpoint into
        // the class. M7's `conforms_to_sup_schema` refuses a slot that
        // denotes more than one address, and that refusal is what keeps the
        // walk's cross product at 1 × 1.
        let wide = Link::triple(enc([&old, &new]), enc([&new]), enc([&sup_addr]));
        assert!(
            matches!(
                writer.editlink(caller, &old, wide, &draft, &draft),
                Err(TxnError::Rejected(EditLinkError::DcViolation))
            ),
            "editlink must refuse a supersedes-classed successor with a two-address endpoint"
        );

        // …while the same successor narrowed to ONE address a side is
        // ADMITTED, which is what makes the refusal above the WIDTH's rather
        // than the successor's shape or its endpoints' residence — the two
        // other ways `conforms_to_sup_schema` can answer no. Its endpoints run
        // the other way round from the managed claim below so that the two are
        // distinct VALUES: `assert_sup` deposits through the managed gate,
        // which dedups on the value, and an identical successor sitting in the
        // class already would absorb it.
        let narrow = Link::triple(enc([&new]), enc([&old]), enc([&sup_addr]));
        writer
            .editlink(caller, &old, narrow, &draft, &draft)
            .expect("a schema-conforming supersedes-classed successor deposits");

        // …and the managed surface's own claim, built rather than accepted.
        writer.assert_sup(caller, &draft, &old, &new).expect("the managed claim deposits");

        // So what IS in the class is what those doors let through — the
        // admitted successor, `editlink`'s own claim over it, and
        // `assert_sup`'s — and every one of them is the 1 × 1 the derivation
        // walks.
        let world = engine.kernel().snapshot().world().clone();
        let claims = world.links.type_slice(&sup, View::Audit);
        assert_eq!(claims.len(), 3, "the refusals left exactly what the three doors admit");
        for claim in &claims {
            let value = world.links.readlink(claim).expect("a slice key is resident");
            for slot in [value.from_slot(), value.to_slot()] {
                assert!(slot.is_address_denoting(), "a claim's endpoints are addresses");
                assert_eq!(slot.addrs().count(), 1, "one denoted address a side: the 1 × 1");
            }
        }
    }

    /// A world holding ONE supersession edge, whose claim is homed in a
    /// private DRAFT while both endpoints are public links of a published
    /// home — so the edge's three tests disagree, and the claim's is what
    /// governs.
    fn a_draft_homed_claim_over_public_links() -> World {
        let (engine, home, draft) = a_published_home_and_a_private_draft();
        let caller = Caller::Principal(USER);
        let visibility = World::visible_to(caller);
        // Two public links in the home under never-minted types in its own
        // subspace 3 (address-form slots, empty endsets).
        let public_link = |n: u32| {
            engine
                .linkstore(&visibility)
                .makelink(
                    caller,
                    &home,
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(vec![element(&home, 3, n)]),
                )
                .expect("a public link in the home")
                .0
        };
        let (old, new) = (public_link(41), public_link(42));
        // The claim: homed in the DRAFT, over the two public links.
        engine
            .linkstore(&visibility)
            .assert_sup(caller, &draft, &old, &new)
            .expect("a draft-homed supersession claim over public links");
        engine.kernel().snapshot().world().clone()
    }

    fn edge_count(tree: &SerdeTree) -> usize {
        match at_path(tree, &["hints", "supersession"]) {
            Some(SerdeTree::Map(entries)) => entries.len(),
            other => panic!("hints.supersession is a map, got {other:?}"),
        }
    }

    /// The two shapes a PREDICATE PROJECTION can take across the draft
    /// boundary, in one account, so that each of the entry's two tests has a
    /// case only it refuses:
    ///
    /// * a `pred_stable` tuple homed in the private DRAFT whose member is a
    ///   position of the PUBLISHED home — the member's own document is
    ///   readable, so the member-home test admits it and the TUPLE's home is
    ///   what must refuse it; and
    /// * one homed in the published HOME whose member is a position of the
    ///   DRAFT — the tuple is readable, so its home admits it and the
    ///   MEMBER's own document is what must refuse it.
    ///
    /// Returns the world, then the public member and the private one.
    fn predicate_tuples_across_the_draft_boundary() -> (World, Address, Address) {
        let (engine, home, draft) = a_published_home_and_a_private_draft();
        let caller = Caller::Principal(USER);
        let visibility = World::visible_to(caller);
        // A content position of each — never minted, which `emit` does not
        // require of a member and which keeps the two slices empty.
        let (public_member, private_member) = (element(&home, 1, 1), element(&draft, 1, 1));
        let pred_stable = engine.registry().reserved_type(ShippedType::PredStable).clone();
        // The draft-homed registration OF the public member…
        engine
            .linkstore(&visibility)
            .emit(caller, &draft, &pred_stable, &public_member, &[])
            .expect("a draft-homed registration over a public member");
        // …and the public registration of the draft's own member.
        engine
            .linkstore(&visibility)
            .emit(caller, &home, &pred_stable, &private_member, &[])
            .expect("a home-homed registration over a draft's member");
        let world = engine.kernel().snapshot().world().clone();
        (world, public_member, private_member)
    }

    fn projection(tree: &SerdeTree, family: &str) -> Vec<String> {
        match at_path(tree, &["hints", family]) {
            Some(SerdeTree::Seq(items)) => items
                .iter()
                .map(|item| match item {
                    SerdeTree::Str(s) => s.clone(),
                    other => panic!("hints.{family} holds dotted addresses, got {other:?}"),
                })
                .collect(),
            other => panic!("hints.{family} is a sequence, got {other:?}"),
        }
    }

    /// A PREDICATE PROJECTION entry is a MEMBER, not a link, so its two
    /// disclosures take two tests (PUB-6.13) — and each case below is refused
    /// by one of them alone.
    ///
    /// The draft-homed registration of a PUBLIC member is the one a single
    /// member-home test admits: the guest's `shipped.pred_stable` slice is
    /// empty, because the tuple is draft-homed, while the projection would
    /// name the member — the harness-only walk's two renderings of one
    /// deposit, disagreeing, with a draft's content in the guest's dump. The
    /// public registration of a DRAFT's member is the mirror, and is what a
    /// single tuple-home test would admit.
    #[test]
    fn a_guest_s_predicate_projections_hold_neither_a_draft_s_tuple_nor_its_member() {
        let (world, public_member, private_member) =
            predicate_tuples_across_the_draft_boundary();
        let dotted = |a: &Address| a.to_string();

        let full = dump_tree(&world);
        for family in ["predicates.stable.audit", "predicates.stable.active"] {
            let members = projection(&full, family);
            assert_eq!(
                members,
                vec![dotted(&public_member), dotted(&private_member)],
                "{family}: the fixture must render both members in address order"
            );
        }

        let guest = tree_visible_to(&world, None);
        for family in ["predicates.stable.audit", "predicates.stable.active"] {
            assert!(
                projection(&guest, family).is_empty(),
                "{family}: a guest reads neither the draft's registration nor its member"
            );
        }
        // …and the two renderings of these deposits agree about each one. The
        // typed slice holds LINK addresses, so the guest keeps the PUBLIC
        // registration there and loses the draft-homed one; the projection
        // then names neither member, because the public tuple's member is the
        // draft's. A guest reads that a registration exists in the published
        // home and not what it registers.
        let slice_count = |tree: &SerdeTree, label: &str| {
            match at_path(tree, &["hints", "types", "shipped.pred_stable", label]) {
                Some(SerdeTree::Seq(items)) => items.len(),
                other => {
                    panic!("the shipped.pred_stable {label} slice is a sequence, got {other:?}")
                }
            }
        };
        for (label, _) in SLICE_VIEWS {
            assert_eq!(slice_count(&full, label), 2, "the fixture deposits two registrations");
            assert_eq!(
                slice_count(&guest, label),
                1,
                "the {label} slice keeps the public registration and drops the draft-homed one"
            );
        }

        // The OWNER reads both homes, so both members stay…
        let owner = tree_visible_to(&world, Some(USER));
        assert_eq!(
            projection(&owner, "predicates.stable.audit"),
            vec![dotted(&public_member), dotted(&private_member)],
            "the owner reads both the tuples' homes and the members' documents"
        );
        // …and under the TOTAL predicate the filter is the identity, which is
        // what [`member_tuples`]' obligation rests on: a re-derivation that
        // keyed fewer members than the harness-only walk renders would drop
        // them here.
        assert_eq!(
            dump_visible(&world, &|_: &Address| true),
            dump(&world),
            "a re-derivation missing a member's tuple would drop the entry here"
        );
    }

    /// Lane 4.2, F4 (register cell I3.a): a supersession CLAIM is a link and
    /// its HOME governs what a reader class sees of it (PUB-6.13, PUB-6.22,
    /// PUB-6.27) — so an edge in `hints.supersession` asserted only by a
    /// DRAFT-homed `assert_sup` over two PUBLIC links leaves the guest's dump
    /// with its claim, while both public endpoints stay, and the owner's dump
    /// — who reads the claim's home — keeps the edge.
    #[test]
    fn a_draft_homed_supersession_claim_over_public_links_leaves_the_guest_s_edges() {
        let world = a_draft_homed_claim_over_public_links();
        let full = dump_tree(&world);
        assert_eq!(edge_count(&full), 1, "the fixture asserts exactly one edge");
        let owner = tree_visible_to(&world, Some(USER));
        assert_eq!(edge_count(&owner), 1, "the owner reads the claim's home, so the edge stays");
        let guest = tree_visible_to(&world, None);
        assert_eq!(edge_count(&guest), 0, "no readably-homed claim asserts it: the edge leaves");
        // …while the two public links themselves stay in the guest's slices.
        let audit_count = |tree: &SerdeTree| match at_path(tree, &["hints", "links.audit"]) {
            Some(SerdeTree::Seq(items)) => items.len(),
            other => panic!("hints.links.audit is a sequence, got {other:?}"),
        };
        assert_eq!(audit_count(&guest), 2, "the two public links; the draft-homed claim left");
        assert_eq!(audit_count(&full), 3, "…where the unfiltered walk carries the claim too");
    }

    /// [`sup_edge_claims`]'s standing obligation, over a world that HAS an
    /// edge: under the total predicate the filter is the identity, so every
    /// rendered edge must be one this re-derivation also keys. That is the
    /// one branch where the restated rule can disagree with M7's own — the
    /// home tests all pass under a total predicate, and an edge whose claim
    /// this walk failed to key would be dropped by `edge_claimed_readably`
    /// alone. The two identity tests that share the populated world hold no
    /// supersession edge, so this is where the branch is exercised.
    #[test]
    fn the_filter_over_a_supersession_edge_is_the_identity_under_the_total_predicate() {
        let world = a_draft_homed_claim_over_public_links();
        assert_eq!(edge_count(&dump_tree(&world)), 1, "the fixture asserts exactly one edge");
        assert_eq!(
            dump_visible(&world, &|_: &Address| true),
            dump(&world),
            "a re-derivation missing the edge's claim would drop the edge here"
        );
    }

    /// A world holding ONE supersession edge asserted by TWO claims over the
    /// same two public links: one homed in the published home and then
    /// RETRACTED, one homed in the private draft and operative. Returns the
    /// world and the retracted public claim.
    fn a_retracted_public_claim_beside_an_operative_draft_claim() -> (World, Address) {
        let (engine, home, draft) = a_published_home_and_a_private_draft();
        let caller = Caller::Principal(USER);
        let visibility = World::visible_to(caller);
        let writer = engine.linkstore(&visibility);
        let public_link = |n: u32| {
            writer
                .makelink(
                    caller,
                    &home,
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(vec![element(&home, 3, n)]),
                )
                .expect("a public link in the home")
                .0
        };
        let (old, new) = (public_link(41), public_link(42));
        let (public_claim, _) =
            writer.assert_sup(caller, &home, &old, &new).expect("a claim in the published home");
        writer.nullify(caller, &home, &public_claim).expect("the owner retracts its own claim");
        // A retracted incumbent is invisible to the managed gate's dedup, so
        // the same edge asserted from the draft is a FRESH claim.
        let (draft_claim, _) =
            writer.assert_sup(caller, &draft, &old, &new).expect("the same edge, from the draft");
        assert_eq!(document_of(&draft_claim), Some(draft), "a fresh draft claim, not a dedup hit");
        (engine.kernel().snapshot().world().clone(), public_claim)
    }

    /// A RETRACTED claim asserts no edge (Df-SUCC), so it can make no edge
    /// readable. Here the edge renders because the DRAFT's claim is operative,
    /// and the one claim homed where a guest reads is the retracted one — so a
    /// re-derivation that kept retracted claims would hand the guest an edge
    /// only a draft asserts. Keying that EXTRA claim leaves the total
    /// predicate's answer unchanged, so the identity tests cannot see it; only
    /// a reader class can.
    #[test]
    fn a_retracted_public_claim_does_not_carry_a_draft_s_edge_to_the_guest() {
        let (world, public_claim) = a_retracted_public_claim_beside_an_operative_draft_claim();
        assert!(world.links.is_nullified(&public_claim), "the fixture must retract the public claim");
        assert_eq!(edge_count(&dump_tree(&world)), 1, "the draft's operative claim renders the edge");
        let owner = tree_visible_to(&world, Some(USER));
        assert_eq!(edge_count(&owner), 1, "the owner reads the operative claim's home");
        let guest = tree_visible_to(&world, None);
        assert_eq!(
            edge_count(&guest),
            0,
            "the only claim a guest reads is retracted, and a retracted claim asserts nothing"
        );
        assert_eq!(dump_visible(&world, &|_: &Address| true), dump(&world));
    }

    /// Two supersession edges whose CLAIMS are homed in the published home,
    /// each with ONE endpoint in the private draft: the first runs OUT of the
    /// draft's link, the second INTO it. Returns the world, the draft's link,
    /// and the public link the second edge runs out of.
    fn public_claims_across_a_draft_endpoint() -> (World, Address, Address) {
        let (engine, home, draft) = a_published_home_and_a_private_draft();
        let caller = Caller::Principal(USER);
        let visibility = World::visible_to(caller);
        let writer = engine.linkstore(&visibility);
        let link_in = |doc: &Address, n: u32| {
            writer
                .makelink(
                    caller,
                    doc,
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(vec![element(doc, 3, n)]),
                )
                .expect("a link in the owner's own document")
                .0
        };
        let draft_link = link_in(&draft, 41);
        let (into, out_of) = (link_in(&home, 42), link_in(&home, 43));
        writer
            .assert_sup(caller, &home, &draft_link, &into)
            .expect("a published claim out of the draft's link");
        writer
            .assert_sup(caller, &home, &out_of, &draft_link)
            .expect("a published claim into the draft's link");
        (engine.kernel().snapshot().world().clone(), draft_link, out_of)
    }

    /// The dotted addresses `hints.supersession` keys its edges by.
    fn edge_keys(tree: &SerdeTree) -> Vec<String> {
        match at_path(tree, &["hints", "supersession"]) {
            Some(SerdeTree::Map(entries)) => entries
                .iter()
                .map(|(k, _)| match k {
                    SerdeTree::Str(s) => s.clone(),
                    other => panic!("hints.supersession keys are dotted addresses, got {other:?}"),
                })
                .collect(),
            other => panic!("hints.supersession is a map, got {other:?}"),
        }
    }

    /// An EDGE's two ENDPOINTS are link addresses, each judged by its own home,
    /// beside the claim's test — and no other fixture isolates either: in
    /// [`every_reduced_family_in_a_draft`] any one test refuses every edge, and
    /// in [`a_draft_homed_claim_over_public_links`] only the claim's does. Here
    /// both claims are published: the edge OUT of the draft's link is refused
    /// by the adjacency map's KEY test alone, the edge INTO it by the pair
    /// test's successor-home clause alone.
    #[test]
    fn an_edge_with_a_draft_endpoint_leaves_the_guest_s_edges_though_its_claim_is_published() {
        let (world, draft_link, out_of) = public_claims_across_a_draft_endpoint();
        assert_eq!(edge_count(&dump_tree(&world)), 2, "the fixture asserts two edges");
        let guest = edge_keys(&tree_visible_to(&world, None));
        assert!(
            !guest.contains(&draft_link.to_string()),
            "the edge OUT of the draft's link: its OLD endpoint's home refuses it: {guest:?}"
        );
        assert!(
            !guest.contains(&out_of.to_string()),
            "the edge INTO the draft's link: its NEW endpoint's home refuses it: {guest:?}"
        );
        assert_eq!(
            edge_count(&tree_visible_to(&world, Some(USER))),
            2,
            "the owner reads every home"
        );
        assert_eq!(dump_visible(&world, &|_: &Address| true), dump(&world));
    }

    /// A `pred_stable` MEMBER — a content position of the PUBLISHED home —
    /// registered twice: once in the home and then RETRACTED, once in the
    /// private draft and operative. Returns the world and the member.
    fn a_member_asserted_by_a_retracted_public_tuple_and_an_operative_draft_tuple(
    ) -> (World, Address) {
        let (engine, home, draft) = a_published_home_and_a_private_draft();
        let caller = Caller::Principal(USER);
        let visibility = World::visible_to(caller);
        let writer = engine.linkstore(&visibility);
        let member = element(&home, 1, 1);
        let pred_stable = engine.registry().reserved_type(ShippedType::PredStable).clone();
        let (public_tuple, _) = writer
            .emit(caller, &home, &pred_stable, &member, &[])
            .expect("a registration in the published home");
        writer.nullify(caller, &home, &public_tuple).expect("the owner retracts its own tuple");
        // As above: the retracted incumbent is invisible to `emit`'s dedup.
        let (draft_tuple, _) = writer
            .emit(caller, &draft, &pred_stable, &member, &[])
            .expect("the same registration, from the draft");
        assert_eq!(document_of(&draft_tuple), Some(draft), "a fresh draft tuple, not a dedup hit");
        (engine.kernel().snapshot().world().clone(), member)
    }

    /// A projection entry is judged at the tuples asserting it UNDER ITS OWN
    /// ROW'S VIEW, and the two views part on a retracted tuple: in AUDIT the
    /// retracted public registration still asserts the member, so the guest
    /// keeps the entry; in ACTIVE only the draft's does, so the guest loses
    /// it. Judging both rows at one view fails one of the two guest assertions
    /// below, whichever view it chose — and since the member keeps a tuple
    /// under either view, the total predicate keeps it either way and the
    /// identity tests see neither.
    #[test]
    fn a_projection_entry_is_judged_at_its_own_row_s_view() {
        let (world, member) =
            a_member_asserted_by_a_retracted_public_tuple_and_an_operative_draft_tuple();
        let dotted = member.to_string();
        let full = dump_tree(&world);
        for family in ["predicates.stable.audit", "predicates.stable.active"] {
            assert_eq!(
                projection(&full, family),
                vec![dotted.clone()],
                "{family}: the fixture must render the member"
            );
        }
        let guest = tree_visible_to(&world, None);
        assert_eq!(
            projection(&guest, "predicates.stable.audit"),
            vec![dotted.clone()],
            "audit: the retracted public registration is readably homed, and still asserts it"
        );
        assert!(
            projection(&guest, "predicates.stable.active").is_empty(),
            "active: the only registration asserting the member is the draft's"
        );
        let owner = tree_visible_to(&world, Some(USER));
        assert_eq!(
            projection(&owner, "predicates.stable.active"),
            vec![dotted],
            "the owner reads the draft's registration"
        );
        assert_eq!(dump_visible(&world, &|_: &Address| true), dump(&world));
    }
}
