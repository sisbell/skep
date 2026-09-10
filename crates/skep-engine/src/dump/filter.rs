//! The per-class POST-FILTER over the dump tree (PUB round 2, lane 3.4 §4) —
//! the reduction that turns the harness-only walk into a reader's dump.
//!
//! [`crate::Engine::world_dump`] and [`crate::Engine::dump_of`] are the
//! HARNESS-ONLY unfiltered walk. The daemon's `/dump` is that walk
//! POST-FILTERED at the request's class — [`crate::Engine::dump_of_visible`]
//! over the same threaded predicate every read answers (PUB-6.39) — and this
//! filter runs over the dump TREE before a byte is rendered, so the two are
//! one tree rendered twice and a class's dump is byte-identical to the walk
//! under the total predicate. Determinism holds per class (PUB-8.26): the
//! text is a function of the world and the class, conditioned on the head's
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
//!   `arrangements` and `provenance` are M5's, `links` is M7's. So a store
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
//!   is what governs, so this module RE-DERIVES the link from the class it
//!   was rendered off ([`sup_edge_claims`], [`member_tuples`]). Each is a
//!   restatement of a rule M7 owns, and the standing obligation on both is to
//!   stay that restatement: one that keyed fewer entries than the walk
//!   renders would drop, under the TOTAL predicate, what the walk wrote, and
//!   the identity that makes a class's dump the walk's own tree would fail.
//!   That is why each is checked against the walk over a world that has the
//!   entry, and not only against a class that reads it.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use skep_address::{document_of, validate, Address, Nat, Tumbler};
use skep_links::{Endset, LinkState, ShippedType, View};

use crate::canon::{SerdeTree, TreeDe};

use super::shipped_label;

/// The hint families reduced BY HOME: each is a sequence of dotted LINK
/// addresses, and an entry stays where the class reads the document its own
/// address is homed in. That one test is the whole rule here BECAUSE the
/// entry is the link — the thing whose existence the entry discloses is the
/// thing being judged.
///
/// The list is the reduction's COMPLETENESS as well as its content — what it
/// accounts for as well as what it does. [`filter_tree`] touches an entry
/// only where some path below names it, so a family `super::hints_tree` adds
/// and this list omits is rendered WHOLE to every class — the guest included.
/// The other families are reduced by an arm of their own rather than here:
/// [`REDUCED_BY_TUPLE`]'s four (a member is not a link, so its asserting
/// tuple is judged too), `types` (per shipped class, per view),
/// `supersession` (the three-test arm) and `publication.drafts` (a map, keyed
/// by the draft). `every_hints_family_is_reduced_or_kept_by_name` holds this
/// list plus those against the section the builder writes.
const REDUCED_BY_HOME: [&str; 3] = ["links.audit", "links.active", "links.nullified"];

/// The hint families reduced BY THE ASSERTING TUPLE as well as by home: each
/// is a sequence of dotted MEMBER addresses — the subjects `LinkState::members`
/// denotes, never the tuples that denote them — so an entry here discloses
/// TWO things and takes a test apiece.
///
/// A member's own document is one of them, judged as everywhere else. The
/// other is the REGISTRATION: that some `pred_def`/`pred_stable` tuple names
/// this member is a fact deposited in that tuple's home, and a link's home
/// governs what a class learns of it (PUB-6.13) exactly as it does for the
/// supersession claims below. A tuple homed in a private draft over a public
/// member would otherwise put the draft's content in the guest's dump beside
/// an EMPTY `types` slice for the same class — the walk's two renderings of
/// one deposit, disagreeing.
///
/// Each row carries the class and the view the builder read the family under,
/// so the re-derivation ([`member_tuples`]) walks the slice the entries came
/// from: an audit entry is asserted by an audit-view tuple, an active entry by
/// an active-view one.
const REDUCED_BY_TUPLE: [(&str, ShippedType, View); 4] = [
    ("predicates.defs.audit", ShippedType::PredDef, View::Audit),
    ("predicates.defs.active", ShippedType::PredDef, View::Active),
    ("predicates.stable.audit", ShippedType::PredStable, View::Audit),
    ("predicates.stable.active", ShippedType::PredStable, View::Active),
];

/// The per-class post-filter over the dump tree — the ONE statement of what
/// the entries it reaches drop and keep, applied before render so the harness
/// walk and every class's dump are one tree. `readable` is the threaded
/// predicate (PUB-6.39); every address is judged at its DOCUMENT
/// (`document_of`, the address arithmetic the link-address rule uses,
/// PUB-6.6), an address with no document — an account, a node — judged
/// readable.
///
/// * `authoritative.namespace` — KEPT whole. The identity state in it is not
///   secret (PUB-1.13, an address is not), but the section is M3's WHOLE
///   serde form and carries three things beside the registries: the
///   `publication` map (every registered document with its bit — so a class
///   reads the draft MEMBERSHIP of documents it cannot open, and the reduced
///   `publication` section below reduces that SECTION and not what a class
///   learns of publication state), the per-namespace frontier COUNTS (so a
///   draft's content and link population is legible without any of its
///   content), and the principal registry. Widening the reduction here would
///   move bytes the crash and wire oracles pin, so what a class is owed of
///   this section is the format owner's question and not this filter's.
/// * `authoritative.content.map` — a CONTENT LINE leaves when its element's
///   document is unreadable.
/// * `authoritative.arrangement.{arrangements, provenance}` — the
///   ARRANGEMENT and LINK-SUBSPACE sections keyed by an unreadable document
///   leave (M5's per-document arrangement holds both subspaces; provenance
///   is keyed by the placing document).
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
///     * The PREDICATE PROJECTIONS ([`REDUCED_BY_TUPLE`]) are MEMBER
///       addresses — `LinkState::members` denotes the subjects, not the
///       tuples — so an entry stays where the class reads the member's own
///       document AND some `pred_def`/`pred_stable` tuple asserting it, at
///       that entry's own view, is readably homed. Either test alone leaks
///       one way: the member's alone puts a draft-homed registration in the
///       guest's dump, the tuple's alone puts a draft's content position
///       there.
///     * A SUPERSESSION EDGE takes a third test beside its two endpoints'
///       homes (lane 4.2, F4; PUB-6.13, PUB-6.22, PUB-6.27): the edge stays
///       only where some operative CLAIM asserting it — the `[K_sup]` link
///       the walk derived the edge from — is homed in a document the class
///       reads. A claim is a link and its home governs, exactly as
///       `in_claims`/`out_claims` filter lineage by the CLAIM's home: a
///       draft-homed `assert_sup` over two public links is invisible to a
///       guest there and leaves the guest's dump here.
///
///   Neither hint's rendered shape is widened — an edge record still carries
///   no claim address and a projection still carries no tuple address — so
///   both re-derivations are read at filter time off `links`, the render's own
///   source, through [`sup_edge_claims`] and [`member_tuples`].
///
/// An entry NO PATH IN THE BODY NAMES is kept whole at every class. So the
/// statement above is this reduction's COMPLETENESS as well as its content,
/// and the gap it admits is the one nothing else here catches: a section or a
/// hint family added to the tree and left out of it goes to the guest
/// unreduced, deterministically and with nothing about it looking wrong. The
/// hint families carry their own lists ([`REDUCED_BY_HOME`],
/// [`REDUCED_BY_TUPLE`]) so that the sum can be held against what the builders
/// write.
///
/// A key that fails to decode is DROPPED (fail-closed): every key here was
/// rendered from an address a moment earlier, so none does, and a filter
/// that met one would rather omit a line than judge it readable. The SHAPE
/// tests run the other way — [`retain_map`] and [`retain_seq`] do nothing
/// where the node at a path is not the shape they expect, and the
/// supersession arm keeps a successor list it does not recognize — so a
/// builder that changed an entry's shape without changing its key leaves the
/// entry whole rather than empty. Both directions are the same fact about
/// this module: it reduces what it recognizes and keeps what it does not.
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
    for (family, ty, view) in REDUCED_BY_TUPLE {
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
        for view in ["audit", "active"] {
            retain_seq(&mut root, &["hints", "types", shipped_label(ty), view], &keep_dotted);
        }
    }
    if let Some(SerdeTree::Map(edges)) = at_path(&mut root, &["hints", "supersession"]) {
        edges.retain_mut(|(old, succs)| {
            // The OLD endpoint's home (fail-closed on a key that does not
            // decode, as everywhere here).
            let Some(old) = dotted_address(old).filter(|a| document_readable(a)) else {
                return false;
            };
            match succs {
                SerdeTree::Seq(items) => {
                    // Each successor by ITS home, and then by the CLAIM's:
                    // the edge `old → new` stays only where a claim asserting
                    // it is homed readably (PUB-6.22).
                    items.retain(|s| {
                        dotted_address(s).is_some_and(|new| {
                            document_readable(&new) && edge_claimed_readably(&old, &new)
                        })
                    });
                    !items.is_empty() // the walk renders no empty successor list
                }
                _ => true,
            }
        });
    }
    retain_map(&mut root, &["hints", "publication.drafts"], &keep_dotted);
    root
}

/// The OPERATIVE supersession claims, keyed by the edge each asserts — the
/// denoted OLD endpoint, then the denoted NEW one — for the per-class filter
/// over the dump's `hints.supersession` section.
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
/// predicate what the walk rendered, and the identity that makes a class's
/// dump the walk's own tree fails. The test below over a world that HAS an
/// edge is where that agreement is checked, and a change to M7's arm has its
/// counterpart here.
///
/// Both slots are read through `Endset::addrs` UNGUARDED, which is
/// `fold_hints`' own reading and must stay it: that iterator already keeps the
/// unit-depth spans and drops the rest, so an `is_address_denoting` test here
/// would be strictly stronger than the rule being mirrored and would key
/// fewer edges than the walk renders.
///
/// Nothing in the class can exercise the difference, and the reason is a
/// CLOSURE rather than a coincidence: `makelink` and `emit` each refuse a
/// supersedes-classed type slot outright (`MakeLinkError::SupersessionClass`,
/// `EmitError::SupersessionClass`), so the only deposits into the class are
/// `assert_sup`'s and `editlink`'s, and both build the value
/// `Link::triple(enc([old]), enc([new]), …)` — one unit-depth span a side.
/// That is what makes the cross product below 1 × 1 per claim rather than a
/// product of two slot widths, and it is what
/// `the_supersession_class_is_closed_to_the_open_surfaces` pins.
///
/// Read through M7's public surface alone — the class's `type_slice` under
/// the audit view, `is_nullified` and `readlink` per claim — at filter time:
/// the dump is a whole-world render and this is one more whole-class walk;
/// the hint's stored shape is not widened. A claim's home is
/// `document_of(claim)`, the same address arithmetic every other hint entry
/// is judged by.
fn sup_edge_claims(links: &LinkState) -> BTreeMap<Tumbler, BTreeMap<Tumbler, Vec<Address>>> {
    let sup = links.reserved_type(ShippedType::Supersedes);
    let mut by_edge: BTreeMap<Tumbler, BTreeMap<Tumbler, Vec<Address>>> = BTreeMap::new();
    for claim in links.type_slice(sup, View::Audit) {
        if links.is_nullified(&claim) {
            continue; // Df-SUCC: a nullified claim asserts no operative edge
        }
        // RESIDENCY is M7's stated postcondition on `type_slice`, and M7
        // fail-stops on it itself (`LinkState::link_at`). Skipping the claim
        // instead would key fewer edges than the walk renders, which is the
        // one departure this derivation's standing obligation forbids: under
        // the total predicate the filter would drop what the walk wrote.
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
/// projections ([`REDUCED_BY_TUPLE`]).
///
/// `LinkState::members` publishes the members and not the tuples behind them,
/// so the derivation is RESTATED here, and the STANDING OBLIGATION is that it
/// stay `members`' own denotation rule: the union of the F-slot's denoted
/// addresses over the class's slice under that view. Two departures from that
/// rule would each break the identity that makes a class's dump the walk's own
/// tree, by keying fewer members than the walk renders —
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
///   does; and
/// * a view of this function's own choosing. `members` subtracts the filtered
///   roots under `View::Default` alone, and the builder reads `Audit` and
///   `Active`, so each row of [`REDUCED_BY_TUPLE`] carries the view its own
///   entries were rendered under.
///
/// The reverse direction is free: keying a member the walk did NOT render
/// costs a lookup nothing probes.
///
/// Read through M7's public surface alone — the class's `type_slice` and
/// `readlink` per tuple — at filter time, as [`sup_edge_claims`] is. A tuple's
/// home is `document_of(tuple)`, the same address arithmetic every other hint
/// entry is judged by.
fn member_tuples(links: &LinkState, ty: &Endset, view: View) -> BTreeMap<Tumbler, Vec<Address>> {
    let mut by_member: BTreeMap<Tumbler, Vec<Address>> = BTreeMap::new();
    for tuple in links.type_slice(ty, view) {
        // RESIDENCY is M7's stated postcondition on `type_slice`, as at
        // `sup_edge_claims`, and skipping the tuple would key fewer members
        // than the walk renders — the departure the standing obligation above
        // forbids.
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
/// tree holds one there.
pub(super) fn at_path<'t>(tree: &'t mut SerdeTree, path: &[&str]) -> Option<&'t mut SerdeTree> {
    let Some((name, rest)) = path.split_first() else {
        return Some(tree);
    };
    let SerdeTree::Map(entries) = tree else {
        return None;
    };
    for (k, v) in entries.iter_mut() {
        if matches!(k, SerdeTree::Str(s) if s.as_str() == *name) {
            return at_path(v, rest);
        }
    }
    None
}

/// Keep the entries of the map at `path` whose KEY `keep` admits.
fn retain_map(tree: &mut SerdeTree, path: &[&str], keep: &dyn Fn(&SerdeTree) -> bool) {
    if let Some(SerdeTree::Map(entries)) = at_path(tree, path) {
        entries.retain(|(k, _)| keep(k));
    }
}

/// Keep the items of the sequence at `path` that `keep` admits.
fn retain_seq(tree: &mut SerdeTree, path: &[&str], keep: &dyn Fn(&SerdeTree) -> bool) {
    if let Some(SerdeTree::Seq(items)) = at_path(tree, path) {
        items.retain(|item| keep(item));
    }
}

/// An address in a STORE's own serde form — a bare tumbler, which is how
/// `Address` serializes and so how the authoritative maps key themselves —
/// back through the types' own doors (`TreeDe`, then `validate`). Read off a
/// map key today, and off whatever node the store wrote it to.
fn serde_form_address(node: &SerdeTree) -> Option<Address> {
    let tumbler = Tumbler::deserialize(TreeDe(node)).ok()?;
    validate(tumbler).ok()
}

/// A dotted-address string — the form the dump's OWN builders render an
/// address in, so the hints' entries and the two sections' — as the address
/// it names. Read off a sequence item and off a map key alike.
fn dotted_address(item: &SerdeTree) -> Option<Address> {
    let SerdeTree::Str(s) = item else {
        return None;
    };
    let comps: Option<Vec<Nat>> = s.split('.').map(|c| c.parse::<Nat>().ok()).collect();
    validate(Tumbler::new(comps?).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use skep_address::validate;
    use skep_arrangement::Caller;
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, TxnError};
    use skep_links::{EmitError, MakeLinkError, ReservedAddrs, SlotArg};
    use skep_namespace::{HasM3, BOOTSTRAP_PRINCIPAL};

    use crate::dump::tests::{addr, populated_world, render_of, USER};
    use crate::dump::{dump, dump_tree, dump_visible, BANNER};
    use crate::world::World;
    use crate::Engine;

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

    /// EVERY path [`filter_tree`] reduces, with the shape its reduction
    /// expects there — built from the filter's own two family lists and the
    /// one shipped-class table, so a family added to either is walked by the
    /// tests below without an edit here.
    fn reduced_paths() -> Vec<(Vec<String>, Shape)> {
        let owned = |path: &[&str]| path.iter().map(|c| (*c).to_owned()).collect::<Vec<String>>();
        let mut paths = vec![
            (owned(&["authoritative", "content", "map"]), Shape::Map),
            (owned(&["authoritative", "arrangement", "arrangements"]), Shape::Map),
            (owned(&["authoritative", "arrangement", "provenance"]), Shape::Map),
            (owned(&["authoritative", "links", "links"]), Shape::Map),
            (owned(&["publication"]), Shape::Seq),
        ];
        for family in REDUCED_BY_HOME {
            paths.push((owned(&["hints", family]), Shape::Seq));
        }
        for (family, _, _) in REDUCED_BY_TUPLE {
            paths.push((owned(&["hints", family]), Shape::Seq));
        }
        for ty in ShippedType::ALL {
            for view in ["audit", "active"] {
                paths.push((owned(&["hints", "types", shipped_label(ty), view]), Shape::Seq));
            }
        }
        paths.push((owned(&["hints", "supersession"]), Shape::Map));
        paths.push((owned(&["hints", "publication.drafts"]), Shape::Map));
        paths
    }

    /// The node at `path`, as a shape and a count.
    fn shape_and_len(tree: &mut SerdeTree, path: &[&str]) -> (Shape, usize) {
        match at_path(tree, path) {
            Some(SerdeTree::Map(entries)) => (Shape::Map, entries.len()),
            Some(SerdeTree::Seq(items)) => (Shape::Seq, items.len()),
            other => panic!("{path:?}: expected a map or a sequence, got {other:?}"),
        }
    }

    fn borrowed(path: &[String]) -> Vec<&str> {
        path.iter().map(String::as_str).collect()
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
        let mut tree = dump_tree(&world);
        for (path, want) in reduced_paths() {
            let path = borrowed(&path);
            let (found, _) = shape_and_len(&mut tree, &path);
            assert_eq!(found, want, "{path:?}: the reduction's shape is not what the builder wrote");
        }
        // …and the two sections kept WHOLE are places in the tree too, so the
        // statement that names them can be read against something.
        for path in [&["authoritative", "namespace"][..], &["grants"]] {
            assert!(at_path(&mut tree, path).is_some(), "{path:?} is a place in the v5 tree");
        }
    }

    /// [`filter_tree`]'s COMPLETENESS, held against the sections the builders
    /// write: an entry no path in the filter names is rendered whole at every
    /// class, so a family added to `super::hints_tree` and left off
    /// [`REDUCED_BY_HOME`] is disclosed to the guest. That is the one failure
    /// neither the fail-closed key rule nor the path-exists test can catch,
    /// and no other test here sees it — the identity tests keep everything by
    /// construction, and the guest tests walk a fixed path list a new family
    /// is not on.
    ///
    /// Asked of GENESIS, because the section keys are FORMAT rather than
    /// content: both builders push every key whatever the world holds, so an
    /// empty world carries the whole set and the assertion is over the format
    /// and not over a fixture.
    #[test]
    fn every_hints_family_is_reduced_or_kept_by_name() {
        let mut tree = dump_tree(&World::genesis());
        let keys_at = |tree: &mut SerdeTree, path: &[&str]| -> BTreeSet<String> {
            match at_path(tree, path) {
                Some(SerdeTree::Map(entries)) => entries
                    .iter()
                    .map(|(k, _)| match k {
                        SerdeTree::Str(s) => s.clone(),
                        other => panic!("{path:?}: section keys are strings, got {other:?}"),
                    })
                    .collect(),
                other => panic!("{path:?}: expected a map, got {other:?}"),
            }
        };

        // The hints section: the by-home families, the by-tuple families, and
        // the three the filter reduces through an arm of their own.
        let named: BTreeSet<String> = REDUCED_BY_HOME
            .iter()
            .copied()
            .chain(REDUCED_BY_TUPLE.iter().map(|(family, _, _)| *family))
            .chain(["types", "supersession", "publication.drafts"])
            .map(|name| name.to_owned())
            .collect();
        assert_eq!(
            keys_at(&mut tree, &["hints"]),
            named,
            "a hints family the filter does not name is rendered whole to every class"
        );

        // …and the root, where each section has a disposition in the filter's
        // one statement: two reduced, two kept whole with the reason given.
        let sections: BTreeSet<String> = ["authoritative", "publication", "grants", "hints"]
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        assert_eq!(
            keys_at(&mut tree, &[]),
            sections,
            "a root section the filter does not name is rendered whole to every class"
        );
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
    /// link leave while the identity section stays whole and the publication
    /// slice empties: the populated world's one document is a DRAFT, so a
    /// guest sees its registration and nothing it holds. Asked of the TREE,
    /// where each section can be named, rather than of the text.
    #[test]
    fn the_guest_filter_drops_a_draft_s_sections_and_keeps_identity() {
        let (_engine, world) = populated_world();
        let mut full = dump_tree(&world);
        let mut guest =
            filter_tree(dump_tree(&world), &|doc: &Address| world.readable(None, doc), &world.links);

        let len_at = |tree: &mut SerdeTree, path: &[&str]| match at_path(tree, path) {
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
            assert!(len_at(&mut full, path) > 0, "{path:?}: the fixture must populate it");
            assert_eq!(len_at(&mut guest, path), 0, "{path:?}: a guest reads nothing of a draft");
        }
        // The identity and grant sections are untouched.
        for path in [&["authoritative", "namespace"][..], &["grants"]] {
            let a = render_of(at_path(&mut full, path).expect("present"));
            let b = render_of(at_path(&mut guest, path).expect("present"));
            assert_eq!(a, b, "{path:?} is kept whole");
        }
    }

    /// A world holding an entry in EVERY family the reduction reaches, all of
    /// it homed in ONE private draft — so a guest is owed nothing of any of
    /// it, and each path's reduction has something to drop.
    ///
    /// Built on [`populated_world`]'s account, draft, content, arrangement and
    /// link, which cover the authoritative maps and the two publication
    /// families; this adds the link population the shipped classes and the
    /// predicate projections need. The links carry ADDRESS-form slots under
    /// ghost types of the draft's own never-minted subspace 3, so each lands
    /// in an unregistered coverage class and the shipped slices hold exactly
    /// the tuples deposited under them.
    fn every_reduced_family_in_a_draft() -> World {
        let (engine, world) = populated_world();
        let draft =
            world.drafts().next().map(|(doc, _)| doc.clone()).expect("the fixture's one draft");
        let caller = Caller::Principal(USER);
        let visibility = World::visible_to(caller);
        let writer = engine.linkstore(&visibility);
        // An element of the draft's subspace `s` — never minted, which
        // neither a slot nor an `emit` member requires.
        let element = |s: u32, n: u32| {
            let mut comps: Vec<Nat> = draft.tumbler().iter().cloned().collect();
            comps.extend([Nat::from(0u32), Nat::from(s), Nat::from(n)]);
            validate(Tumbler::new(comps).expect("nonempty"))
                .expect("an element of a document is T4-valid")
        };
        let ghost_typed_link = |n: u32| {
            writer
                .makelink(
                    caller,
                    &draft,
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(vec![element(3, n)]),
                )
                .expect("a link in the owner's own draft")
                .0
        };
        // Two endpoints for the supersession claim, and one link to retract.
        let (old, new, doomed) = (ghost_typed_link(41), ghost_typed_link(42), ghost_typed_link(43));
        writer
            .assert_sup(caller, &draft, &old, &new)
            .expect("a supersession claim over two of the draft's links");
        writer.nullify(caller, &draft, &doomed).expect("the owner retracts its own link");
        // One managed tuple per remaining shipped class, over members of the
        // draft — which is what puts the predicate projections in the tree.
        for ty in [ShippedType::Retired, ShippedType::PredDef, ShippedType::PredStable] {
            let class = engine.registry().reserved_type(ty).clone();
            writer
                .emit(caller, &draft, &class, &element(1, 9), &[])
                .unwrap_or_else(|_| panic!("a {ty:?} tuple in the owner's own draft"));
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
    #[test]
    fn every_reduced_path_actually_reduces() {
        let world = every_reduced_family_in_a_draft();
        let mut full = dump_tree(&world);
        let mut guest =
            filter_tree(dump_tree(&world), &|doc: &Address| world.readable(None, doc), &world.links);
        for (path, want) in reduced_paths() {
            let path = borrowed(&path);
            let (shape, len) = shape_and_len(&mut full, &path);
            assert_eq!(shape, want, "{path:?}: the reduction's shape is not the builder's");
            assert!(len > 0, "{path:?}: the fixture must populate every reduced family");
            assert_eq!(
                shape_and_len(&mut guest, &path).1,
                0,
                "{path:?}: a guest is owed nothing of a draft, and this path reduces nothing"
            );
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
        let draft =
            world.drafts().next().map(|(doc, _)| doc.clone()).expect("the fixture's one draft");
        let caller = Caller::Principal(USER);
        let visibility = World::visible_to(caller);
        let element = |n: u32| {
            let mut comps: Vec<Nat> = draft.tumbler().iter().cloned().collect();
            comps.extend([Nat::from(0u32), Nat::from(1u32), Nat::from(n)]);
            validate(Tumbler::new(comps).expect("nonempty")).expect("T4-valid")
        };
        let members: Vec<Address> = (10..26u32).map(element).collect();
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
        let mut full = dump_tree(&world);
        assert_eq!(
            projection(&mut full, "predicates.defs.audit").len(),
            members.len(),
            "one deposit, one member per denoted address — the walks' real bound"
        );
        let mut guest =
            filter_tree(dump_tree(&world), &|doc: &Address| world.readable(None, doc), &world.links);
        assert!(
            projection(&mut guest, "predicates.defs.audit").is_empty(),
            "one tuple's home governs every member it denotes"
        );
        // …and the identity holds over the wide slot, which is what a
        // tightened reading of the subject slot would break.
        assert_eq!(dump_visible(&world, &|_: &Address| true), dump(&world));
    }

    /// The CLOSURE [`sup_edge_claims`]' unguarded `Endset::addrs` reading
    /// rests on, and with it the 1 × 1 cross product the filter's cost is
    /// stated at: the supersession class admits no deposit from either open
    /// surface, so every claim in it was built by the managed one with a
    /// single denoted address a side.
    ///
    /// The derivation would still be faithful without this — it mirrors
    /// `fold_hints`' own unguarded read, so the two agree whatever a slot
    /// holds — but the COST would not: a surface that admitted a wide-slotted
    /// supersedes-classed deposit would make the walk below a product of two
    /// slot widths per claim, paid on every filtered dump.
    #[test]
    fn the_supersession_class_is_closed_to_the_open_surfaces() {
        let (engine, world) = populated_world();
        let draft =
            world.drafts().next().map(|(doc, _)| doc.clone()).expect("the fixture's one draft");
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

        // …so what IS in the class was built by the managed surface: one
        // denoted address a side, which is the 1 × 1 the derivation walks.
        let link = |n: u32| {
            let mut comps: Vec<Nat> = draft.tumbler().iter().cloned().collect();
            comps.extend([Nat::from(0u32), Nat::from(3u32), Nat::from(n)]);
            let ty = validate(Tumbler::new(comps).expect("nonempty")).expect("T4-valid");
            writer
                .makelink(
                    caller,
                    &draft,
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(vec![ty]),
                )
                .expect("a link in the owner's own draft")
                .0
        };
        let (old, new) = (link(41), link(42));
        writer.assert_sup(caller, &draft, &old, &new).expect("the managed claim deposits");

        let world = engine.kernel().snapshot().world().clone();
        let claims = world.links.type_slice(&sup, View::Audit);
        assert_eq!(claims.len(), 1, "the two refusals left exactly the managed claim");
        for claim in &claims {
            let value = world.links.readlink(claim).expect("a slice key is resident");
            for slot in [value.from_slot(), value.to_slot()] {
                assert!(slot.is_address_denoting(), "a managed claim's endpoints are addresses");
                assert_eq!(slot.addrs().count(), 1, "one denoted address a side: the 1 × 1");
            }
        }
    }

    /// A world holding ONE supersession edge, whose claim is homed in a
    /// private DRAFT while both endpoints are public links of a published
    /// home. Returns the world and the account's principal, for the two tests
    /// that read the edge from opposite ends.
    fn a_draft_homed_claim_over_public_links() -> World {
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        let engine = Engine::open(cfg).expect("in-memory open cannot fail");
        let prefix = engine
            .kernel()
            .snapshot()
            .world()
            .m3()
            .next_account_prefix(&addr(&[1]))
            .expect("the genesis node has a delegable next-form prefix");
        let (acct, _) = engine
            .namespace()
            .delegate(BOOTSTRAP_PRINCIPAL, prefix.tumbler().clone(), USER)
            .expect("delegation of the peeked prefix succeeds");
        // The account's FIRST flagless mint is its published home (PUB-8.21);
        // a later flagless mint is a private draft.
        let (home, _) =
            engine.namespace().create_new_document(USER, &acct, None).expect("the home mint");
        let (draft, _) = engine
            .namespace()
            .create_new_document(USER, &acct, None)
            .expect("a later mint, private");
        let caller = Caller::Principal(USER);
        let visibility = World::visible_to(caller);
        // Two public links in the home under ghost types of its own
        // never-minted subspace 3 (address-form slots, empty endsets).
        let ghost = |n: u32| {
            let mut comps: Vec<Nat> = home.tumbler().iter().cloned().collect();
            comps.extend([Nat::from(0u32), Nat::from(3u32), Nat::from(n)]);
            validate(Tumbler::new(comps).expect("nonempty"))
                .expect("a subspace-3 element of a document is T4-valid")
        };
        let public_link = |n: u32| {
            engine
                .linkstore(&visibility)
                .makelink(
                    caller,
                    &home,
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(Vec::new()),
                    SlotArg::Addrs(vec![ghost(n)]),
                )
                .expect("a public link in the home")
                .0
        };
        let (l1, l2) = (public_link(41), public_link(42));
        // The claim: homed in the DRAFT, over the two public links.
        engine
            .linkstore(&visibility)
            .assert_sup(caller, &draft, &l1, &l2)
            .expect("a draft-homed supersession claim over public links");

        let world = engine.kernel().snapshot().world().clone();
        assert!(world.readable(None, &home), "the endpoints' home is published");
        assert!(!world.readable(None, &draft), "the claim's home is a draft");
        world
    }

    fn edge_count(tree: &mut SerdeTree) -> usize {
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
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        let engine = Engine::open(cfg).expect("in-memory open cannot fail");
        let prefix = engine
            .kernel()
            .snapshot()
            .world()
            .m3()
            .next_account_prefix(&addr(&[1]))
            .expect("the genesis node has a delegable next-form prefix");
        let (acct, _) = engine
            .namespace()
            .delegate(BOOTSTRAP_PRINCIPAL, prefix.tumbler().clone(), USER)
            .expect("delegation of the peeked prefix succeeds");
        // The account's FIRST flagless mint is its published home (PUB-8.21);
        // a later flagless mint is a private draft.
        let (home, _) =
            engine.namespace().create_new_document(USER, &acct, None).expect("the home mint");
        let (draft, _) = engine
            .namespace()
            .create_new_document(USER, &acct, None)
            .expect("a later mint, private");
        let caller = Caller::Principal(USER);
        let visibility = World::visible_to(caller);
        // A content position of a document — never minted, which `emit` does
        // not require of a member and which keeps the two slices empty.
        let position = |doc: &Address| {
            let mut comps: Vec<Nat> = doc.tumbler().iter().cloned().collect();
            comps.extend([Nat::from(0u32), Nat::from(1u32), Nat::from(1u32)]);
            validate(Tumbler::new(comps).expect("nonempty"))
                .expect("a content element of a document is T4-valid")
        };
        let (public_member, private_member) = (position(&home), position(&draft));
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
        assert!(world.readable(None, &home), "the home is published");
        assert!(!world.readable(None, &draft), "the other document is a draft");
        (world, public_member, private_member)
    }

    fn projection(tree: &mut SerdeTree, family: &str) -> Vec<String> {
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
    /// name the member — the walk's two renderings of one deposit,
    /// disagreeing, with a draft's content in the guest's dump. The public
    /// registration of a DRAFT's member is the mirror, and is what a single
    /// tuple-home test would admit.
    #[test]
    fn a_guest_s_predicate_projections_hold_neither_a_draft_s_tuple_nor_its_member() {
        let (world, public_member, private_member) =
            predicate_tuples_across_the_draft_boundary();
        let dotted = |a: &Address| a.to_string();

        let mut full = dump_tree(&world);
        for family in ["predicates.stable.audit", "predicates.stable.active"] {
            let members = projection(&mut full, family);
            assert_eq!(
                members,
                vec![dotted(&public_member), dotted(&private_member)],
                "{family}: the fixture must render both members in address order"
            );
        }

        let mut guest =
            filter_tree(dump_tree(&world), &|doc: &Address| world.readable(None, doc), &world.links);
        for family in ["predicates.stable.audit", "predicates.stable.active"] {
            assert!(
                projection(&mut guest, family).is_empty(),
                "{family}: a guest reads neither the draft's registration nor its member"
            );
        }
        // …and the two renderings of these deposits agree about each one. The
        // typed slice holds LINK addresses, so the guest keeps the PUBLIC
        // registration there and loses the draft-homed one; the projection
        // then names neither member, because the public tuple's member is the
        // draft's. A guest reads that a registration exists in the published
        // home and not what it registers.
        let slice_count = |tree: &mut SerdeTree, view: &str| {
            match at_path(tree, &["hints", "types", "shipped.pred_stable", view]) {
                Some(SerdeTree::Seq(items)) => items.len(),
                other => panic!("the shipped.pred_stable {view} slice is a sequence, got {other:?}"),
            }
        };
        for view in ["audit", "active"] {
            assert_eq!(slice_count(&mut full, view), 2, "the fixture deposits two registrations");
            assert_eq!(
                slice_count(&mut guest, view),
                1,
                "the {view} slice keeps the public registration and drops the draft-homed one"
            );
        }

        // The OWNER reads both homes, so both members stay…
        let mut owner = filter_tree(
            dump_tree(&world),
            &|doc: &Address| world.readable(Some(USER), doc),
            &world.links,
        );
        assert_eq!(
            projection(&mut owner, "predicates.stable.audit"),
            vec![dotted(&public_member), dotted(&private_member)],
            "the owner reads both the tuples' homes and the members' documents"
        );
        // …and under the TOTAL predicate the filter is the identity, which is
        // what [`member_tuples`]' obligation rests on: a re-derivation that
        // keyed fewer members than the walk renders would drop them here.
        assert_eq!(
            dump_visible(&world, &|_: &Address| true),
            dump(&world),
            "a re-derivation missing a member's tuple would drop the entry here"
        );
    }

    /// Lane 4.2, F4 (register cell I3.a): a supersession CLAIM is a link and
    /// its HOME governs what a class sees of it (PUB-6.13, PUB-6.22,
    /// PUB-6.27) — so an edge in `hints.supersession` asserted only by a
    /// DRAFT-homed `assert_sup` over two PUBLIC links leaves the guest's dump
    /// with its claim, while both public endpoints stay, and the owner's dump
    /// — who reads the claim's home — keeps the edge.
    #[test]
    fn a_draft_homed_supersession_claim_over_public_links_leaves_the_guest_s_edges() {
        let world = a_draft_homed_claim_over_public_links();
        let mut full = dump_tree(&world);
        assert_eq!(edge_count(&mut full), 1, "the fixture asserts exactly one edge");
        let mut owner = filter_tree(
            dump_tree(&world),
            &|doc: &Address| world.readable(Some(USER), doc),
            &world.links,
        );
        assert_eq!(edge_count(&mut owner), 1, "the owner reads the claim's home, so the edge stays");
        let mut guest =
            filter_tree(dump_tree(&world), &|doc: &Address| world.readable(None, doc), &world.links);
        assert_eq!(edge_count(&mut guest), 0, "no readably-homed claim asserts it: the edge leaves");
        // …while the two public links themselves stay in the guest's slices.
        let audit_count = |tree: &mut SerdeTree| match at_path(tree, &["hints", "links.audit"]) {
            Some(SerdeTree::Seq(items)) => items.len(),
            other => panic!("hints.links.audit is a sequence, got {other:?}"),
        };
        assert_eq!(audit_count(&mut guest), 2, "the two public links; the draft-homed claim left");
        assert_eq!(audit_count(&mut full), 3, "…where the unfiltered walk carries the claim too");
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
        assert_eq!(edge_count(&mut dump_tree(&world)), 1, "the fixture asserts exactly one edge");
        assert_eq!(
            dump_visible(&world, &|_: &Address| true),
            dump(&world),
            "a re-derivation missing the edge's claim would drop the edge here"
        );
    }
}
