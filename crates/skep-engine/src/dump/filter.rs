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
//! one statement. Two obligations run underneath it and belong to nothing
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

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use skep_address::{document_of, validate, Address, Nat, Tumbler};
use skep_links::{LinkState, ShippedType, View};

use crate::canon::{SerdeTree, TreeDe};

use super::shipped_label;

/// The hint families reduced BY HOME: each is a sequence of dotted link
/// addresses, and an entry stays where the class reads the document its
/// address is homed in.
///
/// The list is the reduction's COMPLETENESS as well as its content — what it
/// accounts for as well as what it does. [`filter_tree`] touches an entry
/// only where some path below names it, so a family `super::hints_tree` adds
/// and this list omits is rendered WHOLE to every class — the guest included.
/// Three hint families are reduced by an arm of their own rather than here:
/// `types` (per shipped class, per view), `supersession` (the three-test arm)
/// and `publication.drafts` (a map, keyed by the draft).
/// `every_hints_family_is_reduced_or_kept_by_name` holds this list plus those
/// three against the section the builder writes.
const REDUCED_BY_HOME: [&str; 7] = [
    "links.audit",
    "links.active",
    "links.nullified",
    "predicates.defs.audit",
    "predicates.defs.active",
    "predicates.stable.audit",
    "predicates.stable.active",
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
/// * `hints` — every link address (the audit/active/nullified slices, the
///   shipped classes' slices, the supersession edges and their successors,
///   the predicate projections) by its home; the shipped classes' `key`
///   entries are format constants and stay; `publication.drafts` reduced to
///   the readable drafts, as the section is. A SUPERSESSION EDGE takes a
///   third test beside its two endpoints' homes (lane 4.2, F4; PUB-6.13,
///   PUB-6.22, PUB-6.27): the edge stays only where some operative CLAIM
///   asserting it — the `[K_sup]` link the walk derived the edge from — is
///   homed in a document the class reads. A claim is a link and its home
///   governs, exactly as `in_claims`/`out_claims` filter lineage by the
///   CLAIM's home: a draft-homed `assert_sup` over two public links is
///   invisible to a guest there and leaves the guest's dump here. The hint's
///   rendered shape is unchanged — the edge record still carries no claim
///   address — so the claims are read at filter time off `links`, the
///   render's own source, through [`sup_edge_claims`].
///
/// An entry NO PATH IN THE BODY NAMES is kept whole at every class. So the
/// statement above is this reduction's COMPLETENESS as well as its content,
/// and the gap it admits is the one nothing else here catches: a section or a
/// hint family added to the tree and left out of it goes to the guest
/// unreduced, deterministically and with nothing about it looking wrong. The
/// hint families carry their own list ([`REDUCED_BY_HOME`]) so that the sum
/// can be held against what the builders write.
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
        let Some(link) = links.readlink(&claim) else {
            continue; // type-slice keys are resident by construction
        };
        let olds: BTreeSet<&Tumbler> = link.from_slot().addrs().collect();
        let news: BTreeSet<&Tumbler> = link.to_slot().addrs().collect();
        for &old in &olds {
            let by_new = by_edge.entry(old.clone()).or_default();
            for &new in &news {
                by_new.entry(new.clone()).or_default().push(claim.clone());
            }
        }
    }
    by_edge
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
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig};
    use skep_links::SlotArg;
    use skep_namespace::{HasM3, BOOTSTRAP_PRINCIPAL};

    use crate::dump::tests::{addr, populated_world, render_of, USER};
    use crate::dump::{dump, dump_tree, dump_visible, BANNER};
    use crate::world::World;
    use crate::Engine;

    use super::*;

    /// The v5 root: the two publication-round sections sit beside the
    /// authoritative and hints sections, and the filter's paths into the
    /// authoritative slices name fields that exist — a slice renaming its
    /// serde field would otherwise leave the filter silently filtering
    /// nothing, which is the one failure a fail-closed key rule cannot catch.
    #[test]
    fn the_v5_root_and_the_filter_s_paths_exist() {
        let (_engine, world) = populated_world();
        let mut tree = dump_tree(&world);
        for path in [
            &["authoritative", "namespace"][..],
            &["authoritative", "content", "map"],
            &["authoritative", "arrangement", "arrangements"],
            &["authoritative", "arrangement", "provenance"],
            &["authoritative", "links", "links"],
            &["publication"],
            &["grants"],
            &["hints", "links.audit"],
            &["hints", "types", "shipped.supersedes", "audit"],
            &["hints", "supersession"],
            &["hints", "predicates.defs.audit"],
            &["hints", "publication.drafts"],
        ] {
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

        // The hints section: the by-home families, plus the three the filter
        // reduces through an arm of their own.
        let named: BTreeSet<String> = REDUCED_BY_HOME
            .iter()
            .chain(["types", "supersession", "publication.drafts"].iter())
            .map(|name| (*name).to_owned())
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

    fn edges(tree: &mut SerdeTree) -> usize {
        match at_path(tree, &["hints", "supersession"]) {
            Some(SerdeTree::Map(entries)) => entries.len(),
            other => panic!("hints.supersession is a map, got {other:?}"),
        }
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
        assert_eq!(edges(&mut full), 1, "the fixture asserts exactly one edge");
        let mut owner = filter_tree(
            dump_tree(&world),
            &|doc: &Address| world.readable(Some(USER), doc),
            &world.links,
        );
        assert_eq!(edges(&mut owner), 1, "the owner reads the claim's home, so the edge stays");
        let mut guest =
            filter_tree(dump_tree(&world), &|doc: &Address| world.readable(None, doc), &world.links);
        assert_eq!(edges(&mut guest), 0, "no readably-homed claim asserts it: the edge leaves");
        // …while the two public links themselves stay in the guest's slices.
        let audit = |tree: &mut SerdeTree| match at_path(tree, &["hints", "links.audit"]) {
            Some(SerdeTree::Seq(items)) => items.len(),
            other => panic!("hints.links.audit is a sequence, got {other:?}"),
        };
        assert_eq!(audit(&mut guest), 2, "the two public links; the draft-homed claim left");
        assert_eq!(audit(&mut full), 3, "…where the unfiltered walk carries the claim too");
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
        assert_eq!(edges(&mut dump_tree(&world)), 1, "the fixture asserts exactly one edge");
        assert_eq!(
            dump_visible(&world, &|_: &Address| true),
            dump(&world),
            "a re-derivation missing the edge's claim would drop the edge here"
        );
    }
}
