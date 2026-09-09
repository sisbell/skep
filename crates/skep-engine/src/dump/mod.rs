//! The world-dump surface (engine obligation 3, behind the `dump` feature):
//! [`WorldDump`] — a deterministic, byte-comparable rendering of the
//! authoritative observable state, with the recomputable hints in a separate
//! section — plus the hint-faithfulness check the crash/conformance
//! harnesses lean on.
//!
//! Determinism is the contract: the authoritative section is the slices'
//! serde forms pushed through the canonicalizing transcode (maps sorted, so
//! instance-specific hash iteration cannot leak into the bytes); the hints
//! section is built from the stores' PUBLIC read surfaces over
//! already-ordered results. Two dumps of equal worlds are byte-equal — with
//! the type set a compiled format constant there is no configuration left to
//! pair a rendering with, and the per-class sections are the shipped five in
//! their one declaration order.
//!
//! What each section holds, per the contract:
//! * **authoritative** — M3's registry/principals/frontiers, M4's content
//!   map, M5's arrangements (their resident form IS the canonical
//!   maximally-merged decomposition, maintained by M5's fold) and provenance
//!   R, M7's link store. M3 and M4
//!   expose no enumeration API, so their slices (and, uniformly, M5's and
//!   M7's) are rendered through their serde checkpoint forms — the same
//!   bytes-level seam M2's checkpoints already depend on, down to serde's
//!   human-readable flag, which the transcode answers the way bincode does so
//!   a branching `Serialize` impl renders the branch the journal stores. M7's
//!   `#[serde(skip)]` registry/hints are thereby excluded, exactly as the
//!   section demands.
//! * **publication** (v5, PUB round 2, lane 3.4 §3) — M3's AUTHORITATIVE
//!   publication slice reduced to its DRAFT entries, in address order: the
//!   state the exception set is a derived index over, rendered apart from
//!   the hints' copy of it (`hints.publication.drafts`, which STAYS — it is
//!   the faithfulness check's subject, this section the authority it is
//!   checked against).
//! * **grants** (v5) — the grant fold's OPERATIVE set: every admitted,
//!   unsuperseded grant by its link address, with its home, issuer,
//!   content-prefix and grantee. Derived from the fold (the engine keeps no
//!   grant slice), so the faithfulness check covers the fold through it.
//! * **hints** — M7's recomputable state, read through its public surfaces
//!   (`match_links`, `type_slice`, `members`, `succs`): the audit and active
//!   slices, the nullified members of the audit slice, the five shipped
//!   classes' type slices, the supersession forward edges (the BH2 walk),
//!   and M9's definition registry projected as `pdef`/`pd_stable`
//!   membership — and the engine's OWN derived index, the exception set
//!   (`publication.drafts`: draft document → owner account, PUB-7.5),
//!   address-ordered at render. M3/M4 hold no hints of their own; M5's
//!   rebuild is the identity in v1.
//!
//!   THREE of M7's hint families sit outside that reach, so the section — and
//!   the faithfulness check built on it — is an oracle over what it renders
//!   and nothing more. `dedup` has no public read surface at all.
//!   `home_frontier` has one, `LinkState::age`, which is that hint less a
//!   link's own ordinal — so its omission is a decision about this format
//!   rather than a consequence of M7's surface, and closing it would move
//!   bytes the harnesses pin. And M7's fold indexes a type slice for EVERY
//!   coverage class while this section names only the shipped five, so the
//!   typed slice an ordinary content-typed link lands in is never rendered.
//!   Each is exercised by M7's own write-path tests instead.
//!
//!   `links.nullified` renders the nullified members of the audit slice,
//!   which is the whole tombstone set only because `nullify`'s P-tgt gate
//!   admits no target but a resident link or the address the retraction tuple
//!   itself will occupy. M7's fold inserts every denoted to-root of an `[R]`
//!   link, so a root that is not itself a link would sit in the hint and
//!   outside this rendering.
//!
//! ## The per-class filter (lane 3.4 §4)
//!
//! [`Engine::world_dump`] and [`Engine::dump_of`] stay the HARNESS-ONLY
//! unfiltered walk. The daemon's `/dump` is that walk POST-FILTERED at the
//! request's class — [`Engine::dump_of_visible`] over the same threaded
//! predicate every read answers (PUB-6.39) — and the filter runs over the
//! dump TREE before a byte is rendered, so the two are one tree rendered
//! twice and a class's dump is byte-identical to the walk under the total
//! predicate. What it drops and keeps is [`filter_tree`]'s one statement:
//! the CONTENT LINES whose element's document is unreadable, the
//! ARRANGEMENT and LINK-SUBSPACE sections (M5's arrangements and provenance)
//! keyed by unreadable documents, the LINKS homed in them (the authoritative
//! map and every hint family, type keys kept), the SUPERSESSION EDGES no
//! claim homed in a readable document asserts (a claim is a link and its
//! home governs — PUB-6.13, PUB-6.22, PUB-6.27; lane 4.2), and the
//! PUBLICATION slice reduced per entry — EMPTY for the guest; the identity
//! section (M3) and the grant section stay WHOLE. Determinism holds per
//! class (PUB-8.26): the text is a function of the world and the class,
//! conditioned on the head's publication state, grant state and the
//! reader's class.
//!
//! [`Engine::world_dump`]: crate::Engine::world_dump
//! [`Engine::dump_of`]: crate::Engine::dump_of
//! [`Engine::dump_of_visible`]: crate::Engine::dump_of_visible

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Deserialize;
use skep_address::{document_of, validate, Address, Nat, Tumbler};
use skep_kernel::WorldState;
use skep_links::{Endset, LinkState, ShippedType, View};
use skep_namespace::PrincipalId;

use crate::canon::{render, to_tree, SerdeTree, TreeDe};
use crate::world::World;

/// A deterministic rendering of one world. Byte-equality is the comparison
/// the harnesses use: two dumps of equal worlds are byte-equal, and a
/// checkpoint+replay world dumps byte-equal to the live fold it recovers.
/// `Hash` comes with that equality, for a harness collecting the distinct
/// dumps across a sweep of crash points.
///
/// The text goes out — through `Display`, `as_str`, `as_bytes`,
/// `into_string` — and none comes in. A dump exists only because an engine
/// rendered one, which is what makes byte-equality mean the worlds agree; a
/// value parsed from arbitrary text would compare equal to a rendering it was
/// never produced by, and that is the one comparison a harness must not be
/// able to make.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorldDump(String);

impl WorldDump {
    /// The rendered text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The bytes the harnesses compare.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Unwrap the rendering.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for WorldDump {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for WorldDump {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The banner every rendering leads with. v5 (2026-09-06, PUB round 2, lane
/// 3.4): the root gained the `publication` SECTION (M3's authoritative slice,
/// drafts in address order) and the `grants` SECTION (the grant fold's
/// operative set). v4 (2026-09-05) was the hints section gaining
/// `publication.drafts`, the exception set; v3 the ghost-tumbler format. The
/// banner's version moves with the section keys.
const BANNER: &str = "skep-world-dump v5\n";

/// The dump as a TREE, before rendering: the authoritative section, the two
/// publication-round sections, then the hints section over the shipped
/// classes. The per-class filter ([`filter_tree`]) runs over this tree, so
/// the harness-only walk and a class's dump are one tree rendered twice.
fn dump_tree(world: &World) -> SerdeTree {
    SerdeTree::Map(vec![
        (key("authoritative"), authoritative_tree(world)),
        (key("publication"), publication_tree(world)),
        (key("grants"), grants_tree(world)),
        (key("hints"), hints_tree(world)),
    ])
}

/// Banner, tree, newline — the one rendering both dumps share.
fn render_dump(root: &SerdeTree) -> WorldDump {
    let mut s = String::from(BANNER);
    render(root, &mut s);
    s.push('\n');
    WorldDump(s)
}

/// Render one world UNFILTERED — the harness-only walk.
fn dump(world: &World) -> WorldDump {
    render_dump(&dump_tree(world))
}

/// Render one world at a READER'S CLASS: the same tree, post-filtered by the
/// threaded predicate before a byte is written (lane 3.4 §4), the
/// supersession edges keyed by the claims asserting them (lane 4.2).
fn dump_visible(world: &World, readable: &dyn Fn(&Address) -> bool) -> WorldDump {
    render_dump(&filter_tree(dump_tree(world), readable, &world.links))
}

/// The authoritative section: one entry per store slice, each the slice's own
/// serde form through the canonicalizing transcode. Every slice is rendered,
/// so a world differing in any one of them dumps differently — which is what
/// makes the harnesses' byte comparison an oracle over the whole state.
///
/// The section keys are the dump's own wire vocabulary, exactly as
/// [`shipped_label`]'s are: they name each slice for the store it belongs to
/// and match the [`World`] field names by intent, not by construction. They
/// are part of the format, so the banner's version moves with them.
fn authoritative_tree(world: &World) -> SerdeTree {
    SerdeTree::Map(vec![
        (key("namespace"), to_tree(&world.namespace)),
        (key("content"), to_tree(&world.content)),
        (key("arrangement"), to_tree(&world.arrangement)),
        (key("links"), to_tree(&world.links)),
    ])
}

/// Hint faithfulness: dump the live world, rebuild its derived state from
/// scratch through the engine's own recovery path
/// (`WorldState::rebuild_derived` — the same call recovery makes before
/// replay), dump again, compare bytes. Equal dumps certify that every hint
/// THIS DUMP RENDERS matches a from-authoritative rebuild; the authoritative
/// sections are untouched by the rebuild, so any divergence localizes to a
/// hint, and a hint the dump does not render is not in the comparison.
fn hints_faithful(world: &World) -> Result<(), HintDivergence> {
    let live = dump(world);
    let rebuilt = dump(&world.clone().rebuild_derived());
    if live == rebuilt {
        Ok(())
    } else {
        Err(HintDivergence { live, rebuilt })
    }
}

/// The two disagreeing dumps, with a byte-offset localization in `Display`.
#[derive(Debug)]
pub struct HintDivergence {
    pub live: WorldDump,
    pub rebuilt: WorldDump,
}

impl fmt::Display for HintDivergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (live, rebuilt) = (self.live.as_str(), self.rebuilt.as_str());
        let shorter = live.len().min(rebuilt.len());
        let i = live.bytes().zip(rebuilt.bytes()).position(|(x, y)| x != y).unwrap_or(shorter);
        write!(
            f,
            "hint dump diverges at byte {i}: live …{:?}… vs rebuilt …{:?}…",
            window(live, i),
            window(rebuilt, i)
        )
    }
}

impl std::error::Error for HintDivergence {}

/// A char-boundary-safe window around byte `i`, for divergence display.
fn window(s: &str, i: usize) -> &str {
    let mut start = i.saturating_sub(48).min(s.len());
    while start > 0 && !s.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (i + 48).min(s.len());
    while end < s.len() && !s.is_char_boundary(end) {
        end += 1;
    }
    &s[start..end]
}

// ── the hints section, from public reads only ──

fn key(s: impl Into<String>) -> SerdeTree {
    SerdeTree::Str(s.into())
}

fn tum_seq<'a>(it: impl IntoIterator<Item = &'a Tumbler>) -> SerdeTree {
    SerdeTree::Seq(it.into_iter().map(|t| SerdeTree::Str(t.to_string())).collect())
}

fn addr_seq<'a>(addrs: impl IntoIterator<Item = &'a Address>) -> SerdeTree {
    SerdeTree::Seq(addrs.into_iter().map(|a| SerdeTree::Str(a.to_string())).collect())
}

/// The dump's own name for a shipped class. Exhaustive by construction, so
/// the compiler audits the set this section enumerates against `ShippedType`
/// itself: a sixth shipped class upstream cannot reach the dump unnamed, and
/// so cannot drop out of the harnesses' oracle in silence. The vocabulary is
/// the dump's, not M7's — these strings are wire-visible and outlive any
/// rename of the variant.
fn shipped_label(ty: ShippedType) -> &'static str {
    match ty {
        ShippedType::Retired => "shipped.retired",
        ShippedType::Supersedes => "shipped.supersedes",
        ShippedType::Retraction => "shipped.retraction",
        ShippedType::PredDef => "shipped.pred_def",
        ShippedType::PredStable => "shipped.pred_stable",
    }
}

/// One type class's observable projection: its key endset and its
/// audit/active slices (both already address-ordered `OrdSet`s).
///
/// `ty` carries M7's stated precondition — address-denoting or
/// `iextent`-built, else `type_slice` panics naming it — and the one caller
/// below is inside it: a reserved endset is M7's own.
fn class_tree(links: &LinkState, ty: &Endset) -> SerdeTree {
    SerdeTree::Map(vec![
        (key("key"), tum_seq(ty.addrs())),
        (
            key("audit"),
            tum_seq(links.type_slice(ty, View::Audit).iter().map(Address::tumbler)),
        ),
        (
            key("active"),
            tum_seq(links.type_slice(ty, View::Active).iter().map(Address::tumbler)),
        ),
    ])
}

fn hints_tree(world: &World) -> SerdeTree {
    let links = &world.links;
    // Empty constraints ⇒ the whole view slice (M7 §G) — the one public
    // whole-store enumeration.
    let audit = links.match_links(&[], View::Audit);
    let active = links.match_links(&[], View::Active);

    let mut entries: Vec<(SerdeTree, SerdeTree)> = vec![
        (key("links.audit"), tum_seq(audit.iter().map(Address::tumbler))),
        (key("links.active"), tum_seq(active.iter().map(Address::tumbler))),
        (key("links.nullified"), addr_seq(audit.iter().filter(|a| links.is_nullified(a)))),
    ];

    // Per-class typed slices: the shipped classes off M7's own one list.
    let mut classes: Vec<(SerdeTree, SerdeTree)> = Vec::new();
    for ty in ShippedType::ALL {
        classes.push((key(shipped_label(ty)), class_tree(links, links.reserved_type(ty))));
    }
    entries.push((key("types"), SerdeTree::Map(classes)));

    // The supersession forward edges (the BH2 walk over the shipped
    // `[K_sup]` class — the public projection of M7's `sup_fwd` hint).
    let sup = links.reserved_type(ShippedType::Supersedes);
    let mut edges: Vec<(SerdeTree, SerdeTree)> = Vec::new();
    for a in audit.iter() {
        let succs = links.succs(sup, a);
        if !succs.is_empty() {
            edges.push((SerdeTree::Str(a.to_string()), addr_seq(&succs)));
        }
    }
    entries.push((key("supersession"), SerdeTree::Map(edges)));

    // M9's definition registry, projected: `pdef`/`pd_stable` membership
    // (M9 owns no slice; its registry IS these M7 tuples).
    let pred_def = links.reserved_type(ShippedType::PredDef);
    let pred_stable = links.reserved_type(ShippedType::PredStable);
    entries.push((key("predicates.defs.audit"), addr_seq(&links.members(pred_def, View::Audit))));
    entries.push((key("predicates.defs.active"), addr_seq(&links.members(pred_def, View::Active))));
    entries.push((
        key("predicates.stable.audit"),
        addr_seq(&links.members(pred_stable, View::Audit)),
    ));
    entries.push((
        key("predicates.stable.active"),
        addr_seq(&links.members(pred_stable, View::Active)),
    ));

    // The engine's own derived index: the exception set (PUB-7.5), a map
    // draft → owner account. Collected in the set's hash order; `render`
    // sorts map entries, so the text is a function of the contents alone.
    entries.push((key("publication.drafts"), drafts_tree(world)));

    SerdeTree::Map(entries)
}

/// The exception set as a map of dotted addresses, draft → owner account.
/// The one hint that is the assembler's rather than a store's; its seed and
/// its fold are `crate::publication`'s, and this rendering is what
/// [`hints_faithful`] compares them through.
fn drafts_tree(world: &World) -> SerdeTree {
    SerdeTree::Map(
        world
            .drafts()
            .map(|(doc, owner)| (SerdeTree::Str(doc.to_string()), SerdeTree::Str(owner.to_string())))
            .collect(),
    )
}

// ── the two publication-round sections (v5, lane 3.4 §3) ──

/// The PUBLICATION section: M3's AUTHORITATIVE publication slice reduced to
/// its DRAFT entries — the documents whose minting record journaled
/// `published: false` — as dotted addresses in address order. Read off M3's
/// own serde form exactly as the exception set's seed reads it
/// (`crate::publication::publication_map`), so the section and the seed
/// cannot disagree about what M3 holds; the hints' `publication.drafts` is
/// the FOLD's copy, and [`hints_faithful`] compares that copy against the
/// seed. A SEQUENCE — `render` sorts maps alone — in the `OrdMap`'s own
/// address order, which is the order the filter preserves.
fn publication_tree(world: &World) -> SerdeTree {
    let map = crate::publication::publication_map(&world.namespace);
    addr_seq(map.iter().filter(|(_, published)| !**published).map(|(doc, _)| doc))
}

/// The GRANT section: the grant fold's OPERATIVE set — every admitted,
/// unsuperseded grant keyed by the grant link's own address, each entry its
/// `home` (the issuer's doc 1), its `issuer` (ω of the home), the
/// `content_prefix` it shares and its `grantee` (`none` for the ANY-PRINCIPAL
/// form, PUB-5.8). DERIVED — the fold's records, the engine keeping no grant
/// slice — so [`hints_faithful`] covers the grant fold through this section:
/// a seed that disagreed with the fold moves these bytes. Collected in the
/// fold's hash order; `render` sorts. Kept WHOLE by the per-class filter: a
/// grant is a published document's record, and the addresses it names are
/// not secret (PUB-1.13).
fn grants_tree(world: &World) -> SerdeTree {
    SerdeTree::Map(
        world
            .grants
            .records()
            .map(|(addr, rec)| {
                let grantee = match &rec.grantee {
                    Some(g) => SerdeTree::Str(g.to_string()),
                    None => SerdeTree::Null,
                };
                (
                    SerdeTree::Str(addr.to_string()),
                    SerdeTree::Map(vec![
                        (key("content_prefix"), SerdeTree::Str(rec.content_prefix.to_string())),
                        (key("grantee"), grantee),
                        (key("home"), SerdeTree::Str(rec.home.to_string())),
                        (key("issuer"), SerdeTree::Str(rec.issuer.to_string())),
                    ]),
                )
            })
            .collect(),
    )
}

// ── the per-class post-filter (lane 3.4 §4) ──

/// The per-class post-filter over the dump tree — the ONE statement of what a
/// reader's dump drops and keeps, applied before render so the harness walk
/// and every class's dump are one tree. `readable` is the threaded predicate
/// (PUB-6.39); every address is judged at its DOCUMENT (`document_of`, the
/// address arithmetic the link-address rule uses, PUB-6.6), an address with
/// no document — an account, a node — judged readable.
///
/// * `authoritative.namespace` — KEPT whole: the identity section (PUB-1.13,
///   an address is not secret).
/// * `authoritative.content.map` — a CONTENT LINE leaves when its element's
///   document is unreadable.
/// * `authoritative.arrangement.{arrangements, provenance}` — the
///   ARRANGEMENT and LINK-SUBSPACE sections keyed by an unreadable document
///   leave (M5's per-document arrangement holds both subspaces; provenance
///   is keyed by the placing document).
/// * `authoritative.links.links` — a LINK homed in an unreadable document
///   leaves.
/// * `publication` — reduced per entry to the readable drafts: EMPTY for the
///   guest, an owner's own drafts for the owner, a grantee's granted one.
/// * `grants` — KEPT whole.
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
/// A key that fails to decode is DROPPED (fail-closed): every key here was
/// rendered from an address a moment earlier, so none does, and a filter
/// that met one would rather omit a line than judge it readable.
fn filter_tree(
    mut root: SerdeTree,
    readable: &dyn Fn(&Address) -> bool,
    links: &LinkState,
) -> SerdeTree {
    let home_readable = |a: &Address| document_of(a).is_none_or(|home| readable(&home));
    let keep_key = |k: &SerdeTree| key_address(k).is_some_and(|a| home_readable(&a));
    let keep_dotted = |s: &SerdeTree| dotted_address(s).is_some_and(|a| home_readable(&a));
    // The operative claims by the edge they assert, read once for the whole
    // tree; an edge some readably-homed claim asserts is a readable edge.
    let claims = sup_edge_claims(links);
    let edge_claimed_readably = |old: &Address, new: &Address| {
        claims
            .get(&(old.tumbler().clone(), new.tumbler().clone()))
            .is_some_and(|asserting| asserting.iter().any(|claim| home_readable(claim)))
    };

    retain_map(&mut root, &["authoritative", "content", "map"], &keep_key);
    retain_map(&mut root, &["authoritative", "arrangement", "arrangements"], &keep_key);
    retain_map(&mut root, &["authoritative", "arrangement", "provenance"], &keep_key);
    retain_map(&mut root, &["authoritative", "links", "links"], &keep_key);

    retain_seq(&mut root, &["publication"], &keep_dotted);

    for family in [
        "links.audit",
        "links.active",
        "links.nullified",
        "predicates.defs.audit",
        "predicates.defs.active",
        "predicates.stable.audit",
        "predicates.stable.active",
    ] {
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
            let Some(old) = dotted_address(old).filter(|a| home_readable(a)) else {
                return false;
            };
            match succs {
                SerdeTree::Seq(items) => {
                    // Each successor by ITS home, and then by the CLAIM's:
                    // the edge `old → new` stays only where a claim asserting
                    // it is homed readably (PUB-6.22).
                    items.retain(|s| {
                        dotted_address(s).is_some_and(|new| {
                            home_readable(&new) && edge_claimed_readably(&old, &new)
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

/// The OPERATIVE supersession claims, keyed by the edge each asserts —
/// `(old, new)` as denoted tumblers — for the per-class filter over the
/// dump's `hints.supersession` section. Derived the way M7's own `sup_fwd`
/// hint is folded and the walk reads it (`succs`: one edge per DISTINCT
/// denoted `old` × `new` of every `[K_sup]`-classed tuple, filtered to claims
/// not nullified), so an edge the render carries always has at least one
/// claim here, and the identity of the filter under the total predicate
/// holds. Read through M7's public surface alone — the class's `type_slice`
/// under the audit view, `is_nullified` and `readlink` per claim — at filter
/// time: the dump is a whole-world render and this is one more whole-class
/// walk; the hint's stored shape is not widened. A claim's home is
/// `document_of(claim)`, the same address arithmetic every other hint entry
/// is judged by.
fn sup_edge_claims(links: &LinkState) -> BTreeMap<(Tumbler, Tumbler), Vec<Address>> {
    let sup = links.reserved_type(ShippedType::Supersedes);
    let mut by_edge: BTreeMap<(Tumbler, Tumbler), Vec<Address>> = BTreeMap::new();
    for claim in links.type_slice(sup, View::Audit) {
        if links.is_nullified(&claim) {
            continue; // Df-SUCC: a nullified claim asserts no operative edge
        }
        let Some(link) = links.readlink(&claim) else {
            continue; // type-slice keys are resident by construction
        };
        let olds: BTreeSet<&Tumbler> = link.from_slot().addrs().collect();
        let news: BTreeSet<&Tumbler> = link.to_slot().addrs().collect();
        for old in &olds {
            for new in &news {
                by_edge
                    .entry(((*old).clone(), (*new).clone()))
                    .or_default()
                    .push(claim.clone());
            }
        }
    }
    by_edge
}

/// The entry at `path` — a chain of string keys through nested maps — if the
/// tree holds one there.
fn at_path<'t>(tree: &'t mut SerdeTree, path: &[&str]) -> Option<&'t mut SerdeTree> {
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

/// A tumbler-shaped map key — the authoritative maps' serde form (an
/// `Address` serializes as its bare tumbler) — as the address it names, back
/// through the types' own doors (`TreeDe`, then `validate`).
fn key_address(key: &SerdeTree) -> Option<Address> {
    let tumbler = Tumbler::deserialize(TreeDe(key)).ok()?;
    validate(tumbler).ok()
}

/// A dotted-address string — the hints' and the two sections' form — as the
/// address it names.
fn dotted_address(item: &SerdeTree) -> Option<Address> {
    let SerdeTree::Str(s) = item else {
        return None;
    };
    let comps: Option<Vec<Nat>> = s.split('.').map(|c| c.parse::<Nat>().ok()).collect();
    validate(Tumbler::new(comps?).ok()?).ok()
}

impl crate::Engine {
    /// [`crate::Engine::dump_of`] at a READER'S CLASS (PUB round 2, lane 3.4
    /// §4): the same tree, post-filtered by `readable` before render — what
    /// the filter drops and keeps is [`filter_tree`]'s one statement. The
    /// predicate is the threaded one: a world's own `World::readable` closed
    /// over a principal for a live dump, or the HEAD's for a historical world
    /// (`/dump?at=N` — the N-world's state at the head's class, PUB-6.48),
    /// and the caller closes it over ONE snapshot (PUB-6.39). Under the total
    /// predicate this is `dump_of` byte for byte (the unit test pins it).
    ///
    /// COST: [`crate::Engine::dump_of`]'s plus, per filtered entry, one key
    /// decode — a `Tumbler` deserialize off the tree for the authoritative
    /// maps, a dotted parse for the hints and sections — and one predicate
    /// call; plus, since lane 4.2, one walk of the supersession class (a
    /// `readlink` and an `is_nullified` per claim) to key each rendered edge
    /// by the claims asserting it, and one predicate call per such claim.
    /// Nothing is memoized; admission is the caller's to gate.
    pub fn dump_of_visible(&self, world: &World, readable: &dyn Fn(&Address) -> bool) -> WorldDump {
        dump_visible(world, readable)
    }

    /// The committed world at `principal`'s class, over ONE snapshot: the
    /// predicate is that snapshot's own `World::readable`, so the state
    /// dumped and the class it is filtered at stand on one committed state.
    /// `None` is the GUEST (PUB-5.5) — published alone, so the publication
    /// slice renders EMPTY and no draft's content, arrangement or link
    /// appears.
    pub fn world_dump_visible_to(&self, principal: Option<PrincipalId>) -> WorldDump {
        let snap = self.kernel().snapshot();
        let world = snap.world();
        dump_visible(world, &|doc: &Address| world.readable(principal, doc))
    }
}

impl crate::Engine {
    /// Dump the currently committed world (one pinned snapshot) —
    /// UNFILTERED, the HARNESS-ONLY walk (lane 3.4 §4): the crash and
    /// conformance harnesses' oracle, never a wire answer. The daemon's
    /// `/dump` is [`crate::Engine::world_dump_visible_to`].
    ///
    /// COST is [`crate::Engine::dump_of`]'s, over a world whose size the
    /// caller does not choose: this renders whatever the store currently
    /// holds, so the figure there is read against the live world and not
    /// against a request.
    pub fn world_dump(&self) -> WorldDump {
        let snap = self.kernel().snapshot();
        self.dump_of(snap.world())
    }

    /// Dump any world THIS engine produced — a snapshot of its kernel, or a
    /// world [`crate::Engine::world_at`] reconstructed — UNFILTERED, the
    /// harness-only walk; [`crate::Engine::dump_of_visible`] is the same
    /// world at a reader's class. The class sections
    /// are the format's shipped five, so no pairing decision exists: any
    /// world this format wrote renders against the same class list.
    ///
    /// COST, per call, uncached, and linear in the WHOLE world rather than in
    /// anything the caller names. The authoritative half transcodes every
    /// slice into an owned value tree before a byte of text is written, and
    /// the render then materializes each map entry's own rendering as an
    /// owned `String` to sort by — so at peak the text exists at least twice
    /// over. The tree costs a node per serialized ELEMENT, and a content byte
    /// is an element: serde has no byte specialization for `[u8]`, so M4's
    /// `Val` transcodes as a sequence of integers and not as a blob
    /// (`a_content_byte_costs_a_whole_tree_node` pins that, because it is the
    /// term that dominates this figure and it is not what the byte payload
    /// looks like). The hints half adds two whole-store link scans
    /// (`match_links` under the empty constraint set, each lifting every key
    /// it walks), one `is_nullified` and one `succs` per audit member, and two
    /// typed-slice walks per class. Nothing here is memoized, and peak memory
    /// is that figure times the number of calls in flight. Admission and
    /// concurrency are the caller's to gate; this method gates neither.
    pub fn dump_of(&self, world: &World) -> WorldDump {
        dump(world)
    }

    /// Run the hint-faithfulness check against the committed world.
    ///
    /// What `Ok(())` certifies — and the three hint families it leaves
    /// uncertified — is [`crate::Engine::check_hints_of`]'s.
    ///
    /// COST: [`crate::Engine::check_hints_of`]'s, over the committed world.
    pub fn check_hints(&self) -> Result<(), HintDivergence> {
        let snap = self.kernel().snapshot();
        self.check_hints_of(snap.world())
    }

    /// [`crate::Engine::check_hints`] over any world this engine produced.
    ///
    /// `Ok(())` certifies EXACTLY what the dump renders: the audit and active
    /// slices, the nullified members of the audit slice, the shipped classes'
    /// typed slices, the supersession forward edges, the predicate
    /// projections, the exception set and — through the v5 grant section —
    /// the grant fold's operative set each agree with a rebuild from
    /// authoritative state — for the set, that the fold over every
    /// document-minting record and the seed over M3's publication map name
    /// the same drafts with the same owners (PUB-7.7's two halves), and for
    /// the grants that the fold over every link deposit and the seed over
    /// the grants class's type slice admit the same records. It
    /// certifies nothing of the three families the dump does not reach, and
    /// each of those drives something a caller can observe — `dedup` drives
    /// `emit`'s incumbent lookup and with it idempotence; `home_frontier`
    /// drives the address `next_link_address` mints and the answers
    /// `age`/`stale` give; the type slice of a class outside the shipped five
    /// drives every typed read over ordinary content-typed links. A rebuild
    /// that mis-derived one of those passes here.
    ///
    /// COST, per call, uncached: two [`crate::Engine::dump_of`]s plus a clone
    /// of the world and a whole-links `rebuild_derived` over it — so upwards
    /// of twice that figure, and both dumps are resident at once for the
    /// comparison. This is a harness surface: it gates nothing, and it should
    /// not acquire a caller that does not gate it.
    pub fn check_hints_of(&self, world: &World) -> Result<(), HintDivergence> {
        hints_faithful(world)
    }
}

#[cfg(test)]
mod tests {
    use skep_address::{validate, Nat, Span};
    use skep_arrangement::{Caller, VPos, VSpec};
    use skep_content::Val;
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig};
    use skep_links::SlotArg;
    use skep_namespace::{HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL};

    use crate::Engine;

    use super::*;

    const USER: PrincipalId = PrincipalId(7);

    fn addr(comps: &[u32]) -> Address {
        let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c)))
            .unwrap_or_else(|_| panic!("test tumblers are nonempty"));
        validate(t).unwrap_or_else(|_| panic!("test addresses are T4-valid"))
    }

    fn vspec(doc: &Address, ordinal: u32, width: u32) -> VSpec {
        let span = Span::new(
            Tumbler::new([Nat::from(1u32), Nat::from(ordinal)]).expect("nonempty"),
            Tumbler::new([Nat::from(0u32), Nat::from(width)]).expect("nonempty"),
        )
        .unwrap_or_else(|_| panic!("well-formed test span"));
        VSpec { source: doc.clone(), span }
    }

    fn render_of(tree: &SerdeTree) -> String {
        let mut s = String::new();
        render(tree, &mut s);
        s
    }

    /// An in-memory engine whose every slice holds something, driven through
    /// the real drivers: an account and a document (M3), two content values
    /// (M4, arranged by M5), and one link (M7). The integration suite's own
    /// prologue is in `tests/common`, which a unit test cannot reach, so this
    /// restates it — cut to exactly what these tests read.
    fn populated_world() -> (Engine, World) {
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        let engine = Engine::open(cfg).expect("in-memory open cannot fail");

        let prefix = {
            let snap = engine.kernel().snapshot();
            snap.world()
                .m3()
                .next_account_prefix(&addr(&[1]))
                .expect("the genesis node has a delegable next-form prefix")
        };
        let (acct, _) = engine
            .namespace()
            .delegate(BOOTSTRAP_PRINCIPAL, prefix.tumbler().clone(), USER)
            .expect("delegation of the peeked prefix succeeds");
        // A DRAFT (explicit `false`): the flagless first mint would be the
        // published home, which takes no in-place edit (PUB-2.11).
        let (doc, _) = engine
            .namespace()
            .create_new_document(USER, &acct, Some(false))
            .expect("the delegated owner may create a document");
        engine
            .vstream()
            .insert(
                Caller::Principal(USER),
                &doc,
                VPos { subspace: Nat::from(1u32), ordinal: Nat::from(1u32) },
                vec![Val::new(vec![b'a']), Val::new(vec![b'b'])],
                false,
            )
            .expect("insert succeeds");
        engine
            .linkstore(&World::visible_to(Caller::Principal(USER)))
            .makelink(
                Caller::Principal(USER),
                &doc,
                SlotArg::Resolve(vec![vspec(&doc, 1, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 2, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 1, 2)]),
            )
            .expect("makelink succeeds");

        let world = engine.kernel().snapshot().world().clone();
        (engine, world)
    }

    /// Each authoritative section renders ITS OWN slice: a world differing in
    /// exactly one slice must render a different authoritative section, or the
    /// harnesses' byte comparison is blind to that store. Only a test inside
    /// the crate can pose the question, because only here can a world be built
    /// one slice at a time.
    #[test]
    fn each_authoritative_section_renders_its_own_slice() {
        let (engine, rich) = populated_world();
        let bare = World::genesis();
        let _ = &engine;
        let base = render_of(&authoritative_tree(&bare));

        for (slice, hybrid) in [
            ("namespace", World { namespace: rich.namespace.clone(), ..bare.clone() }),
            ("content", World { content: rich.content.clone(), ..bare.clone() }),
            ("arrangement", World { arrangement: rich.arrangement.clone(), ..bare.clone() }),
            ("links", World { links: rich.links.clone(), ..bare.clone() }),
        ] {
            assert_ne!(
                render_of(&authoritative_tree(&hybrid)),
                base,
                "the authoritative section ignores the {slice} slice"
            );
        }
    }

    /// `World`'s DECLARATION order is what M2's bincode checkpoints encode —
    /// positionally, with no field names — so a reordering silently mis-reads
    /// every checkpoint on disk while a rename is byte-neutral. Serde emits
    /// fields in declaration order to any serializer, so the transcode's
    /// COLLECTION order (before `render` sorts) is that order. The names are
    /// here to identify the fields; the ORDER is the claim — the format stamp
    /// FIRST (it is what refuses a foreign layout before any slice is read),
    /// and the skip-serialized exception set absent, since it occupies no
    /// bytes.
    #[test]
    fn the_world_serializes_its_slices_in_declaration_order() {
        let world = World::genesis();
        let SerdeTree::Map(entries) = to_tree(&world) else {
            panic!("a world transcodes as a map of its fields")
        };
        let names: Vec<&str> = entries
            .iter()
            .map(|(k, _)| match k {
                SerdeTree::Str(s) => s.as_str(),
                other => panic!("struct field keys are strings, got {other:?}"),
            })
            .collect();
        assert_eq!(names, ["format", "namespace", "content", "arrangement", "links"]);
    }

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

    /// The term that dominates a dump's cost, pinned where the cost is
    /// claimed: a content byte is a whole serialized ELEMENT, not a byte of a
    /// blob. serde has no byte specialization for `[u8]`, so M4's `Val` walks
    /// the data model through `serialize_seq` — one integer node per byte —
    /// and a world holding N bytes of content transcodes into a tree with N
    /// nodes in it before a byte of text is written. The transcode's `Bytes`
    /// arm exists and says the opposite at a glance, which is exactly why the
    /// ratio [`crate::Engine::dump_of`] states is a test and not a sentence.
    #[test]
    fn a_content_byte_costs_a_whole_tree_node() {
        let payload: Vec<u8> = (0..64u8).collect();
        let SerdeTree::Seq(nodes) = to_tree(&Val::new(payload.clone())) else {
            panic!("a content value transcodes as a sequence, not as a byte blob")
        };
        assert_eq!(nodes.len(), payload.len(), "one tree node per content byte");
        assert!(
            nodes.iter().all(|n| matches!(n, SerdeTree::U64(_))),
            "every content byte arrives as its own integer element"
        );

        // …and the text is proportional to the same term: decimal digits and
        // separators per byte, never the two hex characters the `Bytes` arm
        // would have written.
        let text = render_of(&to_tree(&Val::new(vec![255u8; 4])));
        assert_eq!(text, "[255, 255, 255, 255]");
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

    /// Lane 4.2, F4 (register cell I3.a): a supersession CLAIM is a link and
    /// its HOME governs what a class sees of it (PUB-6.13, PUB-6.22,
    /// PUB-6.27) — so an edge in `hints.supersession` asserted only by a
    /// DRAFT-homed `assert_sup` over two PUBLIC links leaves the guest's dump
    /// with its claim, while both public endpoints stay, and the owner's dump
    /// — who reads the claim's home — keeps the edge.
    #[test]
    fn a_draft_homed_supersession_claim_over_public_links_leaves_the_guest_s_edges() {
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
        let (home, _) = engine
            .namespace()
            .create_new_document(USER, &acct, None)
            .expect("the home mint");
        let (draft, _) = engine
            .namespace()
            .create_new_document(USER, &acct, None)
            .expect("a later mint, private");
        let caller = Caller::Principal(USER);
        let class = World::visible_to(caller);
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
                .linkstore(&class)
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
            .linkstore(&class)
            .assert_sup(caller, &draft, &l1, &l2)
            .expect("a draft-homed supersession claim over public links");

        let world = engine.kernel().snapshot().world().clone();
        assert!(world.readable(None, &home), "the endpoints' home is published");
        assert!(!world.readable(None, &draft), "the claim's home is a draft");
        let edges = |tree: &mut SerdeTree| match at_path(tree, &["hints", "supersession"]) {
            Some(SerdeTree::Map(entries)) => entries.len(),
            other => panic!("hints.supersession is a map, got {other:?}"),
        };
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

    fn divergence(live: &str, rebuilt: &str) -> HintDivergence {
        HintDivergence {
            live: WorldDump(live.to_owned()),
            rebuilt: WorldDump(rebuilt.to_owned()),
        }
    }

    /// The report a real divergence produces — the one text a harness prints
    /// when the check finds what it exists to find: it names the byte the two
    /// renderings first disagree on and shows both sides around it.
    #[test]
    fn a_hint_divergence_localizes_the_first_differing_byte() {
        let rendered = divergence("hints: [a, b]", "hints: [a, c]").to_string();
        assert!(rendered.contains("byte 11"), "the offset must be named: {rendered}");
        assert!(
            rendered.contains("hints: [a, b]") && rendered.contains("hints: [a, c]"),
            "both renderings must be shown: {rendered}"
        );
    }

    /// …and it survives the strings a real divergence carries: a difference
    /// inside multibyte text, where a fixed-width window lands mid-character
    /// at both ends; one at the very first byte; and one where a rendering is
    /// a strict prefix of the other, so there is no differing byte at all and
    /// the shorter length is the offset.
    #[test]
    fn a_hint_divergence_report_survives_multibyte_and_prefix_cases() {
        let snow = "☃".repeat(20);

        let live = format!("{snow}abc{snow}");
        let rebuilt = format!("{snow}abd{snow}");
        let rendered = divergence(&live, &rebuilt).to_string();
        assert!(rendered.contains("byte 62"), "the offset must be named: {rendered}");

        let rendered = divergence(&snow, &format!("z{snow}")).to_string();
        assert!(rendered.contains("byte 0"), "the offset must be named: {rendered}");

        let rendered = divergence("ab", &format!("abx{}", "🌍".repeat(20))).to_string();
        assert!(rendered.contains("byte 2"), "a prefix diverges at its own end: {rendered}");
    }
}
