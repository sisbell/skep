//! The world-dump surface (behind the `dump` feature): [`WorldDump`] — a
//! deterministic, byte-comparable rendering of the authoritative observable
//! state, with the recomputable hints in a separate section — plus the
//! hint-faithfulness check the crash/conformance harnesses lean on. The
//! reduction that turns this rendering into a reader's own is `filter`'s.
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
//! A slice reaches the authoritative section through its SERDE CHECKPOINT
//! FORM rather than through an enumeration: M3 and M4 publish none, and M5's
//! and M7's go the same way so that one seam serves all four. It is the
//! bytes-level seam M2's checkpoints already depend on, down to serde's
//! human-readable flag, which the transcode answers the way bincode does — so
//! a branching `Serialize` impl renders the branch the journal stores, and a
//! `#[serde(skip)]` field is excluded here exactly as the checkpoint excludes
//! it.
//!
//! The four sections, each stated in full at the builder that writes it:
//! * **authoritative** (`authoritative_tree`) — one entry per store slice,
//!   each the slice's own serde form.
//! * **publication** (`publication_tree`, v5, PUB round 2, lane 3.4 §3) —
//!   M3's AUTHORITATIVE publication slice projected to its drafts: the state
//!   the exception set is a derived index over, rendered apart from the
//!   hints' copy of it (`hints.publication.drafts`, which STAYS — it is the
//!   faithfulness check's subject, this section the authority it is checked
//!   against).
//! * **grants** (`grants_tree`, v5) — the grant fold's OPERATIVE set. The
//!   engine keeps no grant slice, so this section is derived, and the
//!   faithfulness check reaches the fold's records through it.
//! * **hints** (`hints_tree`) — M7's recomputable state through its public
//!   read surfaces, M9's definition registry projected, and the engine's own
//!   exception set. What that walk does NOT reach — and so what the
//!   faithfulness check does not certify — is that builder's own statement.
//!
//! ## The per-class filter (lane 3.4 §4)
//!
//! [`Engine::world_dump`] and [`Engine::dump_of`] are the HARNESS-ONLY
//! unfiltered walk; the daemon's `/dump` is [`Engine::dump_of_visible`], the
//! same tree post-filtered at a reader's class before a byte is rendered.
//! What that reduction drops and keeps is the `filter` module's one
//! statement.
//!
//! [`Engine::world_dump`]: crate::Engine::world_dump
//! [`Engine::dump_of`]: crate::Engine::dump_of
//! [`Engine::dump_of_visible`]: crate::Engine::dump_of_visible

mod filter;

use std::fmt;

use skep_address::{Address, Tumbler};
use skep_kernel::WorldState;
use skep_links::{Endset, LinkState, ShippedType, View};
use skep_namespace::PrincipalId;

use crate::canon::{render, to_tree, SerdeTree};
use crate::world::World;

use filter::filter_tree;

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
/// What each entry carries is that slice's checkpoint form and nothing else:
/// M3's four serde fields (the node registry, the principals, the
/// per-namespace frontier counts and the publication map), M4's content map,
/// M5's arrangements — whose resident form IS the canonical maximally-merged
/// decomposition, maintained by M5's fold — and its provenance R, and M7's
/// link store. M7's `#[serde(skip)]` registry and hints are thereby excluded,
/// exactly as this section demands: they are the [`hints_tree`] section's
/// subject, and rendering them here would compare a derived structure against
/// itself.
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

/// The two disagreeing dumps, LOCALIZED by both renderings: `Display` and
/// `Debug` alike name the byte the two first differ at and show a bounded
/// window of each side around it. Neither writes a dump whole, and that is
/// what makes this type printable at all — a rendering costs a tree node per
/// content byte ([`Engine::dump_of`]'s cost), so a world of any size is
/// megabytes of text and two of them is what a caller would otherwise get on
/// one line. A caller that wants a whole rendering reads the field.
///
/// The two carriers exist because a caller reaches this type through both:
/// an operator reads `Display`, and `Result::expect`/`unwrap` print `Debug`.
///
/// `#[non_exhaustive]`, because the assembler may find more of a divergence
/// worth carrying: a receiver reads both fields either way, and nothing
/// outside this crate can build one, since a [`WorldDump`] exists only
/// because an engine rendered it.
///
/// [`Engine::dump_of`]: crate::Engine::dump_of
#[non_exhaustive]
pub struct HintDivergence {
    pub live: WorldDump,
    pub rebuilt: WorldDump,
}

impl fmt::Display for HintDivergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (live, rebuilt) = (self.live.as_str(), self.rebuilt.as_str());
        let i = divergence_offset(live, rebuilt);
        write!(
            f,
            "hint dump diverges at byte {i}: live …{:?}… vs rebuilt …{:?}…",
            window(live, i),
            window(rebuilt, i)
        )
    }
}

impl fmt::Debug for HintDivergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (live, rebuilt) = (self.live.as_str(), self.rebuilt.as_str());
        let i = divergence_offset(live, rebuilt);
        f.debug_struct("HintDivergence")
            .field("at_byte", &i)
            .field("live", &window(live, i))
            .field("rebuilt", &window(rebuilt, i))
            .finish_non_exhaustive()
    }
}

impl std::error::Error for HintDivergence {}

/// The byte the two renderings first differ at — or, where one is a strict
/// prefix of the other, the shorter one's length, which is where it ran out.
fn divergence_offset(live: &str, rebuilt: &str) -> usize {
    let shorter = live.len().min(rebuilt.len());
    live.bytes().zip(rebuilt.bytes()).position(|(x, y)| x != y).unwrap_or(shorter)
}

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

/// A section key — a string node, the one shape a key in this format takes.
/// Every caller hands a compiled `&str`: the section names are literals, and
/// the family and class names are the format's own tables ([`SLICE_VIEWS`],
/// [`PREDICATE_PROJECTIONS`], [`shipped_label`]).
fn key(s: &str) -> SerdeTree {
    SerdeTree::Str(s.to_owned())
}

/// A sequence of dotted TUMBLERS, for the one entry whose values are not
/// addresses: an endset denotes tumblers (`Endset::addrs`), so
/// [`class_tree`]'s type `key` has none in hand. Everything else the dump
/// renders as a dotted sequence holds addresses and goes through
/// [`addr_seq`], which writes the same text — `Address` renders as its own
/// tumbler — off the validated value rather than off a projection of it.
fn tum_seq<'a>(it: impl IntoIterator<Item = &'a Tumbler>) -> SerdeTree {
    SerdeTree::Seq(it.into_iter().map(|t| SerdeTree::Str(t.to_string())).collect())
}

/// A sequence of dotted ADDRESSES.
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

/// The dump's own name for each VIEW a class's slice is rendered under, with
/// the view it is read at — [`class_tree`]'s two slice entries, in the order
/// it writes them.
///
/// TWO rows and not a total function over `View`: this format renders the
/// audit and active slices and no third, so a view M7 has beside them is
/// absent from a class's submap until a row here says otherwise.
///
/// The label and the view it names are one piece of format knowledge, so
/// they are declared together and once, exactly as [`PREDICATE_PROJECTIONS`]
/// is. The builder writes a class's slices off this table and the per-class
/// filter reduces them off the same one, so a slice's entries cannot be
/// judged at a view other than the one they were rendered under. The labels
/// are the dump's own wire vocabulary, as [`shipped_label`]'s are — they are
/// wire-visible and outlive any rename of the variant.
const SLICE_VIEWS: [(&str, View); 2] = [("audit", View::Audit), ("active", View::Active)];

/// M9's definition registry as this format projects it: one hints family per
/// (shipped class, view), each rendering `LinkState::members` — the SUBJECTS
/// those tuples denote, never the tuples themselves.
///
/// The family name, the class it is read off and the view it is read under
/// are one piece of format knowledge, so they are declared together and once.
/// The builder ([`hints_tree`]) writes these families off this table and the
/// per-class filter reduces them off the same one, which is what keeps a
/// family's entries from being judged at a class or a view other than the one
/// they were rendered under — a disagreement two separate declarations could
/// hold without contradicting either.
///
/// The names are the dump's own wire vocabulary, as [`shipped_label`]'s are,
/// and the ORDER is free: `render` sorts a map's entries, so the section's
/// bytes do not depend on it.
const PREDICATE_PROJECTIONS: [(&str, ShippedType, View); 4] = [
    ("predicates.defs.audit", ShippedType::PredDef, View::Audit),
    ("predicates.defs.active", ShippedType::PredDef, View::Active),
    ("predicates.stable.audit", ShippedType::PredStable, View::Audit),
    ("predicates.stable.active", ShippedType::PredStable, View::Active),
];

/// One type class's observable projection: the THREE entries a class submap
/// holds — its key endset, then one slice per row of [`SLICE_VIEWS`], each
/// already an address-ordered `OrdSet`.
///
/// That entry set is format, and it is the third level of the tree the
/// per-class filter's completeness statement is held against: the slices are
/// sequences of link addresses and reduce by home, while `key` is a compiled
/// format constant and stays at every class. A fourth entry added here and
/// left out of that statement would be rendered whole to every reader, which
/// is why `every_hints_family_is_reduced_or_kept_by_name` holds this set as
/// well as the two above it.
///
/// `ty` carries M7's stated precondition — address-denoting or
/// `iextent`-built, else `type_slice` panics naming it — and the one caller
/// below is inside it: a reserved endset is M7's own.
fn class_tree(links: &LinkState, ty: &Endset) -> SerdeTree {
    let mut entries = vec![(key("key"), tum_seq(ty.addrs()))];
    for (label, view) in SLICE_VIEWS {
        entries.push((key(label), addr_seq(links.type_slice(ty, view).iter())));
    }
    SerdeTree::Map(entries)
}

/// The HINTS section: the recomputable state, read through PUBLIC surfaces
/// alone over already-ordered results — never off a store's private hint.
/// M7's is most of it (`match_links`, `type_slice`, `members`, `succs`): the
/// audit and active slices, the nullified LINKS of the audit slice, the
/// five shipped classes' type slices, and the supersession forward edges (the
/// BH2 walk). Beside them, M9's definition registry — which is no slice of
/// M9's but these M7 tuples — projected one family per row of
/// [`PREDICATE_PROJECTIONS`]; and the engine's OWN derived index, the
/// exception set (`publication.drafts`: draft document → owner account,
/// PUB-7.5). M3 and M4 hold no hints of their own, and M5's rebuild is the
/// identity in v1, so neither store appears.
///
/// THREE of M7's hint families sit outside that reach, which is what bounds
/// [`hints_faithful`] to an oracle over what this renders and nothing more:
///
/// * `dedup` has no public read surface at all.
/// * `home_frontier` has one, `LinkState::age`, which is that hint less a
///   link's own ordinal — so its omission is a decision about this FORMAT
///   rather than a consequence of M7's surface, and closing it would move
///   bytes the harnesses pin.
/// * M7's fold indexes a type slice for EVERY coverage class while this
///   section names only the shipped five, so the typed slice an ordinary
///   content-typed link lands in is never rendered.
///
/// Each is exercised by M7's own write-path tests instead.
///
/// `links.nullified` renders the nullified LINKS of the audit slice, which
/// is the whole tombstone set only because `nullify`'s P-tgt gate admits no
/// target but a resident link or the address the retraction tuple itself will
/// occupy. M7's fold inserts every denoted to-root of an `[R]` link, so a
/// root that is not itself a link would sit in the hint and outside this
/// rendering.
///
/// The family names are format, so a family added here is a family the
/// per-class filter must be given a disposition for; `filter_tree`'s
/// statement is where that is held against this builder.
fn hints_tree(world: &World) -> SerdeTree {
    let links = &world.links;
    // Empty constraints ⇒ the whole view slice (M7 §G) — the one public
    // whole-store enumeration.
    let audit = links.match_links(&[], View::Audit);
    let active = links.match_links(&[], View::Active);

    let mut entries: Vec<(SerdeTree, SerdeTree)> = vec![
        (key("links.audit"), addr_seq(audit.iter())),
        (key("links.active"), addr_seq(active.iter())),
        (key("links.nullified"), addr_seq(audit.iter().filter(|addr| links.is_nullified(addr)))),
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
    for addr in audit.iter() {
        let succs = links.succs(sup, addr);
        if !succs.is_empty() {
            edges.push((SerdeTree::Str(addr.to_string()), addr_seq(&succs)));
        }
    }
    entries.push((key("supersession"), SerdeTree::Map(edges)));

    // M9's definition registry, projected: `pdef`/`pd_stable` membership
    // (M9 owns no slice; its registry IS these M7 tuples). One family per row
    // of the format's own table, which the per-class filter reduces off too.
    for (family, ty, view) in PREDICATE_PROJECTIONS {
        entries.push((key(family), addr_seq(&links.members(links.reserved_type(ty), view))));
    }

    // The engine's own derived index: the exception set (PUB-7.5), a map
    // draft → owner account. Collected in the set's hash order; `render`
    // sorts map entries, so the text is a function of the contents alone.
    entries.push((key("publication.drafts"), drafts_tree(world)));

    SerdeTree::Map(entries)
}

/// The exception set as a map of dotted addresses, draft → owner account.
/// The assembler's own derived index rather than a store's — the one the
/// HINTS section carries; the grant fold is the other, and its home is the
/// `grants` section ([`grants_tree`]). This index's seed and fold are
/// `crate::publication`'s, and this rendering is what [`hints_faithful`]
/// compares them through.
fn drafts_tree(world: &World) -> SerdeTree {
    SerdeTree::Map(
        world
            .drafts()
            .map(|d| {
                (SerdeTree::Str(d.document.to_string()), SerdeTree::Str(d.owner.to_string()))
            })
            .collect(),
    )
}

// ── the two publication-round sections (v5, lane 3.4 §3) ──

/// The PUBLICATION section: M3's AUTHORITATIVE publication slice reduced to
/// its DRAFT entries — the documents whose minting record journaled
/// `published: false` — as dotted addresses in address order. Off the same
/// read of M3's serde form the exception set's seed uses
/// (`crate::publication::publication_map`); the hints' `publication.drafts`
/// is the FOLD's copy, and [`hints_faithful`] compares that copy against the
/// seed. A SEQUENCE — `render` sorts maps alone — in the `OrdMap`'s own
/// address order, which is the order the filter preserves.
///
/// One read, TWO RULES over it, and the two agree on an invariant of M3's
/// rather than on a shared test. This section keeps an entry whose stored
/// value is `false`. The seed discards the values and asks M3 itself, per
/// KEY, whether the address is a registered document and what its bit is —
/// which is what keeps the load path's fail-stop off an unregistered address.
/// The rules coincide because M3 writes the publication entry and the
/// registration in one fold step, and only for a document-tier mint, so the
/// map's keys ARE the registered documents. A store that registered a
/// document without an entry, or wrote an entry for anything else, would
/// separate them.
///
/// This section is a PROJECTION of the map, not the only rendering of it: the
/// same authoritative map travels whole inside `authoritative.namespace`, as
/// one of M3's four serde fields. So the per-class filter's reduction of this
/// section reduces THIS SECTION, and a class that cannot open a draft still
/// reads its bit there.
fn publication_tree(world: &World) -> SerdeTree {
    let map = crate::publication::publication_map(&world.namespace);
    addr_seq(map.iter().filter(|(_, published)| !**published).map(|(doc, _)| doc))
}

/// The GRANT section: the grant fold's OPERATIVE set — every admitted,
/// unsuperseded grant keyed by the grant link's own address, each entry its
/// `home` (the issuer's doc 1), its `issuer` (ω of the home), the
/// `content_prefix` it shares and its `grantee` (`none` for the ANY-PRINCIPAL
/// form, PUB-5.8). DERIVED — the fold's records, the engine keeping no grant
/// slice — so [`hints_faithful`] covers the grant fold's RECORDS through this
/// section: a seed that admitted a record the fold did not moves these bytes.
/// It does not cover the fold's two QUERY INDEXES, which are what
/// `grant_exists` probes and which nothing here renders —
/// [`crate::Engine::check_hints_of`] states that gap and why it is not a live
/// divergence. Collected in the
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

/// The dump surface. Every rendering below is a pure function of the world it
/// is handed and, where there is one, the class it is filtered at: the type
/// set is a compiled format constant, so no configuration remains to pair a
/// world with and nothing of this handle's own state reaches the text. The
/// receiver is the engine a caller already holds, and the no-argument methods
/// use it for the one thing it supplies — pinning the committed snapshot the
/// world is read off.
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
    /// call. On top of that, FIVE whole-class walks, because two hint
    /// families name something other than the link whose deposit put it
    /// there and the filter must recover that link to judge it:
    ///
    /// * ONE over the supersession class, a `readlink` and an `is_nullified`
    ///   per claim, to key each rendered edge by the claims asserting it; and
    /// * FOUR over the predicate classes — `pred_def` and `pred_stable`, each
    ///   under both views — a `readlink` per tuple, to key each rendered
    ///   member by the tuples asserting it.
    ///
    /// Each walk costs one `type_slice` and its per-tuple reads, and adds one
    /// predicate call per asserting link at the entries it judges. The two
    /// walks are bounded differently, and by the STORE rather than by the
    /// request:
    ///
    /// * the supersession walk is linear in its class, because that class is
    ///   CLOSED to the open surfaces — `makelink` and `emit` both refuse it —
    ///   so every claim in it carries one denoted address a side; while
    /// * the predicate walks are linear in the SUM OF SUBJECT-SLOT WIDTHS
    ///   over their classes. `makelink` fences only the retraction and
    ///   supersession classes, so a predicate-classed link may be deposited
    ///   through the open surface with a subject slot of up to
    ///   `skep_links::MAX_SLOT_SPANS` spans, each denoting a member of its
    ///   own. That is `LinkState::members`' own bound, which this walk
    ///   mirrors rather than adds to.
    ///
    /// The filter additionally PARSES a dotted address per entry it judges,
    /// which is [`crate::Engine::dump_of`]'s magnitude term run backwards: a
    /// client-chosen component costs its base conversion on the way out and
    /// again on the way in, and a section this filter reduces is one whose
    /// entries it must decode to reduce.
    ///
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
    /// over. M3's slice is transcoded TWICE: once for the authoritative
    /// section, and once more by [`publication_tree`], which additionally
    /// deserializes the publication map back through M1's validating door —
    /// one address validation per REGISTERED DOCUMENT, published or not. That
    /// second read is structural rather than incidental: the section must come
    /// off M3's authoritative map and not off the derived set, which is what
    /// makes it the authority the hint is checked against.
    /// The tree costs a node per serialized ELEMENT, and a content byte
    /// is an element: serde has no byte specialization for `[u8]`, so M4's
    /// `Val` transcodes as a sequence of integers and not as a blob
    /// (`a_content_byte_costs_a_whole_tree_node` pins that, because it is the
    /// term that dominates this figure and it is not what the byte payload
    /// looks like).
    ///
    /// One term is not a count of anything: a component of a tumbler is a
    /// `Nat`, an arbitrary-precision integer with no magnitude bound, and
    /// rendering one DOTTED is a base conversion whose work grows faster than
    /// the component's digit count. That magnitude is not the store's to
    /// choose. An address reaches a link slot straight off a client's
    /// deposit — `makelink` gates neither slot's addresses against M3, so an
    /// address that was never minted and never will be is stored and later
    /// rendered — and the sections that carry such addresses dotted include
    /// the `grants` section, which the per-class filter keeps WHOLE. So every
    /// class pays this term, the guest included
    /// (`a_grant_names_an_address_the_client_invented` pins the reach).
    ///
    /// The hints half adds two whole-store link scans
    /// (`match_links` under the empty constraint set, each lifting every key
    /// it walks), one `is_nullified` and one `succs` per audit LINK, and two
    /// typed-slice walks per class. Nothing here is memoized, and peak memory
    /// is that figure times the number of calls in flight. Admission and
    /// concurrency are the caller's to gate; this method gates neither.
    pub fn dump_of(&self, world: &World) -> WorldDump {
        dump(world)
    }

    /// Run the hint-faithfulness check against the committed world.
    ///
    /// What `Ok(())` certifies — and the five derived structures it leaves
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
    /// slices, the nullified LINKS of the audit slice, the shipped classes'
    /// typed slices, the supersession forward edges, the predicate
    /// projections, the exception set and — through the v5 grant section —
    /// the grant fold's operative set each agree with a rebuild from
    /// authoritative state — for the set, that the fold over every
    /// document-minting record and the seed over M3's publication map name
    /// the same drafts with the same owners (PUB-7.7's two halves), and for
    /// the grants that the fold over every link deposit and the seed over
    /// the grants class's type slice admit the same RECORDS. It
    /// certifies nothing of the FIVE derived structures the dump does not
    /// reach, and each of those drives something a caller can observe:
    ///
    /// * M7's `dedup` drives `emit`'s incumbent lookup and with it
    ///   idempotence; `home_frontier` drives the address `next_link_address`
    ///   mints and the answers `age`/`stale` give; the type slice of a class
    ///   outside the shipped five drives every typed read over ordinary
    ///   content-typed links.
    /// * The grant fold's TWO QUERY INDEXES — `by_grantee` and `universal` —
    ///   drive `grant_exists`, the read predicate's third clause, so a
    ///   mis-derived one is an authorization answer rather than a stale
    ///   figure. The dump's grant section renders the fold's RECORDS and
    ///   neither index, so no comparison here reaches them.
    ///
    /// A rebuild that mis-derived any of the five passes here. For the two
    /// indexes that is a gap in the CERTIFICATE rather than a live
    /// divergence, and the argument belongs beside the claim: both halves of
    /// the discipline drive one `grants::fold_one`, so an index is a function
    /// of the record SEQUENCE alone, and the halves can only order that
    /// sequence differently across homes. An index entry is withdrawn by the
    /// first record naming it, so order can matter only where two grants
    /// SHARE one — which requires a single issuer, and admission ties an
    /// issuer to a single home, so sharing is always intra-home, where the
    /// seed's address order IS the fold's deposit order.
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

    pub(super) const USER: PrincipalId = PrincipalId(7);

    pub(super) fn addr(comps: &[u32]) -> Address {
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

    pub(super) fn render_of(tree: &SerdeTree) -> String {
        let mut s = String::new();
        render(tree, &mut s);
        s
    }

    /// An in-memory engine whose every slice holds something, driven through
    /// the real drivers: an account and a document (M3), two content values
    /// (M4, arranged by M5), and one link (M7). The integration suite's own
    /// prologue is in `tests/common`, which a unit test cannot reach, so this
    /// restates it — cut to exactly what these tests read. Shared with the
    /// `filter` submodule's tests, which need a world holding an entry in
    /// every family the reduction reaches.
    pub(super) fn populated_world() -> (Engine, World) {
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

    /// …and the OTHER carrier localizes too. `Result::expect` and `unwrap`
    /// print `Debug`, which is how every caller of `check_hints` in this
    /// workspace meets a divergence, and a rendering costs a tree node per
    /// content byte — so a `Debug` that carried the two dumps would put two
    /// whole worlds of escaped text on one line. The size assertion is the
    /// claim: the report is smaller than ONE rendering, where carrying them
    /// would make it larger than two.
    #[test]
    fn a_hint_divergence_debugs_as_its_localization_and_not_as_two_worlds() {
        let filler = "a, ".repeat(4096);
        let (live, rebuilt) = (format!("hints: [{filler}b]"), format!("hints: [{filler}c]"));
        let at = "hints: [".len() + filler.len();

        let rendered = format!("{:?}", divergence(&live, &rebuilt));
        assert!(
            rendered.contains(&format!("at_byte: {at}")),
            "the offset must be named: {rendered:.160}"
        );
        assert!(
            rendered.contains("b]") && rendered.contains("c]"),
            "both sides must be shown around it: {rendered:.160}"
        );
        assert!(
            rendered.len() < live.len(),
            "the report carried the renderings: {} bytes for two dumps of {} each",
            rendered.len(),
            live.len()
        );
    }
}
