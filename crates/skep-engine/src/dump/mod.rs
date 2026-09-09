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
//! What each section holds, per the contract:
//! * **authoritative** — M3's four serde fields (the node registry, the
//!   principals, the per-namespace frontier counts and the publication map),
//!   M4's content
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
//!   checked against). A projection: the map itself is one of M3's four
//!   serde fields and travels whole in the authoritative section above.
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
}
