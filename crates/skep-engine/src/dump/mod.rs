//! The world-dump surface (engine obligation 3, behind the `dump` feature):
//! [`WorldDump`] — a deterministic, serializable rendering of the
//! authoritative observable state, with the recomputable hints in a separate
//! section — plus the hint-faithfulness check the crash/conformance
//! harnesses lean on.
//!
//! Determinism is the contract: the authoritative section is the slices'
//! serde forms pushed through the canonicalizing transcode (maps sorted, so
//! instance-specific hash iteration cannot leak into the bytes); the hints
//! section is built from the stores' PUBLIC read surfaces over
//! already-ordered results. Two dumps of equal worlds are byte-equal.
//!
//! What each section holds, per the contract:
//! * **authoritative** — M3's registry/principals/frontiers, M4's content
//!   map, M5's arrangements (their resident form IS the canonical
//!   maximally-merged decomposition, maintained by M5's fold) and provenance
//!   R, M7's link store with its sealed genesis type config. M3 and M4
//!   expose no enumeration API, so their slices (and, uniformly, M5's and
//!   M7's) are rendered through their serde checkpoint forms — the same
//!   bytes-level seam M2's checkpoints already depend on. M7's
//!   `#[serde(skip)]` registry/hints are thereby excluded, exactly as the
//!   section demands.
//! * **hints** — M7's recomputable state, read through its public surfaces
//!   (`match_links`, `type_slice`, `members`, `succs`): the audit and active
//!   slices, the nullified set, per-class type slices (five shipped classes
//!   plus the app decls from the one genesis config), the supersession
//!   forward edges (the BH2 walk), and M9's definition registry projected as
//!   `pdef`/`pd_stable` membership. M7's `dedup` and `home_frontier` hints
//!   have no public read surface and are exercised by the stores' own
//!   write-path tests instead — stated here so their absence is a scope
//!   decision, not an oversight. M3/M4 hold no hints; M5's rebuild is the
//!   identity in v1.

mod canon;

use std::fmt;

use serde::Serialize;
use skep_address::{Address, Tumbler};
use skep_kernel::WorldState;
use skep_links::{Endset, LinkState, ShippedType, View};

use crate::genesis::{GenesisConfig, SHIPPED};
use crate::world::World;
use canon::{render, to_tree, SerdeTree};

/// A deterministic rendering of one world. Byte-equality is the comparison
/// the harnesses use: two dumps of equal worlds are byte-equal, and a
/// checkpoint+replay world dumps byte-equal to the live fold it recovers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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

/// Render one world against the configuration it was sealed under: the four
/// slices' serde forms through the canonicalizing transcode, then the hints
/// section, which reads its app-class keys off `cfg` because that is the one
/// place they live.
///
/// The section keys below are the dump's own wire vocabulary, exactly as
/// [`shipped_label`]'s are: they name each slice for the store it belongs to
/// and match the [`World`] field names by intent, not by construction. They
/// are part of the format, so the banner's version moves with them.
fn dump(world: &World, cfg: &GenesisConfig) -> WorldDump {
    let root = SerdeTree::Map(vec![
        (
            key("authoritative"),
            SerdeTree::Map(vec![
                (key("namespace"), to_tree(&world.namespace)),
                (key("content"), to_tree(&world.content)),
                (key("arrangement"), to_tree(&world.arrangement)),
                (key("links"), to_tree(&world.links)),
            ]),
        ),
        (key("hints"), hints_tree(world, cfg)),
    ]);
    let mut s = String::from("skep-world-dump v2\n");
    render(&root, &mut s);
    s.push('\n');
    WorldDump(s)
}

/// Hint faithfulness: dump the live world, rebuild its derived state from
/// scratch through the engine's own recovery path
/// (`WorldState::rebuild_derived` — the same call recovery makes before
/// replay), dump again, compare bytes. Equal dumps certify that the
/// incrementally-maintained hints match a from-authoritative rebuild; the
/// authoritative sections are untouched by the rebuild, so any divergence
/// localizes to a hint.
fn hints_faithful(world: &World, cfg: &GenesisConfig) -> Result<(), HintDivergence> {
    let live = dump(world, cfg);
    let rebuilt = dump(&world.clone().rebuild_derived(), cfg);
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
        let (a, b) = (self.live.as_str(), self.rebuilt.as_str());
        let shorter = a.len().min(b.len());
        let i = a.bytes().zip(b.bytes()).position(|(x, y)| x != y).unwrap_or(shorter);
        write!(
            f,
            "hint dump diverges at byte {i}: live …{:?}… vs rebuilt …{:?}…",
            window(a, i),
            window(b, i)
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

fn key(s: &str) -> SerdeTree {
    SerdeTree::Str(s.to_owned())
}

fn tum_seq<'a>(it: impl Iterator<Item = &'a Tumbler>) -> SerdeTree {
    SerdeTree::Seq(it.map(|t| SerdeTree::Str(t.to_string())).collect())
}

fn addr_seq(addrs: &[Address]) -> SerdeTree {
    SerdeTree::Seq(addrs.iter().map(|a| SerdeTree::Str(a.to_string())).collect())
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

fn hints_tree(world: &World, cfg: &GenesisConfig) -> SerdeTree {
    let links = &world.links;
    // Empty constraints ⇒ the whole view slice (M7 §G) — the one public
    // whole-store enumeration.
    let audit = links.match_links(&[], View::Audit);
    let active = links.match_links(&[], View::Active);

    let mut entries: Vec<(SerdeTree, SerdeTree)> = vec![
        (key("links.audit"), tum_seq(audit.iter().map(Address::tumbler))),
        (key("links.active"), tum_seq(active.iter().map(Address::tumbler))),
        (
            key("links.nullified"),
            SerdeTree::Seq(
                audit
                    .iter()
                    .filter(|a| links.is_nullified(a))
                    .map(|a| SerdeTree::Str(a.to_string()))
                    .collect(),
            ),
        ),
    ];

    // Per-class typed slices: the shipped classes off the one genesis list,
    // then the app decls in genesis order — the same one configuration
    // genesis sealed.
    let mut classes: Vec<(SerdeTree, SerdeTree)> = Vec::new();
    for t in SHIPPED {
        classes.push((key(shipped_label(t)), class_tree(links, links.reserved_type(t))));
    }
    for (i, d) in cfg.types.decls.iter().enumerate() {
        classes.push((SerdeTree::Str(format!("app.{i}")), class_tree(links, &d.key)));
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
    let pd = links.reserved_type(ShippedType::PredDef);
    let ps = links.reserved_type(ShippedType::PredStable);
    entries.push((key("predicates.defs.audit"), addr_seq(&links.members(pd, View::Audit))));
    entries.push((key("predicates.defs.active"), addr_seq(&links.members(pd, View::Active))));
    entries.push((key("predicates.stable.audit"), addr_seq(&links.members(ps, View::Audit))));
    entries.push((key("predicates.stable.active"), addr_seq(&links.members(ps, View::Active))));

    SerdeTree::Map(entries)
}

impl crate::Engine {
    /// Dump the currently committed world (one pinned snapshot).
    pub fn world_dump(&self) -> WorldDump {
        let snap = self.kernel().snapshot();
        self.dump_of(snap.world())
    }

    /// Dump any world THIS engine produced — a snapshot of its kernel, or a
    /// world [`crate::Engine::world_at`] reconstructed.
    ///
    /// A dump is only meaningful against the configuration its world was
    /// sealed under, because the hints section enumerates its app-class
    /// sections from the genesis decls: rendered against a foreign
    /// configuration it reports classes the world never sealed and omits the
    /// ones it did — and it does so deterministically, so two equally
    /// mispaired dumps compare byte-equal and a harness narrowing on that
    /// comparison sees nothing. Which configuration goes with which world is
    /// assembly knowledge; the engine holds it, so the pairing is made here
    /// and cannot be made anywhere else.
    pub fn dump_of(&self, world: &World) -> WorldDump {
        dump(world, self.genesis_config())
    }

    /// Run the hint-faithfulness check against the committed world.
    pub fn check_hints(&self) -> Result<(), HintDivergence> {
        let snap = self.kernel().snapshot();
        self.check_hints_of(snap.world())
    }

    /// [`crate::Engine::check_hints`] over any world this engine produced,
    /// paired with its genesis configuration exactly as
    /// [`crate::Engine::dump_of`] pairs it.
    pub fn check_hints_of(&self, world: &World) -> Result<(), HintDivergence> {
        hints_faithful(world, self.genesis_config())
    }
}
