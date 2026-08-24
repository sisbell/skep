//! The observation surface (engine obligation 3, behind the `observe`
//! feature): [`WorldDump`] — a deterministic, serializable rendering of the
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
//! * **hints** — M7's recomputable observations through the public reads:
//!   the audit and active slices, the nullified set, per-class type slices
//!   (five shipped classes plus the app decls from the one genesis config),
//!   the supersession forward edges (the BH2 walk), and M9's definition
//!   registry projected as `pdef`/`pd_stable` membership. M7's `dedup` and
//!   `home_frontier` hints have no public read surface and are exercised by the
//!   stores' own write-path tests instead — stated here so their absence is
//!   a scope decision, not an oversight. M3/M4 hold no hints; M5's rebuild
//!   is the identity in v1.

mod canon;

use std::fmt;

use serde::Serialize;
use skep_address::{Address, Tumbler};
use skep_kernel::WorldState;
use skep_links::{Endset, LinkState, ShippedType, View};

use crate::genesis::GenesisConfig;
use crate::world::World;
use canon::{render, to_canon, Canon};

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

/// Render one world. `cfg` must be the genesis configuration the world was
/// opened under — it is the one place the app-declared type keys live, and
/// the engine holds it precisely so observation enumerates the same classes
/// genesis sealed.
pub fn dump(world: &World, cfg: &GenesisConfig) -> WorldDump {
    let root = Canon::Map(vec![
        (
            key("authoritative"),
            Canon::Map(vec![
                (key("m3"), to_canon(&world.m3)),
                (key("content"), to_canon(&world.content)),
                (key("m5"), to_canon(&world.m5)),
                (key("links"), to_canon(&world.links)),
            ]),
        ),
        (key("hints"), hints_canon(world, cfg)),
    ]);
    let mut s = String::from("skep-world-dump v1\n");
    render(&root, &mut s);
    s.push('\n');
    WorldDump(s)
}

/// Hint faithfulness (the contract's helper): dump the live world, rebuild
/// its derived state from scratch through the engine's own recovery path
/// (`WorldState::rebuild_derived` — the same call recovery makes before
/// replay), dump again, compare bytes. Equal dumps certify that the
/// incrementally-maintained hints match a from-authoritative rebuild; the
/// authoritative sections are untouched by the rebuild, so any divergence
/// localizes to a hint.
pub fn hints_faithful(world: &World, cfg: &GenesisConfig) -> Result<(), HintDivergence> {
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

fn key(s: &str) -> Canon {
    Canon::Str(s.to_owned())
}

fn tum_seq<'a>(it: impl Iterator<Item = &'a Tumbler>) -> Canon {
    Canon::Seq(it.map(|t| Canon::Str(t.to_string())).collect())
}

fn addr_seq(addrs: &[Address]) -> Canon {
    Canon::Seq(addrs.iter().map(|a| Canon::Str(a.to_string())).collect())
}

/// One type class's observable projection: its key endset and its
/// audit/active slices (both already address-ordered `OrdSet`s).
fn class_canon(links: &LinkState, ty: &Endset) -> Canon {
    Canon::Map(vec![
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

fn hints_canon(world: &World, cfg: &GenesisConfig) -> Canon {
    let links = &world.links;
    // Empty constraints ⇒ the whole view slice (M7 §G) — the one public
    // whole-store enumeration.
    let audit = links.match_links(&[], View::Audit);
    let active = links.match_links(&[], View::Active);

    let mut entries: Vec<(Canon, Canon)> = vec![
        (key("links.audit"), tum_seq(audit.iter().map(Address::tumbler))),
        (key("links.active"), tum_seq(active.iter().map(Address::tumbler))),
        (
            key("links.nullified"),
            Canon::Seq(
                audit
                    .iter()
                    .filter(|a| links.is_nullified(a))
                    .map(|a| Canon::Str(a.to_string()))
                    .collect(),
            ),
        ),
    ];

    // Per-class typed slices: the five shipped classes, then the app decls in
    // genesis order — the same one configuration genesis sealed.
    let shipped = [
        ("shipped.retired", ShippedType::Retired),
        ("shipped.supersedes", ShippedType::Supersedes),
        ("shipped.retraction", ShippedType::Retraction),
        ("shipped.pred_def", ShippedType::PredDef),
        ("shipped.pred_stable", ShippedType::PredStable),
    ];
    let mut classes: Vec<(Canon, Canon)> = Vec::new();
    for (label, t) in shipped {
        classes.push((key(label), class_canon(links, links.reserved_type(t))));
    }
    for (i, d) in cfg.decls.iter().enumerate() {
        classes.push((Canon::Str(format!("app.{i}")), class_canon(links, &d.key)));
    }
    entries.push((key("types"), Canon::Map(classes)));

    // The supersession forward edges (the BH2 walk over the shipped
    // `[K_sup]` class — the public projection of M7's `sup_fwd` hint).
    let sup = links.reserved_type(ShippedType::Supersedes);
    let mut edges: Vec<(Canon, Canon)> = Vec::new();
    for a in audit.iter() {
        let succs = links.succs(sup, a);
        if !succs.is_empty() {
            edges.push((Canon::Str(a.to_string()), addr_seq(&succs)));
        }
    }
    entries.push((key("supersession"), Canon::Map(edges)));

    // M9's definition registry, projected: `pdef`/`pd_stable` membership
    // (M9 owns no slice; its registry IS these M7 tuples).
    let pd = links.reserved_type(ShippedType::PredDef);
    let ps = links.reserved_type(ShippedType::PredStable);
    entries.push((key("predicates.defs.audit"), addr_seq(&links.members(pd, View::Audit))));
    entries.push((key("predicates.defs.active"), addr_seq(&links.members(pd, View::Active))));
    entries.push((key("predicates.stable.audit"), addr_seq(&links.members(ps, View::Audit))));
    entries.push((key("predicates.stable.active"), addr_seq(&links.members(ps, View::Active))));

    Canon::Map(entries)
}

impl crate::Engine {
    /// Dump the currently committed world (one pinned snapshot).
    pub fn world_dump(&self) -> WorldDump {
        let snap = self.kernel().snapshot();
        dump(snap.world(), self.genesis_config())
    }

    /// Run the hint-faithfulness check against the committed world.
    pub fn check_hints(&self) -> Result<(), HintDivergence> {
        let snap = self.kernel().snapshot();
        hints_faithful(snap.world(), self.genesis_config())
    }
}
