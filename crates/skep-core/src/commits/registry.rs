//! The link-type registry's seed (commons-seeding §1 to §4).
//!
//! It is the board's own daemon writing the registry document `1.1.0.1.0.1`
//! — doc 1 of the system account, born published and empty at genesis — at
//! every open, in-process as the system account's principal with no session,
//! through the head writer's door: one named section and one `defines` link
//! for every link type the build knows ([`skep_registry::vocabulary`]), so
//! any board answers "what is `3.13` called?" to a guest, and a type a later
//! build adds lands on a board that already exists the same way it lands on
//! a fresh one.
//!
//! **Commits, not Σ₀.** `World::genesis` is unchanged: the seed is ordinary
//! commits above it, written at the open under the write path's own
//! serialization guard before the listener binds, each through
//! [`Commits::commit_recorded`] as the head writer's own are — recorded on
//! the change feed with the system testimony, announced, and giving the head
//! writer no turn — so the registry's rows and links ride the same journal,
//! the same feed and the same checkpoints as every other write.
//!
//! **A reopen writes what is missing.** For each row of the table — the
//! meta-type `3.50` first, then the rest in path order — the seed READS
//! FIRST: a `defines` link (`ty` = `…3.50`, `to` = the row's address in
//! addrs form) whose `from` resolves to a span in the registry document
//! stands → the row stands, and nothing is written. Else
//! the row is WRITTEN: its section and its link. Nothing on a board that
//! holds every type the build knows; the additions on an upgraded board; the
//! rest on a board whose seed a crash or a refusal cut short — and never a
//! second section or link for a type that has one: a section a cut-short
//! seed published and never linked is found again by its exact bytes in the
//! registry document's reading surface and linked where it stands.
//!
//! **How it lands.** The rows that lack a section are written as ONE member:
//! their sections — each four newline-ended lines, the name alone on the
//! first ([`skep_registry::Definition::section`]) — inserted per byte, as
//! prose is, into the staging draft the head writer keeps (`1.1.0.1.0.3`,
//! reused through [`super::head::HeadWriter::ensure_draft`]: the system
//! principal mints no other document, whichever of the two mints it first,
//! and row 40's line is the fence), then one publish shot into `1.1.0.1.0.1`
//! minting the next
//! member of its trunk chain, with `base` the current trunk head (the
//! document itself while memberless) at extent 0, so every position the
//! earlier members hold is carried into the new one after the new sections,
//! by identity (PUB-2.45): the registry's latest member always holds the
//! whole vocabulary, which is what lets a client project any `defines` link's
//! `from` into `1.1.0.1.0.1` and retrieve it there. Then, for every row that
//! lacks a link, in the same order, one `make_link` with `home` =
//! `1.1.0.1.0.1`, `from` = the section's span in the member that holds it
//! (resolve form), `to` = `{addrs: [the type]}` and `ty` = `{addrs: [the
//! defines type]}` — `3.50`'s first, so its own link, typed by itself, stands
//! before any link it types. On a fresh board that is one draft mint, one
//! insert, one publish and one link per row.
//!
//! **What a refusal does.** A driver refusal on any of the seed's commits —
//! the draft's mint, the sections' insert, the member's publish or a row's
//! link — ends the seed for this open: said ONCE on the operator stream as a
//! failure naming the type whose commit the refusal met
//! ([`TypeRefusedLine`]), with the cause as the wire renders a rejection
//! (`head.rs`'s rendering, so the two spell one way), how many types stand
//! and that the rest wait for the next open, which writes them and nothing
//! twice. The board serves on: a refused seed never refuses the open.
//!
//! **The cadence.** The seed's commits carry the system testimony, which the
//! head writer's resume reads as the writer's own and counts toward no head;
//! within the uptime the seed takes them off the writer's look
//! ([`super::head::HeadWriter::mark_own_commits_seen`]) so the first write
//! after the open counts itself alone. The claim's head still lands at the
//! claim's own position, now the seed's commits further on. One resume
//! counts them: where the change feed's region is pending at an open, the
//! head writer counts every record above the last head off the kernel's seq
//! (its card's over-count, early and never late), and a fresh board's seed
//! alone passes the count bound — so the first write after a torn-sidecar
//! reopen of a board with no head writes a head in its turn.

use std::fmt;
#[cfg(any(test, feature = "test-hooks"))]
use std::path::{Path, PathBuf};

#[cfg(any(test, feature = "test-hooks"))]
use parking_lot::Mutex;
use skep_address::{is_prefix, Address, Nat, Span, Tumbler};
use skep_arrangement::{trunk_head, Base, Caller, HasM5, Run, Shot, ShotRun, VPos, VSpec};
use skep_content::{HasContent, Val};
use skep_discovery::{findlinks_ftt_on, FourSet, SlotSpec};
use skep_engine::World;
#[cfg(any(test, feature = "test-hooks"))]
use skep_febe::RejectCode;
use skep_febe::{lower_txn, Op, OpKind, Rejection, SlotArg, Stores};
use skep_kernel::Snapshot;
use skep_links::{enc, Endset, HasLinks};
use skep_namespace::{ghost_home_document, HasM3, SYSTEM_PRINCIPAL};
use skep_registry::{defines_type, vocabulary, Definition};
use skep_util::notice::Class;

use super::head::{Refused, SYSTEM_TESTIMONY};
use super::{write_meta, Commits};
use crate::serial::SerialGuard;

/// What [`Commits::seed_registry`] came to.
///
/// It is the count of the table's rows this open wrote a section and a link
/// for, the count that stood already — a reopen of a seeded board counts
/// every row here and writes nothing — and, where a driver refusal ended the
/// seed, the type whose commit it met: the rows before it stand, and it and
/// the rows after it wait for the next open. `written + stood` is the table's
/// size where nothing was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seeded {
    /// The rows whose section and link this open wrote.
    pub written: usize,
    /// The rows whose link stood already, read first and left alone.
    pub stood: usize,
    /// The type whose commit the driver refused, ending the seed; `None`
    /// where every row stood or was written.
    pub refused: Option<Address>,
}

impl Commits {
    /// Seeds the link-type registry: writes what the registry document lacks.
    ///
    /// It is run at the open, under the caller's serialization guard, after
    /// this card has opened and before anything is served: for each row of
    /// the vocabulary in path order, the row's `defines` link read first and
    /// left standing, else its section and its link written as the system
    /// principal through the head writer's door (the module doc states the
    /// route and the member layout). Answers what it did ([`Seeded`]): a
    /// fresh board writes every row, a reopened board that holds them all
    /// writes none, an upgraded or interrupted one writes the missing rows.
    /// A driver refusal ends the seed for this open, said once, and the
    /// answer names the type; the open goes on.
    pub fn seed_registry(&self, serial: &SerialGuard<'_>) -> Seeded {
        let table = vocabulary();
        let registry = ghost_home_document();
        let defines = defines_type();
        let seed = Seed { wp: self, serial, commits: std::cell::Cell::new(0) };

        // READ FIRST, off one snapshot: which rows stand. The meta-type is
        // taken first and the rest in path order — the order the sections
        // and the links are written in, so `defines`' own link stands before
        // any link it types.
        let snap = self.stores.kernel().snapshot();
        let world = snap.world();
        let mut stood = 0;
        let mut lacking: Vec<&'static Definition> = Vec::new();
        let meta_first = table
            .iter()
            .filter(|d| d.address == *defines)
            .chain(table.iter().filter(|d| d.address != *defines));
        for d in meta_first.filter(|d| !self.hidden_from_the_seed(d)) {
            if definition_stands(&snap, &registry, defines, d) {
                stood += 1;
            } else {
                lacking.push(d);
            }
        }
        if lacking.is_empty() {
            return Seeded { written: 0, stood, refused: None };
        }
        let total = stood + lacking.len();

        // The sections a cut-short seed published and never linked, found by
        // their bytes in the registry document's reading surface, and the
        // rows that need a section written.
        let surface = trunk_head(world.m3(), &registry);
        let surface_text = surface.as_ref().map(|member| content_text(world, member));
        let mut places: Vec<(&'static Definition, Address, u64, u64)> = Vec::new();
        let mut unwritten: Vec<&'static Definition> = Vec::new();
        for d in &lacking {
            let found = match (&surface, &surface_text) {
                (Some(member), Some(text)) => {
                    find_section(text, &d.section()).map(|(start, len)| (member.clone(), start, len))
                }
                _ => None,
            };
            match found {
                Some((member, start, len)) => places.push((d, member, start, len)),
                None => unwritten.push(d),
            }
        }

        // The new member, where any row needs a section: one insert of every
        // such section into the staging draft, one publish shot carrying the
        // earlier members' positions after them.
        let mut written = 0;
        if let Some(&first) = unwritten.first() {
            let standing = stood + written;
            let refused = |act: &'static str, cause: String| {
                self.say_type_refused(first, act, &cause, standing, total)
            };
            let Some(draft) = self.head_writer.ensure_draft(self, serial, &refused) else {
                return seed.cut_short(written, stood, first);
            };
            let mut bytes: Vec<u8> = Vec::new();
            let mut offsets: Vec<(&'static Definition, u64, u64)> = Vec::new();
            for d in &unwritten {
                let section = d.section();
                offsets.push((d, bytes.len() as u64 + 1, section.len() as u64));
                bytes.extend_from_slice(section.as_bytes());
            }
            let values: Vec<Val> = bytes.iter().map(|&b| Val::new([b])).collect();
            let next_ordinal = {
                let snap = self.stores.kernel().snapshot();
                snap.world().m5().content_count(&draft) + Nat::from(1u32)
            };
            let Some(start) = seed.insert(&draft, next_ordinal, values, &refused) else {
                return seed.cut_short(written, stood, first);
            };
            let Ok(run) = Run::new(start, Nat::from(bytes.len())) else {
                // Unreachable — the insert answered a content element start
                // — and named, as the head writer names its own: I11 (c).
                self.say_type_refused(
                    first,
                    "publish",
                    "the sections' run is malformed",
                    standing,
                    total,
                );
                return seed.cut_short(written, stood, first);
            };
            let base_member = {
                let snap = self.stores.kernel().snapshot();
                trunk_head(snap.world().m3(), &registry).unwrap_or_else(|| registry.clone())
            };
            let shot = Shot {
                base: Some(Base { member: base_member, extent: Nat::from(0u32) }),
                draft: Some(draft.clone()),
                runs: vec![ShotRun { origin: draft, run }],
            };
            let Some(member) = seed.publish(registry.clone(), shot, &refused) else {
                return seed.cut_short(written, stood, first);
            };
            // The new member holds the new sections first, from position 1.
            for (d, start, len) in offsets {
                places.push((d, member.clone(), start, len));
            }
        }

        // The links, in path order, each from its section's span in the
        // member that holds it.
        for d in &lacking {
            let Some((_, member, start, len)) = places.iter().find(|(p, ..)| p.address == d.address)
            else {
                continue; // unreachable: every lacking row was placed above
            };
            let standing = stood + written;
            let refused = |act: &'static str, cause: String| {
                self.say_type_refused(d, act, &cause, standing, total)
            };
            let from = SlotArg::Resolve(vec![VSpec {
                source: member.clone(),
                span: content_span(*start, *len),
            }]);
            let to = SlotArg::Addrs(vec![d.address.clone()]);
            let ty = SlotArg::Addrs(vec![defines.clone()]);
            if seed.make_link(&registry, from, to, ty, &refused).is_none() {
                return seed.cut_short(written, stood, d);
            }
            written += 1;
        }
        self.head_writer.mark_own_commits_seen();
        Seeded { written, stood, refused: None }
    }

    /// Says the seed's failure line, once per refusal — a refusal ends the
    /// seed for this open, so once by construction.
    fn say_type_refused(
        &self,
        def: &Definition,
        act: &'static str,
        cause: &str,
        standing: usize,
        total: usize,
    ) {
        self.said.say(Class::Failure, TypeRefusedLine { def, act, cause, standing, total });
    }

    /// Returns whether the test seam hides `def` from this board's seed.
    ///
    /// Always `false` in production, where no seam exists.
    fn hidden_from_the_seed(&self, def: &Definition) -> bool {
        #[cfg(any(test, feature = "test-hooks"))]
        {
            let hidden = HIDDEN.lock();
            hidden.iter().any(|(dir, address)| same_dir(dir, &self.data_dir) && *address == def.address)
        }
        #[cfg(not(any(test, feature = "test-hooks")))]
        {
            let _ = def;
            false
        }
    }

    /// Takes the test seam's refusal for the seed's `nth` commit, if armed.
    ///
    /// Always `None` in production, where no seam exists.
    fn seed_refusal(&self, nth: usize, kind: OpKind) -> Option<Rejection> {
        #[cfg(any(test, feature = "test-hooks"))]
        {
            let mut armed = REFUSALS.lock();
            let at = armed.iter().position(|(dir, n)| same_dir(dir, &self.data_dir) && *n == nth)?;
            armed.remove(at);
            let mut refusal = Rejection::classified(kind, RejectCode::Durability, None);
            refusal.detail = Some(SEED_SEAM_DETAIL.to_string());
            Some(refusal)
        }
        #[cfg(not(any(test, feature = "test-hooks")))]
        {
            let _ = (nth, kind);
            None
        }
    }
}

/// One open's seed in flight: the door, the guard and the commits counted,
/// for the test seam that refuses the n-th.
struct Seed<'a> {
    wp: &'a Commits,
    serial: &'a SerialGuard<'a>,
    /// The seed's own commits attempted so far: the sections' insert, the
    /// member's publish, then a link per row. The staging draft's mint is the
    /// head writer's act ([`super::head::HeadWriter::ensure_draft`]) and is
    /// not counted.
    commits: std::cell::Cell<usize>,
}

impl Seed<'_> {
    /// Answers a seed cut short at `def`'s commit, after its line was said.
    fn cut_short(&self, written: usize, stood: usize, def: &Definition) -> Seeded {
        self.wp.head_writer.mark_own_commits_seen();
        Seeded { written, stood, refused: Some(def.address.clone()) }
    }

    /// The next commit's number, and the seam's refusal for it where armed.
    fn next(&self, kind: OpKind) -> Option<Rejection> {
        let n = self.commits.get() + 1;
        self.commits.set(n);
        self.wp.seed_refusal(n, kind)
    }

    /// The sections' insert into the draft, through the head writer's door.
    fn insert(
        &self,
        draft: &Address,
        ordinal: Nat,
        values: Vec<Val>,
        refused: Refused<'_>,
    ) -> Option<Address> {
        if let Some(refusal) = self.next(OpKind::Insert) {
            return self.refuse(OpKind::Insert, refusal, refused);
        }
        self.wp.head_writer.commit_insert(self.wp, self.serial, draft, ordinal, values, refused)
    }

    /// The member's publish into the registry document, through the door.
    fn publish(&self, doc: Address, shot: Shot, refused: Refused<'_>) -> Option<Address> {
        if let Some(refusal) = self.next(OpKind::Publish) {
            return self.refuse(OpKind::Publish, refusal, refused);
        }
        self.wp.head_writer.commit_publish(self.wp, self.serial, doc, shot, refused)
    }

    /// One `defines` link into the registry document, as the system
    /// principal, through [`super::head::HeadWriter::run_commit`]: the `from`
    /// resolved by M7 inside its transact, the `to` and the `ty` deposited
    /// verbatim.
    fn make_link(
        &self,
        home: &Address,
        from: SlotArg,
        to: SlotArg,
        ty: SlotArg,
        refused: Refused<'_>,
    ) -> Option<Address> {
        if let Some(refusal) = self.next(OpKind::MakeLink) {
            return self.refuse(OpKind::MakeLink, refusal, refused);
        }
        let op = Op::MakeLink { home: home.clone(), from, to, ty, replaces: None };
        let meta = write_meta(&op)?.attributed(SYSTEM_TESTIMONY.to_string(), None);
        let Op::MakeLink { home, from, to, ty, .. } = op else {
            return None;
        };
        // The visibility at the system principal's class (PUB-6.25): the
        // system account owns the registry document, so no incumbent is
        // withheld. The refusal lowered as the front door lowers a
        // `make_link`'s.
        let visibility = World::visible_to(Caller::Principal(SYSTEM_PRINCIPAL));
        let stores = &self.wp.stores;
        self.wp.head_writer.run_commit(self.wp, self.serial, meta, refused, move || {
            stores
                .linkstore(&visibility)
                .makelink(Caller::Principal(SYSTEM_PRINCIPAL), &home, from, to, ty)
                .map_err(|e| lower_txn(OpKind::MakeLink, e))
        })
    }

    /// The seam's refusal, taken the way the driver's would be: said through
    /// `refused` with the op and the cause, nothing committed.
    fn refuse(&self, kind: OpKind, refusal: Rejection, refused: Refused<'_>) -> Option<Address> {
        refused(crate::codec::op_name(kind), super::head::render_cause(&refusal));
        None
    }
}

/// Returns whether `def`'s definition stands: a `defines` link whose `to` is
/// the row's address in addrs form and whose `from` resolves to a span in
/// the registry document.
///
/// The query constrains `to` and `ty` — two slots, so no class scan — and is
/// answered from the link store's coverage index, as a client's is. A type's
/// unit span covers its subtypes' (L10: hierarchy is prefix), so the answer
/// to a type with subtypes carries their links too; each candidate's stored
/// `to` is read back and held equal to the row's own, and its `from` held
/// inside the registry document, so a definition someone wrote elsewhere
/// under the same type names nothing here.
fn definition_stands(
    snap: &Snapshot<World>,
    registry: &Address,
    defines: &Address,
    def: &Definition,
) -> bool {
    let to = enc([&def.address]);
    let ty = enc([defines]);
    let q = FourSet {
        to: SlotSpec::Spans(to.clone()),
        ty: SlotSpec::Spans(ty.clone()),
        ..FourSet::any()
    };
    let world = snap.world();
    findlinks_ftt_on(snap, &q, &|_| true).iter().any(|a| {
        world.links().readlink(a).is_some_and(|link| {
            *link.to_slot() == to && *link.type_slot() == ty && lies_in(link.from_slot(), registry)
        })
    })
}

/// Returns whether every span of `from` lies in `doc`: non-empty, each
/// start under the document's prefix.
fn lies_in(from: &Endset, doc: &Address) -> bool {
    !from.is_empty() && from.spans().all(|s| is_prefix(doc.tumbler(), s.start()))
}

/// Returns `member`'s content as `(position, byte)` pairs, in position order.
///
/// The registry's members hold prose written per byte, so every value is one
/// byte; a value of another width ends the read where it stands, and the
/// text read so far is what the search below sees.
fn content_text(world: &World, member: &Address) -> Vec<(u64, u8)> {
    let count = u64::try_from(&world.m5().content_count(member)).unwrap_or(0);
    let mut out = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for position in 1..=count {
        let at = VPos::content(Nat::from(usize::try_from(position).unwrap_or(usize::MAX)));
        let Some(i_addr) = world.m5().point(member, &at) else { break };
        let Some(value) = world.content().value_at(i_addr.tumbler()) else { break };
        let [byte] = value.as_bytes() else { break };
        out.push((position, *byte));
    }
    out
}

/// Returns where `section` stands in `text`: its first position and its
/// width, or `None`.
///
/// A section begins at the text's start or just after a newline, since
/// every section ends with one, and its positions are consecutive — the one
/// run its insert minted, or its carried copy.
fn find_section(text: &[(u64, u8)], section: &str) -> Option<(u64, u64)> {
    let wanted = section.as_bytes();
    let len = wanted.len();
    if len == 0 || text.len() < len {
        return None;
    }
    (0..=text.len() - len)
        .filter(|&at| at == 0 || text[at - 1].1 == b'\n')
        .find(|&at| {
            text[at..at + len].iter().zip(wanted).all(|((_, b), w)| b == w)
                && text[at..at + len].windows(2).all(|w| w[1].0 == w[0].0 + 1)
        })
        .map(|at| (text[at].0, len as u64))
}

/// Returns the content V-span of `len` positions from `start`: the
/// ordinal-level depth-2 span `[1, start] × [0, len]` a resolve-form slot
/// names.
fn content_span(start: u64, len: u64) -> Span {
    let tumbler = |a: u64, b: u64| {
        Tumbler::new([Nat::from(usize::try_from(a).unwrap_or(usize::MAX)), Nat::from(usize::try_from(b).unwrap_or(usize::MAX))])
            .expect("two components are nonempty")
    };
    Span::new(tumbler(1, start), tumbler(0, len)).expect("a content span of positive width")
}

/// The seed's failure line: a type whose commit the driver refused.
///
/// It is in the operator stream's words: the act refused — the staging
/// draft's `create_new_document`, the sections' `insert`, the member's
/// `publish` or the row's `make_link`, as the wire names the op — the type
/// by its address and its name, the cause as the wire renders a rejection,
/// how many types stand, what waits and what still serves: `link-type
/// registry: the {act} for the type {address} ({name}) was refused ({cause});
/// {standing} of {total} types stand, the rest wait for the next open; the
/// board serves`. A pure value the unit suite pins by `to_string()`; emitted
/// under `Class::Failure`, once per open, since a refusal ends the seed.
struct TypeRefusedLine<'a> {
    def: &'a Definition,
    act: &'static str,
    cause: &'a str,
    standing: usize,
    total: usize,
}

impl fmt::Display for TypeRefusedLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "link-type registry: the {} for the type {} ({}) was refused ({}); {} of {} types \
             stand, the rest wait for the next open; the board serves",
            self.act, self.def.address, self.def.name, self.cause, self.standing, self.total
        )
    }
}

/// The seam's standing detail, for a refusal of a seed commit.
#[cfg(any(test, feature = "test-hooks"))]
const SEED_SEAM_DETAIL: &str = "the test seam's refusal";

/// The test seam: the rows hidden from a board's seed, by data directory.
///
/// Keyed by the board's directory because the seed runs inside the open,
/// before any daemon exists to arm a hook on, and a `cargo test` process
/// opens many boards at once: a row hidden for one directory touches no
/// other board's seed.
#[cfg(any(test, feature = "test-hooks"))]
static HIDDEN: Mutex<Vec<(PathBuf, Address)>> = Mutex::new(Vec::new());

/// The test seam: the seed commits to refuse, by data directory and number.
#[cfg(any(test, feature = "test-hooks"))]
static REFUSALS: Mutex<Vec<(PathBuf, usize)>> = Mutex::new(Vec::new());

/// Whether two spellings name one directory — by their canonical paths
/// where both resolve, else as spelled.
#[cfg(any(test, feature = "test-hooks"))]
fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// TEST HOOK: hides the type at `address` from the seed of the board at
/// `data_dir`, so that board is seeded under the table less that row — the
/// upgrade a later build makes, staged. Stands until
/// [`unhide_every_type_from_the_seed`]. Not a stable API.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub fn hide_a_type_from_the_seed(data_dir: &Path, address: Address) {
    HIDDEN.lock().push((data_dir.to_path_buf(), address));
}

/// TEST HOOK: lifts every row hidden from the seed of the board at
/// `data_dir`, so its next open seeds under the whole table. Not a stable
/// API.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub fn unhide_every_type_from_the_seed(data_dir: &Path) {
    HIDDEN.lock().retain(|(dir, _)| !same_dir(dir, data_dir));
}

/// TEST HOOK: arms one driver refusal of the `nth` commit (from 1) the seed
/// of the board at `data_dir` next attempts of its own — the sections'
/// insert, the member's publish, then a link per row in the seed's order,
/// the meta-type's first; the staging draft's mint ahead of them is the head
/// writer's act and is not numbered — taken the way a real refusal is, so it
/// rides the seed's whole refusal path, and disarmed as it fires. The seam
/// beside the head writer's `refuse_next_head_once`. Not a stable API.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub fn refuse_the_seeds_commit_once(data_dir: &Path, nth: usize) {
    REFUSALS.lock().push((data_dir.to_path_buf(), nth));
}

#[cfg(test)]
mod tests;
