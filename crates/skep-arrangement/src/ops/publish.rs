//! PUBLISH, the shot (PUB-2.33): a published document's next member.
//!
//! The member is born published in one commit from the runs the client
//! supplied. Here too are its admission ([`shot_admission`]), its checks
//! through the source gate, offered to a door as a query — and `SettledRun`,
//! the one value its source gate, existence check and placement each walk;
//! [`PublishWorld`], the bound the shot's staging needs, exported so a
//! composite in another crate names it and nothing beneath it; and
//! [`MintedRun`], the pairing of a piece of a draft-native run with the fresh
//! run it was placed as — minted for it, or minted for an earlier run of the
//! shot and placed by reference — which [`stage_publish`] returns beside the
//! member.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use num_traits::Zero;
use skep_address::{Address, Nat};
use skep_content::{ContentStretch, ContentWrite, HasContent, Piece, Val};
use skep_kernel::{Seq, Staging, TxnError, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State};

use super::{
    allocate_for_placement, allocate_stretch_for_placement, head_lock_key, Vstream,
    MAX_PLACED_RUNS, MAX_REINSERTED_VALUES,
};
use crate::chain::{published_target, trunk_head, trunk_of};
use crate::error::PublishError;
use crate::ownership::{gate_write, Caller};
use crate::run::Run;
use crate::run_list::extend_or_push_run;
use crate::run_union::RunUnion;
use crate::shot::{run_origin_document, Shot};
use crate::state::{M5Rec, ShotTerms};
use crate::HasM5;

/// One part of a draft-native run's re-insert.
///
/// It is copied out of the working slice before the run's first stage: a
/// maximal run of single-byte values — consecutive `Piece::Bytes`, and every
/// one-byte `Piece::Value` among them (the length test: the wire canonicalizes
/// a one-byte atom to its per-byte form, so the member's bytes and positions
/// are unchanged) — or any other value, an atom of two bytes or more or an
/// empty value, its `Val` cloned (a refcount bump). The walk completes into
/// an ordered list of these before anything is staged, because the pieces
/// borrow `stg.working().content()` and every stage takes `&mut Staging` and
/// must read the working slice after each push; bounded by the run's width
/// in bytes plus one `Val` handle per other value, under
/// `MAX_REINSERTED_VALUES`.
enum Part {
    Run(Vec<u8>),
    Atom(Val),
}

/// The world the shot's staging needs: what [`stage_publish`] reads and the
/// records it stages, as one name.
///
/// It stands for `publish`'s own bound — M3 read (the registration, the
/// mints), M4 read (the existence walk, the re-insert's bytes) and M5 read
/// (the base's tail, the member's placement), with the records the staging
/// pushes liftable into the world's own: an M3 mint, a content write or
/// stretch, an M5 placement. Blanket-implemented, so every world meeting it
/// has it — the engine's, and any test world of the three slices. Exported so
/// a composite that stages the shot inside a transaction of its own in
/// another crate (the link store's publication, which mints the shot's
/// correspondence records beside the member — the link-sets design §5.7)
/// names this one bound and takes no edge to the content crate for it.
pub trait PublishWorld:
    WorldState<Record: From<M5Rec> + From<M3Rec> + From<ContentWrite> + From<ContentStretch>>
    + HasM5
    + HasM3
    + HasContent
{
}
impl<W> PublishWorld for W where
    W: WorldState<Record: From<M5Rec> + From<M3Rec> + From<ContentWrite> + From<ContentStretch>>
        + HasM5
        + HasM3
        + HasContent
{
}

/// One piece of a draft-native run the shot placed, beside the fresh run it
/// was placed as, and the `runs` entry it came from.
///
/// `from` is a piece of a draft-native run — a whole run, or the part of one
/// — at the draft's own addresses, and `to` the run of fresh identity it
/// stands as in the member, under the content chain of the document the shot
/// names: the two of one width, so a position of either maps onto the other
/// by its offset (the link-sets design §5.5's "`from` and `to` of one
/// width"). `minted` says how the piece was placed: `true` where this entry
/// re-inserted it, minting `to` for it — the piece the shot met for the first
/// time, which the correspondence record homed in the draft names as its two
/// spans — and `false` where an earlier run of the shot had minted the
/// identity and this entry placed the piece by reference to it, `to` then the
/// same piece of that earlier fresh run (the design's "a later occurrence of a
/// minted identity with the first's fresh run"), which no record names again.
/// `index` is the `runs` entry the piece is a part of, so a re-window of the
/// draft at that entry's kept place finds every piece it places there, the
/// referenced ones with the minted.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MintedRun {
    /// The draft-native piece, at the draft's own addresses.
    pub from: Run,
    /// The fresh run it stands as in the member, at the edition's addresses.
    pub to: Run,
    /// The position in the shot's `runs` of the entry the piece is a part of.
    pub index: usize,
    /// Whether this entry minted `to` for the piece, or placed the piece by
    /// reference to an identity an earlier entry minted.
    pub minted: bool,
}

/// The pairing [`stage_publish`] returns: every piece of every draft-native
/// run the shot placed, in placement order — `runs`' order, each run's pieces
/// in I-order, tiling the run from its start — each beside the fresh run it
/// was placed as, with its `runs` entry and whether the entry minted it.
///
/// A list and not an index into the member's runs, because the placement
/// coalesces: the member holds I-adjacent fresh runs as one run, and a
/// by-reference run beside a fresh one merges with it where they are
/// adjacent, so the member's `k`-th run is not the `k`-th run of the request
/// once any two coalesce, and a caller pairing by index would pair a draft
/// run with a run that holds other identity too (the S-gate's ruling). The
/// entries of one `runs` index are consecutive, in I-order, and their `from`
/// pieces tile that run from its start: the first's `from` opens at the run's
/// start and each next one at the previous one's reach, so a piece's offset
/// into its run is the widths of the entry's pieces before it, summed. Empty
/// for a shot that names no draft or re-inserts nothing.
pub type Pairing = Vec<MintedRun>;

/// How one draft-native run is placed, piece by piece, once the identities
/// the shot already minted are taken out of it.
///
/// EACH DRAFT IDENTITY ONCE PER SHOT (the link-sets design §5.7): a position
/// an earlier run of the shot minted is placed by reference to the fresh run
/// it became; the rest is minted. A run that overlaps an earlier one in part
/// splits into the two kinds, in I-order.
enum Portion {
    /// A piece an earlier run minted: the draft-native piece, and the fresh
    /// run to place by reference for it.
    Referenced { from: Run, to: Run },
    /// A piece no earlier run minted: the draft-native run to re-insert.
    Unminted(Run),
}

/// The draft identities this shot has minted so far, with where each landed.
///
/// Keyed by the content chain the draft identity lies on — every component
/// of its address but the ordinal — and then by the piece's first ordinal:
/// its width and the fresh run's start. The pieces of one chain never
/// overlap, since each was minted for exactly the positions no earlier piece
/// held, so the pieces a run overlaps are contiguous in ordinal order and
/// one range walk finds them: `O(log n)` per run plus its overlaps, `n` the
/// pieces minted so far, bounded by the request's runs.
#[derive(Default)]
struct MintedIdentity {
    chains: BTreeMap<Vec<Nat>, BTreeMap<Nat, (Nat, Address)>>,
}

/// Returns a content address as its chain (every component but the last)
/// and its ordinal — the key [`MintedIdentity`] files a piece under.
fn chain_and_ordinal(a: &Address) -> (Vec<Nat>, Nat) {
    let mut chain: Vec<Nat> = a.tumbler().iter().cloned().collect();
    let ord = chain.pop().expect("a tumbler is nonempty");
    (chain, ord)
}

impl MintedIdentity {
    /// Returns how `run`, a draft-native run, is placed: by reference where
    /// an earlier run of the shot minted the identity, minted elsewhere —
    /// the portions in I-order, which is the order they take in the member.
    fn portions_of(&self, run: &Run) -> Vec<Portion> {
        let (chain, start) = chain_and_ordinal(run.i_start());
        let reach = &start + run.width();
        // The pieces minted on this chain that overlap `[start, reach)`,
        // ascending: those starting below the reach, walked back while they
        // still reach past the start — contiguous, the pieces being disjoint.
        let mut covered: Vec<(Nat, Nat, Address)> = Vec::new(); // (lo, hi, fresh at lo)
        if let Some(pieces) = self.chains.get(&chain) {
            for (first, (width, fresh)) in pieces.range(..reach.clone()).rev() {
                let piece_reach = first + width;
                if piece_reach <= start {
                    break;
                }
                let lo = if *first > start { first.clone() } else { start.clone() };
                let hi = if piece_reach < reach { piece_reach } else { reach.clone() };
                let fresh_at_lo =
                    Run::new(fresh.clone(), width.clone()).expect("a minted piece's fresh run").addr_at(&(&lo - first));
                covered.push((lo, hi, fresh_at_lo));
            }
        }
        covered.reverse();
        let mut portions = Vec::new();
        let mut cursor = start.clone();
        let piece = |lo: &Nat, hi: &Nat| -> Run {
            Run::new(run.addr_at(&(lo - &start)), hi - lo)
                .expect("a nonempty piece of a run starts at a full element position")
        };
        for (lo, hi, fresh_at_lo) in covered {
            if cursor < lo {
                portions.push(Portion::Unminted(piece(&cursor, &lo)));
            }
            portions.push(Portion::Referenced {
                from: piece(&lo, &hi),
                to: Run::new(fresh_at_lo, &hi - &lo).expect("a piece of a fresh run is a run"),
            });
            cursor = hi;
        }
        if cursor < reach {
            portions.push(Portion::Unminted(piece(&cursor, &reach)));
        }
        portions
    }

    /// Notes that `piece`, a draft-native run no earlier run had minted, was
    /// re-inserted as `fresh` — the runs its re-insert allocated, in order,
    /// of the piece's width together — for the `runs` entry at `index`, and
    /// appends the pairing of each.
    fn note(&mut self, piece: &Run, fresh: &[Run], index: usize, pairing: &mut Pairing) {
        let (chain, first) = chain_and_ordinal(piece.i_start());
        let pieces = self.chains.entry(chain).or_default();
        let mut offset = Nat::zero();
        for to in fresh {
            let from = Run::new(piece.addr_at(&offset), to.width().clone())
                .expect("a piece of a draft-native run is a run");
            pieces.insert(&first + &offset, (to.width().clone(), to.i_start().clone()));
            offset = &offset + to.width();
            pairing.push(MintedRun { from, to: to.clone(), index, minted: true });
        }
        debug_assert_eq!(&offset, piece.width(), "the fresh runs are the piece's width together");
    }
}

impl<W> Vstream<'_, W>
where
    W: PublishWorld, // reads M3 (registration, mints) + M4 (writes, and the shot's byte reads) + M5; stages M3Rec + ContentWrite/ContentStretch + M5Rec
{
    /// Appends the next member of `doc`'s chain, born published, in one commit.
    ///
    /// PUBLISH, the shot (PUB-2.33), takes the member's arrangement from the
    /// client-supplied runs of `shot` (PUB-8.1) and from nothing any draft
    /// holds at commit. Returns the member's address and the commit `Seq`.
    /// The birth version (PUB-2.34) is minted by this same composite — in the
    /// birth shape, `shot.base` absent, or off the memberless document named
    /// as its own base (the destination, below).
    ///
    /// **Destination** (PUB-2.37, PUB-2.39, PUB-2.55): the next member of the
    /// chain anchored at the base, decided at commit — the trunk's next member
    /// (`mint_version(trunk_of(doc))`, `D.4`) when the base is still the trunk
    /// head ([`trunk_head`], the head every floating reader answers from, read
    /// before the member is minted), the base's own daughter
    /// (`mint_version(base)`, `D.3.1`) when it is not. Two shots racing off
    /// one head both commit, the first on the trunk and the second as the
    /// head's daughter (PUB-2.44); nothing is positionally applied to an
    /// advanced head and nothing is refused for want of a base (PUB-2.38). A
    /// memberless document is its own base, and the base absent is the birth
    /// shape (PUB-2.34); either way the shot mints the birth version, the
    /// chain's first member `D.1`, and either form is admitted only while the
    /// chain is empty — once a member exists the document's own pre-chain
    /// arrangement is no base, and the shot must name the member it was staged
    /// from (`BaseSuperseded`). The two are one destination and not one
    /// arrangement: with no base there is no extent and so no carried tail,
    /// and a deposit that landed in the memberless document after the render
    /// stays in the pre-chain arrangement the member supersedes. A client
    /// wanting the deposit cell honored at birth names the document itself as
    /// its base, with the extent its render took.
    ///
    /// **The member's arrangement** (PUB-2.40, PUB-2.41, PUB-2.42): each
    /// supplied run by its origin document — the trunk (PUB-2.15) of the
    /// document that minted its addresses, which the run's own start settles
    /// (`document_of` then `trunk_of`) and the client's stated `origin` must
    /// project to. The document's own I-space (its own content chain or any
    /// member's) is placed by reference; the staging draft's is re-inserted as
    /// fresh identity under the document's own I-space, each maximal run of
    /// single-byte values as one stretch and each atom as its own value
    /// through INSERT's own allocation steps (`allocate_stretch_for_placement`,
    /// `allocate_for_placement`), the bytes read at the draft's addresses by
    /// M4's run read — a byte read, never an arrangement read — so the
    /// committed member references no address of the draft; any other
    /// document's stays a window, answering its origin. The three families are
    /// disjoint under [`Shot`]'s precondition on `draft`; a draft inside
    /// `doc`'s chain moves the document's own runs into the draft's family, as
    /// `Shot` states. The runs are placed in the order given, then the base's
    /// post-render deposits after them: a published member changes only by
    /// exempt deposits appended at fresh positions (PUB-2.43 — the
    /// append-only edition these operations keep, as [`Vstream`] states), so
    /// its positions past `base.extent` — the extent the staged copy took,
    /// which the client states and M5 refutes only when it exceeds the base's
    /// count ([`Base`](crate::Base) states the obligation) — are exactly the
    /// deposits the render post-dates, asked of the base's arrangement, which
    /// knows its own extent, and carried unchanged (PUB-2.45, PUB-2.67). What
    /// the shot un-arranges is what the stager un-arranged and nothing else.
    /// One [`M5Rec::ShotPlace`] journals the whole arrangement at ordinal 1 —
    /// the fold appends every placed run's I-extent to R (J1★), the
    /// by-reference runs as COPY's are and the fresh ones as INSERT's — and
    /// the shot's terms ([`ShotTerms`]; signed-ops D25): where the client's
    /// runs end — Σ width of its runs, the boundary the run-list erases
    /// whenever the last of them and the carried tail are I-adjacent — and the
    /// base's extent, absent in the birth shape. The record is pushed for
    /// every member the shot mints, an empty placement included, since the
    /// terms exist whatever the placement holds; an empty one leaves the
    /// member reading as the lazy empty arrangement — and a birth version so
    /// minted with its birth extent noted at zero. The member's link subspace
    /// starts empty either way: the shot places content alone, and a link
    /// seated in the base stays the base's — a link is arranged only in its
    /// home document (CL-OWN, PUB-2.12), and the member is a home no link has
    /// yet. A later link write may name the member as its `home`, and then
    /// seats its link in the member's own link subspace, as in any document's
    /// (CL-OWN).
    ///
    /// **Where the fresh identity lands** (PUB-2.40), stated because a reader
    /// the ack does not tell reads it back. The values
    /// [`Shot::reinserted_runs`](crate::Shot::reinserted_runs) names —
    /// [`Shot::reinserted_values`](crate::Shot::reinserted_values) of them,
    /// EACH DRAFT IDENTITY ONCE PER SHOT (the link-sets design §5.7): in
    /// `runs`' order the shot mints a draft-native position the first time it
    /// meets it and places every later occurrence of it, whole or in part, by
    /// reference to the fresh identity it minted, a run overlapping an
    /// earlier one in part splitting into a referenced piece and a minted
    /// piece — are minted in that order, one after another, under the
    /// content chain of the document `doc` projects to (the member's own
    /// trunk), and the commit mints nothing else under that content chain:
    /// the member itself is minted on a version chain, and the
    /// correspondence records a composite stages beside the shot are link
    /// mints in the draft. Each content mint takes the content chain's next
    /// ordinal (`M3State::mint_content`, `M3State::mint_content_range`), the
    /// fact INSERT's one run rests on too, so in the world the commit leaves
    /// they are that content chain's last `reinserted_values()` addresses,
    /// just below its frontier (`M3State::next_content_address`) — where
    /// skep-media's cell index reads them, off the commit's own world, to
    /// enter any reference cell among them. A later content mint under that
    /// content chain moves its frontier past them. So one draft identity has
    /// one fresh identity in the member, and words the draft holds as one
    /// text stay one text in the edition; the signed body is unchanged, a
    /// value stretch being spelled by its values however its positions were
    /// placed. Which draft piece became which fresh run — minted for it, or
    /// placed by reference to the first's — is [`stage_publish`]'s to return
    /// ([`Pairing`]).
    /// `the_values_a_shot_says_it_reinserts_are_the_values_its_commit_writes`
    /// pins the order, the content chain, the once-per-identity rule and the
    /// "nothing else", and
    /// `a_shot_judges_every_address_it_names_as_the_document_it_projects_to`
    /// the content chain of a shot a member names.
    ///
    /// `readable(world, origin_doc)` answers whether the shooter may read
    /// `origin_doc`; `true` admits it. M5 hands it the transaction's working
    /// world — the world in which `publish` has just found `origin_doc`
    /// registered — and asks only about an origin document (PUB-2.15): once
    /// per distinct origin document, in run order, skipping the document's
    /// own and every run the base already arranges. Because it is never asked
    /// of a world that has not registered what it is asked about, a predicate
    /// that is fail-open on an unregistered address (PUB-7.5), and that reads
    /// the world it is handed, cannot decide the gate.
    ///
    /// **Precondition** on `readable`, two clauses the composite cannot check.
    /// First, it answers off the world it is handed, as a function of that
    /// world and the origin document it is asked about — the same pair always
    /// answered alike. The guarantee above holds only for a predicate that
    /// reads that world: one that answers from a world captured before this
    /// transaction — an M2 snapshot, or a consult that ignores its argument —
    /// may be asked about an origin its world never registered, where a
    /// fail-open predicate admits it. And [`shot_admission`]'s one answer
    /// holds only for a predicate that answers each pair alike. Second, it
    /// runs inside this op's transaction, under M2's applier lock, so it
    /// inherits `transact`'s precondition: it must not call `transact` on this
    /// kernel (see Panics, below), and every other writer waits while it
    /// answers.
    ///
    /// **Locks.** The chain's head key (`head_lock_key(doc)`, the trunk's
    /// `version_lock_key`), `content_lock_key(trunk_of(doc))` (the
    /// fresh-identity mints), and the base's own version key when the base is
    /// a member — the daughter chain's frontier, taken since which chain the
    /// member joins is decided inside. Every origin is read off the
    /// transaction's working world; no origin is locked (a window is a
    /// reference).
    ///
    /// A member address given as `doc` is gated as named — its registration
    /// and ω — and then projected to its document (PUB-2.15): the shot is
    /// the document's, whichever member names it, and its publication, chain
    /// and base are judged on that document.
    ///
    /// **The body is [`stage_publish`]**, the closure this method opens its
    /// transaction for: a caller composing the shot with other stagings under
    /// one transaction calls it over a staging of its own, under the union of
    /// the keys, and fills the signature slot itself.
    ///
    /// `shot` is borrowed, as [`shot_admission`] borrows it: the composite
    /// reads the request — its admission, the re-insert's count, the
    /// existence walk — and clones each by-reference run into the member's
    /// placement, so taking it whole would cost a caller that keeps its
    /// request (to report it, or to ask its address form after the commit) a
    /// clone of every run, for nothing the composite moves.
    ///
    /// **Cost, and who owns it.** The re-insert pushes a mint and a content
    /// record per maximal run of single-byte values and per atom of each
    /// draft-native run — two records per run or atom, INSERT's own steps, so
    /// an unscattered draft of `n` typed bytes is two records and a draft of
    /// `n` atoms `2n` — and `n`, the values, is capped at
    /// [`MAX_REINSERTED_VALUES`], counted off the request before any address
    /// is probed. Beside them sit the member's mint and one placement, whose
    /// run count (the client's runs, coalesced, plus the base's deposit runs)
    /// is capped at [`MAX_PLACED_RUNS`], measured as each run is accumulated.
    /// Both are ceilings a shot cannot be split to meet, since the member it
    /// produces is born whole. Two terms are set by stored state rather than
    /// by the request's size. The carried-run test merges the base's runs into
    /// their union once per admission — `O(n log n)` in
    /// [`content_run_count`](crate::M5State::content_run_count) of the base,
    /// and pointers alone, one per run to sort them and room for two per run
    /// once built — and answers each supplied run by one binary search of it,
    /// whatever the run's width. The existence check
    /// probes every distinct address the supplied runs name, once — their
    /// I-extents merged first — stopping at the first one M4 does not hold.
    /// Over the draft-native runs that walk is bounded by the re-insert's cap;
    /// over the by-reference runs it is the union they name — for a shot that
    /// commits, every distinct position — which is the stored content the
    /// request points at and not its repetition of it: a run list naming one
    /// I-extent many times walks it once, and a short run list still walks as
    /// far as the stored content it names. The wire caps the run count and not
    /// that union. Those two — the base's run count, which the arrangement
    /// answers without reading a run, and the size of the union the
    /// by-reference runs name — are the numbers a route that carries this op
    /// owes.
    ///
    /// # Errors
    ///
    /// Each refusal comes as `TxnError::Rejected`, in this order (which error
    /// wins), PUB-6.36's slots: `DocNotRegistered` → `NotOwner` (slot 1, ω on
    /// the address named — a question [`Caller::System`] passes) →
    /// registration (slot 3): `SourceNotRegistered` for the base, then the
    /// document the draft projects to (PUB-2.15) — and, right after the
    /// draft's registration, THE UNOWNED-DRAFT EDGE (the link-sets design
    /// §5.7): whenever `draft` is named the caller must own the document it
    /// projects to, else `NotOwner` carrying that document, ahead of every
    /// readability question, so ω speaks and readability never does — a
    /// readable draft of a sub-account's or a grantor's is refused here too,
    /// the shot's records being homed in the draft — then each run's origin
    /// document in run order,
    /// each run's shape (`BadRun`) settled as its origin document is derived →
    /// `PrivateSourceVersionless` (slot 5: a private document has no chain,
    /// PUB-2.9's `true` face) → the base's shape: `BaseNotInChain` →
    /// `BaseSuperseded` → `BaseExtentTooLarge` → the source gate (slot 6,
    /// PUB-6.23; PUB-8.1's second constraint): `readable` consulted per
    /// distinct origin document, in run order, skipping the document's own
    /// I-space and every run the base already arranges (PUB-6.24's carried
    /// cell), the first unreadable origin document answering `Withheld` with
    /// it — before any existence answer, so a run onto an unreadable origin
    /// is refused whether or not its addresses exist; every verdict to here is
    /// [`shot_admission`]'s, which this composite opens with on its working
    /// world → `TooManyValues`
    /// ([`Shot::reinserted_values`](crate::Shot::reinserted_values) against
    /// [`MAX_REINSERTED_VALUES`] — request arithmetic, so it answers before
    /// any address is probed) → existence, `DanglingSource` where an address
    /// some run names holds no value, each run of the union of the runs'
    /// I-extents read once by M4's run read → then the placement, run by run
    /// in the order given: a draft-native run's maximal byte-runs and atoms
    /// `Mint` → `Content` apiece, and after each run `TooManyRuns` once the
    /// accumulator passes the budget; then `TooManyRuns` as the base's tail is
    /// carried; last the member's own `Mint`. The mints and writes are
    /// defensive (M3's frontier gate, M4's write-once guard), so on a correct
    /// store no honest request sees them contend with `TooManyRuns`. The
    /// kernel's own failures — `OverBudget`, `Unencodable`, `Durability`,
    /// `Poisoned` — come back as `transact_attested` returns them.
    ///
    /// # Panics
    ///
    /// Panics where `readable` calls `transact` on this kernel: M2 answers
    /// that nested write with its reentrancy panic, the caller's bug.
    pub fn publish(
        &self,
        caller: Caller,
        doc: &Address,
        shot: &Shot,
        readable: &dyn Fn(&W, &Address) -> bool,
    ) -> Result<(Address, Seq), TxnError<PublishError>> {
        let trunk = trunk_of(doc);
        let mut keys = vec![head_lock_key(doc), M3State::content_lock_key(&trunk)];
        if let Some(base) = &shot.base {
            if base.member != trunk {
                keys.push(M3State::version_lock_key(&base.member));
            }
        }
        // The attested arm (signed ops): `transact` itself where this handle
        // carries no attestation, else the same commit with its marker's
        // signature slot filled. The body is `stage_publish`, which this
        // method opens the transaction for; the pairing it returns beside the
        // member is a composite's input, not this op's answer.
        self.kernel.transact_attested(&keys, self.attest, |stg| {
            stage_publish(stg, caller, doc, shot, readable).map(|(member, _pairing)| member)
        })
    }
}

/// Stages `publish`'s body into the caller's transaction.
///
/// It is [`Vstream::publish`]'s closure as a function over a caller-opened
/// [`Staging`]: the shot's admission, the re-insert's count, the existence
/// walk, the placement — the draft-native runs re-inserted as fresh identity,
/// each draft identity once, the base's tail carried — the member's mint and
/// its one [`M5Rec::ShotPlace`], every check in the order `publish` states,
/// every refusal and every record pushed `publish`'s own. Returns the
/// member's address and THE PAIRING ([`Pairing`]): every piece of every
/// draft-native run the shot placed, in placement order, beside the fresh
/// run it stands as in the member, with its `runs` entry and whether that
/// entry minted it — the minted pieces, each the correspondence a composite
/// records in the draft, one record per minted piece (the link-sets design
/// §5.5, §5.7), and the pieces placed by reference to an identity an earlier
/// entry minted, paired with the same piece of that fresh run and recorded
/// by no second record; both what a re-window of the draft at a run's kept
/// place places there, piece by piece at each piece's offset. A list,
/// because the member's runs coalesce and an index into them pairs nothing
/// once two have; empty where the shot names no draft or re-inserts nothing.
/// The commit's `Seq` is the transaction's to report. Offered so a caller can
/// compose the shot with other stagings under ONE transaction, which the
/// public ops cannot, each opening a transaction of its own and the kernel
/// refusing a nested one: the link-sets design's one commit, the member
/// minted with its correspondence records and the draft re-windowed at its
/// kept places — "a `reinstate` of the fresh I-run at the run's place and a
/// `delete` of the draft-native run, staged in the same commit and applied
/// in turn so positions stay true"
/// ([`stage_reinstate_at`](crate::stage_reinstate_at),
/// [`stage_delete_at`](crate::stage_delete_at)) — a transaction that "either
/// stands whole or not at all" (the link-sets design, §5.7). Its bound is
/// [`PublishWorld`], so such a caller names one trait.
///
/// It reads the transaction's working world, `stg.working()` — the admission
/// and the base's tail off its registry and arrangement slices, the existence
/// walk and the re-insert's bytes off its content slice, each mint off the
/// frontier the records staged so far left — so what an earlier staging of
/// the same transaction pushed is seen here, and what this pushes is seen by
/// the next. It opens no transaction and takes no lock: the kernel's lock
/// keys are the caller's, `publish`'s own being the chain's head key
/// ([`head_lock_key`]`(doc)`), `content_lock_key` of the document `doc`
/// projects to, and the base's own `version_lock_key` where the base is a
/// member and not that document — a caller composing several stagings under
/// one transaction supplies the union of their keys. It carries no
/// attestation either: the signature slot is the transaction's, filled by
/// the caller's `transact_attested` as `publish` fills it under the handle's
/// arm.
///
/// # Errors
///
/// `publish`'s refusals, in the order it states — `DocNotRegistered` through
/// the member's own `Mint` — as the bare `PublishError` the caller's
/// transaction answers as `TxnError::Rejected`; an `Err` commits nothing of
/// that transaction, the records this staged and every other staging's alike.
///
/// # Panics
///
/// As `publish`: where `readable` calls `transact` on the caller's kernel.
pub fn stage_publish<W: PublishWorld>(
    stg: &mut Staging<W>,
    caller: Caller,
    doc: &Address,
    shot: &Shot,
    readable: &dyn Fn(&W, &Address) -> bool,
) -> Result<(Address, Pairing), PublishError> {
    let trunk = trunk_of(doc);
    // The values the shot re-inserts: request arithmetic, reading no world —
    // `Shot::reinserted_values`, the count's one spelling, which a caller
    // pricing the shot ahead of this op asks too. Refused at its own slot,
    // below.
    let reinserted = shot.reinserted_values();
    // Slots 1 through 6 — the shot's admission, asked of this transaction's
    // working world: its verdicts are `shot_admission`'s, and what the rest
    // of the composite needs of it is the anchor the member is minted under
    // and the runs settled beside their origin documents.
    let Admission { anchor, supplied } = admit(stg.working(), caller, doc, shot, readable)?;
    // Which runs are the staging draft's, re-inserted as fresh
    // identity rather than placed by reference (PUB-2.40) — the
    // family rule `Shot` states, by which `Shot::reinserted_runs`
    // names the runs this placement re-inserts: both compare the
    // run's origin document with `Shot::draft_document`, and
    // `the_values_a_shot_says_it_reinserts_are_the_values_its_commit_writes`
    // holds them to one answer, value for value and in the order they
    // land.
    let draft_doc = shot.draft_document();
    let draft_native = |origin_doc: &Address| draft_doc.as_ref() == Some(origin_doc);
    // The re-insert's size, refused before any address is probed:
    // every address of every draft-native run is re-inserted below,
    // two staged records per maximal byte-run or atom — two per value
    // at the worst case, every value an atom — and nothing M2 measures
    // stops the staging before it is whole. Request arithmetic
    // (`reinserted`, counted above before any address is probed), so it
    // discloses nothing — and refused here, it bounds the existence
    // walk over those runs too.
    if reinserted > Nat::from(MAX_REINSERTED_VALUES) {
        return Err(PublishError::TooManyValues);
    }
    // Existence (S3★): every address a run names holds a value. Each
    // address is asked, not only the start: a by-reference run is the
    // client's I-extent rather than one an arrangement resolved. Each
    // is asked once, over the union of the supplied runs' I-extents
    // (`RunUnion`), which holds every address any run names, each in
    // one of its runs: a value found there is found for every run
    // naming it, and a request naming one stored extent many times
    // walks it once. And each is asked through `pieces`, M4's run
    // read — one predecessor lookup per run of the union, then a walk
    // piece by piece, `covered` saying whether every address answered
    // — the accessor the re-insert below reads the draft-native bytes
    // with. COPY places by reference and reads no value back, so
    // presence is the whole of its question; the shot does read them,
    // and asking with the read's own accessor makes the answer found
    // here the answer the re-insert gets — M4's fold only ever adds
    // (S0), so no write staged in between can take a value away.
    let content = stg.working().content();
    for run in RunUnion::of(supplied.iter().map(|settled| settled.run)).runs() {
        if !content.pieces(run.i_start().tumbler(), run.width()).covered() {
            return Err(PublishError::DanglingSource);
        }
    }
    // The shot's first term (signed-ops D25), `placed`: the positions
    // the client placed — Σ width of its runs, whatever family each
    // is — read off the request before the placement below erases
    // the boundary between the last of them and the carried tail,
    // which `placed` never counts.
    let placed = supplied.iter().map(|settled| settled.run.width()).sum::<Nat>();
    // The member's placement: the client's runs in order — the
    // draft-native ones re-inserted as fresh identity under the
    // document's own I-space, each draft identity once — then the base's
    // post-render deposits.
    let mut placement: Vec<Run> = Vec::new();
    let mut minted = MintedIdentity::default();
    let mut pairing: Pairing = Vec::new();
    for (index, SettledRun { run, origin_doc }) in supplied.into_iter().enumerate() {
        if draft_native(&origin_doc) {
            // EACH DRAFT IDENTITY ONCE PER SHOT: the run split by the
            // identities this shot already minted, each referenced piece
            // placed as the fresh run it became — and paired with it, under
            // this entry's index, as a piece the entry did not mint — and
            // each unminted piece re-inserted, then noted with the fresh
            // runs it became — one pairing entry per fresh run, which is one
            // per piece on the frontier allocator M3 has.
            for portion in minted.portions_of(run) {
                match portion {
                    Portion::Referenced { from, to } => {
                        extend_or_push_run(&mut placement, to.clone());
                        pairing.push(MintedRun { from, to, index, minted: false });
                    }
                    Portion::Unminted(piece) => {
                        let fresh = reinsert(stg, &trunk, &piece)?;
                        minted.note(&piece, &fresh, index, &mut pairing);
                        for run in fresh {
                            extend_or_push_run(&mut placement, run);
                        }
                    }
                }
            }
        } else {
            extend_or_push_run(&mut placement, run.clone());
        }
        if placement.len() > MAX_PLACED_RUNS {
            return Err(PublishError::TooManyRuns);
        }
    }
    // The base's positions past the extent its staged copy took are
    // the deposits the render post-dates (PUB-2.43, PUB-2.45) — asked
    // of the arrangement, which knows its own extent, and measured as
    // each is accumulated, the walk stopping at the cap.
    if let Some(base) = &shot.base {
        for run in stg.working().m5().content_runs_past(&base.member, &base.extent) {
            extend_or_push_run(&mut placement, run);
            if placement.len() > MAX_PLACED_RUNS {
                return Err(PublishError::TooManyRuns);
            }
        }
    }
    // The member: born published (PUB-2.5, PUB-2.10), under the
    // anchor its admission decided.
    let (member, m3rec) = stg.working().m3().mint_version(&anchor, true)?;
    stg.push(m3rec.into());
    // Its placing record, pushed whatever the placement holds: the
    // whole arrangement and the shot's terms, the base's extent absent
    // in the birth shape (signed-ops D25).
    stg.push(
        M5Rec::ShotPlace {
            doc: member.clone(),
            runs: placement,
            terms: ShotTerms {
                placed,
                base_extent: shot.base.as_ref().map(|base| base.extent.clone()),
            },
        }
        .into(),
    );
    Ok((member, pairing))
}

/// Re-inserts one unminted piece of a draft-native run as fresh identity
/// under `trunk`'s content chain, and returns the fresh runs it became.
///
/// The walk completes before the first stage ([`Part`]): the piece's
/// values, read by M4's run read off the working slice, are copied into an
/// owned, ordered list — every `Bytes` piece and every one-byte `Value`
/// extending the pending byte-run, every other `Value` (an atom of two bytes
/// or more, or an empty one) closing it and taking its `Val` by clone —
/// `covered` is asked, the borrow of the working slice ends, and only then
/// is each part staged in the list's order: a maximal byte-run as one
/// stretch under the trunk's chain, each other value as its own mint and
/// write. So a draft typed in bursts and published unscattered is one
/// stretch in the member, and one whose edits scattered its arrangement
/// into K runs costs K. The fresh runs come back as the two allocation
/// steps accumulated them — one run, the addresses being I-adjacent under
/// one frontier — of the piece's width together.
///
/// # Errors
///
/// `Mint` where a content mint is refused, `Content` where a write is — the
/// two steps' own, in their order.
///
/// # Panics
///
/// Panics where the piece's addresses are not all held by M4, which the
/// existence walk ahead of every re-insert rules out and M4's add-only fold
/// keeps ruled out.
fn reinsert<W: PublishWorld>(
    stg: &mut Staging<W>,
    trunk: &Address,
    piece: &Run,
) -> Result<Vec<Run>, PublishError> {
    let parts = {
        let content = stg.working().content();
        let mut pieces = content.pieces(piece.i_start().tumbler(), piece.width());
        let mut parts: Vec<Part> = Vec::new();
        let mut pending: Vec<u8> = Vec::new();
        for value in pieces.by_ref() {
            match value {
                Piece::Bytes(bytes) => pending.extend_from_slice(bytes),
                // The length test: a one-byte value is a per-byte value,
                // and joins the run.
                Piece::Value(v) if v.len() == 1 => {
                    pending.extend_from_slice(v.as_bytes());
                }
                Piece::Value(v) => {
                    if !pending.is_empty() {
                        parts.push(Part::Run(std::mem::take(&mut pending)));
                    }
                    parts.push(Part::Atom(v.clone()));
                }
            }
        }
        assert!(
            pieces.covered(),
            "the existence check found a value at every address of every run, and M4's fold only adds"
        );
        if !pending.is_empty() {
            parts.push(Part::Run(pending));
        }
        parts
    };
    let mut fresh: Vec<Run> = Vec::new();
    for part in parts {
        match part {
            Part::Run(bytes) => allocate_stretch_for_placement::<_, PublishError>(
                stg,
                trunk,
                Arc::from(bytes),
                &mut fresh,
            )?,
            Part::Atom(value) => {
                allocate_for_placement::<_, PublishError>(stg, trunk, value, &mut fresh)?;
            }
        }
    }
    Ok(fresh)
}

/// Returns the shot's admission: `publish`'s checks through its source gate.
///
/// They are the checks [`Vstream::publish`] makes through its source gate,
/// before it probes an address, stages a record or mints: registration and ω
/// of the address named, the registration and shape of every argument, the
/// document's publication, the base's shape, and the source gate — PUB-6.36's
/// slots 1 through 6, in the order `publish` states — asked of `world` and
/// nothing else. `Ok` is a shot `publish` carries past its source gate in
/// `world`; whatever it answers after that — `TooManyValues` onward — is the
/// composite's alone.
///
/// **One answer, not two**: `publish` opens with this check on its working
/// world, so a door asking it of the world the transaction will open on,
/// with the predicate `publish` will be handed, is told what `publish` will
/// answer through its gate, with nothing simulated or staged to learn it.
/// `readable` is asked as `publish` asks it — once per distinct origin
/// document, in run order, of `world` — and is held to the first clause of
/// `publish`'s precondition on it: a function of the world it is handed and
/// the origin it is asked about. The one answer rests on that premise, which
/// nothing here can check: a predicate that answers one pair two ways — off a
/// budget, a clock or a count of its calls — can tell this query one thing
/// and `publish` another.
///
/// **Cost**: `publish`'s own through its gate — the carried-run test (the
/// base's runs merged into their union once, each supplied run one search of
/// it), one consult per distinct origin document — and nothing of the
/// existence walk or the placement. It reads no content store, so a world of
/// M3 and M5 alone answers it.
///
/// # Errors
///
/// `Err` is the refusal `publish` answers there, and only a verdict of those
/// slots: `DocNotRegistered`, `NotOwner`, `SourceNotRegistered`, `BadRun`,
/// `PrivateSourceVersionless`, `BaseNotInChain`, `BaseSuperseded`,
/// `BaseExtentTooLarge`, `Withheld` — the first in the order `publish`
/// states.
pub fn shot_admission<W: HasM3 + HasM5>(
    world: &W,
    caller: Caller,
    doc: &Address,
    shot: &Shot,
    readable: &dyn Fn(&W, &Address) -> bool,
) -> Result<(), PublishError> {
    admit(world, caller, doc, shot, readable).map(|_| ())
}

/// Runs `publish`'s checks through its source gate, asked of `world` alone.
///
/// They are PUB-6.36's slots 1 to 6, in the order `publish` states:
/// [`shot_admission`]'s verdict, with what the rest of the composite needs of
/// it.
///
/// # Errors
///
/// Returns [`shot_admission`]'s refusal, the first in the order `publish`
/// states.
fn admit<'s, W: HasM3 + HasM5>(
    world: &W,
    caller: Caller,
    doc: &Address,
    shot: &'s Shot,
    readable: &dyn Fn(&W, &Address) -> bool,
) -> Result<Admission<'s>, PublishError> {
    let trunk = trunk_of(doc);
    // Slot 1: registration and ω, on the address named.
    gate_write(
        world.m3(),
        caller,
        doc,
        PublishError::DocNotRegistered,
        PublishError::NotOwner,
    )?;
    let (m3, m5) = (world.m3(), world.m5());
    // Slot 3: registration — the base, the document the draft projects to,
    // every origin document (PUB-6.37: an unregistered argument answers
    // registration and nothing later).
    if let Some(base) = &shot.base {
        if !m3.is_registered_document(&base.member) {
            return Err(PublishError::SourceNotRegistered);
        }
    }
    if let Some(draft_doc) = shot.draft_document() {
        if !m3.is_registered_document(&draft_doc) {
            return Err(PublishError::SourceNotRegistered);
        }
        // THE UNOWNED-DRAFT EDGE (the link-sets design §5.7): whenever a
        // draft is named the caller owns it — ω exact, the predicate slot 1
        // asks of `doc` — asked right after the draft's registration and
        // ahead of every readability question, so ω speaks and readability
        // never does; a draft-native run present or not, the shot's records
        // being homed in the draft. `System` passes, as it passes slot 1.
        if !caller.is_owner(m3, &draft_doc) {
            return Err(PublishError::NotOwner(draft_doc));
        }
    }
    // Each run settled beside its origin document (`SettledRun`): derived
    // from the run's own start, required to be the document the client's
    // stated `origin` projects to, then registered — the first defective run
    // in order deciding.
    let supplied: Vec<SettledRun<'s>> = shot
        .runs
        .iter()
        .map(|stated| -> Result<SettledRun<'s>, PublishError> {
            let origin_doc = run_origin_document(&stated.run).ok_or(PublishError::BadRun)?;
            if origin_doc != trunk_of(&stated.origin) {
                return Err(PublishError::BadRun);
            }
            if !m3.is_registered_document(&origin_doc) {
                return Err(PublishError::SourceNotRegistered);
            }
            Ok(SettledRun {
                run: &stated.run,
                origin_doc,
            })
        })
        .collect::<Result<_, _>>()?;
    // Slot 5: the model's refusal — a private document has no chain to
    // append to (PUB-2.9).
    if !published_target(m3, doc) {
        return Err(PublishError::PrivateSourceVersionless);
    }
    // The base's shape, and the anchor the member is minted under — judged
    // against the head every floating reader answers from, read before the
    // member is minted.
    let head = trunk_head(m3, doc);
    let anchor = match &shot.base {
        None => {
            if head.is_some() {
                return Err(PublishError::BaseSuperseded);
            }
            trunk.clone()
        }
        Some(base) => {
            if base.member == trunk {
                if head.is_some() {
                    return Err(PublishError::BaseSuperseded);
                }
            } else if trunk_of(&base.member) != trunk {
                return Err(PublishError::BaseNotInChain);
            }
            if base.extent > m5.content_count(&base.member) {
                return Err(PublishError::BaseExtentTooLarge);
            }
            // The head/pinned distinction is the commit's own (PUB-2.39's
            // head/older): the memberless document, or a base that is still
            // the head ⇒ the trunk's next member; else the base's daughter.
            if base.member == trunk || head.as_ref() == Some(&base.member) {
                trunk.clone()
            } else {
                base.member.clone()
            }
        }
    };
    // Slot 6: the source gate, per distinct origin document, in run order —
    // the document's own I-space needs no consult, a run the base already
    // arranges takes none (PUB-6.24), and the first unreadable origin
    // document speaks before any existence answer. An origin document joins
    // `admitted` only once the consult admits it: a carried run adds nothing
    // to it, so a later run from the same origin that the base does not
    // arrange is still asked about. The base's runs are merged into their
    // union once, at the first run the gate must ask about, and every run is
    // then one search of it: a carried run admits no origin, so a request of
    // carried runs asks this of every one.
    let mut base_union: Option<RunUnion<'_>> = None;
    let mut admitted: BTreeSet<&Address> = BTreeSet::new();
    for SettledRun { run, origin_doc } in &supplied {
        if *origin_doc == trunk || admitted.contains(origin_doc) {
            continue;
        }
        let carried = shot.base.as_ref().is_some_and(|base| {
            base_union
                .get_or_insert_with(|| RunUnion::of(m5.content_runs(&base.member)))
                .covers(run)
        });
        if carried {
            continue;
        }
        if !readable(world, origin_doc) {
            return Err(PublishError::Withheld(origin_doc.clone()));
        }
        admitted.insert(origin_doc);
    }
    Ok(Admission { anchor, supplied })
}

/// What the shot's admission ([`admit`]) hands the rest of the composite.
///
/// It is the anchor its member is minted under — decided with the base's
/// shape — and the runs settled beside their origin documents.
struct Admission<'s> {
    anchor: Address,
    supplied: Vec<SettledRun<'s>>,
}

/// A supplied run beside the origin document its own start settles.
///
/// The document is [`run_origin_document`]'s, checked against the client's
/// stated `origin` and found registered: the one value the shot's source
/// gate, existence check and placement each walk, so every question about a
/// run is asked of that run's own origin document and no second list has to
/// stay in step with the runs for the gate to judge the run it is looking at.
/// [`ShotRun`](crate::ShotRun) is the client's statement; this is the
/// statement checked, beside the run it checked.
struct SettledRun<'s> {
    run: &'s Run,
    origin_doc: Address,
}

#[cfg(test)]
mod tests;
