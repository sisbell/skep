//! PUBLISH, the SHOT (PUB-2.33; PUB round 2, lane 3.2): the next member of a
//! published document's chain, born published in one commit from the runs
//! the client supplied — and `SettledRun`, the one value its source gate,
//! existence check and placement each walk.

use std::collections::BTreeSet;

use skep_address::{Address, Nat};
use skep_content::{ContentWrite, HasContent};
use skep_kernel::{Seq, TxnError, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State};

use super::{
    allocate_for_placement, head_lock_key, Vstream, MAX_PLACED_RUNS, MAX_REINSERTED_VALUES,
};
use crate::chain::{published_target, trunk_head, trunk_of};
use crate::error::PublishError;
use crate::ownership::{gate_write, Caller};
use crate::run::Run;
use crate::runlist::extend_or_push_run;
use crate::shot::{run_origin_document, Shot};
use crate::state::M5Rec;
use crate::HasM5;

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3 + HasContent, // reads M3 (registration, mints) + M4 (writes, and the shot's byte reads) + M5
    W::Record: From<M5Rec> + From<M3Rec> + From<ContentWrite>, // stages M3Rec + ContentWrite + M5Rec
{
    /// PUBLISH — the SHOT (PUB-2.33; PUB round 2, lane 3.2): append the next
    /// member of `doc`'s chain, born PUBLISHED, in ONE commit, its
    /// arrangement taken from the CLIENT-SUPPLIED runs of `shot` (PUB-8.1)
    /// and from nothing any draft holds at commit. Returns the member's
    /// address and the commit `Seq`. The mint ceremony's birth version
    /// (PUB-2.34) is minted by this same composite in its birth shape,
    /// `shot.base` absent.
    ///
    /// DESTINATION (PUB-2.37, PUB-2.39, PUB-2.55): the next member of the
    /// chain anchored at the base, decided AT COMMIT — the trunk's next
    /// member (`mint_version(trunk_of(doc))`, `D.4`) when the base is still
    /// the trunk head ([`trunk_head`], the head every floating reader answers
    /// from, read before the member is minted), the base's own DAUGHTER
    /// (`mint_version(base)`, `D.3.1`) when it is not. Two shots racing off
    /// one head both commit, the first on the trunk and the second as the
    /// head's daughter (PUB-2.44); nothing is positionally applied to an
    /// advanced head and nothing is refused for want of a base (PUB-2.38). A
    /// memberless document is its own base, and the base absent is the birth
    /// shape (PUB-2.34); either way the shot mints the birth version, the
    /// chain's first member `D.1`, and either form is admitted only while the
    /// chain is empty — once a member exists the document's own pre-chain
    /// arrangement is no base, and the shot must name the member it was staged
    /// from (`BaseSuperseded`). The two are ONE DESTINATION and not one
    /// arrangement: with no base there is no extent and so no carried tail,
    /// and a deposit that landed in the memberless document after the render
    /// stays in the pre-chain arrangement the member supersedes. A client
    /// wanting the deposit cell honored at birth names the document itself as
    /// its base, with the extent its render took.
    ///
    /// THE MEMBER'S ARRANGEMENT (PUB-2.40, PUB-2.41, PUB-2.42): each supplied
    /// run by its ORIGIN DOCUMENT — the trunk (PUB-2.15) of the document that
    /// minted its addresses, which the run's own start settles (`document_of`
    /// then `trunk_of`) and the client's stated `origin` must project to. The
    /// document's OWN I-space (its own content chain or any member's) is
    /// placed by reference; the STAGING DRAFT's is RE-INSERTED as fresh
    /// identity under the document's own I-space, each value through INSERT's
    /// own allocation step (`allocate_for_placement`), the bytes read at the
    /// draft's addresses — a byte read, never an arrangement read — so the
    /// committed member references no address of the draft; any OTHER
    /// document's stays a window, answering its origin. The three families are
    /// disjoint under [`Shot`](crate::Shot)'s REQUIRES on `draft`; a draft
    /// inside `doc`'s chain moves the document's own runs into the draft's
    /// family, as `Shot` states. The runs are placed
    /// in the order given, then the BASE'S POST-RENDER DEPOSITS after them: a
    /// published member changes only by exempt deposits appended at fresh
    /// positions (PUB-2.43 — the append-only edition this surface keeps, as
    /// [`Vstream`] states), so its positions past `base.extent` — the extent
    /// the staged copy took, which the client states and M5 refutes only when
    /// it exceeds the base's count ([`Base`](crate::Base) states the
    /// obligation) — are exactly the deposits the render post-dates, asked of
    /// the base's arrangement, which knows its own extent, and carried
    /// unchanged (PUB-2.45, PUB-2.67). What the shot un-arranges is what the
    /// stager un-arranged and nothing else. One [`M5Rec::ShotPlace`] journals
    /// the whole arrangement at ordinal 1 — the fold appends every placed
    /// run's I-extent to R (J1★), the by-reference runs as COPY's are and the
    /// fresh ones as INSERT's — AND THE SHOT's TWO CLIENT TERMS (the
    /// signed-ops design record's D25, arm (c′)): `placed`, Σ width of the
    /// client's runs — where its runs end and the carried tail begins, which
    /// the run-list erases whenever the two are I-adjacent — and
    /// `base_extent`, `None` in the birth shape. The record is pushed for
    /// EVERY member the shot mints, an empty placement included, since the
    /// terms exist whatever the placement holds; an empty one leaves the
    /// member reading as the lazy empty arrangement, its birth extent noted
    /// at zero. The member's LINK subspace starts empty either way: the shot
    /// places content alone, and a link seated in the base stays the base's
    /// — a link is arranged only in its home document (CL-OWN, PUB-2.12),
    /// and the member is a home no link has yet.
    ///
    /// Check order (which error wins), PUB-6.36's slots: `DocNotRegistered`
    /// → `NotOwner` (slot 1, ω on the address named — the only question the
    /// shot asks of its caller, and one [`Caller::System`] passes) → registration
    /// (slot 3): `SourceNotRegistered` for the base, then the document the
    /// draft projects to (PUB-2.15), then each run's origin document in run
    /// order, each run's SHAPE (`BadRun`)
    /// settled as its origin document is derived → `PrivateSourceVersionless`
    /// (slot 5: a private document has no chain, PUB-2.9's `true` face) → the
    /// base's shape: `BaseNotInChain` → `BaseSuperseded` →
    /// `BaseExtentTooLarge` → the SOURCE GATE (slot 6, PUB-6.23; PUB-8.1's
    /// second constraint):
    /// `readable` consulted PER DISTINCT ORIGIN DOCUMENT, in run order,
    /// skipping the document's own I-space and every run the base already
    /// arranges (PUB-6.24's carried cell), the FIRST unreadable origin
    /// document answering `Withheld` with it — BEFORE any existence answer,
    /// so a run onto an unreadable origin is refused whether or not its
    /// addresses exist → `TooManyValues` (the draft-native runs' widths
    /// summed against [`MAX_REINSERTED_VALUES`] — request arithmetic, so it
    /// answers before any address is probed) → existence, `DanglingSource` on
    /// the first run any of whose addresses M4 does not hold → then the
    /// placement, RUN BY RUN in the order given: a draft-native run's values
    /// `Mint` → `Content` apiece, and after each run `TooManyRuns` once the
    /// accumulator passes the budget; then `TooManyRuns` as the base's tail is
    /// carried; last the member's own `Mint`. The mints and writes are
    /// defensive (M3's frontier gate, M4's write-once guard), so on a correct
    /// store no honest request sees them contend with `TooManyRuns`.
    ///
    /// `readable(world, origin_doc)` answers whether the shooter may read
    /// `origin_doc`; `true` admits it. M5 hands it the TRANSACTION's working
    /// world — the world in which `publish` has just found `origin_doc`
    /// registered — and asks only about an ORIGIN DOCUMENT (PUB-2.15): once
    /// per distinct origin document, in run order, skipping the document's
    /// own and every run the base already arranges. Because it is never asked
    /// of a world that has not registered what it is asked about, a predicate
    /// that is fail-open on an unregistered address (PUB-7.5), and that reads
    /// the world it is handed, cannot decide the gate.
    ///
    /// REQUIRES of `readable`, two clauses the composite cannot check. It
    /// answers off the world it is HANDED: the guarantee above holds only for
    /// a predicate that reads that world, and one that answers from a world
    /// captured before this transaction — an M2 snapshot, or a consult that
    /// ignores its argument — may be asked about an origin its world never
    /// registered, where a fail-open predicate admits it. And it runs inside
    /// this op's transaction, under M2's applier lock, so it inherits
    /// `transact`'s precondition: it must not call `transact` on this kernel
    /// (M2 answers that nested write with its reentrancy panic, the caller's
    /// bug), and every other writer waits while it answers.
    ///
    /// LOCKS: the chain's head key (`head_lock_key(doc)`, the trunk's
    /// `version_lock_key`), `content_lock_key(trunk_of(doc))` (the
    /// fresh-identity mints), and the base's own version key when the base is
    /// a member — the daughter chain's frontier, taken since which chain the
    /// member joins is decided inside. Every origin is read off the
    /// transaction's working world; no origin is locked (a window is a
    /// reference).
    ///
    /// A member address given as `doc` is gated AS NAMED — its registration
    /// and ω — and then projected to its document (PUB-2.15): the shot is
    /// the document's, whichever member names it, and its publication, chain
    /// and base are judged on that document.
    ///
    /// `shot` is taken by value because the composite keeps it: the member's
    /// arrangement is built from the shot's runs, and each by-reference run
    /// moves into the placement record rather than being cloned out of a
    /// borrow.
    ///
    /// COST, AND WHO OWNS IT. The re-insert pushes a mint and a content write
    /// per draft-native value — `2n` records for `n` values, INSERT's own
    /// per-value step — and `n` is capped at [`MAX_REINSERTED_VALUES`],
    /// counted off the request before any address is probed. Beside them sit
    /// the member's mint and one placement, whose run count (the client's
    /// runs, coalesced, plus the base's deposit runs) is capped at
    /// [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS), measured as each run is
    /// accumulated. Both are ceilings a shot cannot be split to meet, since
    /// the member it produces is born whole. Two terms are set by stored state
    /// rather than by the request's size. The carried-run test sweeps the
    /// base's runs once per supplied run — a length comparison per resident,
    /// and an intersection per resident of the supplied run's own length,
    /// whatever the run's width — so it grows with
    /// [`content_run_count`](crate::M5State::content_run_count) of the base.
    /// The existence check derives and probes every address of every supplied
    /// run, stopping only at the first one M4 does not hold. Over the
    /// draft-native runs that walk is bounded by the re-insert's cap; over the
    /// BY-REFERENCE runs it is their `Σ width` — for a shot that commits,
    /// every position they name — so a short run list walks as far as the
    /// stored content it names, each run paying its whole width even where
    /// runs repeat one I-extent. The wire caps the run COUNT and not
    /// `Σ width`. Those two — the base's run count, which the arrangement
    /// answers without reading a run, and the by-reference runs' `Σ width` —
    /// are the numbers a route that carries this op owes.
    pub fn publish(
        &self,
        caller: Caller,
        doc: &Address,
        shot: Shot,
        readable: &dyn Fn(&W, &Address) -> bool,
    ) -> Result<(Address, Seq), TxnError<PublishError>> {
        let trunk = trunk_of(doc);
        let mut keys = vec![head_lock_key(doc), M3State::content_lock_key(&trunk)];
        if let Some(base) = &shot.base {
            if base.member != trunk {
                keys.push(M3State::version_lock_key(&base.member));
            }
        }
        // The seam's one line: the attested arm, which is `transact` where
        // this handle carries no attestation (signed ops).
        self.kernel.transact_attested(&keys, self.attest, |stg| {
            // Slot 1: registration and ω, on the address named.
            gate_write(
                stg.working().m3(),
                caller,
                doc,
                PublishError::DocNotRegistered,
                PublishError::NotOwner,
            )?;
            let world = stg.working();
            let (m3, m5, content) = (world.m3(), world.m5(), world.content());
            // Slot 3: registration — the base, the document the draft
            // projects to, every origin document (PUB-6.37: an unregistered
            // argument answers registration and nothing later).
            if let Some(base) = &shot.base {
                if !m3.is_registered_document(&base.member) {
                    return Err(PublishError::SourceNotRegistered);
                }
            }
            let draft_doc: Option<Address> = shot.draft.as_ref().map(trunk_of);
            if let Some(d) = &draft_doc {
                if !m3.is_registered_document(d) {
                    return Err(PublishError::SourceNotRegistered);
                }
            }
            // Which runs are the STAGING DRAFT's, re-inserted as fresh
            // identity rather than placed by reference (PUB-2.40): one
            // spelling, asked by the re-insert's count and by the placement
            // alike, so the count bounds exactly the runs the placement
            // re-inserts.
            let draft_native = |origin_doc: &Address| draft_doc.as_ref() == Some(origin_doc);
            // Each run settled beside its origin document (`SettledRun`):
            // derived from the run's own start, required to be the document
            // the client's stated `origin` projects to, then registered — the
            // first defective run in order deciding.
            let supplied: Vec<SettledRun> = shot
                .runs
                .into_iter()
                .map(|stated| -> Result<SettledRun, PublishError> {
                    let origin_doc =
                        run_origin_document(&stated.run).ok_or(PublishError::BadRun)?;
                    if origin_doc != trunk_of(&stated.origin) {
                        return Err(PublishError::BadRun);
                    }
                    if !m3.is_registered_document(&origin_doc) {
                        return Err(PublishError::SourceNotRegistered);
                    }
                    Ok(SettledRun { run: stated.run, origin_doc })
                })
                .collect::<Result<_, _>>()?;
            // Slot 5: the model's refusal — a private document has no chain
            // to append to (PUB-2.9).
            if !published_target(m3, doc) {
                return Err(PublishError::PrivateSourceVersionless);
            }
            // The base's shape, and the anchor the member is minted under —
            // judged against the head every floating reader answers from,
            // read before the member is minted.
            let head = trunk_head(m3, doc);
            let anchor: &Address = match &shot.base {
                None => {
                    if head.is_some() {
                        return Err(PublishError::BaseSuperseded);
                    }
                    &trunk
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
                    // The head/pinned distinction is the commit's own
                    // (PUB-2.39's head/older): the memberless document, or a
                    // base that is still the head ⇒ the trunk's next member;
                    // else the base's daughter.
                    if base.member == trunk || head.as_ref() == Some(&base.member) {
                        &trunk
                    } else {
                        &base.member
                    }
                }
            };
            // Slot 6: the source gate, per distinct origin document, in run
            // order — the document's own I-space needs no consult, a run the
            // base already arranges takes none (PUB-6.24), and the FIRST
            // unreadable origin document speaks before any existence answer.
            // An origin document joins `admitted` only once the consult admits
            // it: a carried run adds nothing to it, so a later run from the
            // same origin that the base does not arrange is still asked about.
            let mut admitted: BTreeSet<&Address> = BTreeSet::new();
            for SettledRun { run, origin_doc } in &supplied {
                if *origin_doc == trunk || admitted.contains(origin_doc) {
                    continue;
                }
                let carried = shot
                    .base
                    .as_ref()
                    .is_some_and(|base| m5.arranges_run(&base.member, run));
                if carried {
                    continue;
                }
                if !readable(world, origin_doc) {
                    return Err(PublishError::Withheld(origin_doc.clone()));
                }
                admitted.insert(origin_doc);
            }
            // The re-insert's size, before any address is probed: every
            // address of every draft-native run is re-inserted below, two
            // staged records apiece, and nothing M2 measures stops the staging
            // before it is whole. Request arithmetic, so it discloses nothing —
            // and asked here, it bounds the existence walk over those runs too.
            let reinserted = supplied
                .iter()
                .filter(|settled| draft_native(&settled.origin_doc))
                .map(|settled| settled.run.width())
                .sum::<Nat>();
            if reinserted > Nat::from(MAX_REINSERTED_VALUES) {
                return Err(PublishError::TooManyValues);
            }
            // Existence (S3★): every address a run names holds a value. Each
            // address is asked, not only the start: a by-reference run is the
            // CLIENT's I-extent rather than one an arrangement resolved. And each
            // is asked through `value_at`, the accessor the re-insert below
            // reads the draft-native bytes with. COPY places by reference and
            // reads no value back, so presence is the whole of its question;
            // the shot does read them, and asking with the read's own accessor
            // makes the answer found here the answer the re-insert gets — M4's
            // fold only ever adds (S0), so no write staged in between can take
            // a value away.
            for SettledRun { run, .. } in &supplied {
                if !run.addrs().all(|a| content.value_at(a.tumbler()).is_some()) {
                    return Err(PublishError::DanglingSource);
                }
            }
            // THE SHOT's FIRST TERM (D25 (c′)): the positions the client
            // placed — Σ width of its runs, whatever family each is — read off
            // the request before the placement erases the boundary between
            // the last of them and the carried tail.
            let placed_count = supplied.iter().map(|settled| settled.run.width()).sum::<Nat>();
            // The member's arrangement: the client's runs in order — the
            // draft-native ones re-inserted as fresh identity under the
            // document's own I-space — then the base's post-render deposits.
            let mut placed: Vec<Run> = Vec::new();
            for SettledRun { run, origin_doc } in supplied {
                if draft_native(&origin_doc) {
                    for a in run.addrs() {
                        let value = stg
                            .working()
                            .content()
                            .value_at(a.tumbler())
                            .cloned()
                            .expect("the existence check found a value at every address of every run, and M4's fold only adds");
                        allocate_for_placement::<_, PublishError>(stg, &trunk, value, &mut placed)?;
                    }
                } else {
                    extend_or_push_run(&mut placed, run);
                }
                if placed.len() > MAX_PLACED_RUNS {
                    return Err(PublishError::TooManyRuns);
                }
            }
            // The base's positions past the extent its staged copy took are
            // the deposits the render post-dates (PUB-2.43, PUB-2.45) — asked
            // of the arrangement, which knows its own extent, and measured as
            // each is accumulated, the walk stopping at the cap.
            if let Some(base) = &shot.base {
                for run in stg.working().m5().content_runs_past(&base.member, &base.extent) {
                    extend_or_push_run(&mut placed, run);
                    if placed.len() > MAX_PLACED_RUNS {
                        return Err(PublishError::TooManyRuns);
                    }
                }
            }
            // The member: born published (PUB-2.5, PUB-2.10), under the
            // anchor decided above.
            let (member, m3rec) = stg.working().m3().mint_version(anchor, true)?;
            stg.push(m3rec.into());
            // Its placing record, pushed whatever the placement holds: the
            // whole arrangement and the shot's two client terms, the second
            // absent in the birth shape (D25 (c′)).
            stg.push(
                M5Rec::ShotPlace {
                    doc: member.clone(),
                    runs: placed,
                    placed: placed_count,
                    base_extent: shot.base.as_ref().map(|base| base.extent.clone()),
                }
                .into(),
            );
            Ok(member)
        })
    }
}

/// A supplied run beside the ORIGIN DOCUMENT its own start settles
/// ([`run_origin_document`]), checked against the client's stated `origin`
/// and found registered: the ONE value the shot's source gate, existence
/// check and placement each walk, so every question about a run is asked of
/// that run's own origin document and no second list has to stay in step
/// with the runs for the gate to judge the run it is looking at.
/// [`ShotRun`](crate::ShotRun) is the client's statement; this is the
/// statement checked.
struct SettledRun {
    run: Run,
    origin_doc: Address,
}

#[cfg(test)]
mod tests;
