//! `POST /op`: the dispatch, the three write sequences, and the claim flip.

#[cfg(any(test, feature = "test-hooks"))]
use std::sync::atomic::Ordering;
#[cfg(any(test, feature = "test-hooks"))]
use std::thread;

use skep_engine::World;
use skep_febe::{Codec, Request, Response, SessionId};
use skep_identity::{HasIdentity, IdentityState};
use skep_kernel::{Attestation, Seq, Snapshot};
use skep_media::door::media_door;
#[cfg(any(test, feature = "test-hooks"))]
use skep_util::notice;
use skep_util::notice::{Class, Moment};
use skep_util::permits::{edge_clock_now, Permit, PoolEdgeLine};

use super::actor::Resolved;
use super::reply::{
    credential_refused, media_door_refused, op_answer, publication_over_budget, refuse_scan_busy,
    refuse_write_busy, registry_refused, retract_refused, with_signal, Reply,
};
use super::request::HttpRequest;
use super::{ClaimLine, Daemon, WRITE_POOL};
use skep_core::auth::key_set_of;
use skep_core::auth::policy::{
    deposits_credential_link, deposits_registry_link, op_shape_refusal, plain_admission,
    publication_read_refusal, registry_admission, retract_class_refusal, CredentialRefusal,
    DepositSpans, RecordSig,
};
use skep_core::auth::session::Actor;
use skep_core::auth::LockWrite;
use skep_core::codec::{key_set_reply, DaemonOp};
use skep_core::serial::SerialGuard;
use skep_core::commits::{write_meta, FrameMeta, Signed};

impl Daemon {
    /// Runs the claim flip's consequences, under the claim's two guards.
    ///
    /// The consequences are whole. The first is the board's first head
    /// `H.1`, written in this same serialized step unless the head writer's
    /// driver refuses it (the refusal is stated below): every attested write
    /// from here on names the board by `H.1`'s pair (signed-ops D13), so a
    /// fresh claimed board takes them from the claim on rather than after the
    /// cadence's first 64 commits, checkpoint or hour. Then come the
    /// config-lockout warnings logged a second time (RES-30 requires it at
    /// the flip unconditionally), the blocked-prefix list re-installed
    /// against the claimant this commit first seated (RES-65 item 4 — the
    /// comparand the header defers to wherever it names none), and the list
    /// in force named where the issue has anything to say.
    ///
    /// One method because the four fire together and only here — the claim
    /// is set once, so this is the one transition at which the first head is
    /// owed, a comparand appears and the two logs are owed again — which is
    /// [`skep_core::auth::AuthState::commit_tail`]'s own reason for bundling
    /// its two obligations, the memo and the flip, one step earlier. The two
    /// guards are that obligation and not a decoration. `serial` is the write
    /// path's lock the claim's `commit_under` ran under, held through this
    /// method: every commit this daemon makes takes it
    /// ([`Commits::serial_lock`](skep_core::commits::Commits::serial_lock) —
    /// the three write sequences, and the head writer's door inside them and
    /// at the open), so no write of any kind lands between the claim and
    /// `H.1`: the head names the claim's own position, and — where the head
    /// writer's driver admits it — the first write admitted after the claim
    /// finds the board term present. Where the driver refuses it, the claim
    /// stands, whatever the refusal: its ack is owed, so
    /// [`Commits::write_first_head`](skep_core::commits::Commits::write_first_head)'s
    /// answer is read for one thing here — the flip's landing line
    /// (`operations.md` §1.1 m14), which says whether `H.1` was written, stood
    /// from before the claim, or is owed — and decides nothing: the head
    /// stays owed, written at the write path's next turn, a refused write's
    /// turn included (SO-I4 (a)): the first attested write after the refusal
    /// answers `attestation_invalid:board_unavailable`, its own turn writes
    /// `H.1`, and its retry is admitted. What a refusal is and when the first
    /// head comes after one are the head writer's (`head.rs`, what a refusal
    /// does); what an attested write meets meanwhile is
    /// `skep_core::commits::board_term`'s. `credential_lock` is the
    /// credential write lock's write guard: the re-install replaces the list
    /// under the lock the claim itself committed under, so no session write
    /// lands between the claim and the comparands it moves — every one takes
    /// this lock. The head writer's own commits are the one kind that lands
    /// inside this step: `H.1`'s here, or the cadence's where the head
    /// writer's turn after the claim's commit already wrote it (an operator
    /// pausing an hour before the ceremony's last step is enough), in which
    /// case `H.1` stands and
    /// [`Commits::write_first_head`](skep_core::commits::Commits::write_first_head)
    /// writes nothing — made by no session, they meet no list, and they
    /// deposit no credential, so the slice is as the claim left it.
    /// `identity` is the post-commit world's slice — the one that names the
    /// claimant the flip seated, which the re-install compares against and
    /// the landing line names. `position` is the claim's own — the credential
    /// sequence's ack, passed down — which the landing line names (P21's
    /// boundary): never the head's position after the flip, which `H.1`'s
    /// own commits have moved by the time the line is said.
    ///
    /// **The flip says itself** (m14). One `landing:` line, said first — the
    /// account, the position, the mode the board is now in and what became
    /// of `H.1` — then the claim-time warnings, which say what is wrong with
    /// the configuration the line has just said the state of, then the list.
    /// A well-configured board's claim thus writes one line.
    ///
    /// # Panics
    ///
    /// Panics if `identity` names no claimant: the flip is the transition to
    /// a slice that names one.
    fn on_claim_flip(
        &self,
        credential_lock: &LockWrite<'_>,
        serial: &SerialGuard<'_>,
        identity: &IdentityState,
        position: Seq,
    ) {
        // The crash window's seam: armed, the process is held here — the
        // claim durable and flipped, no head — for the harness to kill.
        #[cfg(any(test, feature = "test-hooks"))]
        if self.hold_between_claim_and_head.load(Ordering::Relaxed) {
            notice::emit(Class::Failure, Self::CLAIM_HOLD_NOTICE);
            loop {
                thread::park();
            }
        }
        // The answer is read for the line and decides nothing: a refused
        // `H.1` fails nothing here — the claim stands (the card above), the
        // head writer surfaces the refusal itself and owes the head at its
        // next turn, a refused write's included.
        let head = self.commits.write_first_head(serial);
        let claimant = identity
            .claimant()
            .expect("the flip is the transition to a slice that names a claimant");
        let mode = self.auth.cfg.mode(true).to_string();
        self.say(Class::Landing, ClaimLine { claimant, position, mode: &mode, head });
        self.log_config_warnings(Moment::AtClaim);
        self.auth.reinstall_blocked_at_claim(credential_lock, identity);
        // The flip can only have made an entry inert, so an issue with no
        // entries has nothing to say; where it has one, the whole list in
        // force is named (AUTH-4.36 step 4b's "ignored at install and said
        // so in the log").
        if !self.auth.cfg.blocked_prefixes().issue_is_empty() {
            self.log_blocked_prefixes(Moment::AtClaim);
        }
    }

    /// Answers `POST /op`: one frame in, one marshaled answer out.
    ///
    /// The HTTP exchange is the correlation envelope. The frame is either the
    /// daemon-served `key_set` read, an M10 read (no lock, the actor's
    /// session), or a write, which runs one of the three pinned write
    /// sequences (AUTH-3.35 / AUTH-3.37 / the record grade for registry
    /// records) under a permit of the write pool and the credential lock.
    pub(super) fn post_op(&self, resolved: &Resolved, req: &HttpRequest) -> Reply {
        match self.codec.parse_daemon(&req.body) {
            Err(e) => self.op_reply(&self.codec.unparseable(e)),
            Ok(DaemonOp::KeySet { account }) => {
                // The one dispatcher (AUTH-6.20): the head snapshot, whose
                // World carries the key table (AUTH-2.79). Principal-free.
                //
                // One snapshot carries both the account registry and the
                // table, so the answer is the set at the position it names —
                // never ahead of its `as_of`, never behind it: the engine
                // steps the slice inside the commit that deposits the
                // credential (AUTH-2.80), so there is no second read to
                // order.
                let snap = self.engine.kernel().snapshot();
                let set = key_set_of(snap.world(), &account);
                op_answer(key_set_reply(snap.seq(), set))
            }
            Ok(DaemonOp::Febe { request: frame, presented }) => match write_meta(&frame.op) {
                // Reads execute directly and take no lock (AUTH-3.36) — under
                // a permit of the class-scan bound where the frame is
                // class-scan-shaped or a region read (wire v7.9; the
                // home-index record's D3), taken here: after the parse and
                // the session read, before M10 is asked; a region read whose
                // document is at its width waits for one of its permits
                // first, `REGION_READ_WAIT` at most, holding its worker and no
                // lock (D3 (b)); a refusal names the bound that refused in
                // its `detail`. The guard lives to the end of this arm, so
                // the permit spans the whole answer — M10's own doc-argument
                // consult and the store call inside `execute`, and the
                // marshal — and returns on every exit.
                None => {
                    let _scan = match self.scans.admit(&frame.op) {
                        Ok(permit) => permit,
                        Err(busy) => return refuse_scan_busy(frame.op.kind(), busy),
                    };
                    self.read_reply(self.febe.execute(resolved.sid(), *frame))
                }
                Some(meta) => self.write_sequence(resolved, meta, *frame, presented, req),
            },
        }
    }

    /// Runs one write through its pinned sequence.
    ///
    /// The sequence is the credential path for a deposit-classified op
    /// (`deposits_credential_link`, decided lock-free off the op's own type
    /// slot), the registry path for a registry-typed one
    /// (`deposits_registry_link`, its sibling, asked second — the two sets
    /// are disjoint), the plain path for everything else.
    ///
    /// The `attest` the frame presented goes to the plain sequence alone: a
    /// credential or registry deposit's link takes no entry signature
    /// (signed-ops D26; REG-1.86 (e)), so on those routes the member goes no
    /// further than here. `frame` arrives with its `attest` empty — the codec
    /// split the member out at the door (`DaemonOp::Febe`) — so the plain
    /// sequence's assignment of what its admission verified is
    /// `Request::attest`'s one writer.
    ///
    /// # Panics
    ///
    /// Panics in a debug build if `frame` carries an `attest`.
    fn write_sequence(
        &self,
        resolved: &Resolved,
        meta: FrameMeta,
        frame: Request,
        presented: Option<Attestation>,
        req: &HttpRequest,
    ) -> Reply {
        debug_assert!(
            frame.attest.is_none(),
            "the codec hands the presented attest beside the request, never inside it"
        );
        if deposits_credential_link(&frame.op) {
            self.credential_sequence(resolved, meta, frame, req)
        } else if deposits_registry_link(&frame.op) {
            self.registry_sequence(resolved, meta, frame, req)
        } else {
            self.plain_sequence(resolved, meta, frame, presented, req)
        }
    }

    /// Runs the registry sequence: the record grade for registry records.
    ///
    /// Its steps (2b; REG-1.86 (e)) are the pre-lock actor check, then the
    /// write pool's permit, then the credential lock's read arm → the
    /// serialization lock → [`Daemon::locked_state`] → the registry
    /// admission's ordered producers (`policy/registry.rs`: above the claim
    /// and from a signed session, the home pin, the form, the record value
    /// by the kind the slot names, the `sig`, the trial under the set that
    /// opens the home's account) → execute. The read arm, because the
    /// sequence reads the fold's key table and steps nothing: a registry
    /// record enrols no key, so there is no committed tail, no fold step and
    /// no memo. The marker slot stays empty by route, as the credential
    /// sequence's does (signed-ops D26): the record's own `sig`, verified at
    /// this `make_link`, covers both of the deposit's positions, and the row
    /// records it — the link row signed by its record (`Signed::RecordSig`),
    /// serving no `key` and no `attest`.
    ///
    /// **The permit**, as the other two sequences take theirs (`operations.md`
    /// §4 row 25). This is a third write path that commits through
    /// `commit_under` under the same guard an inline backstop holds, so a
    /// registry write parked behind a run would hold a worker outside the
    /// pool's bound — the fault the pool closes. Taken before its locks, held
    /// in this frame through the commit; a write that finds none is refused
    /// `503 write_busy` before any lock.
    fn registry_sequence(
        &self,
        resolved: &Resolved,
        meta: FrameMeta,
        frame: Request,
        req: &HttpRequest,
    ) -> Reply {
        // 1 — the pre-lock actor check, as the credential sequence's.
        if let Actor::Guest(_) = resolved.actor {
            return self.guest_reply(frame);
        }
        // 1b — the write pool's permit (§4 rows 25, 27), before the locks:
        // one of `MAX_CONCURRENT_WRITES`, or the refusal at once. Bound to
        // this frame, so it returns after the commit below and never earlier.
        let Some(_permit) = self.take_write_permit() else {
            return refuse_write_busy(meta.kind);
        };
        // 2 — the locks, the locked snapshot, and this site's own resolution.
        let credential_lock = self.auth.credential_lock.read();
        let serial = self.commits.serial_lock();
        let (snap, Resolved { actor, closed }) = self.locked_state(&serial, req);
        let binding = match actor {
            Actor::Principal(b) => b,
            Actor::Guest(_) => return with_signal(self.guest_reply(frame), closed),
        };
        // 3 — the admission's ordered producers.
        if let Err(r) =
            registry_admission(&credential_lock, snap.world(), &frame.op, binding.signer.as_ref())
        {
            // A refused write's turn for the head writer, as on every path.
            self.commits.take_turn_after_refusal(&serial);
            return with_signal(registry_refused(meta.kind, &r), closed);
        }
        // 4 — execute, the link row signed by its record.
        let signed = Some(Signed::RecordSig);
        let resp =
            self.commits.commit_under(&serial, meta.attributed(binding.testimony(), signed), || {
                self.febe.execute(binding.sid, frame)
            });
        with_signal(self.op_reply(&resp), closed)
    }

    /// Takes a write permit through the write pool's one door.
    ///
    /// It answers one of `MAX_CONCURRENT_WRITES`, or `None` (`operations.md`
    /// §4 rows 25, 27; §1.1 m12) — the three write sequences take it before
    /// any lock, so a write that finds none is refused `503 write_busy` at
    /// once and nothing is committed. Beside it is the pool's edge pair,
    /// judged here and said at the edge through [`Daemon::say`], with no
    /// answer changed by it: the refusal or the permit taken is told to the
    /// pool's tracker at the edge clock's instant, and the edge it answers —
    /// the first refusal of an episode, the first permit taken a hold-down
    /// past its last refusal — goes out in the pool's words (`the write pool
    /// is saturated` / `the write pool has room again after {n} refusals`),
    /// once per episode and nothing per request. The landing carries the
    /// episode's refusals, the upload pool's counted form
    /// (`PoolEdgeLine::counted`): they are writes refused, the evidence of
    /// whether `MAX_CONCURRENT_WRITES` parks too many writers through a
    /// backstop (§4 row 27), and they count no reader. One helper for the
    /// three sites, so the pair cannot be judged at two of them and missed at
    /// the third. The test hook (`Daemon::try_hold_write_permit`) takes its
    /// permits beside this door and crosses no edge: what a suite holds is
    /// the pool, not a request. The head writer's own commits take no permit
    /// and pass no door: they run inside the triggering write's turn, or at
    /// the open before anything is served.
    #[must_use = "a permit dropped at once returns its slot at once: bind it for the sequence's \
                  whole frame"]
    fn take_write_permit(&self) -> Option<Permit<'_>> {
        let permit = self.write_permits.try_acquire();
        let now = edge_clock_now();
        let edge = match &permit {
            Some(_) => self.write_edge.admitted(now),
            None => self.write_edge.refused(now),
        };
        if let Some(edge) = edge {
            self.say(edge.class(), PoolEdgeLine::counted(WRITE_POOL, edge));
        }
        permit
    }

    /// Returns the world snapshot and this site's resolution against it.
    ///
    /// The locked state one write sequence stands on is that pair: the
    /// snapshot carries the key table its gates read (AUTH-2.79), and the
    /// resolution is this site's own (AUTH-4.28's which-lookup pin). Taken
    /// after the serialization lock — which is what the guard argument
    /// proves — so no commit can intervene between what the gates read and
    /// what the execute they gate runs against.
    ///
    /// This is a command: [`Daemon::resolve_actor`]'s death arm retires the
    /// binding a dead or unknown token names, in this daemon's map, in M10
    /// and in the credential memo — so this is not a pure read of the locked
    /// state, despite the name. Idempotent, for the reason
    /// [`Daemon::resolve_at_head`] states.
    ///
    /// **Precondition.** The credential lock is the caller's: the three
    /// sequences hold different guard types (the read arm for the plain and
    /// registry paths, the write arm for the credential path), and holding
    /// one is the half this signature cannot state.
    fn locked_state(&self, _serial: &SerialGuard<'_>, req: &HttpRequest) -> (Snapshot<World>, Resolved) {
        let snap = self.engine.kernel().snapshot();
        let resolved = self.resolve_actor(req, snap.world());
        (snap, resolved)
    }

    /// Returns the answer every `Guest` arm gives.
    ///
    /// It executes under M10's guest session, [`SessionId::GUEST`], which
    /// answers M10's own `Unauthenticated` with the op kind named. This
    /// daemon holds no authorization policy of its own, so the refusal is
    /// M10's to word.
    fn guest_reply(&self, frame: Request) -> Reply {
        self.read_reply(self.febe.execute(SessionId::GUEST, frame))
    }

    /// Runs the plain sequence (AUTH-3.35).
    ///
    /// Its steps are the price of a publication's in-lock reads
    /// (`publication_read_refusal`, ahead of everything, below) → the write
    /// pool's permit → the read lock → the serialization lock →
    /// [`Daemon::locked_state`] (the head snapshot, the key table it carries,
    /// and this site's own resolve) → the retry memo's recall
    /// (`OperationSurface::recall`: a committed write's ack under the same
    /// session, id and kind, answered before any producer judges the retry —
    /// the link-sets design §5.7's ruling 4) → `plain_admission`'s ordered
    /// producers → the `retract` class (`retract_class_refusal`, the
    /// `nullify` class's own place) → the media door → execute. The permit
    /// is the first act past the price (`operations.md` §4 rows 25, 27):
    /// taken before either lock, held in this frame through `commit_under`'s
    /// return, so a write parked on the guard behind an inline backstop holds
    /// it the whole wait and the pool bounds the workers writes occupy; a
    /// write that finds none is refused `503 write_busy` at once, no lock
    /// taken and nothing committed. The serial lock is taken before the
    /// snapshot so the gates' answers and the execute they gate stand on one
    /// committed state; the producers' order is `plain_admission`'s, not this
    /// site's, and the media door's place — after every producer, ahead of
    /// the store — is [`skep_media::door`]'s to state.
    ///
    /// **The price ahead of the lock** (the link-sets design §5.7, EVERY
    /// IN-LOCK READ IS BOUNDED BY A REFUSAL AHEAD OF THE LOCK; lane S4). A
    /// `publish` is priced before the permit, off a lock-free snapshot of the
    /// head and the pre-lock resolution's principal: the caller's
    /// link-holding home count × (`links` entries + `read_with` entries),
    /// plus the draft's content run count × the request's runs — the work of
    /// the four reads the composite makes under the lock — against M7's
    /// `MAX_PUBLICATION_READS`, and refused `publication_over_budget` past it
    /// with every term in its detail: a refusal that costs no permit, takes
    /// no lock and commits nothing. Ahead of `serial_lock()` means off a
    /// snapshot the lock does not cover (the survey's C8): the counts may
    /// move before the composite reads them, and the budget is conservative
    /// by design. A guest is not priced — the sequence refuses it below as
    /// it did — and every other op passes the step untouched. The twin
    /// fence, the plan's reads and the kept-place check stay where S1 and S2
    /// put them; the price merely bounds them.
    fn plain_sequence(
        &self,
        resolved: &Resolved,
        meta: FrameMeta,
        mut frame: Request,
        presented: Option<Attestation>,
        req: &HttpRequest,
    ) -> Reply {
        // The price of a publication's in-lock reads, ahead of the permit
        // and both locks: a pure read of a lock-free snapshot and the frame,
        // refused past the budget with nothing taken. No `with_signal`, for
        // the credential path's reason: a pre-lock refusal carries the head
        // resolution's death signal, which `token_route`'s wrap attaches.
        if let Actor::Principal(binding) = &resolved.actor {
            let snap = self.engine.kernel().snapshot();
            if let Some(price) = publication_read_refusal(snap.world(), &frame.op, binding.principal) {
                return publication_over_budget(meta.kind, &price);
            }
        }
        // The write pool's permit, first past the price (§4 rows 25, 27):
        // one of `MAX_CONCURRENT_WRITES`, before the credential lock and the
        // guard, or the refusal at once. Bound to this frame — declared
        // ahead of the two guards, so it drops after them, once the answer
        // below is built.
        let Some(_permit) = self.take_write_permit() else {
            return refuse_write_busy(meta.kind);
        };
        let credential_lock = self.auth.credential_lock.read();
        let serial = self.commits.serial_lock();
        // The guard's hold (test seam): armed, this writer parks here with
        // its permit and both locks held — the shape of the trigger inside an
        // inline backstop — so a suite parks W − 1 more writers on
        // `serial_lock()` above, each holding a permit, and meets the pool's
        // refusal with the one past it.
        #[cfg(any(test, feature = "test-hooks"))]
        super::hooks::park_while_the_write_guard_is_held();
        let (snap, Resolved { actor, closed }) = self.locked_state(&serial, req);
        let binding = match actor {
            Actor::Principal(b) => b,
            Actor::Guest(_) => return with_signal(self.guest_reply(frame), closed),
        };
        // The memo ahead of the admission (the link-sets design §5.7's
        // ruling 4; lane S3): a retry of a write this session already
        // committed under `id` is answered from M10's retry memo BEFORE the
        // producers judge it — `OperationSurface::recall`, the lookup
        // `execute` makes first — so a publication whose own commit made
        // the originals it claimed public is never re-judged for its own
        // effect and refused `old_refused` where its ack was lost. Keyed as
        // the memo is, by session, id and op-kind; a miss falls through to
        // the producers and to `execute`, which misses the same way. Under
        // the locks, as the credential sequence's recall is: the memo is
        // read on the same committed state the admission would read.
        if let Some(id) = &frame.id {
            if let Some(ack) = self.febe.recall(binding.sid, id, frame.op.kind()) {
                return with_signal(self.op_reply(&ack), closed);
            }
        }
        // The attestation's one door (signed ops; the design record §4.5
        // (1)–(2), §5.5): the producers judge the presented member beside the
        // op, and what reaches the store is what they admitted — the value
        // the check verified against the fold's key set at this base, or
        // nothing. `Request::attest` holds nothing until the assignment below
        // — the codec split the member out at parse — so a member the
        // admission dropped (`board_state_admission`'s card lists every arm
        // that drops one) never reaches a handle, and no later layer can fill
        // the marker slot of a write the producer set excludes.
        let admitted = match plain_admission(
            &credential_lock,
            snap.world(),
            &frame.op,
            binding.principal,
            binding.signer.as_ref(),
            presented,
        ) {
            Ok(admitted) => admitted,
            Err(r) => {
                // A refused write's turn: the head writer owes a first head
                // the driver refused at every turn of the write path, this
                // one included — the one trigger the refused writer can fire.
                self.commits.take_turn_after_refusal(&serial);
                return with_signal(credential_refused(meta.kind, &r), closed);
            }
        };
        // A publication's `retract` entries' class (the link-sets design
        // §5.7; lane S3): the `nullify` class's own producer over each
        // target, in the `nullify` class's own place — after the admission,
        // behind the board-state pair and the write-path check, so a session
        // that may not write here is never told what a target link is — and
        // ahead of the media door and the store. Answered as the typed
        // `retract_refused` with the entry and the class token as its detail,
        // the daemon's own cell of that code; the admitted attestation is
        // dropped with the write, as at every refusal ahead of the store.
        if let Some(r) = retract_class_refusal(&credential_lock, snap.world(), &frame.op, binding.principal) {
            self.commits.take_turn_after_refusal(&serial);
            return with_signal(retract_refused(meta.kind, r), closed);
        }
        // The media door (`skep_media::door`): one step of its own, after
        // every producer above and ahead of the store, on the same locked
        // snapshot the commit will read — so the check that passed and the
        // commit it guards are one interval. A step and never a producer: it
        // reads the lease store and `blobs/` through the daemon's media gate,
        // which no producer may. Its refusal commits nothing and takes the
        // head writer's turn as an admission refusal does; the admitted
        // attestation is dropped with the write, as every refusal ahead of
        // the store drops it.
        if let Some(refusal) = media_door(snap.world(), &frame.op, binding.principal, &self.media) {
            self.commits.take_turn_after_refusal(&serial);
            return with_signal(media_door_refused(meta.kind, refusal), closed);
        }
        // The entry's signedness, for the change feed's row (signed-ops D12):
        // the marker the admission filled — the admitted value itself, which
        // the attest store appends beside `commits.log` when the write path
        // records the commit — or nothing, for an entry the plain sequence
        // admitted unsigned, whose row serves its `key`: a credential record
        // deposit's atom among them — the atom row always carries `key`, the
        // daemon's testimony of the writing session; the record's `sig` is
        // judged at its `make_link`, whose row the credential sequence
        // records as signed by it (signed-ops D26).
        let signed = admitted.as_ref().map(|a| Signed::Marker(a.clone()));
        frame.attest = admitted;
        let resp =
            self.commits.commit_under(&serial, meta.attributed(binding.testimony(), signed), || {
                self.febe.execute(binding.sid, frame)
            });
        with_signal(self.op_reply(&resp), closed)
    }

    /// Runs the credential sequence (AUTH-3.37).
    ///
    /// The pre-lock actor is `resolve_at_head`'s; `op_shape_refusal` and the
    /// verbatim deposit — both pure functions of the frame — run ahead of
    /// the lock; then the write pool's permit (`operations.md` §4 rows 25, 27
    /// — before the lock, the guard and the memo's recall, so a retry that
    /// finds no permit is refused `write_busy` and meets the memo once it has
    /// one: one commit either way) → the write lock → serial →
    /// [`Daemon::locked_state`] → recall → precheck → execute — which steps
    /// the World's identity slice inside the commit itself (AUTH-2.80) — →
    /// the memo and the claim-flip tail, all under the write guard, which is
    /// what keeps the precheck and the execute it gates one atomic step
    /// (AUTH-3.3).
    ///
    /// # Panics
    ///
    /// Panics in a debug build where a credential-classified op is not an
    /// address-form `make_link` (`DepositSpans::of` answers `None`), a
    /// premise broken.
    fn credential_sequence(
        &self,
        resolved: &Resolved,
        meta: FrameMeta,
        frame: Request,
        req: &HttpRequest,
    ) -> Reply {
        // 1 — the pre-lock actor check: both outcomes are refusals that
        // execute nothing (AUTH-3.38). No `with_signal` here: this arm
        // reads the head resolution, whose death signal
        // [`Daemon::token_route`]'s wrap already carries.
        if let Actor::Guest(_) = resolved.actor {
            return self.guest_reply(frame);
        }
        // 2 — slots (1)–(2), ahead of the lock (AUTH-3.5).
        if let Some(r) = op_shape_refusal(&frame.op) {
            return credential_refused(meta.kind, &r);
        }
        // 2b — the verbatim deposit (AUTH-3.17), a pure function of the
        // frame and so built ahead of the lock like slots (1)–(2): its
        // three slots are `enc(addrs)` over lists the codec caps at
        // `MAX_WIRE_LIST` apiece, so a frame of a few hundred kilobytes
        // names order twelve thousand spans — each two multi-component
        // tumblers — with no reason to build them inside the serialization
        // point. Its unreachable arm's refusal then takes no lock either,
        // which is the property `op_shape_refusal` already claims for its
        // own.
        let Some(dep) = DepositSpans::of(&frame.op) else {
            // Unreachable by construction: only a MakeLink with
            // address-form slots classifies credential past slots (1)–(2).
            // The assert is what makes the premise loud — the release
            // answer refuses in the shape vocabulary rather than inventing
            // one, and a `resolved_from` a caller's frame did not earn is
            // indistinguishable from a genuine slot-(2) refusal, which is
            // exactly what a silent arm here would ship. Same treatment
            // `precheck` gives its own `NotCredential` line. No
            // `with_signal`, for step 1's reason: a pre-lock refusal
            // carries the head resolution's death signal, which
            // [`Daemon::token_route`]'s wrap already attaches.
            debug_assert!(false, "a classified deposit is an address-form MakeLink");
            let r = CredentialRefusal::ResolvedFrom;
            return credential_refused(meta.kind, &r);
        };
        // 2c — the write pool's permit (§4 rows 25, 27): after the two pure
        // refusals above, which cost no permit, and before the write lock,
        // the guard and the memo's recall at 5 — one of
        // `MAX_CONCURRENT_WRITES`, or `503 write_busy` at once. Bound to this
        // frame, ahead of the two guards, so it drops after them: once the
        // commit and the tail after it are done.
        let Some(_permit) = self.take_write_permit() else {
            return refuse_write_busy(meta.kind);
        };
        // 3 — the credential write lock, the serialization lock, the locked
        // snapshot, and this site's own resolution.
        let credential_lock = self.auth.credential_lock.write();
        let serial = self.commits.serial_lock();
        let (snap, Resolved { actor, closed }) = self.locked_state(&serial, req);
        let binding = match actor {
            Actor::Principal(b) => b,
            // 4 — the only reachable arms are Unknown | BindingDead
            // (AUTH-3.37 item 4); the close-and-signal already fired.
            Actor::Guest(_) => return with_signal(self.guest_reply(frame), closed),
        };
        // 5 — recall, kind-blind, atomic with the precheck-and-execute it
        // guards (AUTH-3.40/3.41): the original ack, byte-identical,
        // executing nothing.
        if let Some(id) = &frame.id {
            if let Some(ack) = self.auth.memo.recall(&credential_lock, binding.sid, id) {
                return with_signal(op_answer(ack), closed);
            }
        }
        // 6 — the precheck's ordered slots over the deposit built at 2b. The
        // actor is what the session's opening fixed — its signer and, beside
        // it, its scope, this being the scope's one read (AUTH-4.39) — and the
        // seat is the carve's one input (AUTH-3.15), read here so the precheck
        // declares the collaborator it has rather than the whole config —
        // beside it the one setting slot (4) reads, `allow_preview_keys`
        // (AUTH-1.44; RES-206), handed over the same way. The list is stable
        // under the write guard held here: its install takes the same one.
        let list = self.auth.cfg.blocked_prefixes();
        let record_sig = match skep_core::auth::policy::precheck(
            &credential_lock,
            snap.world(),
            &dep,
            binding.signer.as_ref(),
            binding.scope,
            list.header().binding_writer.as_ref(),
            self.auth.cfg.allow_preview_keys,
        ) {
            Ok(record_sig) => record_sig,
            Err(r) => {
                // A refused write's turn for the head writer, as on the plain
                // path.
                self.commits.take_turn_after_refusal(&serial);
                return with_signal(credential_refused(meta.kind, &r), closed);
            }
        };
        // 7 — execute (commit-record-announce under the held serial lock,
        // then the head writer's turn, which may land the head's own commits
        // before `commit_under` returns — the `post` snapshot at 8 then holds
        // them; they deposit no credential, so the slice they carry is the
        // one this commit stepped). The slice moves here: the engine's fold
        // hook steps the World's identity slice inside the transaction that
        // deposits the link (AUTH-2.80), so the committed world and its key
        // table are installed together and no reader can see one without the
        // other.
        //
        // The credential deposit's marker slot stays empty (signed-ops D26):
        // the `make_link` half of a credential deposit is covered by the
        // record's own `sig` member — the record grade's carrier, which the
        // precheck at 6 verified above the claim (2a: its
        // `record_grade_check`, under the set that opens the record's home)
        // — and takes no entry signature of its own, so the `attest` a client
        // attached is never handed to this sequence (`write_sequence` passes
        // `presented` to the plain path alone) and `Request::attest` arrives
        // empty from the codec: never verified, never written. This is how
        // the check tells signed-ops D26's case by route — a credential-typed
        // link write never reaches the plain sequence's producers at all.
        // What the row records instead (signed-ops D12) is the precheck's own
        // answer: the record's `sig` verified — the link row signed by its
        // credential record's `sig`, its `key` absent (the atom's row keeps
        // its `key`) — or unjudged at or below the claim, the ceremony's rows
        // serving their `key`.
        let signed = match record_sig {
            RecordSig::Verified => Some(Signed::RecordSig),
            RecordSig::Unjudged => None,
        };
        let req_id = frame.id.clone();
        let resp =
            self.commits.commit_under(&serial, meta.attributed(binding.testimony(), signed), || {
                self.febe.execute(binding.sid, frame)
            });
        let ack = self.codec.marshal(&resp);
        if let Response::AckAddr { at, .. } = &resp {
            // 8 — the committed tail (AUTH-3.43): the memo entry under the
            // write guard, and the flip read off the two slices — the locked
            // snapshot's before the commit, the post-commit snapshot's after.
            //
            // The `AckAddr` test is a shape test standing in for "this write
            // committed", on two premises: only an address-form `MakeLink`
            // reaches here ([`DepositSpans::of`] is `Some` for nothing
            // else), and M10 acks a committed `make_link` with `AckAddr`.
            // If either failed, a committed deposit would skip this tail
            // and the ack would go unmemoized and the claim flip's
            // consequences unrun — never a key: the slice moved inside the
            // commit, whatever this tail does.
            let post = self.engine.kernel().snapshot();
            let flipped = self.auth.commit_tail(
                &credential_lock,
                snap.world().identity(),
                post.world().identity(),
                binding.sid,
                req_id,
                &ack,
            );
            // 9 — the claim flip's tail, under both guards: `H.1` in this
            // same step (signed ops) and the flip's line naming the ack's
            // position — the claim's own — then the warnings and the list.
            if flipped {
                self.on_claim_flip(&credential_lock, &serial, post.world().identity(), *at);
            }
        }
        with_signal(op_answer(ack), closed)
    }

    /// Returns one M10 answer, marshaled, as its reply.
    ///
    /// It goes through [`op_answer`], which is where that channel's status
    /// is chosen.
    pub(super) fn op_reply(&self, resp: &Response) -> Reply {
        op_answer(self.codec.marshal(resp))
    }

    /// Returns one M10 read answer, dated, marshaled, as its reply.
    ///
    /// It is [`Daemon::op_reply`] for the read routes — `/op`'s read arm and
    /// `/op-at` — with the one thing a read answer owes that M10 cannot
    /// supply: the daemon's testimony of when a minted address's position
    /// committed, on the two reads that answer an address's age
    /// (`read_link`, `doc_metadata`; wire.md §Links (raw reads), §Namespace).
    /// M10 answers the position off the world and leaves the time slot open
    /// (`Response::mint_mut`); this fills it from the commits' testimony —
    /// the change feed's line for the position, else the hourly time record
    /// (`Commits::mint_time`) — off the head's world, where every record at
    /// or below the position stands whichever snapshot the read was answered
    /// from. Every other shape passes through untouched: one match, no
    /// snapshot, for a read that carries no age.
    pub(super) fn read_reply(&self, mut resp: Response) -> Reply {
        if let Some((at, slot)) = resp.mint_mut() {
            let head = self.engine.kernel().snapshot();
            *slot = self.commits.mint_time(head.world(), at);
        }
        self.op_reply(&resp)
    }
}
