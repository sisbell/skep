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

use super::actor::Resolved;
use super::reply::{
    credential_refused, media_door_refused, op_answer, refuse_scan_busy, refuse_write_busy,
    registry_refused, with_signal, Reply,
};
use super::request::HttpRequest;
use super::scan::ScanBusy;
use super::{ClaimLine, Daemon};
use crate::auth::key_set_of;
use crate::auth::policy::{
    deposits_credential_link, deposits_registry_link, op_shape_refusal, plain_admission,
    registry_admission, CredentialRefusal, DepositSpans, RecordSig,
};
use crate::auth::session::Actor;
use crate::auth::LockWrite;
use crate::codec::{key_set_reply, DaemonOp};
use crate::serial::SerialGuard;
use crate::write_path::{write_meta, FrameMeta, Signed};

impl Daemon {
    /// THE CLAIM FLIP's consequences, whole and under the two guards the
    /// claim committed under: the board's FIRST HEAD `H.1`, written in this
    /// same serialized step unless the head writer's driver refuses it (the
    /// refusal is stated below; signed ops, s1; RULED 2026-09-25 — "THE CLAIM
    /// WRITES `H.1`": every attested write from here on names the board by
    /// `H.1`'s pair, D13, so a fresh claimed board takes them from the claim
    /// on rather than after the cadence's first 64 commits, checkpoint or
    /// hour), the config-lockout warnings logged a second time (RES-30
    /// requires it at the flip unconditionally), the blocked-prefix list
    /// RE-INSTALLED against the claimant this commit first seated (RES-65
    /// item 4 — the comparand the header defers to wherever it names none),
    /// and the list in force named where the issue has anything to say.
    ///
    /// One method because the four fire TOGETHER and only here — the claim
    /// is set once, so this is the one transition at which the first head is
    /// owed, a comparand appears and the two logs are owed again — which is
    /// [`crate::auth::AuthState::commit_tail`]'s own reason for bundling its
    /// three obligations one step earlier. The two guards are that obligation
    /// and not a decoration. `serial` is the write path's lock the claim's
    /// `commit_under` ran under, held through this method: every commit this
    /// daemon makes takes it ([`WritePath::serial_lock`](crate::write_path::WritePath::serial_lock) — both write
    /// sequences, and the head writer's door inside them), so no write of any
    /// kind lands between the claim and `H.1`: the head names the claim's own
    /// position, and — where the head writer's driver ADMITS it — the first
    /// write admitted after the claim finds the board term present. Where the
    /// driver REFUSES it, the claim STANDS, whatever the refusal: its ack is
    /// owed, so
    /// [`WritePath::write_first_head`](crate::write_path::WritePath::write_first_head)'s
    /// answer is read for ONE thing here — the flip's landing line
    /// (`operations.md` §1.1 m14), which says whether `H.1` was written, stood
    /// from before the claim, or is owed — and decides nothing: the head
    /// stays OWED, written at the write path's NEXT TURN, a refused write's
    /// turn included (l7-C1; SO-I4 (a)): the first attested write after the
    /// refusal answers `attestation_invalid:board_unavailable`, its own turn
    /// writes `H.1`, and its retry is admitted. What a refusal is and when
    /// the first head comes after one are the head writer's (`head.rs`, WHAT
    /// A REFUSAL DOES); what an attested write meets meanwhile is
    /// [`crate::write_path::board_term`]'s. `credential_lock` is the
    /// credential write lock's write guard: the re-install replaces the list
    /// under the lock the claim itself committed under, so no SESSION write
    /// lands between the claim and the comparands it moves — every one takes
    /// this lock. The head writer's own commits are the one kind that lands
    /// inside this step: `H.1`'s here, or the cadence's where the head
    /// writer's turn after the claim's commit already wrote it (an operator
    /// pausing an hour before the ceremony's last step is enough), in which
    /// case `H.1` stands and
    /// [`WritePath::write_first_head`](crate::write_path::WritePath::write_first_head)
    /// writes nothing — made by no session, they meet no list, and they
    /// deposit no credential, so the slice is as the claim left it. `identity`
    /// is the POST-COMMIT world's slice — the one that names the claimant the
    /// flip seated, which the re-install compares against and the landing
    /// line names. `position` is the claim's own — the credential sequence's
    /// ack, passed down — which the landing line names (P21's boundary):
    /// never the head's position after the flip, which `H.1`'s own commits
    /// have moved by the time the line is said.
    ///
    /// THE FLIP SAYS ITSELF (m14): one `landing:` line, said FIRST — the
    /// account, the position, the mode the board is now in and what became
    /// of `H.1` — then the claim-time warnings, which say what is wrong with
    /// the configuration the line has just said the state of, then the list.
    /// A well-configured board's claim thus writes one line where it wrote
    /// none.
    fn on_claim_flip(
        &self,
        credential_lock: &LockWrite<'_>,
        serial: &SerialGuard<'_>,
        identity: &IdentityState,
        position: Seq,
    ) {
        // THE CRASH WINDOW's seam: armed, the process is held HERE — the
        // claim durable and flipped, no head — for the harness to kill.
        #[cfg(any(test, feature = "test-hooks"))]
        if self.hold_between_claim_and_head.load(Ordering::Relaxed) {
            notice::line(Self::CLAIM_HOLD_NOTICE);
            loop {
                thread::park();
            }
        }
        // The answer is read for the line and decides nothing: a refused
        // `H.1` fails nothing here — the claim stands (the card above), the
        // head writer surfaces the refusal itself and owes the head at its
        // next turn, a refused write's included (l7-C1).
        let head = self.writes.write_first_head(serial);
        let claimant = identity
            .claimant()
            .expect("the flip is the transition to a slice that names a claimant");
        let mode = self.auth.cfg.mode(true).to_string();
        self.say(Class::Landing, ClaimLine { claimant, position, mode: &mode, head });
        self.log_config_warnings(Moment::AtClaim);
        self.auth.reinstall_blocked_at_claim(credential_lock, identity);
        // The flip can only have made an entry INERT, so an issue with no
        // entries has nothing to say; where it has one, the whole list in
        // force is named (AUTH-4.36 step 4b's "ignored at install and said
        // so in the log").
        if !self.auth.cfg.blocked_prefixes().issue_is_empty() {
            self.log_blocked_prefixes(Moment::AtClaim);
        }
    }

    /// `POST /op` — one frame in, one marshaled answer out; the HTTP
    /// exchange is the correlation envelope. The frame is either the
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
                // ONE snapshot carries both the account registry and the
                // table, so the answer is the set AT the position it names —
                // never ahead of its `as_of`, never behind it. The straddle
                // that stood here — a fold stepped after its deposit's
                // commit, read in a second step beside the world — is CLOSED:
                // the engine steps the slice inside the commit that deposits
                // the credential (AUTH-2.80), and there is no second read to
                // order.
                let snap = self.engine.kernel().snapshot();
                let set = key_set_of(snap.world(), &account);
                op_answer(key_set_reply(snap.seq(), set))
            }
            Ok(DaemonOp::Febe { request: frame, presented }) => match write_meta(&frame.op) {
                // Reads execute directly and take no lock (AUTH-3.36) — under
                // a class-scan permit where the frame is class-scan-shaped
                // (wire v7.9; lane 3.7 §2), taken here: after the parse and
                // the session read, before M10 is asked. The guard lives to
                // the end of this arm, so the permit spans the whole answer —
                // M10's own doc-argument consult and the store call inside
                // `execute`, and the marshal — and returns on every exit.
                None => {
                    let _scan = match self.scans.admit(&frame.op) {
                        Ok(permit) => permit,
                        Err(ScanBusy) => return refuse_scan_busy(frame.op.kind()),
                    };
                    self.op_reply(&self.febe.execute(resolved.sid(), *frame))
                }
                Some(meta) => self.write_sequence(resolved, meta, *frame, presented, req),
            },
        }
    }

    /// One write, through its pinned sequence: the credential path for a
    /// deposit-classified op (`deposits_credential_link`, decided lock-free
    /// off the op's own type slot), the registry path for a registry-typed
    /// one (`deposits_registry_link`, its sibling, asked second — the two
    /// sets are disjoint), the plain path for everything else.
    ///
    /// The `attest` the frame presented goes to the plain sequence alone: a
    /// credential or registry deposit's link takes no entry signature (D26;
    /// REG-1.86 (e)), so on those routes the member goes no further than
    /// here. `frame` arrives with its `attest` EMPTY — the codec split the
    /// member out at the door (`DaemonOp::Febe`) — so the plain sequence's
    /// assignment of what its admission verified is `Request::attest`'s one
    /// writer.
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
            self.plain_sequence(meta, frame, presented, req)
        }
    }

    /// The REGISTRY sequence (the record grade for registry records, 2b;
    /// REG-1.86 (e)): the pre-lock actor check, then the write pool's permit,
    /// then the credential lock's READ arm → the serialization lock →
    /// [`Daemon::locked_state`] → the registry admission's ordered producers
    /// (`policy/registry.rs`: above the claim and from a signed session, the
    /// home pin, the form, the record value by the kind the slot names, the
    /// `sig`, the trial under the set that opens the home's account) →
    /// execute. The READ arm, because the sequence reads the fold's key table
    /// and steps nothing: a registry record enrols no key, so there is no
    /// committed tail, no fold step and no memo. The marker slot stays EMPTY
    /// by route, as the credential sequence's does (D26): the record's own
    /// `sig`, verified at this `make_link`, covers both of the deposit's
    /// positions, and the row records it — the LINK row signed by its record
    /// (`Signed::RecordSig`), serving no `key` and no `attest`.
    ///
    /// THE PERMIT, as the other two sequences take theirs (`operations.md`
    /// §4 row 25): this is a third write path that commits through
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
        // 1b — THE WRITE POOL's PERMIT (§4 rows 25, 27), before the locks:
        // one of `MAX_CONCURRENT_WRITES`, or the refusal at once. Bound to
        // this frame, so it returns after the commit below and never earlier.
        let Some(_permit) = self.write_permits.try_acquire() else {
            return refuse_write_busy(meta.kind);
        };
        // 2 — the locks, the locked snapshot, and this site's own resolution.
        let credential_lock = self.auth.credential_lock.read();
        let serial = self.writes.serial_lock();
        let (snap, Resolved { actor, closed }) = self.locked_state(&serial, req);
        let binding = match actor {
            Actor::Principal(b) => b,
            Actor::Guest(_) => return with_signal(self.guest_reply(frame), closed),
        };
        // 3 — the admission's ordered producers.
        if let Err(r) =
            registry_admission(&credential_lock, snap.world(), &frame.op, binding.signer.as_ref())
        {
            // A refused write's TURN (l7-C1), as on every path.
            self.writes.take_turn_after_refusal(&serial);
            return with_signal(registry_refused(meta.kind, &r), closed);
        }
        // 4 — execute, the link row signed by its record.
        let signed = Some(Signed::RecordSig);
        let resp =
            self.writes.commit_under(&serial, meta.attributed(binding.testimony(), signed), || {
                self.febe.execute(binding.sid, frame)
            });
        with_signal(self.op_reply(&resp), closed)
    }

    /// The locked state one write sequence stands on: the world snapshot —
    /// which carries the key table its gates read (AUTH-2.79) — and this
    /// site's own resolution against it (AUTH-4.28's WHICH-lookup pin). Taken
    /// AFTER the serialization lock — which is what the guard argument proves
    /// — so no commit can intervene between what the gates read and what the
    /// execute they gate runs against.
    ///
    /// The credential lock is the CALLER's: the three sequences hold
    /// different guard types (the read arm for the plain and registry paths,
    /// the write arm for the credential path), and holding one is the half
    /// this signature cannot state.
    ///
    /// A COMMAND: [`Daemon::resolve_actor`]'s death arm retires the binding
    /// a dead or unknown token names, in this daemon's map, in M10 and in
    /// the credential memo — so this is not a pure read of the locked
    /// state, despite the name. Idempotent, for the reason
    /// [`Daemon::resolve_at_head`] states.
    fn locked_state(&self, _serial: &SerialGuard<'_>, req: &HttpRequest) -> (Snapshot<World>, Resolved) {
        let snap = self.engine.kernel().snapshot();
        let resolved = self.resolve_actor(req, snap.world());
        (snap, resolved)
    }

    /// The answer every Guest arm gives: execute under M10's guest session,
    /// [`SessionId::GUEST`], which is M10's own `Unauthenticated` with the
    /// op kind named. This daemon holds no authorization policy of its own,
    /// so the refusal is M10's to word.
    fn guest_reply(&self, frame: Request) -> Reply {
        self.op_reply(&self.febe.execute(SessionId::GUEST, frame))
    }

    /// The PLAIN sequence (AUTH-3.35): the write pool's permit → the read
    /// lock → the serialization lock → [`Daemon::locked_state`] (the head
    /// snapshot, the key table it carries, and this site's own resolve) →
    /// `plain_admission`'s ordered producers → the media door → execute. The
    /// permit is the FIRST act (`operations.md` §4 rows 25, 27): taken before
    /// either lock, held in this frame through `commit_under`'s return, so a
    /// write parked on the guard behind an inline backstop holds it the whole
    /// wait and the pool bounds the workers writes occupy; a write that finds
    /// none is refused `503 write_busy` at once, no lock taken and nothing
    /// committed. The serial lock is taken before the snapshot so the gates'
    /// answers and the execute they gate stand on one committed state; the
    /// producers' ORDER is `plain_admission`'s, not this site's, and the
    /// media door's place — after every producer, ahead of the store — is
    /// [`skep_media::door`]'s to state.
    fn plain_sequence(
        &self,
        meta: FrameMeta,
        mut frame: Request,
        presented: Option<Attestation>,
        req: &HttpRequest,
    ) -> Reply {
        // THE WRITE POOL's PERMIT, FIRST (§4 rows 25, 27): one of
        // `MAX_CONCURRENT_WRITES`, before the credential lock and the guard,
        // or the refusal at once. Bound to this frame — declared ahead of the
        // two guards, so it drops after them, once the answer below is built.
        let Some(_permit) = self.write_permits.try_acquire() else {
            return refuse_write_busy(meta.kind);
        };
        let credential_lock = self.auth.credential_lock.read();
        let serial = self.writes.serial_lock();
        // THE GUARD's HOLD (test seam): armed, this writer parks HERE with
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
        // THE ATTESTATION's one door (signed ops; the design record §4.5
        // (1)–(2), §5.5): the producers judge the PRESENTED member beside the
        // op, and what reaches the store is what they ADMITTED — the value
        // the check verified against the fold's key set at this base, or
        // nothing. `Request::attest` held nothing until the assignment below
        // — the codec split the member out at parse — so a member the
        // admission DROPPED (`board_state_admission`'s card lists every arm
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
                // A refused write's TURN (l7-C1): the head writer owes a
                // first head the driver refused at every turn of the write
                // path, this one included — the one trigger the refused
                // writer can fire.
                self.writes.take_turn_after_refusal(&serial);
                return with_signal(credential_refused(meta.kind, &r), closed);
            }
        };
        // THE MEDIA DOOR (media lanes A and B; `skep_media::door`): one step of
        // its own, after every producer above and ahead of the store, on the
        // same locked snapshot the commit will read — so the check that
        // passed and the commit it guards are one interval. A step and never
        // a producer: it reads the lease store and `blobs/` through the
        // daemon's media gate, which no producer may. Its refusal commits
        // nothing and takes the head writer's turn as an admission refusal
        // does (l7-C1); the admitted attestation is dropped with the write,
        // as every refusal ahead of the store drops it.
        if let Some(refusal) = media_door(snap.world(), &frame.op, binding.principal, &self.media) {
            self.writes.take_turn_after_refusal(&serial);
            return with_signal(media_door_refused(meta.kind, refusal), closed);
        }
        // THE ENTRY'S SIGNEDNESS, for the change feed's row (D12): the marker
        // the admission filled — the admitted value itself, which the attest
        // store appends beside `commits.log` when the write path records the
        // commit — or nothing, for an entry the plain sequence admitted
        // unsigned, whose row serves its `key`: a credential record deposit's
        // ATOM among them (as7-E2 (a), owner 2026-10-01 — the atom row ALWAYS
        // carries `key`, the daemon's testimony of the writing session; the
        // record's `sig` is judged at its `make_link`, whose row the
        // credential sequence records as signed by it, D26).
        let signed = admitted.as_ref().map(|a| Signed::Marker(a.clone()));
        frame.attest = admitted;
        let resp =
            self.writes.commit_under(&serial, meta.attributed(binding.testimony(), signed), || {
                self.febe.execute(binding.sid, frame)
            });
        with_signal(self.op_reply(&resp), closed)
    }

    /// The CREDENTIAL sequence (AUTH-3.37): the pre-lock actor is
    /// `resolve_at_head`'s; `op_shape_refusal` and the verbatim deposit —
    /// both pure functions of the frame — run ahead of the lock; then the
    /// write pool's permit (`operations.md` §4 rows 25, 27 — before the
    /// lock, the guard and the memo's recall, so a retry that finds no permit
    /// is refused `write_busy` and meets the memo once it has one: one commit
    /// either way) → the write lock → serial → [`Daemon::locked_state`] →
    /// recall → precheck → execute — which steps the World's identity slice
    /// inside the commit itself (AUTH-2.80) — → the memo and the claim-flip
    /// tail, all under the write guard, which is what keeps the precheck and
    /// the execute it gates one atomic step (AUTH-3.3).
    fn credential_sequence(
        &self,
        resolved: &Resolved,
        meta: FrameMeta,
        frame: Request,
        req: &HttpRequest,
    ) -> Reply {
        // 1 — the pre-lock actor check: both outcomes are refusals that
        // execute nothing (AUTH-3.38). No `with_signal` here: this arm
        // reads the HEAD resolution, whose death signal
        // [`Daemon::token_route`]'s wrap already carries.
        if let Actor::Guest(_) = resolved.actor {
            return self.guest_reply(frame);
        }
        // 2 — slots (1)–(2), ahead of the lock (AUTH-3.5).
        if let Some(r) = op_shape_refusal(&frame.op) {
            return credential_refused(meta.kind, &r);
        }
        // 2b — the verbatim deposit (AUTH-3.17), a pure function of the
        // frame and so built AHEAD of the lock like slots (1)–(2): its
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
            // The assert is what makes the premise LOUD — the release
            // answer refuses in the shape vocabulary rather than inventing
            // one, and a `resolved_from` a caller's frame did not earn is
            // indistinguishable from a genuine slot-(2) refusal, which is
            // exactly what a silent arm here would ship. Same treatment
            // `precheck` gives its own `NotCredential` line. No
            // `with_signal`, for step 1's reason: a pre-lock refusal
            // carries the HEAD resolution's death signal, which
            // [`Daemon::token_route`]'s wrap already attaches.
            debug_assert!(false, "a classified deposit is an address-form MakeLink");
            let r = CredentialRefusal::ResolvedFrom;
            return credential_refused(meta.kind, &r);
        };
        // 2c — THE WRITE POOL's PERMIT (§4 rows 25, 27): after the two pure
        // refusals above, which cost no permit, and before the write lock,
        // the guard and the memo's recall at 5 — one of
        // `MAX_CONCURRENT_WRITES`, or `503 write_busy` at once. Bound to this
        // frame, ahead of the two guards, so it drops after them: once the
        // commit and the tail after it are done.
        let Some(_permit) = self.write_permits.try_acquire() else {
            return refuse_write_busy(meta.kind);
        };
        // 3 — the credential write lock, the serialization lock, the locked
        // snapshot, and this site's OWN resolution.
        let credential_lock = self.auth.credential_lock.write();
        let serial = self.writes.serial_lock();
        let (snap, Resolved { actor, closed }) = self.locked_state(&serial, req);
        let binding = match actor {
            Actor::Principal(b) => b,
            // 4 — the only reachable arms are Unknown | BindingDead
            // (AUTH-3.37 item 4); the close-and-signal already fired.
            Actor::Guest(_) => return with_signal(self.guest_reply(frame), closed),
        };
        // 5 — recall, kind-blind, atomic with the precheck-and-execute it
        // guards (AUTH-3.40/3.41): the ORIGINAL ack, byte-identical,
        // executing nothing.
        if let Some(id) = &frame.id {
            if let Some(ack) = self.auth.memo.recall(&credential_lock, binding.sid, id) {
                return with_signal(op_answer(ack), closed);
            }
        }
        // 6 — the precheck's ordered slots over the deposit built at 2b. The
        // actor is what the session's opening fixed — its signer and, beside
        // it, its scope, this being the scope's ONE read (AUTH-4.39) — and the
        // SEAT is the carve's one input (AUTH-3.15), read HERE so the precheck
        // declares the collaborator it has rather than the whole config —
        // beside it the ONE setting slot (4) reads, `allow_preview_keys`
        // (AUTH-1.44; RES-206), handed over the same way. The list is stable
        // under the write guard held here: its install takes the same one.
        let list = self.auth.cfg.blocked_prefixes();
        let record_sig = match crate::auth::policy::precheck(
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
                // A refused write's TURN (l7-C1), as on the plain path.
                self.writes.take_turn_after_refusal(&serial);
                return with_signal(credential_refused(meta.kind, &r), closed);
            }
        };
        // 7 — execute (commit-record-announce under the held serial lock,
        // then the head writer's turn, which may land the head's own commits
        // before `commit_under` returns — the `post` snapshot at 8 then holds
        // them; they deposit no credential, so the slice they carry is the
        // one this commit stepped). THE SLICE MOVES HERE: the engine's fold
        // hook steps the World's identity slice inside the transaction that
        // deposits the link (AUTH-2.80), so the committed world and its key
        // table are installed together and no reader can see one without the
        // other.
        //
        // THE CREDENTIAL DEPOSIT'S MARKER SLOT STAYS EMPTY (signed ops; D26,
        // RULED 2026-09-25): the `make_link` half of a credential deposit is
        // covered by the record's own `sig` member — the record grade's
        // carrier, which the precheck at 6 VERIFIED above the claim (2a: its
        // `record_grade_check`, under the set that opens the record's home)
        // — and takes no entry signature of its own, so the `attest` a client
        // attached is never handed to this sequence (`write_sequence` passes
        // `presented` to the plain path alone) and `Request::attest` arrives
        // empty from the codec: never verified, never written. This is how
        // the check tells D26's case by ROUTE — a credential-typed link write
        // never reaches the plain sequence's producers at all. What the row
        // records instead (D12) is the precheck's own answer: the record's
        // `sig` VERIFIED — the LINK row signed by its credential record's
        // `sig`, its `key` absent (the atom's row keeps its `key`, as7-E2
        // (a)) — or unjudged at or below the claim, the ceremony's rows
        // serving their `key`.
        let signed = match record_sig {
            RecordSig::Verified => Some(Signed::RecordSig),
            RecordSig::Unjudged => None,
        };
        let req_id = frame.id.clone();
        let resp =
            self.writes.commit_under(&serial, meta.attributed(binding.testimony(), signed), || {
                self.febe.execute(binding.sid, frame)
            });
        let ack = self.codec.marshal(&resp);
        if let Response::AckAddr { at, .. } = &resp {
            // 8 — the committed tail (AUTH-3.43): the memo entry under the
            // write guard, and the flip read off the two slices — the locked
            // snapshot's before the commit, the post-commit snapshot's after.
            //
            // The `AckAddr` test is a SHAPE test standing in for "this write
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
            // same step (signed ops, s1) and the flip's line naming the
            // ack's position — the claim's own — then the warnings and the
            // list.
            if flipped {
                self.on_claim_flip(&credential_lock, &serial, post.world().identity(), *at);
            }
        }
        with_signal(op_answer(ack), closed)
    }

    /// One M10 answer, marshaled, as its reply — through [`op_answer`],
    /// which is where that channel's status is chosen.
    pub(super) fn op_reply(&self, resp: &Response) -> Reply {
        op_answer(self.codec.marshal(resp))
    }
}
