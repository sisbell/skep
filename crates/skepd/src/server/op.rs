//! `POST /op`: the dispatch, the two write sequences, and the claim flip.

#[cfg(any(test, feature = "test-hooks"))]
use std::sync::atomic::Ordering;
#[cfg(any(test, feature = "test-hooks"))]
use std::thread;

use skep_engine::World;
use skep_febe::{Codec, Request, Response, SessionId};
use skep_identity::IdentityState;
use skep_kernel::{Attestation, Snapshot};

use super::actor::Resolved;
use super::reply::{credential_refused, op_answer, refuse_scan_busy, with_signal, Reply};
use super::request::HttpRequest;
use super::scan::ScanBusy;
use super::{Daemon, Moment};
use crate::auth::fold::key_set_of;
use crate::auth::policy::{
    deposits_credential_link, op_shape_refusal, plain_admission, CredentialRefusal,
    DepositSpans,
};
use crate::auth::session::Actor;
use crate::auth::LockWrite;
use crate::codec::{key_set_reply, DaemonOp};
#[cfg(any(test, feature = "test-hooks"))]
use crate::notice;
use crate::serial::SerialGuard;
use crate::write_path::{write_meta, FrameMeta};

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
    /// owed, which is why
    /// [`WritePath::write_first_head`](crate::write_path::WritePath::write_first_head)'s
    /// answer is not read here. What a refusal is and when the first head
    /// comes after one are the head writer's (`head.rs`, WHAT A REFUSAL
    /// DOES); what an attested write meets meanwhile is
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
    /// writes nothing — made by no session, they meet no list, and
    /// `IdentityFold::step_committed`'s premise already counts them.
    fn on_claim_flip(&self, credential_lock: &LockWrite<'_>, serial: &SerialGuard<'_>) {
        // THE CRASH WINDOW's seam: armed, the process is held HERE — the
        // claim durable and flipped, no head — for the harness to kill.
        #[cfg(any(test, feature = "test-hooks"))]
        if self.hold_between_claim_and_head.load(Ordering::Relaxed) {
            notice::line(Self::CLAIM_HOLD_NOTICE);
            loop {
                thread::park();
            }
        }
        // Its answer is not read: a refused `H.1` fails nothing here — the
        // claim stands (the card above), and the head writer surfaces the
        // refusal itself.
        self.writes.write_first_head(serial);
        self.log_config_warnings(Moment::AtClaim);
        self.auth.reinstall_blocked_at_claim(credential_lock);
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
    /// session), or a write, which runs one of the two pinned write
    /// sequences (AUTH-3.35 / AUTH-3.37) under the credential write lock.
    pub(super) fn post_op(&self, resolved: &Resolved, req: &HttpRequest) -> Reply {
        match self.codec.parse_daemon(&req.body) {
            Err(e) => self.op_reply(&self.codec.unparseable(e)),
            Ok(DaemonOp::KeySet { account }) => {
                // The one dispatcher (AUTH-6.20): the head pair — the live
                // fold beside the head snapshot. Principal-free.
                //
                // The FOLD IS READ FIRST, and that order is load-bearing:
                // the fold is stepped AFTER its deposit commits
                // (`commit_under` then `commit_tail`), so a fold read taken
                // after the world read can hold a key committed past
                // `as_of` and the answer would then be AHEAD of the
                // position it names. Read first, every discrepancy is the
                // one AUTH-3.36 licenses: a set at or behind its stamp,
                // never past it.
                let identity = self.auth.fold.snapshot();
                let snap = self.engine.kernel().snapshot();
                let set = key_set_of(snap.world(), &identity, &account);
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
                    self.op_reply(&self.febe.execute(self.actor_sid(&resolved.actor), *frame))
                }
                Some(meta) => self.write_sequence(resolved, meta, *frame, presented, req),
            },
        }
    }

    /// The session a request's dispatch runs under: the actor's, or M10's
    /// guest, [`SessionId::GUEST`] (M10 serves reads and refuses writes
    /// `Unauthenticated` under it).
    fn actor_sid(&self, actor: &Actor) -> SessionId {
        match actor {
            Actor::Principal(binding) => binding.sid,
            Actor::Guest(_) => SessionId::GUEST,
        }
    }

    /// One write, through its pinned sequence: the credential path for a
    /// deposit-classified op (`deposits_credential_link`, decided lock-free
    /// off the op's own type slot), the plain path for everything else.
    ///
    /// The `attest` the frame presented goes to the plain sequence alone: a
    /// credential deposit's link takes no entry signature (D26), so on that
    /// route the member goes no further than here. `frame` arrives with its
    /// `attest` EMPTY — the codec split the member out at the door
    /// (`DaemonOp::Febe`) — so the plain sequence's assignment of what its
    /// admission verified is `Request::attest`'s one writer.
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
        } else {
            self.plain_sequence(meta, frame, presented, req)
        }
    }

    /// The locked state one write sequence stands on: the world snapshot,
    /// the fold snapshot beside it, and this site's own resolution against
    /// that pair (AUTH-4.28's WHICH-lookup pin). Taken AFTER the
    /// serialization lock — which is what the guard argument proves — so no
    /// commit can intervene between what the gates read and what the
    /// execute they gate runs against.
    ///
    /// The credential lock is the CALLER's: the two sequences hold
    /// different guard types (read for the plain path, write for the
    /// credential path), and holding one is the half this signature cannot
    /// state.
    ///
    /// A COMMAND: [`Daemon::resolve_actor`]'s death arm retires the binding
    /// a dead or unknown token names, in this daemon's map, in M10 and in
    /// the credential memo — so this is not a pure read of the locked
    /// state, despite the name. Idempotent, for the reason
    /// [`Daemon::resolve_at_head`] states.
    fn locked_state(
        &self,
        _serial: &SerialGuard<'_>,
        req: &HttpRequest,
    ) -> (Snapshot<World>, IdentityState, Resolved) {
        let snap = self.engine.kernel().snapshot();
        let identity = self.auth.fold.snapshot();
        let resolved = self.resolve_actor(req, snap.world(), &identity);
        (snap, identity, resolved)
    }

    /// The answer every Guest arm gives: execute under M10's guest session,
    /// [`SessionId::GUEST`], which is M10's own `Unauthenticated` with the
    /// op kind named. This daemon holds no authorization policy of its own,
    /// so the refusal is M10's to word.
    fn guest_reply(&self, frame: Request) -> Reply {
        self.op_reply(&self.febe.execute(SessionId::GUEST, frame))
    }

    /// The PLAIN sequence (AUTH-3.35): the read lock → the serialization
    /// lock → [`Daemon::locked_state`] (the head snapshot, the fold beside
    /// it, and this site's own resolve) → `plain_admission`'s ordered
    /// producers → execute. The serial lock is taken before the snapshot so
    /// the gates' answers and the execute they gate stand on one committed
    /// state; the producers' ORDER is `plain_admission`'s, not this site's.
    fn plain_sequence(
        &self,
        meta: FrameMeta,
        mut frame: Request,
        presented: Option<Attestation>,
        req: &HttpRequest,
    ) -> Reply {
        let credential_lock = self.auth.credential_lock.read();
        let serial = self.writes.serial_lock();
        let (snap, identity, Resolved { actor, closed }) = self.locked_state(&serial, req);
        let binding = match actor {
            Actor::Principal(b) => b,
            Actor::Guest(_) => return with_signal(self.guest_reply(frame), closed),
        };
        // THE ATTESTATION's one door (signed ops; the design record §4.5
        // (1)–(2), §5.5): the producers judge the PRESENTED member beside the
        // op, and what reaches the store is what they ADMITTED — the value
        // the check verified against the fold's key set at this base, or
        // nothing. `Request::attest` held nothing until the assignment below
        // — the codec split the member out at parse — so a member the check
        // DROPPED (off the publish class; at or below the claim, A5) never
        // reaches a handle, and no later layer can fill the marker slot of a
        // write the producer set excludes.
        let admitted = match plain_admission(
            &credential_lock,
            snap.world(),
            &identity,
            &frame.op,
            binding.principal,
            binding.signer.as_ref(),
            presented,
        ) {
            Ok(admitted) => admitted,
            Err(r) => return with_signal(credential_refused(meta.kind, &r), closed),
        };
        frame.attest = admitted;
        let resp = self.writes.commit_under(&serial, meta.attributed(binding.testimony()), || {
            self.febe.execute(binding.sid, frame)
        });
        with_signal(self.op_reply(&resp), closed)
    }

    /// The CREDENTIAL sequence (AUTH-3.37): the pre-lock actor is
    /// `resolve_at_head`'s; `op_shape_refusal` and the verbatim deposit —
    /// both pure functions of the frame — run ahead of the lock; then the
    /// write lock → serial → [`Daemon::locked_state`] → recall → precheck →
    /// execute → the fold step, the memo, and the claim-flip tail — all
    /// under the write guard.
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
        // 3 — the credential write lock, the serialization lock, the locked
        // snapshot, and this site's OWN resolution.
        let credential_lock = self.auth.credential_lock.write();
        let serial = self.writes.serial_lock();
        let (snap, identity, Resolved { actor, closed }) = self.locked_state(&serial, req);
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
        if let Err(r) = crate::auth::policy::precheck(
            &credential_lock,
            snap.world(),
            &identity,
            &dep,
            binding.signer.as_ref(),
            binding.scope,
            list.header().binding_writer.as_ref(),
            self.auth.cfg.allow_preview_keys,
        ) {
            return with_signal(credential_refused(meta.kind, &r), closed);
        }
        // 7 — execute (commit-record-announce under the held serial lock,
        // then the head writer's turn, which may land the head's own commits
        // before `commit_under` returns — the `post` snapshot at 8 then holds
        // them, which `step_committed`'s premise accounts for).
        //
        // THE CREDENTIAL DEPOSIT'S MARKER SLOT STAYS EMPTY (signed ops; D26,
        // RULED 2026-09-25): the `make_link` half of a credential deposit is
        // covered by the record's own `sig` member — the record grade's
        // carrier, the record grade's lane — and takes no entry signature of
        // its own, so the `attest` a client attached is never handed to this
        // sequence (`write_sequence` passes `presented` to the plain path
        // alone) and `Request::attest` arrives empty from the codec: never
        // verified, never written. This is how the check tells D26's case by
        // ROUTE — a credential-typed link write never reaches the plain
        // sequence's producers at all.
        let req_id = frame.id.clone();
        let resp = self.writes.commit_under(&serial, meta.attributed(binding.testimony()), || {
            self.febe.execute(binding.sid, frame)
        });
        let ack = self.codec.marshal(&resp);
        if matches!(resp, Response::AckAddr { .. }) {
            // 8 — the committed tail (AUTH-3.43): the fold step from the
            // committed deposit against the post-commit snapshot, and the
            // memo entry, as one operation under the write guard.
            //
            // The `AckAddr` test is a SHAPE test standing in for "this write
            // committed", on two premises: only an address-form `MakeLink`
            // reaches here ([`DepositSpans::of`] is `Some` for nothing
            // else), and M10 acks a committed `make_link` with `AckAddr`.
            // If either failed, a committed deposit would skip this tail
            // and the live fold would fall SILENTLY behind the world until
            // restart, with `/op`'s `key_set` and `/op-at`'s at the head
            // disagreeing meanwhile.
            let post = self.engine.kernel().snapshot();
            let flipped = self.auth.commit_tail(
                &credential_lock,
                post.world(),
                &dep.deposit(),
                binding.sid,
                req_id,
                &ack,
            );
            // 9 — the claim flip's tail, under both guards: `H.1` in this
            // same step (signed ops, s1), then the warnings and the list.
            if flipped {
                self.on_claim_flip(&credential_lock, &serial);
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
