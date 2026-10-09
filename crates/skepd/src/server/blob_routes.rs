//! THE BLOB UPLOAD — "the PUT", the record's word for the surface
//! (`media.md` Op inventory 1, "THE RESUMABLE UPLOAD IS THE STANDARD SHAPE,
//! STATED ONCE", its seven clauses, the lease's crash story, the deposit
//! read; the register M-I2 (e), M-I5 (a), (c), M-I6 (b), (e); the ruling
//! ms5-R; wire.md §Media): the path family `/blob/upload`, every method of
//! it TOKEN-ACCEPTING through [`Daemon::resolve_actor`], the readiness
//! refusal of the cell index's three readers, and the pruner's pass as the
//! daemon runs it.
//!
//! THE SHAPE (the owner's ruling ms3-2: the tus protocol's SHAPE, no byte
//! of its wire): the CREATION — `POST /blob/upload?length=<N>`, the
//! identifier minted and answered before any body byte (with a body, the
//! standard's creation-with-upload: the identifier rides the `100 Continue`
//! a client that asked for one is sent before the body is invited, and the
//! answer after it); the OFFSET RESUME — `PATCH /blob/upload/<id>?offset=<K>`,
//! the bytes from `K`, refused naming the record's offset where `K` is not
//! it, and refused while another stream holds the upload; the PROGRESS —
//! `GET /blob/upload/<id>`, the offset a resume continues from; the
//! EXPIRATION — one expiry per upload, re-fixed from each byte received,
//! after which the identifier answers "no upload"; the TERMINATION —
//! `DELETE /blob/upload/<id>`, nothing kept; and THE DEPOSIT READ — `GET
//! /blob/upload`, the principal's own deposits and uploads, no surface of
//! its own (m-Q10). Every spelling here is an INTERIM pin (sm-Q8), stated
//! once in wire.md §Media.
//!
//! THE ORDER OF ONE REQUEST THAT CARRIES BYTES: the session-layer gate
//! ([`upload_admission`], the session layer's own: a guest, an unclaimed
//! board, a node-tier principal, refused before anything — D12, PUB-6.35's
//! I10, P13); THE UPLOAD SETTING — on a board whose uploads are CLOSED
//! (`--no-uploads`, echoed on `/health` as `media.uploads`) the creation
//! and the resume answer `403 upload_refused` with `detail`
//! `uploads_closed` before any body byte,
//! the upload kept where one stood, and every read and the termination
//! are served (`media.md` Op inventory 1, "ONLY ON A BOARD WHOSE UPLOADS
//! ARE OPEN"; M-I7 (e)); THE READINESS — the creation and the resume read
//! the own scope, whose base is the cell index's number, so until the
//! index's walk at open completes both are refused `index_rebuilding`,
//! 503, retry-class, as the deposit read is (ms5-R: the index's three
//! readers wait, and nothing else — the progress read, the termination,
//! every text read and write, the door's own binding arm are served
//! throughout); THE PERMIT — the creation and the resume, the two acts that
//! take bytes and no other, are admitted at most the UPLOAD POOL at once
//! ([`UploadPool`](skep_media::UploadPool),
//! [`MAX_CONCURRENT_UPLOADS`](skep_media::limits::MAX_CONCURRENT_UPLOADS) slots;
//! `media.md` Op inventory 1, "AN UPLOAD IS ADMITTED AT MOST AN UPLOAD PERMIT POOL AT
//! ONCE"; M-I5 (f): bounded by a pool, never a queue; P29, the budget
//! refuses at the layer whose work the stream multiplies — the worker each
//! stream holds to its end; P13), taken AFTER the three cheaper refusals
//! above and BEFORE the shape, the cap and every gate read, so a request
//! past the pool is refused `503 upload_busy`, retry-class as `fetch_busy`
//! and `history_busy` are, before any body byte, any record and any
//! partial: a creation refused here makes NO upload, a resume refused here
//! leaves its upload KEPT where it stood; the permit is held for the
//! request's whole life, the body's stream and the finish included, and
//! returns as the reply is composed — the progress read, the deposit read
//! and the termination take none, and the refusal names no headroom and no
//! holder (M-I6 (h); D9); the request's shape; the per-file cap and the
//! own scope on the DECLARED total, before the body — refused there, the
//! upload is KEPT (clause (6)); AT THE CREATION, before its partial and its
//! record, THE
//! STANDING-UPLOADS BOUND and THE FLOOR read on no declared length (P13,
//! P29; M-I5 (f), M-I6 (b): a creation refused `standing` or `floor` makes
//! no upload, its face naming the end of one of them where the bound
//! fired); the hold (clause (5)); then the body, chunk by chunk through
//! the one buffer, each chunk gated — the own scope, the venue's total, the
//! floor, in that order — and refused there the upload is ENDED, nothing
//! kept, the refusal naming the scope and the bytes it had taken (ms4-E1,
//! the venue total's priced residue); then, where the offset reaches the
//! length, THE FINISH under the credential lock's READ arm and never
//! `Serial`: the requester re-resolved against the head (dead there, the
//! upload is ended), the store's rename through the lease's sync, the
//! record retired, THEN the answer — one shape whether or not the file was
//! already here (M-I5 (a); "NO ANSWER OF THE UPLOAD SAYS WHETHER THE FILE
//! WAS ALREADY HERE") — and one TIME: the replaced instance's unlink is the
//! store's deferred step, run by the transport after the reply is written
//! ([`Daemon::retire_asides`]) and swept by the pruner's pass where that
//! did not run. A finish cut before its rename — a failure there, a crash
//! — leaves the upload standing over its partial at its record's offset:
//! an ordinary resume finishes it, an EMPTY one where that offset is its
//! length (clause (7); M-I5 (c)).
//!
//! THE TRANSPORT SEAM. The transport reads the request head and, for the
//! two body-carrying methods of this family, reads NO body: it hands the
//! router a [`BodySource`] over a clone of the connection's socket BESIDE
//! the request, through the daemon's private door (`Daemon::route_parked`),
//! and the router hands the source to the route, which drains the socket
//! one [`BLOB_CHUNK`](crate::limits::BLOB_CHUNK) at a time into the store. A
//! caller over its own transport — the socket-free router, the tests — has
//! none, and the route reads the request's own `body` through the same
//! type. The arm's whole memory is the one buffer the source holds; nothing
//! here ever holds the body whole.
//!
//! AND THE FETCH — `GET /blob?i=<address>`, with `HEAD` for the head alone
//! (`media.md` Op inventory 3; the register M-I2 (a)–(d), (g), M-I3 (b),
//! M-I5 (f), M-I7 (a), (b); wire.md §Media, THE FETCH): the one path beside the
//! family, TOKEN-ACCEPTING through [`Daemon::resolve_actor`] like every
//! method of it, its order THE SERVE's (`skep-media`'s `serve.rs` — the shape, M10's
//! read by identity as the gate, the classification, the permit, the whole
//! file checked before its first byte) and its answer the transport's to
//! stream ([`Routed::Fetch`]), the requester re-resolved between chunks
//! through [`Daemon::fetch_still_admitted`]. Every refusal is a reply of
//! this route's own (`reply::refuse_fetch`), class-varying as the family's
//! are; a `HEAD` is answered as its `GET` is and the transport writes the
//! head alone. Unlike the family, the fetch meets NO session-layer gate of
//! its own: a guest reads a published picture as a guest reads its cell,
//! and what the guest may not read M10's gate withholds (M-I2 (a)).

use std::io;
use std::time::Duration;

use serde_json::Value;
use skep_address::Address;
use skep_blobs::{BlobError, Finished, HashFunction, Stream, UploadId, UploadRecord};
use skep_media::gate::{DepositScope, MediaGate};
use skep_media::limits::MAX_STANDING_UPLOADS;
use skep_media::pruner::{self, PrunePass};
use skep_media::serve;
use skep_namespace::PrincipalId;
use skep_util::json::obj;

use super::actor::Resolved;
use super::reply::{
    class_varying, refuse, refuse_fetch, refuse_with, with_signal, Fetch, Reply, Routed,
    TransportError,
};
use super::request::{sole_param, BodySource, HttpRequest};
use super::Daemon;
use crate::auth::policy::{upload_admission, UploadRefusal};
use crate::auth::session::Actor;
use crate::codec::wire_address;

/// The family's own path — the creation's and the deposit read's; one
/// upload's paths lie beneath it.
const FAMILY: &str = "/blob/upload";

/// THE FETCH's one path — beside the family, never of it: `/blob/upload`
/// is the family's and `/blob/<anything else>` is unknown.
const FETCH: &str = "/blob";

/// Whether `path` is the fetch's — the router's `path_is_known` half for
/// it, and the arm test of its two methods and its preflight.
pub(super) fn is_fetch_path(path: &str) -> bool {
    path == FETCH
}

/// What a path of the family names.
pub(super) enum BlobPath {
    /// `/blob/upload` — the family's own path: the creation and the deposit
    /// read.
    Family,
    /// `/blob/upload/<id>` — one upload: the resume, the progress, the end.
    Upload(UploadId),
    /// `/blob/upload/<not an identifier>` — known, and malformed.
    Malformed,
}

/// The family's parse: `None` for a path outside it.
pub(super) fn blob_path(path: &str) -> Option<BlobPath> {
    if path == FAMILY {
        return Some(BlobPath::Family);
    }
    let rest = path.strip_prefix("/blob/upload/")?;
    Some(match UploadId::parse(rest) {
        Some(id) => BlobPath::Upload(id),
        None => BlobPath::Malformed,
    })
}

/// Whether `path` is of the family — the router's `path_is_known` half.
pub(super) fn is_blob_path(path: &str) -> bool {
    blob_path(path).is_some()
}

/// Whether a request STREAMS its body: the creation's `POST` and the
/// resume's `PATCH`, the two methods of the family that carry bytes.
pub(super) fn streams_body(method: &str, path: &str) -> bool {
    matches!(
        (method, blob_path(path)),
        ("POST", Some(BlobPath::Family)) | ("PATCH", Some(BlobPath::Upload(_)))
    )
}

// ── the routes ───────────────────────────────────────────────────────────

impl Daemon {
    /// The family's one entry: resolve the actor against the head, dispatch,
    /// attach the death signal the answer may owe.
    pub(super) fn blob_route(&self, req: &HttpRequest, body: &mut BodySource<'_>) -> Reply {
        let resolved = self.resolve_at_head(req);
        let reply = self.blob_dispatch(&resolved, req, body);
        with_signal(reply, resolved.closed)
    }

    /// THE FETCH's entry — `GET /blob?i=` and `HEAD /blob?i=` (wire.md
    /// §Media, THE FETCH): the actor resolved against the head, as every
    /// token-accepting route resolves it — the death arm closing a dead
    /// token's binding and the signal owed on the answer — then the query's
    /// shape, then THE SERVE's order (`skep-media`'s `serve.rs`) as the resolved
    /// session, the guest where none was. An admitted fetch is the
    /// transport's to stream ([`Routed::Fetch`]), its headers stamped here:
    /// the class-varying pair — the answer is a function of the presented
    /// token's class, as `/op`'s is — the inert pair, and the signal. Every
    /// refusal is an ordinary reply, class-varying and signalled the same.
    /// A `HEAD` is routed as its `GET` is — the same order, the same answer
    /// — and the transport writes the head alone (`http::write_reply`, the
    /// stream's own first step): HTTP's rule, kept in one place.
    pub(super) fn fetch_route(&self, req: &HttpRequest) -> Routed<'_> {
        let resolved = self.resolve_at_head(req);
        let refusal =
            |reply: Reply| Routed::Reply(class_varying(with_signal(reply, resolved.closed)));
        let i = match fetch_query(req.query.as_deref()) {
            Ok(i) => i,
            Err(detail) => return refusal(refuse(TransportError::MalformedBlob, Some(&detail))),
        };
        match serve::fetch(&self.febe, resolved.sid(), &self.media, &self.fetches, i) {
            Ok(admitted) => Routed::Fetch(Fetch::new(admitted, resolved.closed)),
            Err(why) => refusal(refuse_fetch(why)),
        }
    }

    /// THE MID-STREAM RE-CHECK (M-I2 (g); s6-E1 (a)): the requester
    /// re-resolved against the head — a token closed since the stream
    /// opened resolves dead, and its binding is retired by the same arm —
    /// and M10's gate run again as the session it now resolves to
    /// (`serve::gate_admits`): `false` ends the stream by a reset. A guest
    /// stays a guest and is re-gated as one: a picture unpublished
    /// mid-stream is withheld from it at the next interval.
    pub(super) fn fetch_still_admitted(&self, req: &HttpRequest, i: &Address) -> bool {
        let resolved = self.resolve_at_head(req);
        if resolved.closed {
            return false;
        }
        serve::gate_admits(&self.febe, resolved.sid(), i)
    }

    /// The media gate's clock, unix milliseconds — what the stream's time
    /// interval is judged on, so a suite drives it through the clock seam.
    pub(super) fn fetch_clock_ms(&self) -> u64 {
        self.media.now_ms()
    }

    /// THE SESSION-LAYER GATE ([`upload_admission`], which states its order
    /// and its reasons), then THE UPLOAD SETTING, then THE READINESS, then
    /// THE PERMIT, then the method. The readiness (ms5-R): the creation, the
    /// resume and the deposit read — the index's three readers at this
    /// family — are refused `index_rebuilding` until the walk at open
    /// completes; the progress read and the termination read no base and
    /// are served. The permit (M-I5 (f); P29, P13): the creation and the
    /// resume take one of the upload pool's or are refused `upload_busy` —
    /// after the three refusals above, which spend no permit, and before any
    /// byte, record or partial; held for the request's life.
    fn blob_dispatch(
        &self,
        resolved: &Resolved,
        req: &HttpRequest,
        body: &mut BodySource<'_>,
    ) -> Reply {
        let Some(target) = blob_path(&req.path) else {
            return refuse(TransportError::NoSuchEndpoint, Some(&req.path));
        };
        // THE SESSION-LAYER GATE (`auth::policy::upload_admission`), off ONE
        // head snapshot: the claim and the tier are one committed state.
        let principal = {
            let snap = self.engine.kernel().snapshot();
            match upload_admission(snap.world(), &resolved.actor) {
                Ok(principal) => principal,
                Err(refusal) => return refuse_upload(&refusal.token()),
            }
        };
        // THE UPLOAD SETTING: the two acts that take bytes, refused before
        // any body byte on a closed board; the reads and the end served.
        let takes_bytes = matches!(
            (req.method.as_str(), &target),
            ("POST", BlobPath::Family) | ("PATCH", BlobPath::Upload(_))
        );
        if takes_bytes && !self.media.uploads_open() {
            return refuse_upload("uploads_closed");
        }
        let reads_the_index = matches!(
            (req.method.as_str(), &target),
            ("POST", BlobPath::Family) | ("GET", BlobPath::Family) | ("PATCH", BlobPath::Upload(_))
        );
        if reads_the_index && !self.media.index_ready() {
            return refuse_rebuilding();
        }
        // THE PERMIT (M-I5 (f); P29, P13): the two acts that take bytes are
        // admitted at most the upload pool at once — taken here, after the
        // cheaper refusals above and before the shape, the cap and every
        // gate read, so a request past the pool is refused before any body
        // byte, any record and any partial: a creation refused here makes
        // no upload, a resume refused here leaves its upload where it
        // stood. Bound to this frame, so it spans the body's whole stream
        // and the finish, and returns as the reply is composed — a bodiless
        // creation holds it for the milliseconds its record takes; the
        // finish's deferred step (`retire_asides`) runs after the reply and
        // outside it. The reads and the termination take none.
        let _permit = if takes_bytes {
            let Some(permit) = self.uploads.admit() else {
                return refuse_upload_busy();
            };
            Some(permit)
        } else {
            None
        };
        match (req.method.as_str(), target) {
            ("POST", BlobPath::Family) => self.blob_create(principal, req, body),
            ("GET", BlobPath::Family) => Reply::json(200, deposit_read(&self.media, principal)),
            ("PATCH", BlobPath::Upload(id)) => self.blob_resume(principal, id, req, body),
            ("GET", BlobPath::Upload(id)) => self.blob_progress(principal, id),
            ("DELETE", BlobPath::Upload(id)) => self.blob_end(principal, id),
            (_, BlobPath::Malformed) => refuse(
                TransportError::MalformedBlob,
                Some("the upload's identifier is 32 lowercase hex characters"),
            ),
            _ => refuse(
                TransportError::MethodNotAllowed,
                Some("see wire.md §Media for the upload's methods"),
            ),
        }
    }

    /// THE CREATION (clause (1)): `length=<N>`, the per-file cap on it, the
    /// own scope on it BEFORE the body, then the standing-uploads bound and
    /// the floor on no declared length (`MediaGate::admit_creation`) — each
    /// refusal before the partial and the record, no upload made — the
    /// identifier minted and the record written; with no body the answer is
    /// the record; with one — the creation-with-upload — the identifier is
    /// held and the body streamed.
    fn blob_create(
        &self,
        principal: PrincipalId,
        req: &HttpRequest,
        body: &mut BodySource<'_>,
    ) -> Reply {
        let length = match create_query(req.query.as_deref()) {
            Ok(n) => n,
            Err(detail) => return refuse(TransportError::MalformedBlob, Some(&detail)),
        };
        let limits = self.media.limits();
        if length > limits.per_file_cap {
            return refuse(
                TransportError::PayloadTooLarge,
                Some(&format!(
                    "length {length} exceeds the {}-byte per-file cap",
                    limits.per_file_cap
                )),
            );
        }
        if body.declared() as u64 > length {
            return refuse(
                TransportError::UploadLength,
                Some(&format!(
                    "the body's {} bytes exceed the declared length {length}",
                    body.declared()
                )),
            );
        }
        let now = self.media.now_ms();
        if let Err(scope) = self.media.admit_declared(principal, length, now) {
            return refuse_deposit(scope, RefusedAt::BeforeTheBody, 0);
        }
        if let Err(scope) = self.media.admit_creation(principal, now) {
            return refuse_deposit(scope, RefusedAt::BeforeTheBody, 0);
        }
        let interval = Duration::from_millis(limits.lease_interval_ms);
        let record = match self.media.store().create_upload(
            &MediaGate::key(principal),
            HashFunction::Blake3,
            length,
            interval,
            now,
        ) {
            Ok(r) => r,
            Err(e) => return refuse(TransportError::BlobIo, Some(&e.to_string())),
        };
        if body.declared() == 0 {
            return progress_reply(&record);
        }
        let id = record.id;
        // Fresh, so no other stream can hold it; held all the same, so the
        // pruner's re-read and a racing resume meet the hold until it drops.
        let _hold = self.media.claim(id);
        let hex = id.to_hex();
        self.stream_body(principal, record, req, body, &[("Upload-Id", hex.as_str())])
    }

    /// THE RESUME (clauses (3), (5), (6)): the record under the requester's
    /// own key, the hold, the stated offset against the record's, the
    /// request's bytes against the length, the own scope on what the upload
    /// leaves past the offset BEFORE the body — refused there, the upload
    /// is kept — then the body.
    fn blob_resume(
        &self,
        principal: PrincipalId,
        id: UploadId,
        req: &HttpRequest,
        body: &mut BodySource<'_>,
    ) -> Reply {
        let offset = match resume_query(req.query.as_deref()) {
            Ok(n) => n,
            Err(detail) => return refuse(TransportError::MalformedBlob, Some(&detail)),
        };
        let now = self.media.now_ms();
        let Some(record) = self.media.store().upload(&MediaGate::key(principal), &id, now) else {
            return refuse(TransportError::NoUpload, None);
        };
        let Some(_hold) = self.media.claim(id) else {
            return refuse(TransportError::UploadHeld, Some("another stream holds this upload"));
        };
        self.resume_held(principal, record, offset, req, body)
    }

    /// The resume under its hold: the stated `offset` held to the record's
    /// own — the one offset [`Daemon::stream_body`] resumes at — then the
    /// request's bytes against the length and the own scope, then the body.
    fn resume_held(
        &self,
        principal: PrincipalId,
        record: UploadRecord,
        offset: u64,
        req: &HttpRequest,
        body: &mut BodySource<'_>,
    ) -> Reply {
        if offset != record.offset {
            return refuse_with(
                TransportError::UploadOffset,
                vec![("offset", Value::Number(record.offset.into()))],
            );
        }
        let declared = body.declared() as u64;
        if offset.saturating_add(declared) > record.length {
            return refuse(
                TransportError::UploadLength,
                Some(&format!(
                    "{declared} bytes at offset {offset} would pass the declared length {}",
                    record.length
                )),
            );
        }
        let now = self.media.now_ms();
        if let Err(scope) = self.media.admit_declared(principal, record.length - offset, now) {
            return refuse_deposit(scope, RefusedAt::BeforeTheBody, record.offset);
        }
        self.stream_body(principal, record, req, body, &[])
    }

    /// THE BODY, chunk by chunk: resumed at the record's own offset — a
    /// fresh record's zero at the creation, the stated offset the resume held
    /// to it — each chunk gated as the body is written and then appended; a
    /// connection that dies or stalls KEEPS the upload at its durable point;
    /// a refusal as the body is written ENDS it; a body that leaves the
    /// upload short of its length settles and answers the record; one that
    /// reaches it goes on to the finish. The store's records are keyed to
    /// `principal` ([`MediaGate::key`]).
    fn stream_body(
        &self,
        principal: PrincipalId,
        record: UploadRecord,
        req: &HttpRequest,
        body: &mut BodySource<'_>,
        interim: &[(&str, &str)],
    ) -> Reply {
        let store = self.media.store();
        let key = MediaGate::key(principal);
        let id = record.id;
        let now = self.media.now_ms();
        let mut stream = match store.resume(&key, &id, record.offset, now) {
            Ok(stream) => stream,
            Err(e) => return blob_refusal(e),
        };
        if body.begin(interim).is_err() {
            return refuse(TransportError::MalformedHttp, Some("client went away at 100-continue"));
        }
        let mut written = record.offset;
        loop {
            let chunk = match body.next_chunk() {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => {
                    // The connection died or stalled: the upload is KEPT at
                    // its durable point — what was written settles.
                    let _ = stream.settle(self.media.now_ms());
                    return refuse(
                        TransportError::MalformedHttp,
                        Some(&format!("request body not delivered: {e}")),
                    );
                }
            };
            let n = chunk.len() as u64;
            if let Err(scope) = self.media.admit_bytes(principal, &id, written, n, now) {
                // REFUSED IS ENDED (clause (6)): nothing kept.
                drop(stream);
                let _ = store.end_upload(&key, &id, now);
                return refuse_deposit(scope, RefusedAt::AsTheBodyIsWritten, written);
            }
            match stream.append(chunk, self.media.now_ms()) {
                Ok(w) => written = w,
                Err(e) => return blob_refusal(e),
            }
        }
        // `Stream::finish`'s precondition, discharged here: the bytes written
        // reach the length, or the request settles instead of finishing.
        if written < record.length {
            return match stream.settle(self.media.now_ms()) {
                Ok(r) => progress_reply(&r),
                Err(e) => blob_refusal(e),
            };
        }
        self.blob_finish(principal, id, stream, req)
    }

    /// THE FINISH (clause (7); M-I5 (a)), under the credential lock's READ
    /// arm from the rename through the lease's sync — the lock the plain
    /// write path's door holds, so the check that reads the lease and the
    /// finish that writes it never interleave with a credential write; never
    /// `Serial`, which orders commits and the PUT commits nothing. The
    /// requester is re-resolved against the head under it: a session killed
    /// mid-transfer is dead at its rename — its token resolves to an actor
    /// other than `principal`, the stream's own — its upload ended, nothing
    /// kept (clause (6); M-I2 (g)).
    fn blob_finish(
        &self,
        principal: PrincipalId,
        id: UploadId,
        stream: Stream<'_>,
        req: &HttpRequest,
    ) -> Reply {
        let store = self.media.store();
        let _credential_lock = self.auth.credential_lock.read();
        let now = self.media.now_ms();
        let resolved = {
            let snap = self.engine.kernel().snapshot();
            self.resolve_actor(req, snap.world())
        };
        let same = matches!(&resolved.actor, Actor::Principal(b) if b.principal == principal);
        if !same {
            drop(stream);
            let _ = store.end_upload(&MediaGate::key(principal), &id, now);
            return with_signal(
                refuse_upload(&UploadRefusal::Unauthenticated.token()),
                resolved.closed,
            );
        }
        match stream.finish(Duration::from_millis(self.media.limits().lease_interval_ms), now) {
            Ok(finished) => finish_reply(&finished),
            Err(e) => blob_refusal(e),
        }
    }

    /// THE PROGRESS: the upload's record under the requester's own key — the
    /// offset a resume continues from.
    fn blob_progress(&self, principal: PrincipalId, id: UploadId) -> Reply {
        match self.media.store().upload(&MediaGate::key(principal), &id, self.media.now_ms()) {
            Some(r) => progress_reply(&r),
            None => refuse(TransportError::NoUpload, None),
        }
    }

    /// THE END (clause (6), the termination): claimed as a stream claims
    /// it, then ended — nothing kept; `204`.
    fn blob_end(&self, principal: PrincipalId, id: UploadId) -> Reply {
        let Some(_hold) = self.media.claim(id) else {
            return refuse(TransportError::UploadHeld, Some("another stream holds this upload"));
        };
        match self.media.store().end_upload(&MediaGate::key(principal), &id, self.media.now_ms()) {
            Ok(()) => Reply { status: 204, body: None, headers: Vec::new() },
            Err(e) => blob_refusal(e),
        }
    }

    /// THE DEFERRED STEP of a replace (the store's `unlink_asides`): the
    /// replaced instance's names unlinked, off the answer's path — the
    /// transport runs it after a blob reply is written; the pruner's pass
    /// sweeps whatever it did not reach. An I/O failure here is the
    /// operator's line, never a client's: the aside stands for the pass or
    /// the next open.
    pub(super) fn retire_asides(&self) {
        // THE FAULT (test seam): a panic inside the deferred step, which the
        // transport's catch around this call contains.
        #[cfg(any(test, feature = "test-hooks"))]
        self.fire_the_unlinks_fault();
        if let Err(e) = self.media.store().unlink_asides() {
            skep_util::notice::line(format_args!(
                "blob store: a replaced file's aside could not be unlinked: {e}"
            ));
        }
    }

    /// THE PRUNER's PASS, as the daemon runs it (`skep-media`'s `pruner.rs`): the
    /// credential lock's WRITE arm taken for one file at a time. `None`
    /// where the index is not ready — the pass does not start (ms5-R).
    pub(super) fn prune_pass(&self) -> io::Result<Option<PrunePass>> {
        pruner::pass(&self.media, || self.auth.credential_lock.write())
    }

    /// Whether the cell index's walk at open has completed — what the
    /// pruner's loop waits on before its first pass.
    pub(super) fn index_is_ready_for_pruning(&self) -> bool {
        self.media.index_ready()
    }
}

// ── the queries, the answers, the refusals ───────────────────────────────

/// THE FETCH's query: exactly `i=<address>` ([`sole_param`]), the address in
/// the wire's dotted-decimal form through the codec's own door
/// (`wire_address`), so a query string's address and a frame's meet one
/// grammar under one budget. What the address must NAME — an element
/// position of a document — is the serve's step 0, not this parse's.
fn fetch_query(query: Option<&str>) -> Result<Address, String> {
    let i = sole_param(query, "i")?.ok_or("the required parameter is i=<address>")?;
    wire_address(i).map_err(|e| format!("i: {e}"))
}

/// The creation's query: exactly `length=<bytes>` ([`sole_param`]).
fn create_query(query: Option<&str>) -> Result<u64, String> {
    let length = sole_param(query, "length")?.ok_or("the required parameter is length=<bytes>")?;
    count(length, "length")
}

/// The resume's query: exactly `offset=<bytes>` ([`sole_param`]).
fn resume_query(query: Option<&str>) -> Result<u64, String> {
    let offset = sole_param(query, "offset")?.ok_or("the required parameter is offset=<bytes>")?;
    count(offset, "offset")
}

/// A byte count: `1*DIGIT`, in range.
fn count(v: &str, name: &str) -> Result<u64, String> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{name}: '{v}' is not a byte count"));
    }
    v.parse().map_err(|_| format!("{name}: '{v}' is not a byte count"))
}

/// The record as the wire answers it: the identifier, the offset a resume
/// continues from, the length, the expiry.
fn progress_reply(r: &UploadRecord) -> Reply {
    Reply::json(
        200,
        obj(vec![
            ("expires", Value::Number(r.expires.into())),
            ("length", Value::Number(r.length.into())),
            ("offset", Value::Number(r.offset.into())),
            ("upload", Value::String(r.id.to_hex())),
        ]),
    )
}

/// The finish as the wire answers it: the designation, the hash, the size
/// — what the client compares with its own and never adopts (Q-sm2).
fn finish_reply(f: &Finished) -> Reply {
    Reply::json(
        200,
        obj(vec![
            ("designation", Value::String(f.designation.clone())),
            ("hash", Value::String(f.hex.clone())),
            ("size", Value::Number(f.size.into())),
        ]),
    )
}

/// `403 upload_refused`, naming which: the session layer's refusal
/// ([`UploadRefusal::token`]) or the closed setting's `uploads_closed`.
fn refuse_upload(detail: &str) -> Reply {
    refuse(TransportError::UploadRefused, Some(detail))
}

/// THE READINESS REFUSAL (ms5-R): the cell index's walk at open is not
/// done, and this request is one of its three readers.
fn refuse_rebuilding() -> Reply {
    refuse(
        TransportError::IndexRebuilding,
        Some("the cell index is being rebuilt from the board; retry shortly"),
    )
}

/// THE PERMIT's REFUSAL (M-I5 (f); P29): every upload permit is in use, and
/// this request is the creation or the resume — the fetch's `fetch_busy`
/// twin, its `detail` naming the one act the person holds, the retry
/// (M-I7 (e)), and no headroom and no holder (M-I6 (h); D9).
fn refuse_upload_busy() -> Reply {
    refuse(TransportError::UploadBusy, Some("all upload permits are in use; retry shortly"))
}

/// Where the media gate refused a deposit — clause (6)'s two cases, each
/// with what it leaves of the upload, which the refusal's `ended` reports.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RefusedAt {
    /// Before the body, on the declared total or at the creation: the upload
    /// is KEPT (none made, at a creation).
    BeforeTheBody,
    /// As the body is written: the upload is ENDED, nothing kept.
    AsTheBodyIsWritten,
}

/// The media gate's refusal: the scope it fired on, where — and so whether
/// the upload was ended or kept ([`RefusedAt`]) — and the bytes received; no
/// headroom (M-I6 (h)). At the standing-uploads bound, a `detail` naming the
/// end of one of them as the act the person holds (M-I7 (e)) — the count the
/// bound pins, which the same principal's deposit read lists upload by
/// upload.
fn refuse_deposit(scope: DepositScope, at: RefusedAt, offset: u64) -> Reply {
    let mut fields = vec![
        ("ended", Value::Bool(at == RefusedAt::AsTheBodyIsWritten)),
        ("offset", Value::Number(offset.into())),
        ("scope", Value::String(scope.token().into())),
    ];
    if scope == DepositScope::Standing {
        fields.push((
            "detail",
            Value::String(format!(
                "this account holds {} standing uploads, the most this board keeps: end one of them, \
                 then create again",
                MAX_STANDING_UPLOADS
            )),
        ));
    }
    refuse_with(TransportError::DepositRefused, fields)
}

/// THE DEPOSIT READ (`media.md` Op inventory 1, "THE DEPOSITOR CAN READ
/// THEIR OWN DEPOSIT RECORD, AND THE RESUME NAMES ONE ACT PER RESIDUE"; "IT
/// ANSWERS THE REQUESTER's OWN USAGE BESIDE THEM"; the register M-I5 (c),
/// M-I2 (e), M-I6 (a), (b)): one read of the asking principal's OWN records
/// — its standing deposits (hash, size, expiry; a live lease over a file
/// that is not there marked LAPSED, at this read as at the `insert`), its
/// standing uploads (identifier, the offset a resume continues from, the
/// length, the expiry), its usage as two figures — the BASE, the cell
/// index's number for its account (the distinct hashes its cells name, at
/// their size), and its PENDING bytes (its live leases on hashes none of
/// its cells names, and its uploads' bytes received) — the limits
/// record's address as installed, or `null` where none is — and THE
/// PER-ACCOUNT LIMIT IN FORCE, `per_account`, whatever its source: the
/// daemon's default where no record is installed, echoed as a written
/// limit is, so R68's read-before-refusal holds under the default (P37; the
/// register M-I6 (b), (d)); `null` only where a written record sets none.
///
/// NO SURFACE OF ITS OWN (m-Q10, RULED): it is the resumable PUT's own
/// state made readable, served on the upload's path family (`GET
/// /blob/upload`) and priced with the transport delta — a route helper
/// beside the family's refusals, built off the media gate's reads as the
/// family's other wire shapes are built here and in `reply.rs`, the one
/// wire shape of the resource's that the daemon composes. It is keyed to
/// the asking principal's own record and never to a file's presence beyond
/// that record's live lease: it lists no deposit of another's, and answers
/// "this board holds these bytes" of nothing a principal did not deposit
/// itself. Its base is one of the index's three readers: the route refuses
/// it `index_rebuilding` until the walk at open completes (ms5-R). The
/// sweep-3 subtraction of this read was DECLINED (sm-Q10): the records
/// exist for the resume and the binding, and the listing is this one
/// function over them.
///
/// The read, as its JSON object, off `media_gate`, the media gate whose store
/// holds the records. The caller has read the index's readiness: the base
/// here is the index's number.
fn deposit_read(media_gate: &MediaGate, principal: PrincipalId) -> Value {
    let key = MediaGate::key(principal);
    let now = media_gate.now_ms();
    let store = media_gate.store();
    let deposits: Vec<Value> = store
        .live_leases_of(&key, now)
        .into_iter()
        .map(|l| {
            // Exact of what is on disk: a lease over a file that is absent
            // or not whole reads as LAPSED here as at the insert — and so,
            // as the binding takes it, does one whose size cannot be read.
            let whole = store.blob_size(&l.designation, &l.hex).ok().flatten() == Some(l.size);
            obj(vec![
                ("designation", Value::String(l.designation)),
                ("expires", Value::Number(l.expires.into())),
                ("hash", Value::String(l.hex)),
                ("lapsed", Value::Bool(!whole)),
                ("size", Value::Number(l.size.into())),
            ])
        })
        .collect();
    let uploads: Vec<Value> = store
        .uploads_of(&key, now)
        .into_iter()
        .map(|r| {
            obj(vec![
                ("expires", Value::Number(r.expires.into())),
                ("length", Value::Number(r.length.into())),
                ("offset", Value::Number(r.offset.into())),
                ("upload", Value::String(r.id.to_hex())),
            ])
        })
        .collect();
    let limits = media_gate.limits();
    obj(vec![
        // Record-derived: the index's one number for the account.
        ("base", Value::Number(media_gate.index().base(principal).into())),
        ("deposits", Value::Array(deposits)),
        ("limits", limits.address.map_or(Value::Null, Value::String)),
        ("pending", Value::Number(media_gate.own_pending(principal, now).into())),
        // The limit in force, the default or the record's — the echo R68's
        // read keys on.
        ("per_account", limits.per_account.map_or(Value::Null, |n| Value::Number(n.into()))),
        ("uploads", Value::Array(uploads)),
    ])
}

/// The store's refusal as the wire's.
fn blob_refusal(e: BlobError) -> Reply {
    match e {
        BlobError::NoUpload => refuse(TransportError::NoUpload, None),
        BlobError::Offset { recorded } => refuse_with(
            TransportError::UploadOffset,
            vec![("offset", Value::Number(recorded.into()))],
        ),
        BlobError::Length { length, offset } => refuse(
            TransportError::UploadLength,
            Some(&format!("the bytes at offset {offset} would pass the declared length {length}")),
        ),
        BlobError::Io(e) => refuse(TransportError::BlobIo, Some(&e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The family's parse: the creation, an upload by a well-formed
    /// identifier, a malformed one (known, refused by name), and the paths
    /// outside it; and which method/path pairs stream.
    #[test]
    fn the_path_family_and_the_streaming_pairs() {
        assert!(matches!(blob_path("/blob/upload"), Some(BlobPath::Family)));
        let id = "0123456789abcdef0123456789abcdef";
        assert!(matches!(blob_path(&format!("/blob/upload/{id}")), Some(BlobPath::Upload(_))));
        assert!(matches!(blob_path("/blob/upload/"), Some(BlobPath::Malformed)));
        assert!(matches!(blob_path("/blob/upload/xyz"), Some(BlobPath::Malformed)));
        assert!(matches!(
            blob_path(&format!("/blob/upload/{}", id.to_uppercase())),
            Some(BlobPath::Malformed)
        ));
        for outside in ["/blob", "/blob/", "/blob/uploads", "/blob/upload2", "/op", "/"] {
            assert!(blob_path(outside).is_none(), "{outside}");
        }
        assert!(streams_body("POST", "/blob/upload"));
        assert!(streams_body("PATCH", &format!("/blob/upload/{id}")));
        for (m, p) in [
            ("GET", "/blob/upload"),
            ("DELETE", &format!("/blob/upload/{id}")[..]),
            ("POST", &format!("/blob/upload/{id}")[..]),
            ("PATCH", "/blob/upload"),
            ("POST", "/op"),
        ] {
            assert!(!streams_body(m, p), "{m} {p}");
        }
        assert_eq!(create_query(Some("length=12")), Ok(12));
        assert!(create_query(Some("length=12&length=13")).is_err());
        assert!(create_query(Some("length=+1")).is_err());
        assert!(create_query(Some("size=1")).is_err());
        assert!(create_query(None).is_err());
        assert_eq!(resume_query(Some("offset=0")), Ok(0));
        assert!(resume_query(Some("offset=")).is_err());
        let r = refuse_rebuilding();
        assert_eq!(r.status, 503);
        assert!(String::from_utf8_lossy(r.bytes()).contains("\"error\":\"index_rebuilding\""));
        // The permit's refusal (M-I5 (f)): retry-class, its detail naming
        // the retry and no figure.
        let r = refuse_upload_busy();
        assert_eq!(r.status, 503);
        let text = String::from_utf8_lossy(r.bytes()).to_string();
        assert!(text.contains("\"error\":\"upload_busy\""), "{text}");
        assert!(text.contains("retry") && !text.chars().any(|c| c.is_ascii_digit()), "{text}");
        // The fetch's path beside the family, and its query: exactly one
        // `i`, an address by the codec's grammar; what it names is the
        // serve's to judge.
        assert!(is_fetch_path("/blob"));
        for not in ["/blob/", "/blob/upload", "/blob?i=1", "/Blob", "/blobs"] {
            assert!(!is_fetch_path(not), "{not}");
        }
        assert_eq!(
            fetch_query(Some("i=1.0.1.0.2.0.1.1")).map(|a| a.tumbler().to_string()),
            Ok("1.0.1.0.2.0.1.1".into())
        );
        assert_eq!(
            fetch_query(Some("i=1.0.1.0.2")).map(|a| a.tumbler().to_string()),
            Ok("1.0.1.0.2".into()),
            "a document: the shape is the serve's"
        );
        for bad in [
            None,
            Some(""),
            Some("i="),
            Some("i=1..2"),
            Some("i=x"),
            Some("i=1.1&i=1.2"),
            Some("at=1.1"),
            Some("i"),
        ] {
            assert!(fetch_query(bad).is_err(), "{bad:?}");
        }
    }
}
