//! The blob upload — "the PUT", the record's word — and the blob fetch.
//!
//! The upload is the surface of `media.md` Op inventory 1 ("the resumable
//! upload is the standard shape, stated once", its seven clauses, the
//! lease's crash story, the deposit read; the register M-I2 (e), M-I5 (a),
//! (c), M-I6 (b), (e); wire.md §Media): the path family `/blob/upload`,
//! every method of it token-accepting through [`Daemon::resolve_actor`],
//! the readiness refusal of the cell index's three readers, and the
//! pruner's pass as the daemon runs it.
//!
//! **The shape** is the tus protocol's *shape*, no byte of its wire: the
//! creation — `POST /blob/upload?length=<N>`, the identifier minted before
//! any body byte and answered at once where no body follows (with a body,
//! the standard's creation-with-upload: the identifier rides the
//! `100 Continue` a client that asked for one is sent before the body is
//! invited, and the answer comes after the body — the record where the
//! upload stays short of its length, the finish's answer where it reaches
//! it); the offset resume — `PATCH /blob/upload/<id>?offset=<K>`, the
//! bytes from `K`, refused naming the record's offset where `K` is not it,
//! and refused while another stream holds the upload; the progress —
//! `GET /blob/upload/<id>`, the offset a resume continues from; the
//! expiration — one expiry per upload, re-fixed from each byte received,
//! after which the identifier answers "no upload"; the termination —
//! `DELETE /blob/upload/<id>`, nothing kept; and the deposit read —
//! `GET /blob/upload`, the principal's own deposits and uploads, no surface
//! of its own. Every spelling here is an interim pin, stated once in
//! wire.md §Media.
//!
//! **The order of one request that carries bytes.** The session-layer gate
//! ([`upload_admission`], the session layer's own: a guest, an unclaimed
//! board, a node-tier principal, refused before anything — D12, PUB-6.35's
//! I10, P13); the upload setting — on a board whose uploads are closed
//! (`--no-uploads`, echoed on `/health` as `media.uploads`) the creation
//! and the resume answer `403 upload_refused` with `detail`
//! `uploads_closed` before any body byte, the upload kept where one stood,
//! and every read and the termination are served (`media.md` Op inventory
//! 1, "only on a board whose uploads are open"; M-I7 (e)); the readiness —
//! the creation and the resume read the own scope, whose base is the cell
//! index's number, so until the index's walk at open completes both are
//! refused `index_rebuilding`, 503, retry-class, as the deposit read is
//! (the index's three readers wait, and nothing else — the progress read,
//! the termination, every text read and write, the door's own binding arm
//! are served throughout, the door answering `index_rebuilding` only where
//! its lease arm alone refuses) — or, where that walk died,
//! `index_failed`, 503, for the life of the process, its `detail` naming
//! the operator's act and no retry (`operations.md` §4 row 26; PATTERNS
//! P10), read ahead of the readiness so a failed index never answers the
//! retry-class token; the permit — the creation and the resume, the two
//! acts that take bytes and no other, are admitted at most the upload pool
//! at once ([`UploadPool`](skep_media::pools::UploadPool),
//! [`MAX_CONCURRENT_UPLOADS`](skep_media::limits::MAX_CONCURRENT_UPLOADS)
//! slots; `media.md` Op inventory 1, "an upload is admitted at most an
//! upload permit pool at once"; M-I5 (f): bounded by a pool, never a
//! queue; P29, the budget refuses at the layer whose work the stream
//! multiplies — the worker each stream holds to its end; P13), taken after
//! the three cheaper refusals above and before the shape, the cap and every
//! gate read, so a request past the pool is refused `503 upload_busy`,
//! retry-class as `fetch_busy` and `history_busy` are, before any body
//! byte, any record and any partial: a creation refused here makes no
//! upload, a resume refused here leaves its upload kept where it stood; the
//! permit is held for the request's whole life, the body's stream and the
//! finish included, and returns as the reply is composed — the progress
//! read, the deposit read and the termination take none, and the refusal
//! names no headroom and no holder (M-I6 (h); D9); the request's shape; the
//! per-file cap, the request's bytes against the declared length and the
//! own scope on the declared total, before the body — refused there, the
//! upload is kept (clause (6)); at the creation, before its partial and its
//! record, the standing-uploads bound and the floor read on no declared
//! length (P13, P29; M-I5 (f), M-I6 (b): a creation refused `standing` or
//! `floor` makes no upload, its face naming the end of one of them where
//! the bound fired); the hold (clause (5)) — at the
//! resume taken once its record is found, ahead of its offset and its own
//! scope; then the body, chunk by chunk through the one buffer, each chunk
//! gated — the own scope, the venue's total, the floor, in that order — and
//! refused there the upload is ended, nothing kept, the refusal naming the
//! scope and the bytes it had taken (the venue total's priced residue);
//! then, where the offset reaches the length, the finish under the
//! credential lock's read arm and never `Serial`: the requester re-resolved
//! against the head (dead there, the upload is ended), the store's rename
//! through the lease's sync, the record retired, *then* the answer — one
//! shape whether or not the file was already here (M-I5 (a); "no answer of
//! the upload says whether the file was already here") — and one *time*:
//! the replaced instance's unlink is the store's deferred step, run by the
//! transport after the reply is written ([`Daemon::retire_asides`]) and
//! swept by the pruner's pass where that did not run. A finish cut before
//! its rename — a failure there, a crash — leaves the upload standing over
//! its partial at its record's offset: an ordinary resume finishes it, an
//! empty one where that offset is its length (clause (7); M-I5 (c)).
//!
//! **The transport seam.** The transport reads the request head and, for
//! the two body-carrying methods of this family, reads no body: it hands
//! the router a [`BodySource`] over a clone of the connection's socket
//! *beside* the request, through the daemon's private door
//! (`Daemon::route_parked`), and the router hands the source to the route,
//! which drains the socket one [`BLOB_CHUNK`](crate::limits::BLOB_CHUNK) at
//! a time into the store. A caller over its own transport — the socket-free
//! router, the tests — has none, and the route reads the request's own
//! `body` through the same type. The arm's whole memory is the one buffer
//! the source holds and the body bytes that arrived with the head; nothing
//! here ever holds the body whole.
//!
//! **And the fetch** — `GET /blob?i=<address>`, with `HEAD` for the head
//! alone (`media.md` Op inventory 3; the register M-I2 (a)–(d), (g),
//! M-I3 (b), M-I5 (f), M-I7 (a), (b); wire.md §Media, the fetch): the one
//! path beside the family, token-accepting through
//! [`Daemon::resolve_actor`] like every method of it, its order the serve's
//! (`skep-media`'s `serve.rs` — the shape, M10's read by identity as the
//! gate, the classification, the permit, the whole file checked before its
//! first byte) and its answer the transport's to stream ([`Routed::Fetch`]),
//! the requester re-resolved between chunks through
//! [`Daemon::fetch_still_admitted`]. Every refusal is a reply of this
//! route's own (`reply::refuse_fetch`, and `malformed_blob` for its query),
//! class-varying as the family's are; a `HEAD` is answered as its `GET` is
//! and the transport writes the head alone. Unlike the family, the fetch
//! meets no session-layer gate of its own: a guest reads a published
//! picture as a guest reads its cell, and what the guest may not read M10's
//! gate withholds (M-I2 (a)).

use std::sync::atomic::Ordering;
use std::time::Instant;

use serde_json::Value;
use skep_address::Address;
use skep_blobs::{BlobError, Finished, Stream, UploadId, UploadRecord};
use skep_media::gate::{DepositScope, MediaGate};
use skep_media::limits::MAX_STANDING_UPLOADS;
use skep_media::pruner::PrunePass;
use skep_media::serve;
use skep_namespace::PrincipalId;
use skep_util::json::obj;
use skep_util::notice::Class;

use super::actor::Resolved;
use super::reply::{
    class_varying, refuse, refuse_fetch, refuse_with, with_signal, Fetch, Reply, Routed,
    TransportError,
};
use super::request::{sole_param, BodySource, HttpRequest};
use super::Daemon;
use skep_core::auth::policy::{upload_admission, UploadRefusal};
use skep_core::auth::session::Actor;
use skep_core::codec::wire_address;

/// The family's own path: the creation's and the deposit read's.
///
/// One upload's paths lie beneath it.
const FAMILY: &str = "/blob/upload";

/// The fetch's one path, beside the family and never of it.
///
/// `/blob/upload` is the family's and `/blob/<anything else>` is unknown.
const FETCH: &str = "/blob";

/// Returns whether `path` is the fetch's.
///
/// It is the router's `path_is_known` half for it, and the arm test of its
/// two methods and its preflight.
pub(super) fn is_fetch_path(path: &str) -> bool {
    path == FETCH
}

/// What a path of the family names.
pub(super) enum BlobPath {
    /// `/blob/upload`, the family's own path.
    ///
    /// It names the creation and the deposit read.
    Family,
    /// `/blob/upload/<id>` — one upload: the resume, the progress, the end.
    Upload(UploadId),
    /// `/blob/upload/<not an identifier>` — known, and malformed.
    Malformed,
}

/// Parses a path of the family, or answers `None` for a path outside it.
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

/// Returns whether `path` is of the family: the router's `path_is_known` half.
pub(super) fn is_blob_path(path: &str) -> bool {
    blob_path(path).is_some()
}

/// Returns whether a request streams its body.
///
/// It does for the creation's `POST` and the resume's `PATCH`, the two
/// methods of the family that carry bytes.
pub(super) fn streams_body(method: &str, path: &str) -> bool {
    matches!(
        (method, blob_path(path)),
        ("POST", Some(BlobPath::Family)) | ("PATCH", Some(BlobPath::Upload(_)))
    )
}

// ── the routes ───────────────────────────────────────────────────────────

impl Daemon {
    /// Routes one request of the family, through its one entry.
    ///
    /// It resolves the actor against the head, dispatches, and attaches the
    /// death signal the answer may owe.
    pub(super) fn blob_route(&self, req: &HttpRequest, body: &mut BodySource<'_>) -> Reply {
        let resolved = self.resolve_at_head(req);
        let reply = self.blob_dispatch(&resolved, req, body);
        with_signal(reply, resolved.closed)
    }

    /// Routes the fetch: `GET /blob?i=` and `HEAD /blob?i=`.
    ///
    /// It follows wire.md §Media, the fetch: the actor resolved against the
    /// head, as every token-accepting route resolves it — the death arm
    /// closing a dead token's binding and the signal owed on the answer —
    /// then the query's shape, then the serve's order (`skep-media`'s
    /// `serve.rs`) as the resolved session, the guest where none was. An
    /// admitted fetch is the transport's to stream ([`Routed::Fetch`]), its
    /// headers stamped here: the class-varying pair — the answer is a
    /// function of the presented token's class, as `/op`'s is — the inert
    /// pair, and the signal. Every refusal is an ordinary reply,
    /// class-varying and signalled the same. A `HEAD` is routed as its `GET`
    /// is — the same order, the same answer — and the transport writes the
    /// head alone (`http::write_reply` for a refusal; for an admitted fetch,
    /// `http::write_fetch_head`, the stream's own first step): HTTP's rule,
    /// kept at the transport.
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

    /// Re-checks the requester mid-stream (M-I2 (g)).
    ///
    /// The requester is re-resolved against the head — a token closed since
    /// the stream opened resolves dead, and its binding is retired by the
    /// same arm — and M10's gate run again as the session it now resolves to
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

    /// Returns the media gate's clock, in unix milliseconds.
    ///
    /// It is what the stream's time interval is judged on, so a suite drives
    /// it through the clock seam.
    pub(super) fn fetch_clock_ms(&self) -> u64 {
        self.media.now_ms()
    }

    /// Dispatches one request of the family, its gates first.
    ///
    /// The order is the session-layer gate ([`upload_admission`], which
    /// states its order and its reasons), then the upload setting, then the
    /// readiness, then the permit, then the method. The readiness: the
    /// creation, the resume and the deposit read — the index's three readers
    /// at this family — are refused `index_rebuilding` until the walk at open
    /// completes, and `index_failed` for the uptime where that walk died
    /// (`operations.md` §4 row 26), the failed state read first so a failed
    /// index never answers the retry-class token; the progress read and the
    /// termination read no base and are served. The permit (M-I5 (f); P29,
    /// P13): the creation and the resume take one of the upload pool's or
    /// are refused `upload_busy` — after the three refusals above, which
    /// spend no permit, and before any byte, record or partial; held for the
    /// request's life.
    fn blob_dispatch(
        &self,
        resolved: &Resolved,
        req: &HttpRequest,
        body: &mut BodySource<'_>,
    ) -> Reply {
        let Some(target) = blob_path(&req.path) else {
            return refuse(TransportError::NoSuchEndpoint, Some(&req.path));
        };
        // The session-layer gate (`skep_core::auth::policy::upload_admission`),
        // off one head snapshot: the claim and the tier are one committed
        // state.
        let principal = {
            let snap = self.engine.kernel().snapshot();
            match upload_admission(snap.world(), &resolved.actor) {
                Ok(principal) => principal,
                Err(refusal) => return refuse_upload(&refusal.token()),
            }
        };
        // The upload setting: the two acts that take bytes, refused before
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
        // The failed state before the not-ready one (`operations.md` §4 row
        // 26): a walk that died readies nothing, so a failed index must
        // never answer the retry-class token — the final refusal is read
        // first, and the window's only where the walk still runs.
        if reads_the_index && self.media.index_failed() {
            return refuse_failed();
        }
        if reads_the_index && !self.media.index_ready() {
            return refuse_rebuilding();
        }
        // The permit (M-I5 (f); P29, P13): the two acts that take bytes are
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

    /// Runs the creation (clause (1)).
    ///
    /// It takes `length=<N>`, the per-file cap on it, the request's bytes
    /// against it, the own scope on it *before* the body, then the
    /// standing-uploads bound and the floor on no declared length
    /// (`MediaGate::admit_creation`) — each refusal before the partial and
    /// the record, no upload made — the identifier minted and the record
    /// written under the gate's terms (`MediaGate::create_upload`: the key,
    /// the deposit's function, the lease interval in force); with no body the
    /// answer is the record; with one — the creation-with-upload — the
    /// identifier is held and the body streamed.
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
        let record = match self.media.create_upload(principal, length, now) {
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

    /// Runs the resume (clauses (3), (5), (6)).
    ///
    /// In order: the record under the requester's own key, the hold, the
    /// stated offset against the record's, the request's bytes against the
    /// length, the own scope on what the upload leaves past the offset
    /// *before* the body — refused there, the upload is kept — then the
    /// body.
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

    /// Runs the resume under its hold.
    ///
    /// The stated `offset` is held to the record's own — the one offset
    /// [`Daemon::stream_body`] resumes at — then the request's bytes against
    /// the length and the own scope, then the body.
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

    /// Streams the body into the store, chunk by chunk.
    ///
    /// It resumes at the record's own offset — a fresh record's zero at the
    /// creation, the stated offset the resume held to it — each chunk gated
    /// as the body is written and then appended; a connection that dies or
    /// stalls keeps the upload at its durable point; a refusal as the body is
    /// written ends it; a body that leaves the upload short of its length
    /// settles and answers the record; one that reaches it goes on to the
    /// finish. The store's records are keyed to `principal`
    /// ([`MediaGate::key`]).
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
                    // The connection died or stalled: the upload is kept at
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
                // Refused is ended (clause (6)): nothing kept.
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

    /// Runs the finish (clause (7); M-I5 (a)), under the credential lock.
    ///
    /// It holds the lock's read arm from the rename through the lease's sync
    /// — the lock the plain write path's door holds, so the check that reads
    /// the lease and the finish that writes it never interleave with a
    /// credential write; never `Serial`, which orders commits and the PUT
    /// commits nothing. The requester is re-resolved against the head under
    /// it: a session killed mid-transfer is dead at its rename — its token
    /// resolves to an actor other than `principal`, the stream's own — its
    /// upload ended, nothing kept (clause (6); M-I2 (g)). The finish is the
    /// media gate's (`MediaGate::finish_upload`): the lease taken for the
    /// lease interval in force, and the finished size noted (`operations.md`
    /// §1.1 m9), the one site the floor's lift is said from — a finish is
    /// proof the volume held a whole file above the floor, where an
    /// admission proves nothing the next chunk cannot undo.
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
        match self.media.finish_upload(stream, now) {
            Ok(finished) => finish_reply(&finished),
            Err(e) => blob_refusal(e),
        }
    }

    /// Answers the progress: the upload's record under the requester's key.
    ///
    /// It carries the offset a resume continues from.
    fn blob_progress(&self, principal: PrincipalId, id: UploadId) -> Reply {
        match self.media.store().upload(&MediaGate::key(principal), &id, self.media.now_ms()) {
            Some(r) => progress_reply(&r),
            None => refuse(TransportError::NoUpload, None),
        }
    }

    /// Ends the upload (clause (6), the termination), nothing kept.
    ///
    /// It is claimed as a stream claims it, then ended; the answer is `204`.
    fn blob_end(&self, principal: PrincipalId, id: UploadId) -> Reply {
        let Some(_hold) = self.media.claim(id) else {
            return refuse(TransportError::UploadHeld, Some("another stream holds this upload"));
        };
        match self.media.store().end_upload(&MediaGate::key(principal), &id, self.media.now_ms()) {
            Ok(()) => Reply { status: 204, body: None, headers: Vec::new() },
            Err(e) => blob_refusal(e),
        }
    }

    /// Runs a replace's deferred step: the store's `unlink_asides`.
    ///
    /// The replaced instance's names are unlinked, off the answer's path —
    /// the transport runs it after a blob reply is written; the pruner's
    /// pass sweeps whatever it did not reach. An I/O failure here is the
    /// operator's line, never a client's: the aside stands for the pass or
    /// the next open.
    ///
    /// **Row 37, once per standing fault** (`operations.md` §1.1 row 37; §1's
    /// never list — a line is said once per condition, never per request;
    /// the family's requests write no line of their own, D9). The store
    /// re-queues a failed aside at the queue's head, so every later request
    /// of the family meets the same fault; the once-flag
    /// (`Daemon::aside_fault_said`) says it at the first and not again,
    /// naming the aside as the store's error names it —
    /// `{file}: remove: {cause}`, the file by its name under the data
    /// directory as every blob-store line names it, never an absolute path,
    /// and the OS's cause — and the act that clears it. The error is this
    /// call's own, so the line names the aside this call met whatever
    /// another worker's call has taken from the queue since. A later call
    /// that answers `Ok` with the flag set — the queue drained here, or swept
    /// by the pruner's pass first — says the clearing line once and clears
    /// the flag; the common case, `Ok` with the flag clear, writes nothing.
    /// Through the write path's classed door, so the pair stands in the one
    /// record beside the daemon's other lines.
    pub(super) fn retire_asides(&self) {
        // The fault (test seam): a panic inside the deferred step, which the
        // transport's catch around this call contains.
        #[cfg(any(test, feature = "test-hooks"))]
        self.fire_the_unlinks_fault();
        match self.media.store().unlink_asides() {
            Ok(_) => {
                if self.aside_fault_said.swap(false, Ordering::AcqRel) {
                    self.commits.lines().say(Class::Landing, "blob store: the asides unlink again");
                }
            }
            Err(e) => {
                if self.aside_fault_said.swap(true, Ordering::AcqRel) {
                    return;
                }
                self.commits.lines().say(
                    Class::Failure,
                    format_args!(
                        "blob store: the deferred unlink failed: {e}; the aside stands for the \
                         pass or the next open"
                    ),
                );
            }
        }
    }

    /// Runs the pruner's pass as the daemon runs it, through its one pruner.
    ///
    /// The pass is `skep-media`'s `pruner.rs` (`Pruner::pass`), the
    /// credential lock's write arm taken for one file at a time, timed by the
    /// daemon's own `Instant` around it ([`TimedPass`]), so the cadence's
    /// loop and the test seam's pass carry one figure. `None` where the index
    /// is not ready — the pass does not start.
    pub(super) fn prune_pass(&self) -> Option<TimedPass> {
        let began = Instant::now();
        let report = self.pruner.pass(&self.media, || self.auth.credential_lock.write())?;
        Some(TimedPass { report, duration_ms: began.elapsed().as_millis() })
    }

    /// Says the pass (`operations.md` §1.1 rows 34, 35): one line per pass.
    ///
    /// The line is the report's own `Display` — each step's failure where one
    /// failed (`the pass failed: {step}: {cause}`), then its figures and the
    /// bytes they freed, the halt, and the compaction half: each log's size
    /// and what a compaction rewrote it from, a stop lifted, a compaction
    /// failed, a log `STOPPED` with its cause, its age and the appends it
    /// refused — then the pass's duration (`; the pass took {d} ms`), on the
    /// daemon's classed door. Row 34 goes under `Class::Landing` where no
    /// step failed, followed by a reading of the resident set
    /// ([`ResidentRead`](super::ResidentRead)), so a board whose index walk
    /// completed reads its memory at the pass's cadence whether or not a
    /// checkpoint lands; row 35 under `Class::Failure` where one did — so the
    /// line names each failure *and* what the pass did past it, whether the
    /// stop it may have met is lifted or stands, why it stood, what it cost
    /// and how long the pass held the credential lock's write arm. Nothing
    /// where the pass did not start (`None`: the index not ready). The
    /// cadence's loop and the test seam's pass say it alike.
    pub(super) fn say_the_pass(&self, pass: &Option<TimedPass>) {
        let Some(TimedPass { report, duration_ms }) = pass else { return };
        if report.failed.is_empty() {
            self.say(
                Class::Landing,
                format_args!("{report}; the pass took {duration_ms} ms; {}", self.resident.read()),
            );
        } else {
            self.say(Class::Failure, format_args!("{report}; the pass took {duration_ms} ms"));
        }
    }

    /// Returns whether the cell index's walk at open has completed.
    ///
    /// It is what the pruner's loop waits on before its first pass.
    pub(super) fn index_is_ready_for_pruning(&self) -> bool {
        self.media.index_ready()
    }
}

/// One pruner pass as the daemon ran it: its report and its duration.
///
/// [`Daemon::prune_pass`] answers it; [`Daemon::say_the_pass`] says both,
/// the duration the time the pass held the credential lock's write arm one
/// file at a time against every finish and every door read — the LANDING
/// class's duration (`operations.md` §1, the grammar; §1.1 rows 34, 35), and
/// the one trend the stream keeps between landings of how the volume serves
/// the pass.
pub(super) struct TimedPass {
    /// What the pass did (`skep-media`'s `PrunePass`).
    pub(super) report: PrunePass,
    /// The pass's duration, whole milliseconds, the daemon's own `Instant`.
    pub(super) duration_ms: u128,
}

// ── the queries, the answers, the refusals ───────────────────────────────

/// Parses the fetch's query: exactly `i=<address>` ([`sole_param`]).
///
/// The address is in the wire's dotted-decimal form, through the codec's
/// own door (`wire_address`), so a query string's address and a frame's
/// meet one grammar under one budget. What the address must name — an
/// element position of a document — is the serve's step 0, not this
/// parse's.
///
/// # Errors
///
/// The detail of a query that is not one `i` and nothing else, or whose
/// address the codec refuses.
fn fetch_query(query: Option<&str>) -> Result<Address, String> {
    let i = sole_param(query, "i")?.ok_or("the required parameter is i=<address>")?;
    wire_address(i).map_err(|e| format!("i: {e}"))
}

/// Parses the creation's query: exactly `length=<bytes>` ([`sole_param`]).
///
/// # Errors
///
/// The detail of a query that is not one `length` and nothing else, or
/// whose value is not a byte count ([`count`]).
fn create_query(query: Option<&str>) -> Result<u64, String> {
    let length = sole_param(query, "length")?.ok_or("the required parameter is length=<bytes>")?;
    count(length, "length")
}

/// Parses the resume's query: exactly `offset=<bytes>` ([`sole_param`]).
///
/// # Errors
///
/// The detail of a query that is not one `offset` and nothing else, or
/// whose value is not a byte count ([`count`]).
fn resume_query(query: Option<&str>) -> Result<u64, String> {
    let offset = sole_param(query, "offset")?.ok_or("the required parameter is offset=<bytes>")?;
    count(offset, "offset")
}

/// Parses a byte count: `1*DIGIT`, in range.
///
/// # Errors
///
/// A value that is empty, holds anything but digits, or does not fit a
/// `u64`, named by `name`.
fn count(v: &str, name: &str) -> Result<u64, String> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{name}: '{v}' is not a byte count"));
    }
    v.parse().map_err(|_| format!("{name}: '{v}' is not a byte count"))
}

/// Returns the record as the wire answers it.
///
/// It carries the identifier, the offset a resume continues from, the
/// length, the expiry.
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

/// Returns the finish as the wire answers it.
///
/// It carries the designation, the hash, the size — what the client
/// compares with its own and never adopts.
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

/// Returns `403 upload_refused`, naming which refusal it is.
///
/// It is the session layer's refusal ([`UploadRefusal::token`]) or the
/// closed setting's `uploads_closed`.
fn refuse_upload(detail: &str) -> Reply {
    refuse(TransportError::UploadRefused, Some(detail))
}

/// Returns the readiness refusal, `index_rebuilding`.
///
/// The cell index's walk at open is not done, and this request is one of
/// its three readers.
fn refuse_rebuilding() -> Reply {
    refuse(
        TransportError::IndexRebuilding,
        Some("the cell index is being rebuilt from the board; retry shortly"),
    )
}

/// Returns the failed refusal, `index_failed`.
///
/// It answers `operations.md` §4 row 26, §1.1 row 41 and PATTERNS P10: the
/// cell index's walk at open died, on its thread or at the open where the
/// OS refused it one — caught, the index failed for the life of the
/// process — and this request is one of its three readers. The `detail`
/// states the state and the one act that exists, elsewhere and another
/// hand's — a restart — and carries no retry hint, since no retry can
/// succeed: a client that retries retry-class tokens stops here. The
/// operator's faces of the same state are the catch's line, the pruner's
/// `no pass runs` line and the standing line's clause.
fn refuse_failed() -> Reply {
    refuse(
        TransportError::IndexFailed,
        Some(
            "the cell index failed to build at this start; uploads and the deposit read are \
             refused until a restart",
        ),
    )
}

/// Returns the permit's refusal, `upload_busy` (M-I5 (f); P29).
///
/// Every upload permit is in use, and this request is the creation or the
/// resume — the fetch's `fetch_busy` twin, its `detail` naming the one act
/// the person holds, the retry (M-I7 (e)), and no headroom and no holder
/// (M-I6 (h); D9).
fn refuse_upload_busy() -> Reply {
    refuse(TransportError::UploadBusy, Some("all upload permits are in use; retry shortly"))
}

/// Where the media gate refused a deposit: clause (6)'s two cases.
///
/// Each carries what it leaves of the upload, which the refusal's `ended`
/// reports.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RefusedAt {
    /// Before the body, on the declared total or at the creation.
    ///
    /// The upload is kept (none made, at a creation).
    BeforeTheBody,
    /// As the body is written: the upload is ended, nothing kept.
    AsTheBodyIsWritten,
}

/// Returns the media gate's refusal, `deposit_refused`.
///
/// It names the scope it fired on, where — and so whether the upload was
/// ended or kept ([`RefusedAt`]) — and the bytes received; no headroom
/// (M-I6 (h)). At the standing-uploads bound, a `detail` names the end of
/// one of them as the act the person holds (M-I7 (e)) — the count the bound
/// pins, which the same principal's deposit read lists upload by upload.
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

/// Returns the deposit read: the asking principal's own records, as JSON.
///
/// It answers `media.md` Op inventory 1 ("the depositor can read their own
/// deposit record, and the resume names one act per residue"; "it answers
/// the requester's own usage beside them"; the register M-I5 (c), M-I2 (e),
/// M-I6 (a), (b)): one read of the asking principal's *own* records — its
/// standing deposits (hash, size, expiry; a live lease over a file that is
/// not there marked lapsed, at this read as at the `insert`), its standing
/// uploads (identifier, the offset a resume continues from, the length, the
/// expiry), its usage as two figures — the base, the cell index's number
/// for its account (the distinct hashes its cells name, at their size), and
/// its pending bytes (its live leases on hashes none of its cells names,
/// and its uploads' bytes received) — the limits record's address as
/// installed, or `null` where none is — and the per-account limit in force,
/// `per_account`, whatever its source: the daemon's default where no record
/// is installed, echoed as a written limit is, so R68's read-before-refusal
/// holds under the default (P37; the register M-I6 (b), (d)); `null` only
/// where a written record sets none.
///
/// **No surface of its own.** It is the resumable PUT's own state made
/// readable, served on the upload's path family (`GET /blob/upload`) and
/// priced with the transport delta — a route helper beside the family's
/// refusals, built off the media gate's reads as the family's other wire
/// shapes are built here and in `reply.rs`, the one wire shape of the
/// resource's that the daemon composes. It is keyed to the asking
/// principal's own record and never to a file's presence beyond that
/// record's live lease: it lists no deposit of another's, and answers "this
/// board holds these bytes" of nothing a principal did not deposit itself.
/// Its base is one of the index's three readers: the route refuses it
/// `index_rebuilding` until the walk at open completes, and `index_failed`
/// for the uptime where that walk died (`operations.md` §4 row 26).
/// Removing the read would save nothing: the records exist for the resume
/// and the binding, and the listing is this one function over them.
///
/// It is built as its JSON object off `media_gate`, the media gate whose
/// store holds the records.
///
/// **Precondition.** The caller has read the index's readiness: the base
/// here is the index's number.
fn deposit_read(media_gate: &MediaGate, principal: PrincipalId) -> Value {
    let key = MediaGate::key(principal);
    let now = media_gate.now_ms();
    let store = media_gate.store();
    let deposits: Vec<Value> = store
        .live_leases_of(&key, now)
        .into_iter()
        .map(|l| {
            // Exact of what is on disk, by the binding's own reading
            // (`MediaGate::deposit_whole`): a lease over a file that is
            // absent or not whole reads as lapsed here as at the insert, and
            // so does one whose size the store could not read, until the
            // design gives a storage fault an answer of its own; the gate
            // says that read on the operator stream.
            let whole = media_gate.deposit_whole(&l.designation, &l.hex, l.size);
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

/// Returns the store's refusal as the wire's.
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

    /// Checks the family's parse and which method/path pairs stream.
    ///
    /// The parse covers the creation, an upload by a well-formed identifier,
    /// a malformed one (known, refused by name), and the paths outside it.
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
        // The failed refusal (`operations.md` §4 row 26; P10): 503 under its
        // own name, the detail the state and the operator's act — and no
        // retry hint, by either word, since none can succeed.
        let r = refuse_failed();
        assert_eq!(r.status, 503);
        let text = String::from_utf8_lossy(r.bytes()).to_string();
        assert!(text.contains("\"error\":\"index_failed\""), "{text}");
        assert!(
            text.contains(
                "\"detail\":\"the cell index failed to build at this start; uploads and the \
                 deposit read are refused until a restart\""
            ),
            "{text}"
        );
        assert!(!text.contains("retry") && !text.contains("shortly"), "no retry hint: {text}");
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
