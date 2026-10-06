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
//! (a guest, an unclaimed board, a node-tier principal: refused before
//! anything — D12, PUB-6.35's I10, P13); THE UPLOAD SETTING — on a board
//! whose uploads are CLOSED (`--no-uploads`, echoed on `/health` as
//! `media.uploads`) the creation and the resume answer `403
//! upload_refused` with `detail` `uploads_closed` before any body byte,
//! the upload kept where one stood, and every read and the termination
//! are served (`media.md` Op inventory 1, "ONLY ON A BOARD WHOSE UPLOADS
//! ARE OPEN"; M-I7 (e)); THE READINESS — the creation and the resume read
//! the own scope, whose base is the cell index's number, so until the
//! index's walk at open completes both are refused `index_rebuilding`,
//! 503, retry-class, as the deposit read is (ms5-R: the index's three
//! readers wait, and nothing else — the progress read, the termination,
//! every text read and write, the door's own binding arm are served
//! throughout); the request's shape; the per-file cap and the own scope on
//! the DECLARED total, before the body — refused there, the upload is KEPT
//! (clause (6)); AT THE CREATION, before its partial and its record, THE
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
//! two body-carrying methods of this family, reads NO body: it leaves a
//! [`BodySource`] over a clone of the connection's socket in the request's
//! own slot (`HttpRequest::body_stream`) and returns the head; the router
//! takes the slot at the head of every routing and hands the source to the
//! route, which drains the socket one [`BLOB_CHUNK`](crate::limits::BLOB_CHUNK)
//! at a time into the store. A caller over its own transport — the socket-free router, the
//! tests — leaves the slot empty, and the route reads the request's own
//! `body` through the same type. The arm's whole memory is the one buffer
//! the source holds; nothing here ever holds the body whole.
//!
//! AND THE FETCH — `GET /blob?i=<address>`, with `HEAD` for the head alone
//! (`media.md` Op inventory 3; the register M-I2 (a)–(d), (g), M-I3 (b),
//! M-I7 (a), (b); wire.md §Media, THE FETCH): the one path beside the
//! family, TOKEN-ACCEPTING through [`Daemon::resolve_actor`] like every
//! method of it, its order THE SERVE's (`media/serve.rs` — the shape, M10's
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
use skep_identity::HasIdentity;
use skep_namespace::{HasM3, PrincipalId};

use super::actor::Resolved;
use super::reply::{
    class_varying, refuse, refuse_fetch, refuse_with, with_signal, Fetch, Reply, Routed,
    TransportError,
};
use super::request::{at_most_once, query_pairs, BodySource, HttpRequest};
use super::Daemon;
use crate::auth::session::Actor;
use crate::codec::{obj, wire_address};
use crate::media::deposit_read::deposit_read;
use crate::media::gate::{MediaGate, Scope};
use crate::media::pruner::{self, PrunePass};
use crate::media::serve;
#[cfg(feature = "test-hooks")]
use crate::notice;

/// The family's one path.
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
    /// `/blob/upload` — the creation and the deposit read.
    Create,
    /// `/blob/upload/<id>` — one upload: the resume, the progress, the end.
    Upload(UploadId),
    /// `/blob/upload/<not an identifier>` — known, and malformed.
    Malformed,
}

/// The family's parse: `None` for a path outside it.
pub(super) fn blob_path(path: &str) -> Option<BlobPath> {
    if path == FAMILY {
        return Some(BlobPath::Create);
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
        ("POST", Some(BlobPath::Create)) | ("PATCH", Some(BlobPath::Upload(_)))
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
    /// shape, then THE SERVE's order (`media/serve.rs`) as the resolved
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
        match serve::fetch(&self.febe, resolved.sid(), &self.media, &self.fetches, &i) {
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

    /// THE SESSION-LAYER GATE, then THE READINESS, then the method. The gate
    /// (D12; PUB-6.35's I10; sweep-5 media-leak
    /// `upload-admitted-where-no-op-would-be`): a guest is refused; before
    /// the claim every act of the upload and the deposit read answers
    /// `claim_first`; a NODE-TIER principal — principal 0 of this node or of
    /// a sub-node, which owns no documents — is refused before any body
    /// byte, so no deposit stands that no account's scope counts. The
    /// readiness (ms5-R): the creation, the resume and the deposit read —
    /// the index's three readers at this family — are refused
    /// `index_rebuilding` until the walk at open completes; the progress
    /// read and the termination read no base and are served.
    fn blob_dispatch(
        &self,
        resolved: &Resolved,
        req: &HttpRequest,
        body: &mut BodySource<'_>,
    ) -> Reply {
        let Some(target) = blob_path(&req.path) else {
            return refuse(TransportError::NoSuchEndpoint, Some(&req.path));
        };
        let principal = match &resolved.actor {
            Actor::Principal(b) => b.principal,
            Actor::Guest(_) => return refuse_upload("unauthenticated"),
        };
        // ONE head snapshot for the claim and the tier: the world and the
        // table it carries are one committed state.
        let snap = self.engine.kernel().snapshot();
        if snap.world().identity().claimant().is_none() {
            return refuse_upload("claim_first");
        }
        let account_tier = snap
            .world()
            .m3()
            .principal_prefix(principal)
            .is_some_and(|p| p.level() == skep_address::Level::Account);
        drop(snap);
        if !account_tier {
            return refuse_upload("node_tier");
        }
        // THE UPLOAD SETTING: the two acts that take bytes, refused before
        // any body byte on a closed board; the reads and the end served.
        let takes_bytes = matches!(
            (req.method.as_str(), &target),
            ("POST", BlobPath::Create) | ("PATCH", BlobPath::Upload(_))
        );
        if takes_bytes && !self.media.uploads_open() {
            return refuse_upload("uploads_closed");
        }
        let reads_the_index = matches!(
            (req.method.as_str(), &target),
            ("POST", BlobPath::Create) | ("GET", BlobPath::Create) | ("PATCH", BlobPath::Upload(_))
        );
        if reads_the_index && !self.media.index_ready() {
            return refuse_rebuilding();
        }
        let key = MediaGate::key(principal);
        match (req.method.as_str(), target) {
            ("POST", BlobPath::Create) => self.blob_create(principal, &key, req, body),
            ("GET", BlobPath::Create) => Reply::json(200, deposit_read(&self.media, principal)),
            ("PATCH", BlobPath::Upload(id)) => self.blob_append(principal, &key, id, req, body),
            ("GET", BlobPath::Upload(id)) => self.blob_progress(&key, id),
            ("DELETE", BlobPath::Upload(id)) => self.blob_end(&key, id),
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
        key: &str,
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
            return refuse_deposit(scope, false, 0);
        }
        if let Err(scope) = self.media.admit_creation(principal, now) {
            return refuse_deposit(scope, false, 0);
        }
        let interval = Duration::from_millis(limits.lease_interval_ms);
        let record = match self.media.store().create_upload(
            key,
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
        // pruner's re-read and a racing resume meet the hold.
        self.media.claim(id);
        let hex = id.to_hex();
        let reply =
            self.stream_body(principal, key, record, 0, req, body, &[("Upload-Id", hex.as_str())]);
        self.media.release(id);
        reply
    }

    /// THE RESUME (clauses (3), (5), (6)): the record under the requester's
    /// own key, the hold, the stated offset against the record's, the
    /// request's bytes against the length, the own scope on what the upload
    /// leaves past the offset BEFORE the body — refused there, the upload
    /// is kept — then the body.
    fn blob_append(
        &self,
        principal: PrincipalId,
        key: &str,
        id: UploadId,
        req: &HttpRequest,
        body: &mut BodySource<'_>,
    ) -> Reply {
        let offset = match append_query(req.query.as_deref()) {
            Ok(n) => n,
            Err(detail) => return refuse(TransportError::MalformedBlob, Some(&detail)),
        };
        let now = self.media.now_ms();
        let Some(record) = self.media.store().upload(key, &id, now) else {
            return refuse(TransportError::NoUpload, None);
        };
        if !self.media.claim(id) {
            return refuse(TransportError::UploadHeld, Some("another stream holds this upload"));
        }
        let reply = self.append_held(principal, key, record, offset, req, body);
        self.media.release(id);
        reply
    }

    fn append_held(
        &self,
        principal: PrincipalId,
        key: &str,
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
            return refuse_deposit(scope, false, record.offset);
        }
        self.stream_body(principal, key, record, offset, req, body, &[])
    }

    /// THE BODY, chunk by chunk: resumed at `offset`, each chunk gated as
    /// the body is written and then appended; a connection that dies or
    /// stalls KEEPS the upload at its durable point; a refusal as the body
    /// is written ENDS it; a body that leaves the upload short of its
    /// length settles and answers the record; one that reaches it goes on
    /// to the finish.
    #[allow(clippy::too_many_arguments)]
    fn stream_body(
        &self,
        principal: PrincipalId,
        key: &str,
        record: UploadRecord,
        offset: u64,
        req: &HttpRequest,
        body: &mut BodySource<'_>,
        interim: &[(&str, &str)],
    ) -> Reply {
        let store = self.media.store();
        let id = record.id;
        let now = self.media.now_ms();
        let mut stream = match store.resume(key, &id, offset, now) {
            Ok(stream) => stream,
            Err(e) => return blob_refusal(e),
        };
        if body.begin(interim).is_err() {
            return refuse(TransportError::MalformedHttp, Some("client went away at 100-continue"));
        }
        let mut written = offset;
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
                let _ = store.end_upload(key, &id, now);
                return refuse_deposit(scope, true, written);
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
        self.blob_finish(key, id, stream, req)
    }

    /// THE FINISH (clause (7); M-I5 (a)), under the credential lock's READ
    /// arm from the rename through the lease's sync — the lock the plain
    /// write path's door holds, so the check that reads the lease and the
    /// finish that writes it never interleave with a credential write; never
    /// `Serial`, which orders commits and the PUT commits nothing. The
    /// requester is re-resolved against the head under it: a session killed
    /// mid-transfer is dead at its rename, its upload ended, nothing kept
    /// (clause (6); M-I2 (g)).
    fn blob_finish(&self, key: &str, id: UploadId, stream: Stream<'_>, req: &HttpRequest) -> Reply {
        let store = self.media.store();
        let _credential_lock = self.auth.credential_lock.read();
        let now = self.media.now_ms();
        let resolved = {
            let snap = self.engine.kernel().snapshot();
            self.resolve_actor(req, snap.world(), snap.world().identity())
        };
        let same =
            matches!(&resolved.actor, Actor::Principal(b) if MediaGate::key(b.principal) == key);
        if !same {
            drop(stream);
            let _ = store.end_upload(key, &id, now);
            return with_signal(refuse_upload("unauthenticated"), resolved.closed);
        }
        match stream.finish(Duration::from_millis(self.media.limits().lease_interval_ms), now) {
            Ok(finished) => finish_reply(&finished),
            Err(e) => blob_refusal(e),
        }
    }

    /// THE PROGRESS: the upload's record under the requester's own key — the
    /// offset a resume continues from.
    fn blob_progress(&self, key: &str, id: UploadId) -> Reply {
        match self.media.store().upload(key, &id, self.media.now_ms()) {
            Some(r) => progress_reply(&r),
            None => refuse(TransportError::NoUpload, None),
        }
    }

    /// THE END (clause (6), the termination): claimed as a stream claims
    /// it, then ended — nothing kept; `204`.
    fn blob_end(&self, key: &str, id: UploadId) -> Reply {
        if !self.media.claim(id) {
            return refuse(TransportError::UploadHeld, Some("another stream holds this upload"));
        }
        let reply = match self.media.store().end_upload(key, &id, self.media.now_ms()) {
            Ok(()) => Reply { status: 204, body: None, headers: Vec::new() },
            Err(e) => blob_refusal(e),
        };
        self.media.release(id);
        reply
    }

    /// THE DEFERRED STEP of a replace (the store's `unlink_asides`): the
    /// replaced instance's names unlinked, off the answer's path — the
    /// transport runs it after a blob reply is written; the pruner's pass
    /// sweeps whatever it did not reach. An I/O failure here is the
    /// operator's line, never a client's: the aside stands for the pass or
    /// the next open.
    pub(super) fn retire_asides(&self) {
        if let Err(e) = self.media.store().unlink_asides() {
            crate::notice::line(format_args!(
                "blob store: a replaced file's aside could not be unlinked: {e}"
            ));
        }
    }

    /// THE PRUNER's PASS, as the daemon runs it (`media/pruner.rs`): the
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

    /// The line [`Daemon::hold_blob_finish_at`]'s hold writes on the
    /// operator stream as it parks — what the harness watches the child's
    /// stderr for before it kills.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub const BLOB_HOLD_NOTICE: &'static str =
        "test seam: held inside a blob finish; kill this process";

    /// TEST HOOK (the standing of every hook in `server/hooks.rs`:
    /// `#[doc(hidden)]`, not a stable API): HOLD every later finish of the
    /// blob store before the named step — writing
    /// [`Daemon::BLOB_HOLD_NOTICE`] on the operator stream and parking
    /// the request's thread for good — so the dirty-crash harness
    /// (`tests/it/hazard.rs`) can SIGKILL the process THERE and judge the
    /// reopen over exactly the directory a crash at that step leaves. Held
    /// at the deferred `UnlinkAside` step, the hold parks the TRANSPORT's
    /// thread after the reply is written, the answer already given. Not
    /// disarmable.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn hold_blob_finish_at(&self, step: skep_blobs::Step) {
        self.media.store().hold_at(step, || {
            notice::line(Self::BLOB_HOLD_NOTICE);
            loop {
                std::thread::park();
            }
        });
    }

    /// TEST HOOK (the same standing): the volume's capacity the media gate
    /// read once at the open — the default per-account limit's source — so
    /// a suite judges the deposit read's `per_account` against the same
    /// read; `None` where the host answered none.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn media_capacity(&self) -> Option<u64> {
        self.media.capacity()
    }

    /// TEST HOOK (the same standing): FAIL every later finish of the blob
    /// store at the named step with an I/O error, or `None` to fail nothing
    /// — the store's own injection (`skep-blobs`'s `fail_at`), so a suite
    /// drives a finish cut before its rename over the wire and judges the
    /// empty resume that finishes it.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn fail_blob_finish_at(&self, step: Option<skep_blobs::Step>) {
        self.media.store().fail_at(step);
    }

    /// TEST HOOK (the same standing): INSTALL a media limits record — the
    /// serving layer's channel (AUTH-4.70) in a suite's hand until that
    /// channel lands: the per-account limit, the venue's total, the lease
    /// interval (`None` keeps the daemon's default) and the record's
    /// address the deposit read echoes.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn install_media_limits(
        &self,
        per_account: Option<u64>,
        venue_total: Option<u64>,
        lease_interval_ms: Option<u64>,
        address: Option<String>,
    ) {
        use crate::media::gate::{Limits, LEASE_INTERVAL_DEFAULT_MS};
        self.media.install(Limits {
            per_account,
            venue_total,
            lease_interval_ms: lease_interval_ms.unwrap_or(LEASE_INTERVAL_DEFAULT_MS),
            per_file_cap: crate::limits::MAX_BLOB_BYTES,
            address,
        });
    }

    /// TEST HOOK (the same standing): advance the media gate's clock by
    /// `ms` — every upload expiry and lease is judged against it — so a
    /// suite drives an expiration through a seam rather than a `sleep`.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn advance_media_clock_ms(&self, ms: u64) {
        self.media.advance_clock_ms(ms);
    }

    /// TEST HOOK (the same standing): the floor reads `bytes` as the
    /// volume's free space (`None`: the host's again), so a suite reaches
    /// the floor's refusal without filling a disk.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn set_media_free_space(&self, bytes: Option<u64>) {
        self.media.set_free_space(bytes);
    }
}

// ── the queries, the answers, the refusals ───────────────────────────────

/// THE FETCH's query: exactly `i=<address>`, the address in the wire's
/// dotted-decimal form through the codec's own door (`wire_address`), so a
/// query string's address and a frame's meet one grammar under one budget.
/// What the address must NAME — an element position of a document — is the
/// serve's step 0, not this parse's.
fn fetch_query(query: Option<&str>) -> Result<Address, String> {
    let query = match query {
        None | Some("") => return Err("the required parameter is i=<address>".into()),
        Some(q) => q,
    };
    let mut i: Option<Address> = None;
    for (k, v) in query_pairs(query)? {
        match k {
            "i" => {
                at_most_once(&i, "parameter", "i")?;
                i = Some(wire_address(v).map_err(|e| format!("i: {e}"))?);
            }
            other => return Err(format!("unknown parameter '{other}'")),
        }
    }
    i.ok_or_else(|| "the required parameter is i=<address>".to_string())
}

/// The creation's query: exactly `length=<bytes>`.
fn create_query(query: Option<&str>) -> Result<u64, String> {
    let query = match query {
        None | Some("") => return Err("the required parameter is length=<bytes>".into()),
        Some(q) => q,
    };
    let mut length: Option<u64> = None;
    for (k, v) in query_pairs(query)? {
        match k {
            "length" => {
                at_most_once(&length, "parameter", "length")?;
                length = Some(count(v, "length")?);
            }
            other => return Err(format!("unknown parameter '{other}'")),
        }
    }
    length.ok_or_else(|| "the required parameter is length=<bytes>".to_string())
}

/// The resume's query: exactly `offset=<bytes>`.
fn append_query(query: Option<&str>) -> Result<u64, String> {
    let query = match query {
        None | Some("") => return Err("the required parameter is offset=<bytes>".into()),
        Some(q) => q,
    };
    let mut offset: Option<u64> = None;
    for (k, v) in query_pairs(query)? {
        match k {
            "offset" => {
                at_most_once(&offset, "parameter", "offset")?;
                offset = Some(count(v, "offset")?);
            }
            other => return Err(format!("unknown parameter '{other}'")),
        }
    }
    offset.ok_or_else(|| "the required parameter is offset=<bytes>".to_string())
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

/// The session-layer gate's refusal, naming which.
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

/// The gate's refusal: the scope it fired on, whether the upload was ended
/// or kept, and the bytes received — no headroom (M-I6 (h)); at the
/// standing-uploads bound, a `detail` naming the end of one of them as the
/// act the person holds (M-I7 (e)) — the count the bound pins, which the
/// same principal's deposit read lists upload by upload.
fn refuse_deposit(scope: Scope, ended: bool, offset: u64) -> Reply {
    let mut fields = vec![
        ("ended", Value::Bool(ended)),
        ("offset", Value::Number(offset.into())),
        ("scope", Value::String(scope.token().into())),
    ];
    if scope == Scope::Standing {
        fields.push((
            "detail",
            Value::String(format!(
                "this account holds {} standing uploads, the most this board keeps: end one of them, \
                 then create again",
                crate::limits::MAX_STANDING_UPLOADS
            )),
        ));
    }
    refuse_with(TransportError::DepositRefused, fields)
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
        assert!(matches!(blob_path("/blob/upload"), Some(BlobPath::Create)));
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
        assert_eq!(append_query(Some("offset=0")), Ok(0));
        assert!(append_query(Some("offset=")).is_err());
        let r = refuse_rebuilding();
        assert_eq!(r.status, 503);
        assert!(String::from_utf8_lossy(r.bytes()).contains("\"error\":\"index_rebuilding\""));
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
