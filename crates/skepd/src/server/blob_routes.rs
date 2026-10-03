//! THE BLOB UPLOAD — "the PUT", the record's word for the surface (media
//! lane B; `media.md` Op inventory 1, "THE RESUMABLE UPLOAD IS THE STANDARD
//! SHAPE, STATED ONCE", its seven clauses, the lease's crash story, the
//! deposit read; the register M-I2 (e), M-I5 (a), (c), M-I6 (b), (e);
//! wire.md §Media): the path family `/blob/upload`, every method of it
//! TOKEN-ACCEPTING through [`Daemon::resolve_actor`], and the one transport
//! seam a request/response signature cannot carry — the body that streams.
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
//! its own (m-Q10). Every spelling here is an INTERIM pin (sm-Q8),
//! stated once in wire.md §Media.
//!
//! THE ORDER OF ONE REQUEST THAT CARRIES BYTES: the session-layer gate
//! (a guest, an unclaimed board, a node-tier principal: refused before
//! anything — D12, PUB-6.35's I10, P13); the request's shape; the per-file
//! cap and the own scope on the DECLARED total, before the body — refused
//! there, the upload is KEPT (clause (6)); the hold (clause (5)); then the
//! body, chunk by chunk through the one buffer, each chunk gated — the own
//! scope, the venue's total, the floor, in that order — and refused there
//! the upload is ENDED, nothing kept, the refusal naming the scope and the
//! bytes it had taken (ms4-E1, the venue total's priced residue); then,
//! where the offset reaches the length, THE FINISH under the credential
//! lock's READ arm and never `Serial`: the requester re-resolved against the
//! head (dead there, the upload is ended), the store's rename through the
//! lease's sync, the record retired, THEN the answer — one shape whether or
//! not the file was already here (M-I5 (a); "NO ANSWER OF THE UPLOAD SAYS
//! WHETHER THE FILE WAS ALREADY HERE").
//!
//! THE TRANSPORT SEAM. The transport reads the request head and, for the
//! two body-carrying methods of this family, reads NO body: it parks a
//! [`BodySource`] over a clone of the connection's socket in this thread's
//! slot ([`park`]) and returns the head; the router takes the slot
//! ([`take_parked`]) on the same thread and hands it to the route, which
//! drains the socket one [`BLOB_CHUNK`] at a time into the store. A caller
//! over its own transport — the socket-free router, the tests — parks
//! nothing, and the route reads the request's own `body` through the same
//! type. The arm's whole memory is the one buffer the source holds; nothing
//! here ever holds the body whole.

use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Instant;

use serde_json::Value;
use skep_blobs::{BlobError, Finished, UploadId, UploadRecord};
use skep_namespace::HasM3;

use super::actor::Resolved;
use super::reply::{refuse, refuse_with, with_signal, Reply, TransportError};
use super::request::{at_most_once, query_pairs, HttpRequest};
use super::Daemon;
use crate::auth::session::Actor;
use crate::codec::obj;
use crate::limits::{BLOB_CHUNK, BLOB_TRANSFER_BOUND};
use crate::media::deposit_read::deposit_read;
use crate::media::gate::{MediaGate, Scope, DESIGNATION};
#[cfg(feature = "test-hooks")]
use crate::notice;

/// The family's one path.
const FAMILY: &str = "/blob/upload";

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

// ── the body source ──────────────────────────────────────────────────────

/// Where a body's bytes come from: the connection's socket (its clone,
/// owned here), or the request's own bytes.
enum Conn<'a> {
    Socket(TcpStream),
    Bytes(&'a [u8]),
}

/// THE STREAMING ARM's reader: the body of one blob request, handed to the
/// route one chunk at a time through the ONE buffer this value holds — the
/// arm's whole memory per in-flight upload, [`BLOB_CHUNK`] and the
/// counters beside it (asserted by `the_arm_holds_one_chunk_and_no_body`).
/// Over a socket it carries the early bytes the head's read took with it,
/// the declared length, the `Expect: 100-continue` the transport deferred to
/// the route, and the transfer bound; the socket's own read deadline is the
/// idle bound, set by the transport.
pub(super) struct BodySource<'a> {
    conn: Conn<'a>,
    early: Vec<u8>,
    early_at: usize,
    declared: usize,
    consumed: usize,
    expects_continue: bool,
    continued: bool,
    deadline: Instant,
    buf: Box<[u8]>,
    /// An end met while a chunk was filling — the connection closed, a
    /// deadline — answered AFTER the bytes filled so far, so a dropped
    /// connection's last bytes are received before its drop is.
    pending_end: Option<io::Error>,
}

impl<'a> BodySource<'a> {
    /// A source over the connection's socket, parked by the transport: the
    /// bytes that arrived with the head, the declared length, and whether
    /// the client is holding the body for a `100 Continue`.
    pub(super) fn parked(
        socket: TcpStream,
        early: Vec<u8>,
        declared: usize,
        expects_continue: bool,
    ) -> BodySource<'static> {
        BodySource {
            conn: Conn::Socket(socket),
            early,
            early_at: 0,
            declared,
            consumed: 0,
            expects_continue,
            continued: false,
            deadline: Instant::now() + BLOB_TRANSFER_BOUND,
            buf: vec![0u8; BLOB_CHUNK].into_boxed_slice(),
            pending_end: None,
        }
    }

    /// A source over a request's own bytes — the socket-free router's.
    pub(super) fn bytes(body: &'a [u8]) -> BodySource<'a> {
        BodySource {
            conn: Conn::Bytes(body),
            early: Vec::new(),
            early_at: 0,
            declared: body.len(),
            consumed: 0,
            expects_continue: false,
            continued: false,
            deadline: Instant::now() + BLOB_TRANSFER_BOUND,
            buf: vec![0u8; BLOB_CHUNK].into_boxed_slice(),
            pending_end: None,
        }
    }

    /// The declared length of the body.
    pub(super) fn declared(&self) -> usize {
        self.declared
    }

    /// Invite the body: where the client asked `Expect: 100-continue`, the
    /// interim `100 Continue` carrying `interim`'s headers — the creation's
    /// identifier, so it reaches the uploader before the first body byte
    /// (clause (1)) — written once; nothing otherwise.
    pub(super) fn begin(&mut self, interim: &[(&str, &str)]) -> io::Result<()> {
        if !self.expects_continue || self.continued {
            return Ok(());
        }
        self.continued = true;
        if let Conn::Socket(s) = &mut self.conn {
            let mut head = b"HTTP/1.1 100 Continue\r\n".to_vec();
            for (name, value) in interim {
                head.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
            }
            head.extend_from_slice(b"\r\n");
            s.write_all(&head)?;
        }
        Ok(())
    }

    /// The next chunk of the body — [`BLOB_CHUNK`] bytes, FILLED to that
    /// grain from the early bytes and the socket however the socket paces
    /// them, or the body's last bytes; `None` once the declared length is
    /// consumed. The grain is what the gate's refusal offset is read at: a
    /// refusal as the body is written fires at a chunk's boundary, never at
    /// whatever a socket read happened to deliver. A connection closed
    /// inside the body, a read past the idle bound, or a transfer past its
    /// bound is an error — answered after the bytes it found filled, so a
    /// dropped connection's last bytes are received before its drop is — and
    /// the route keeps the upload at its durable point.
    pub(super) fn next_chunk(&mut self) -> io::Result<Option<&[u8]>> {
        if let Some(end) = self.pending_end.take() {
            return Err(end);
        }
        let left = self.declared - self.consumed;
        if left == 0 {
            return Ok(None);
        }
        let want = left.min(self.buf.len());
        let mut filled = 0usize;
        while filled < want {
            let n = if self.early_at < self.early.len() {
                let take = (self.early.len() - self.early_at).min(want - filled);
                self.buf[filled..filled + take]
                    .copy_from_slice(&self.early[self.early_at..self.early_at + take]);
                self.early_at += take;
                take
            } else {
                let read = match &mut self.conn {
                    Conn::Bytes(b) => {
                        let at = self.consumed + filled;
                        let take = (want - filled).min(b.len().saturating_sub(at));
                        if take == 0 {
                            Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "the request's body is shorter than its declared length",
                            ))
                        } else {
                            self.buf[filled..filled + take].copy_from_slice(&b[at..at + take]);
                            Ok(take)
                        }
                    }
                    Conn::Socket(s) => {
                        if Instant::now() >= self.deadline {
                            Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "request body not delivered within the blob transfer bound",
                            ))
                        } else {
                            match s.read(&mut self.buf[filled..want]) {
                                Ok(0) => Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "connection closed inside the request body",
                                )),
                                other => other,
                            }
                        }
                    }
                };
                match read {
                    Ok(n) => n,
                    Err(e) if filled > 0 => {
                        self.pending_end = Some(e);
                        break;
                    }
                    Err(e) => return Err(e),
                }
            };
            filled += n;
        }
        self.consumed += filled;
        Ok(Some(&self.buf[..filled]))
    }
}

thread_local! {
    /// The body the transport parked for the request this thread is
    /// serving — set by [`park`] after the head is read, taken by the
    /// router before dispatch, on the one thread a connection is served
    /// on.
    static PARKED: RefCell<Option<BodySource<'static>>> = const { RefCell::new(None) };
}

/// Park a streaming body for the router — the transport's half of the seam.
pub(super) fn park(body: BodySource<'static>) {
    PARKED.with(|slot| *slot.borrow_mut() = Some(body));
}

/// Take the parked body, if any — the router's half, at the head of every
/// routing, so a body parked for one request can never be read by the
/// next.
pub(super) fn take_parked() -> Option<BodySource<'static>> {
    PARKED.with(|slot| slot.borrow_mut().take())
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

    /// THE SESSION-LAYER GATE, then the method. The gate (D12; PUB-6.35's
    /// I10; sweep-5 media-leak `upload-admitted-where-no-op-would-be`): a
    /// guest is refused; before the claim every act of the upload and the
    /// deposit read answers `claim_first`; a NODE-TIER principal —
    /// principal 0 of this node or of a sub-node, which owns no documents —
    /// is refused before any body byte, so no deposit stands that no
    /// account's scope counts.
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
        if self.auth.fold.snapshot().claimant().is_none() {
            return refuse_upload("claim_first");
        }
        let account_tier = {
            let snap = self.engine.kernel().snapshot();
            snap.world()
                .m3()
                .principal_prefix(principal)
                .is_some_and(|p| p.level() == skep_address::Level::Account)
        };
        if !account_tier {
            return refuse_upload("node_tier");
        }
        let key = MediaGate::key(principal);
        match (req.method.as_str(), target) {
            ("POST", BlobPath::Create) => self.blob_create(&key, req, body),
            ("GET", BlobPath::Create) => Reply::json(200, deposit_read(&self.media, principal)),
            ("PATCH", BlobPath::Upload(id)) => self.blob_append(&key, id, req, body),
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
    /// own scope on it BEFORE the body, the identifier minted and the record
    /// written; with no body the answer is the record; with one — the
    /// creation-with-upload — the identifier is held and the body streamed.
    fn blob_create(&self, key: &str, req: &HttpRequest, body: &mut BodySource<'_>) -> Reply {
        let length = match create_query(req.query.as_deref()) {
            Ok(n) => n,
            Err(detail) => return refuse(TransportError::MalformedBlob, Some(&detail)),
        };
        let limits = self.media.limits();
        if length > limits.per_file_cap {
            return refuse(
                TransportError::PayloadTooLarge,
                Some(&format!("length {length} exceeds the {}-byte per-file cap", limits.per_file_cap)),
            );
        }
        if body.declared() as u64 > length {
            return refuse(
                TransportError::UploadLength,
                Some(&format!("the body's {} bytes exceed the declared length {length}", body.declared())),
            );
        }
        let now = self.media.now_ms();
        if let Err(scope) = self.media.admit_declared(key, length, now) {
            return refuse_deposit(scope, false, 0);
        }
        let record = match self.media.store().create_upload(
            key,
            DESIGNATION,
            length,
            now.saturating_add(limits.lease_interval_ms),
            None,
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
        let reply = self.stream_body(key, record, 0, req, body, &[("Upload-Id", hex.as_str())]);
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
        let reply = self.append_held(key, record, offset, req, body);
        self.media.release(id);
        reply
    }

    fn append_held(
        &self,
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
        if let Err(scope) = self.media.admit_declared(key, record.length - offset, now) {
            return refuse_deposit(scope, false, record.offset);
        }
        self.stream_body(key, record, offset, req, body, &[])
    }

    /// THE BODY, chunk by chunk: resumed at `offset`, each chunk gated as
    /// the body is written and then appended; a connection that dies or
    /// stalls KEEPS the upload at its durable point; a refusal as the body
    /// is written ENDS it; a body that leaves the upload short of its
    /// length settles and answers the record; one that reaches it goes on
    /// to the finish.
    fn stream_body(
        &self,
        key: &str,
        record: UploadRecord,
        offset: u64,
        req: &HttpRequest,
        body: &mut BodySource<'_>,
        interim: &[(&str, &str)],
    ) -> Reply {
        let store = self.media.store();
        let interval = self.media.limits().lease_interval_ms;
        let id = record.id;
        let now = self.media.now_ms();
        if let Err(e) = store.resume(key, &id, offset, now) {
            return blob_refusal(e);
        }
        if body.begin(interim).is_err() {
            store.release(&id);
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
                    let _ = store.settle(key, &id, self.media.now_ms(), interval);
                    store.release(&id);
                    return refuse(
                        TransportError::MalformedHttp,
                        Some(&format!("request body not delivered: {e}")),
                    );
                }
            };
            let n = chunk.len() as u64;
            if let Err(scope) = self.media.admit_bytes(key, &id, written, n, now) {
                // REFUSED IS ENDED (clause (6)): nothing kept.
                let _ = store.end_upload(key, &id, now);
                return refuse_deposit(scope, true, written);
            }
            match store.append(key, &id, chunk, self.media.now_ms(), interval) {
                Ok(w) => written = w,
                Err(e) => {
                    store.release(&id);
                    return blob_refusal(e);
                }
            }
        }
        if written < record.length {
            return match store.settle(key, &id, self.media.now_ms(), interval) {
                Ok(r) => progress_reply(&r),
                Err(e) => {
                    store.release(&id);
                    blob_refusal(e)
                }
            };
        }
        self.blob_finish(key, record, req)
    }

    /// THE FINISH (clause (7); M-I5 (a)), under the credential lock's READ
    /// arm from the rename through the lease's sync — the lock the plain
    /// write path's door holds, so the check that reads the lease and the
    /// finish that writes it never interleave with a credential write; never
    /// `Serial`, which orders commits and the PUT commits nothing. The
    /// requester is re-resolved against the head under it: a session killed
    /// mid-transfer is dead at its rename, its upload ended, nothing kept
    /// (clause (6); M-I2 (g)).
    fn blob_finish(&self, key: &str, record: UploadRecord, req: &HttpRequest) -> Reply {
        let store = self.media.store();
        let id = record.id;
        let _credential_lock = self.auth.credential_lock.read();
        let now = self.media.now_ms();
        let resolved = {
            let snap = self.engine.kernel().snapshot();
            let identity = self.auth.fold.snapshot();
            self.resolve_actor(req, snap.world(), &identity)
        };
        let same = matches!(&resolved.actor, Actor::Principal(b) if MediaGate::key(b.principal) == key);
        if !same {
            let _ = store.end_upload(key, &id, now);
            return with_signal(refuse_upload("unauthenticated"), resolved.closed);
        }
        let lease_expires = now.saturating_add(self.media.limits().lease_interval_ms);
        match store.finish(key, &id, now, lease_expires) {
            Ok(finished) => finish_reply(&finished),
            Err(e) => {
                store.release(&id);
                blob_refusal(e)
            }
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
    /// [`Daemon::BLOB_HOLD_NOTICE`] on the operator stream and parking the
    /// request's thread for good — so the dirty-crash harness
    /// (`tests/it/hazard.rs`) can SIGKILL the process THERE and judge the
    /// reopen over exactly the directory a crash at that step leaves. Not
    /// disarmable.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn hold_blob_finish_at(&self, step: skep_blobs::Step) {
        self.media.store().hold_at(
            step,
            Box::new(|| {
                notice::line(Self::BLOB_HOLD_NOTICE);
                loop {
                    std::thread::park();
                }
            }),
        );
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

/// The gate's refusal: the scope it fired on, whether the upload was ended
/// or kept, and the bytes received — no headroom (M-I6 (h)).
fn refuse_deposit(scope: Scope, ended: bool, offset: u64) -> Reply {
    refuse_with(
        TransportError::DepositRefused,
        vec![
            ("ended", Value::Bool(ended)),
            ("offset", Value::Number(offset.into())),
            ("scope", Value::String(scope.token().into())),
        ],
    )
}

/// The store's refusal as the wire's.
fn blob_refusal(e: BlobError) -> Reply {
    match e {
        BlobError::NoUpload => refuse(TransportError::NoUpload, None),
        BlobError::Offset { recorded } => {
            refuse_with(TransportError::UploadOffset, vec![("offset", Value::Number(recorded.into()))])
        }
        BlobError::Length { length, offset } => refuse(
            TransportError::UploadLength,
            Some(&format!("the bytes at offset {offset} would pass the declared length {length}")),
        ),
        BlobError::Io(e) => refuse(TransportError::BlobIo, Some(&e.to_string())),
        // Defects of this route's own sequencing, never a wire state.
        BlobError::Incomplete { .. } | BlobError::NotResumed => {
            refuse(TransportError::BlobIo, Some(&format!("defect: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE RSS BOUND BY CONSTRUCTION (the investigation §3.4, "memory per
    /// in-flight PUT under the streaming arm — O(chunk), never O(body)"):
    /// the arm's one buffer is [`BLOB_CHUNK`] long, the source's own size
    /// is a few words beside it — no `Vec` that grows with the body — and a
    /// body of many chunks comes through it one chunk at a time, every
    /// chunk at most the buffer's length. The number: 64 KiB per in-flight
    /// upload, against a 64 MiB cap.
    #[test]
    fn the_arm_holds_one_chunk_and_no_body() {
        assert_eq!(BLOB_CHUNK, 64 * 1024);
        assert!(std::mem::size_of::<BodySource<'_>>() <= 160, "{}", std::mem::size_of::<BodySource<'_>>());
        let body = vec![7u8; 10 * BLOB_CHUNK + 13];
        let mut source = BodySource::bytes(&body);
        assert_eq!(source.buf.len(), BLOB_CHUNK);
        let mut chunks = 0;
        let mut total = 0;
        while let Some(chunk) = source.next_chunk().expect("bytes") {
            assert!(chunk.len() <= BLOB_CHUNK);
            assert!(chunk.iter().all(|&b| b == 7));
            total += chunk.len();
            chunks += 1;
        }
        assert_eq!(total, body.len());
        assert_eq!(chunks, 11);
        assert_eq!(source.buf.len(), BLOB_CHUNK, "the buffer never grew");
    }

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
        assert!(matches!(blob_path(&format!("/blob/upload/{}", id.to_uppercase())), Some(BlobPath::Malformed)));
        for outside in ["/blob", "/blob/", "/blob/uploads", "/blob/upload2", "/op", "/"] {
            assert!(blob_path(outside).is_none(), "{outside}");
        }
        assert!(streams_body("POST", "/blob/upload"));
        assert!(streams_body("PATCH", &format!("/blob/upload/{id}")));
        for (m, p) in [("GET", "/blob/upload"), ("DELETE", &format!("/blob/upload/{id}")[..]), ("POST", &format!("/blob/upload/{id}")[..]), ("PATCH", "/blob/upload"), ("POST", "/op")] {
            assert!(!streams_body(m, p), "{m} {p}");
        }
        assert_eq!(create_query(Some("length=12")), Ok(12));
        assert!(create_query(Some("length=12&length=13")).is_err());
        assert!(create_query(Some("length=+1")).is_err());
        assert!(create_query(Some("size=1")).is_err());
        assert!(create_query(None).is_err());
        assert_eq!(append_query(Some("offset=0")), Ok(0));
        assert!(append_query(Some("offset=")).is_err());
    }
}
