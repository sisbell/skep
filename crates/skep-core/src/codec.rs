//! The one concrete [`Codec`]: JSON frames ↔ M10's typed `Request`/`Response`.
//!
//! The wire conventions are a cross-client contract, specified for client
//! authors in `skep/docs/wire.md` and pinned by the tests in skepd's
//! `tests/it/wire_doc.rs` (the doc's examples are asserted, not decorative).
//! The rules the whole file hangs on:
//!
//! * Requests are internally tagged objects (`{"op": "insert", ...}`) with
//!   snake_case op names mirroring `OpKind`; unknown ops and unknown fields
//!   are parse failures, never ignored (the never-silent contract applied to
//!   client typos).
//! * `make_link`'s three endset slots are three-form (wire v5, widened by the
//!   I-span form, W6 (a)): a V-spec array (content-resolved, byte-identical
//!   to v4 — a v4 frame means under v5 exactly what it means under v4),
//!   `{"addrs": [addresses…]}` — the names recorded verbatim, no resolution;
//!   the addrs-object encoding is identical to `edit_link`'s successor `ty`
//!   addrs form — or `{"spans": [{"start": …, "width": …}, …]}`, content
//!   I-spans in `retrieve_i`'s I-span shape, recorded verbatim; `edit_link`'s
//!   successor `from` and `to` take the first and the third, its `ty` all
//!   three (the first as `{"resolve": […]}`).
//! * Tumblers and addresses are dotted-decimal strings (`"1.1.0.1.0.2"`);
//!   spans are `{"start": …, "width": …}` objects; unbounded ℕ values ride
//!   as decimal strings (T0 admits magnitudes no JSON number can carry),
//!   with non-negative JSON integers accepted leniently on parse;
//!   machine-bounded values (`Seq`, slots, counts, principal ids) are JSON
//!   numbers.
//! * Content values carry granularity explicitly (wire v2): the per-byte
//!   write forms (`"str"`, `{"hex"}`) mint one single-byte value per byte —
//!   the substrate's text discipline, under which V-span widths measure
//!   exact bytes — while `{"atom"}`/`{"atom_hex"}` mint *one* composite value
//!   whose interior is permanently unaddressable. A `delivery` renders
//!   maximal per-byte runs as one `content`/`hex` item and every composite
//!   value as its own `atom`/`atom_hex` item, so the marshal is injective
//!   across granularity: two distinct position-value sequences never render
//!   alike.
//! * Marshaling is deterministic: every object is built through [`obj`],
//!   which sorts keys, so two marshals of one response are byte-equal and
//!   the canonical form never depends on serde_json's map backend.
//! * Every `Response` variant — every `Rejected` shape included — has a
//!   defined encoding: a client that cannot decode a rejection has been
//!   silently failed.
//!
//! What `marshal.rs` renders is the operation channel: M10's `Response`s, the
//! canonical request encoding [`JsonCodec::marshal_request`] writes, the
//! daemon-originated rejections ([`credential_refused_reply`],
//! [`registry_refused_reply`]), and the `key_set` row. The transport's own
//! shapes — `/health`, `/session`, `/challenge`, `/changes` and its entries,
//! the `{"error": …}` bodies, the commit stream's payload — are built where
//! their state lives, and reach determinism by going through [`obj`] and
//! [`to_bytes`] rather than by living here.
//!
//! Parsing strings into `skep-address` values goes through M1's validating
//! front doors (`Tumbler::new`, `validate`, `Span::new`), so no malformed
//! address or zero-width span survives the trust boundary.

mod marshal;

use std::str::FromStr;

use serde_json::{Map, Value};
use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_arrangement::{trunk_of, Base, Run, Shot, ShotRun, VPos, VSpec};
use skep_content::Val;
use skep_discovery::{FourSet, SlotSpec};
use skep_febe::{
    Codec, Deposit, FaultSite, ISpan, Op, OpKind, ParseError, Rejection, ReqId, Request, Response,
    SlotArg, SuccessorSpec, MAX_REQ_ID_BYTES,
};
use skep_identity::SigAlgRow;
use skep_kernel::Attestation;
use skep_links::{
    member_end, request_image, EndArg, Endset, LinkEntry, MemberSpan, NamedAddress,
    PublishDeposits, PublishTarget, View, MAX_SLOT_SPANS,
};
use skep_namespace::PrincipalId;
use skep_retrieval::{RegionSpec, Spec};
use skep_util::json::{hex_nibble, obj};

pub use marshal::{credential_refused_reply, key_set_reply, op_name, registry_refused_reply};
pub(crate) use marshal::j_attest;
use marshal::{j_response, req_pairs};

/// The most elements one wire array may carry, applied at [`p_list`].
///
/// Every attacker-sized list on the request surface (span regions, spec and
/// region lists, address lists, v-spec lists, `rearrange` cuts, the shot
/// runs of `reinstate` and `publish`, `retrieve_i`'s spans, `emit`'s type
/// endset, and the query endsets of the ftt family) meets it there, at one
/// door — save `insert`'s `values`, whose minted values [`MAX_INSERT_VALUES`]
/// bounds instead.
///
/// Not a round number: it is M7's published per-slot budget
/// ([`MAX_SLOT_SPANS`]), whose argument transfers verbatim. That argument
/// is that a span's live cost is not bounded by the wire bytes that carry
/// it — an address is ~19 wire bytes and the span it becomes is two
/// multi-component `BigUint` tumblers, order half a kilobyte — so a list
/// bounded only by the request body names hundreds of thousands of spans.
/// A query endset is built the same way and then costs more, not less: M7
/// answers a descriptor's first constraint from its coverage index at one
/// probe per query span, and tests every later constraint's spans against
/// every link the first finds, so a query's span count multiplies the links
/// it reaches rather than one stored value.
///
/// Reading the two budgets as one number is the point: a query slot larger
/// than the largest slot that can be *stored* cannot discriminate anything a
/// smaller one does not, so the cap costs no expressible question. The
/// refusal rides the ordinary parse channel — an over-cap frame is
/// `unparseable`/`malformed` with the count named, exactly as any other
/// malformed frame is, rather than a new wire vocabulary.
///
/// Applied at [`p_list`], so the cap is per array. Two ops nest —
/// `compare`'s two operands and `find_docs_containing`'s `regions` are
/// lists of regions, each carrying its own span list — so a frame's total
/// span count is the product of two caps and is bounded by
/// [`crate::limits`]'s request-body cap alone. The budget argument above
/// transfers to one query slot; it does not price a region set, whose cost
/// model is M6's rather than M8's. Anyone raising the body cap for a route
/// that carries these ops owes that number.
///
/// The transferred argument likewise prices a list of spans, which become
/// spans one for one. It does not price a list of V-specs — `copy`'s
/// `specs`, `make_link`'s three slots and `edit_link`'s successor — whose
/// elements resolve against stored arrangement state: one spec becomes as
/// many spans as the source document has runs under it, so a list at this
/// cap expands by a factor this door cannot see and that grows with the
/// source's edit history. M7's own
/// [`RejectCode::SlotTooLarge`](skep_febe::RejectCode::SlotTooLarge) is the
/// evidence that a resolution can exceed its budget; whether that budget
/// is measured before the resolution is built, and what this cap should be
/// if it is not, are M7's and M5's.
const MAX_WIRE_LIST: usize = MAX_SLOT_SPANS;

/// The most values one `insert` frame may mint.
///
/// It is denominated in values and not in wire bytes, because the per-byte
/// write discipline mints one [`Val`] per input byte: each is its own
/// `Arc<[u8]>` allocation — order 32 live bytes after allocator rounding,
/// plus 16 for the fat pointer the vector holds — so the daemon's 8 MiB body
/// cap bounds the request at roughly one part in forty of the allocation it
/// commands. That ratio, not the body size, is what this cap exists to
/// bound.
///
/// The number is M2's transaction budget divided by what one value costs
/// inside it, at the worst case that holds. An `insert` of N atoms commits
/// 2N + 1 records (a mint and a content write per atom, plus one placement),
/// each content record carrying a multi-component address, so an atom's
/// encoded share of the transaction runs to order three hundred bytes; a
/// run of N single-byte values commits two records however long (one range
/// mint and one stretch, about N + 300 bytes), so the per-byte case the cap
/// is cut for stages a few hundred kilobytes under it. For small atoms
/// the cap does not reach M2's ceiling: 2¹⁸ two-byte atoms are about 3.7 MB
/// of request, inside the daemon's body cap, and stage about 75 MB past
/// [`skep_kernel::MAX_TXN_BYTES`] (64 MiB) — there the refusal is M2's,
/// after the staging, lifting with a smaller request. The cap stays
/// denominated in values at this number — the point being *when* it is
/// enforced for the request shapes it bounds: without it the refusal
/// arrives from M2 after the codec has allocated and M5 has staged; with
/// it, a frame that cannot commit is refused before either. Whether the
/// number moves is the configuration register's question.
const MAX_INSERT_VALUES: usize = 1 << 18;

/// The most decimal digits one decimal natural may carry on the wire.
///
/// That is a tumbler component, and every natural field alike (a `width`, a
/// V-position's `subspace` and `ordinal`, a shot run's `width`, a
/// `base_extent`): both doors, [`wire_tumbler`] and [`p_nat`], parse a
/// decimal through [`p_nat_str`], which spends this.
///
/// M1 leaves component magnitude unbounded (T0(a)) and this does not narrow
/// that: the carrier stays a `BigUint`, and M3 — which owns the one door by
/// which caller-chosen component values enter the permanent name space —
/// records that a magnitude bound, should a deployment want one, "belongs
/// where the codec parses a tumbler". This is that place.
///
/// The budget is the read path's, not storage's. A stored magnitude costs
/// once; a magnitude in a query span is cloned on every comparison an M8
/// query makes against it — `classify_spans` derives both operands'
/// endpoints, which copies the start tumbler and computes its reach — so one
/// span carrying a D-digit component costs order D bytes of allocator traffic
/// per stored span it is tested against, per query span. That is the
/// amplification a digit cap closes.
/// A natural *field* meets the same cap through [`p_nat`]: the per-comparison
/// argument above is a tumbler's, and what bounds every decimal alike is the
/// radix conversion, which [`p_nat_str`] refuses before it runs.
///
/// 4096 digits is far above anything the substrate can mint: every ordinal
/// M3 allocates is bounded by the commit count, and every address under a
/// node inherits that node's magnitudes, so a component naming a real
/// entity is a handful of digits. It is chosen to leave the T0(a) carrier
/// visibly unbounded in kind while removing the per-comparison multiplier —
/// a component that would take 10^4000 commits to reach cannot be one a
/// caller needs to name.
///
/// Private, and that is the point: it is spent at [`p_nat_str`] and nowhere
/// else — the one decimal parse [`wire_tumbler`] and [`p_nat`] both call —
/// so a route that admits a tumbler or a natural goes through those doors
/// rather than reassembling this budget beside another module's grammar.
const MAX_NAT_DIGITS: usize = 4096;

/// The most components one tumbler may carry on the wire.
///
/// It is the same budget as [`MAX_NAT_DIGITS`] on the other axis: a
/// tumbler's components are cloned together on every comparison, so depth
/// multiplies exactly as magnitude does. M3 caps a registered node at 32
/// components and every other address is a registered parent extended by
/// separators, a subspace identifier and an ordinal — four fields at most —
/// so an element of a document minted in a deep node's account is under forty
/// components, each sub-account and each version step adding its own fields
/// to that. 256 leaves that room over several times without admitting a
/// tumbler whose depth is the request's only real content. Private for
/// [`MAX_NAT_DIGITS`]'s reason, and spent at the same door.
const MAX_TUMBLER_COMPONENTS: usize = 256;

/// The largest principal id `delegate` will register: `2^53 − 1`.
///
/// It is the top of the range a JSON number carries exactly (AUTH-6.36's
/// clause; AUTH-5.20). Principal ids ride the wire as plain JSON numbers and
/// are `u64` server-side, and a JavaScript-backed client reads every number
/// as a double: past this value it rounds, so such a client would hold a
/// different id from the one the board registered.
///
/// A client that only ever meets ids it minted itself avoids that mistake on
/// its own (AUTH-5.20's "must" binds the minting hand). It is the board's to
/// refuse because the setup act adopts whatever principal sits at
/// `inc(X, 1)` (AUTH-5.87 op (1); the owner-of-address read, AUTH-6.37): a
/// squatter's `delegate` of that address under an id `≥ 2^53` would seat a
/// principal no JavaScript-backed frontend can name — its
/// `GET /challenge?principal=N` and its `POST /session` body would carry the
/// rounded number, a different principal — and the holder's agent space
/// would be unopenable from that client on every device, at a cell an
/// adversary chooses at zero cost. Refused here, no `delegate` off this wire
/// registers an id a client cannot say back.
///
/// **A parse fault and no new token.** It is spent at [`p_minted_id`], on
/// `delegate`'s `new_id` alone — the one field that mints an id — and
/// answered as the ordinary `unparseable` rejection. The fold, M3 and M10
/// carry no such bound: `PrincipalId` is a `u64`, and an `Op` assembled by
/// hand past this bound is this codec's caller's to answer for
/// ([`JsonCodec::marshal_request`]).
const MAX_MINTED_PRINCIPAL_ID: u64 = (1 << 53) - 1;

// The most bytes one frame's idempotency `id` may carry is
// [`MAX_REQ_ID_BYTES`], imported above. This daemon never interprets the id;
// the bound is M10's, because the retention is M10's — the memo keeps the key
// for the life of its entry — and its budget is written where the number is.
// Refusing at parse is this codec's part: the client is told, and told which
// cap it passed.

/// The daemon's JSON codec — stateless; one instance serves every client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    /// Parses a frame as presented: M10's seam, and not the daemon's.
    ///
    /// It is the door the round-trip oracle and tests parse through: a
    /// frame's `attest` member (admitted on the checked set alone — the ten
    /// publish-class kinds `in_checked_set` states — under a `SIG_ALGS` row's
    /// token) rides in [`Request::attest`] parsed and unverified. M10's card
    /// makes that field the signature the daemon's write-path check
    /// *admitted*, which `execute` hands the store and the kernel writes into
    /// the commit marker as it stands, so a request from this door is one to
    /// judge, not to execute. The daemon's own routes never execute one: they
    /// parse through `parse_daemon`, which takes the member out for the check
    /// and hands `execute` a request whose `attest` that check alone fills. A
    /// caller that executes what this returns owes the check itself, or
    /// clears the field.
    ///
    /// # Errors
    ///
    /// A [`ParseError`] whose detail names the fault: a frame that is not
    /// JSON, or one the frame grammar refuses.
    fn parse(&self, frame: &[u8]) -> Result<Request, ParseError> {
        parse_request(frame).map_err(ParseError::from)
    }

    fn marshal(&self, resp: &Response) -> Vec<u8> {
        to_bytes(&j_response(resp))
    }
}

impl JsonCodec {
    /// Returns the canonical request encoding.
    ///
    /// It is the inverse seam `Codec` itself does not name (M10 fixes parse
    /// only). skepd's fuzz oracle and the round-trip tests use it.
    ///
    /// **Precondition.** `req` is within the wire caps this codec enforces on
    /// parse — `MAX_WIRE_LIST` elements per array but `insert`'s `values`,
    /// `MAX_INSERT_VALUES` minted values per `insert`, `MAX_NAT_DIGITS` per
    /// decimal natural (a tumbler component or a natural field),
    /// `MAX_TUMBLER_COMPONENTS` per tumbler, [`MAX_REQ_ID_BYTES`] per
    /// idempotency id, `MAX_MINTED_PRINCIPAL_ID` for a `delegate`'s `new_id`
    /// — carries no zero-byte `Val`, which `marshal::j_atom` renders as
    /// `{"atom": ""}` and `p_val_form` refuses by design (coarse granularity
    /// must be said, and a zero-byte atom says nothing), carries a
    /// `publish`'s `places` either empty or `runs`' length with a place in
    /// it, each place a content position beside a draft-native run (the
    /// form [`Fields::places`] hands on), carries an `id`, if
    /// any, that is UTF-8, which a `ReqId` this codec parsed always is, and
    /// carries an `attest`, if any, only on an op of the checked set (the ten
    /// publish-class kinds `in_checked_set` states and the parse side admits
    /// the member on), under a marker tag a `SIG_ALGS` row names, which an
    /// `Attestation` this codec parsed always is. Under all of that,
    /// `parse(marshal_request(r))` reproduces `r` and re-marshaling the parse
    /// is byte-identical.
    ///
    /// Outside it, marshaling succeeds and yields a frame `parse` refuses:
    /// this is the parse side's trust-boundary obligation and this direction
    /// does not re-check it (one check, one owner). The upstream value types
    /// admit every violation — `Endset::from_spans` takes any span count,
    /// T0(a) leaves a component's magnitude unbounded by design and a `Nat`
    /// field is unbounded by its type, `Val::new` takes any bytes,
    /// `PrincipalId` is any `u64`, `ReqId`'s field is public, and
    /// `Request::attest` rides any op under any tag `Attestation::new` admits
    /// — so a caller assembling a `Request` by hand owes the whole
    /// precondition. A `Request` this codec produced satisfies it by
    /// construction, which is what makes the round-trip oracle sound.
    ///
    /// One normalization survives the precondition rather than being
    /// excluded by it: `SlotSpec::Spans` over an empty endset marshals as
    /// `[]`, which `p_slotspec` deliberately reads back as
    /// `SlotSpec::Empty` — M8's same constraint under its canonical name. So
    /// for such an `r` the round trip is the same query and not an equal
    /// `Request` (`FourSet`'s `Eq` is representational), and re-marshaling
    /// gives `"empty"`. `parse` cannot mint that value, so a `Request` this
    /// codec produced is again unaffected.
    ///
    /// A non-UTF-8 `id` is the one violation of this precondition that
    /// neither round-trips nor is refused: it is rendered lossily rather
    /// than panicking, and the frame parses — to a *different* `ReqId`. That
    /// matters because `id` is an idempotency key M10 matches exactly: two
    /// distinct non-UTF-8 ids collapse onto one replacement string, so a
    /// retry can hit a memo entry it did not write, or miss the one it did.
    /// A `ReqId` this codec parsed is the UTF-8 bytes of the frame's `id`
    /// string and cannot be one.
    pub fn marshal_request(&self, req: &Request) -> Vec<u8> {
        let (name, mut pairs) = req_pairs(&req.op);
        if let Some(ReqId(bytes)) = &req.id {
            pairs.push(("id", Value::String(String::from_utf8_lossy(bytes).into_owned())));
        }
        // The `attest` member, where the request carries one (signed ops):
        // the tag lifted back to its `alg` token, the blob as hex. A tag no
        // row names, or an op outside the checked set, is outside the
        // precondition: the one renders a token `parse` refuses, the other a
        // member `parse` refuses as an unknown field.
        if let Some(a) = &req.attest {
            pairs.push(("attest", j_attest(a)));
        }
        pairs.push(("op", Value::String(name.into())));
        to_bytes(&obj(pairs))
    }

    /// Parses a daemon-level frame: the `key_set` frame or the ordinary one.
    ///
    /// The `key_set` frame is served by the daemon's own dispatcher because
    /// M10 carries no `key_set` row (AUTH-6.18–6.20); the other is the
    /// ordinary M10 frame. One grammar discipline for both: internally
    /// tagged, unknown fields refused.
    ///
    /// # Errors
    ///
    /// A [`ParseError`] whose detail names the fault: `invalid JSON: …` for a
    /// frame that is not JSON, or the grammar's refusal of either frame.
    pub fn parse_daemon(&self, frame: &[u8]) -> Result<DaemonOp, ParseError> {
        let v: Value = match serde_json::from_slice(frame) {
            Ok(v) => v,
            Err(e) => {
                return Err(ParseError { detail: Some(format!("invalid JSON: {e}")), site: None })
            }
        };
        self.parse_daemon_value(v)
    }

    /// Parses an already-decoded value as [`JsonCodec::parse_daemon`] does.
    ///
    /// The value is the `/op-at` envelope's frame.
    ///
    /// # Errors
    ///
    /// A [`ParseError`] whose detail names the grammar's refusal of the
    /// `key_set` frame or of the ordinary frame.
    pub fn parse_daemon_value(&self, v: Value) -> Result<DaemonOp, ParseError> {
        if v.as_object().and_then(|m| m.get("op")).and_then(Value::as_str) == Some("key_set") {
            return parse_key_set(v).map_err(|e| ParseError::from(Refusal::from(e)));
        }
        parse_value(v)
            .map(|mut request| {
                let presented = request.attest.take();
                DaemonOp::Febe { request: Box::new(request), presented }
            })
            .map_err(ParseError::from)
    }

    /// Returns the rejection that answers a frame which failed to parse.
    ///
    /// It is the transport's one never-silent obligation outside M10's
    /// dispatch (M10 §Codec): a frame that failed to parse still gets exactly
    /// one response. M10 classifies it — the code and its disposition come
    /// from the same table every other rejection goes through — and this
    /// crate marshals it like any other.
    pub fn unparseable(&self, e: ParseError) -> Response {
        Response::Rejected(Rejection::unparseable(e))
    }
}

/// One parsed daemon-level frame: an M10 request or the `key_set` read.
///
/// The `key_set` read is the one the daemon serves itself (AUTH-6.18–6.20).
/// No `Debug`: both consumers match rather than print. The request rides
/// boxed — it is an order of magnitude wider than the other arm, and this
/// enum sits on every dispatch path.
pub enum DaemonOp {
    /// An M10 request, its `attest` empty, beside the one the frame presented.
    ///
    /// The request's `attest` is empty whatever the frame carried, and the
    /// member the frame *presented* rides beside it — unverified, the
    /// write-path check's to judge (signed ops). Split here, at the door, so
    /// that on the daemon's dispatch path `Request::attest` only ever holds
    /// what M10's own card says it holds: the signature the daemon's check
    /// *admitted*, set by the write sequence that ran the check and by
    /// nothing else. A route that never judges `presented` then commits with
    /// the marker slot empty — never with a blob nobody verified, which the
    /// kernel writes opaquely and a reader of the journal takes for an
    /// author's attestation this board admitted.
    Febe {
        /// The request, its `attest` emptied.
        request: Box<Request>,
        /// The `attest` the frame presented, unverified.
        presented: Option<Attestation>,
    },
    /// The `key_set` read the daemon serves itself (AUTH-6.18).
    KeySet {
        /// The account whose key set is asked.
        account: Address,
    },
}

/// Parses the `key_set` frame, `{"op":"key_set","account":"<address>"}`.
///
/// It takes the optional idempotency `id` too, accepted and dropped — reads
/// are never memoized — and holds the frame to the same field discipline as
/// every other frame.
///
/// # Errors
///
/// A [`PErr`] where the frame is not an object, its `id` is refused
/// ([`Fields::req_id`]), its `account` is missing or no wire address, or a
/// field is left unknown.
fn parse_key_set(v: Value) -> PResult<DaemonOp> {
    let Value::Object(m) = v else {
        return Err(PErr("request frame must be a JSON object".into()));
    };
    let mut fields = Fields(m);
    let _ = fields.string("op")?;
    let _ = fields.req_id()?;
    let account = fields.addr("account")?;
    fields.finish()?;
    Ok(DaemonOp::KeySet { account })
}

/// Returns a finished `Value` tree's bytes, compact JSON.
///
/// It is the one place this crate turns a `Value` into bytes, with
/// `append_bytes` its form into a buffer the caller holds, so the proof
/// that it cannot fail is written once and holds everywhere it is used:
/// wire responses, transport-error bodies, the change feed's pages, the
/// commit stream's event payloads and the sidecar's own file lines are all
/// trees built out of [`obj`] and the leaf marshalers, which means string
/// keys only and no foreign `Serialize` impl to fault. The tree is borrowed:
/// serializing reads it, so a caller that still needs the value keeps it
/// without a copy.
pub fn to_bytes(v: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    append_bytes(&mut out, v);
    out
}

/// Appends a `Value` tree's bytes to `out`, as [`to_bytes`] writes them.
///
/// It is that marshal into a buffer the caller holds, for a document marshaled
/// a part at a time — the change feed's page, a row at a time — under the
/// same proof.
pub(crate) fn append_bytes(out: &mut Vec<u8>, v: &Value) {
    serde_json::to_writer(out, v)
        .expect("serializing a serde_json::Value with string keys cannot fail");
}

// ── parse (wire → Request) ──────────────────────────────────────────────

/// Internal parse fault; becomes `ParseError::detail`.
#[derive(Debug)]
struct PErr(String);

impl std::fmt::Display for PErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

type PResult<T> = Result<T, PErr>;

/// A parse fault as the door answers it: the detail, and the entry of the
/// request's own list it is localized to, where it is one — the site the
/// `Unparseable` rejection carries (`site.index`).
///
/// Every leaf parser answers a bare [`PErr`], which lifts into this naming
/// no entry; the one parser that localizes its refusal — the publish shot's
/// `places`, refused entry by entry ([`Fields::places`]) — answers this
/// directly. The request's own faults ride it to [`ParseError`]. A tuple as
/// [`PErr`] is, its detail first, so a reader of either names the text the
/// same way.
#[derive(Debug)]
struct Refusal(String, Option<usize>);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<PErr> for Refusal {
    fn from(e: PErr) -> Refusal {
        Refusal(e.0, None)
    }
}

impl From<Refusal> for ParseError {
    fn from(r: Refusal) -> ParseError {
        ParseError {
            detail: Some(r.0),
            site: r.1.map(|index| FaultSite { index: Some(index), ..FaultSite::default() }),
        }
    }
}

fn parse_request(frame: &[u8]) -> Result<Request, Refusal> {
    let v: Value = serde_json::from_slice(frame).map_err(|e| PErr(format!("invalid JSON: {e}")))?;
    parse_value(v)
}

/// Parses a decoded value by the frame grammar: everything past `from_slice`.
///
/// So a frame that arrives already decoded meets the identical rules.
///
/// # Errors
///
/// A [`Refusal`], in this order: the value is not an object; its `op` is
/// missing or no string; its `id` is refused ([`Fields::req_id`]); the op is
/// unknown or its own fields are refused ([`parse_op`]); its `attest` member
/// is refused ([`Fields::attest`]); a field is left unknown.
fn parse_value(v: Value) -> Result<Request, Refusal> {
    let Value::Object(m) = v else {
        return Err(PErr("request frame must be a JSON object".into()).into());
    };
    let mut fields = Fields(m);
    let name = fields.string("op")?;
    // The id is capped where it is minted, and before it is copied: M10
    // retains it for the life of a memoized write, so its length is the
    // second factor in a retention bill — one the memo bounds again by
    // declining a longer key (see [`MAX_REQ_ID_BYTES`]).
    let id = fields.req_id()?;
    let op = parse_op(&name, &mut fields)?;
    // The optional `attest` member, admitted on the checked set
    // [`in_checked_set`] states and on no other op — left in the map
    // elsewhere, so `finish` refuses it by the unknown-field rule, as a
    // daemon that predates the member does (the design record §7.3 (ii)).
    let attest = fields.attest(op.kind())?;
    fields.finish()?;
    Ok(Request { id, op, attest })
}

/// Lifts the wire's `attest` object to the kernel's `Attestation`.
///
/// The object is `{"alg": <an ALGS token>, "sig": <hex>}` (the design record
/// §7.3 (ii)): the token goes to the marker tag its `SIG_ALGS` row names (a
/// token no row carries is a grammar failure — the token set is an I2
/// frozen constant, so an unknown one is refused as an unknown op is), the
/// hex to the blob (empty is refused: absence is the member's own —
/// missing, or `null`, which [`Fields::attest`] reads alike — never an empty
/// blob). The blob's *width* under the tag is the check's to judge, not the
/// grammar's — save the one width no tag admits: past
/// [`skep_kernel::MAX_SIG_BYTES`] the kernel's own constructor refuses the
/// blob, and that refusal is the grammar's.
///
/// # Errors
///
/// A [`PErr`] where the value is no object or carries a key beside `alg`
/// and `sig`, where `alg` is missing, no string or a token no row carries,
/// where `sig` is missing or no even-length hex, or where the kernel's
/// constructor refuses the blob.
fn p_attest(v: &Value) -> PResult<Attestation> {
    let m = p_obj(v, &["alg", "sig"])?;
    let alg = field(m, "alg", p_string)?;
    let row = SigAlgRow::of_token(&alg)
        .ok_or_else(|| PErr(format!("field 'alg': unknown algorithm token '{}'", bounded(&alg))))?;
    let sig = field(m, "sig", |v| p_hex(p_str(v)?))?;
    Attestation::new(row.tag, sig).map_err(|e| PErr(format!("field 'sig': {e}")))
}

/// Parses the op `name` names, one request-envelope arm per `Op` variant.
///
/// Field names are the wire contract (wire.md §Operations); the Rust-name
/// departures are `principal_prefix`, whose argument rides as `"principal"`
/// because the envelope key `"id"` is the idempotency slot, and `publish`,
/// whose `shot` rides flattened into the envelope — its base's member as
/// `"base"` and its extent as `"base_extent"`, beside `"draft"` and
/// `"runs"` — with its kept places beside them as `"places"`.
///
/// # Errors
///
/// A [`Refusal`] naming an unknown op, or a field of the op's own that is
/// missing or refused — the entry named where the field is a `publish`'s
/// `places` ([`Fields::places`]).
fn parse_op(name: &str, fields: &mut Fields) -> Result<Op, Refusal> {
    Ok(match name {
        "create_new_document" => Op::CreateNewDocument {
            account: fields.addr("account")?,
            published: fields.published()?,
        },
        "delegate" => Op::Delegate {
            new_prefix: fields.tum("new_prefix")?,
            new_id: PrincipalId(fields.minted_id("new_id")?),
        },
        "register_node" => Op::RegisterNode { addr: fields.tum("addr")? },
        "fork" => Op::Fork { published: fields.published()? },
        "next_account_prefix" => Op::NextAccountPrefix { parent: fields.addr("parent")? },
        "principal_prefix" => Op::PrincipalPrefix { id: PrincipalId(fields.u64("principal")?) },
        "effective_owner" => Op::EffectiveOwner { addr: fields.addr("addr")? },
        "doc_metadata" => Op::DocMetadata { doc: fields.addr("doc")? },
        "insert" => Op::Insert {
            doc: fields.addr("doc")?,
            at: fields.vpos("at")?,
            values: fields.vals("values")?,
            deposit: fields.deposit()?,
        },
        "delete" => Op::Delete {
            doc: fields.addr("doc")?,
            p: fields.vpos("p")?,
            width: fields.nat("width")?,
        },
        "copy" => Op::Copy {
            doc: fields.addr("doc")?,
            at: fields.vpos("at")?,
            specs: fields.vspecs("specs")?,
        },
        // The write by identity (wire.md §Arrangement, `reinstate`): the runs
        // in the shot's own form, through the one run parser, so no
        // zero-width run and no start that is not a full element position
        // survives the trust boundary here either.
        "reinstate" => Op::Reinstate {
            doc: fields.addr("doc")?,
            at: fields.vpos("at")?,
            runs: fields.shot_runs("runs")?,
        },
        "rearrange" => Op::Rearrange { doc: fields.addr("doc")?, cuts: fields.vposes("cuts")? },
        "version" => Op::Version { d_src: fields.addr("d_src")?, published: fields.published()? },
        // The target, the claim's flag, the shot, then its kept places and
        // its deposits beside it (the link-sets design §5.7): the places
        // parallel to the runs the shot just took, so they are read against
        // them; the deposits' member positions read against the same runs.
        // The claim rides either form (skep #692) and names the rendering
        // draft, so `draft` is required beside it at both.
        "publish" => {
            let target = fields.publish_target()?;
            let claim = fields.flag("claim")?;
            let shot = fields.shot()?;
            if claim && shot.draft.is_none() {
                return Err(PErr("field 'claim': the edition claim names the rendering draft, so 'draft' is required beside it".into()).into());
            }
            let places = fields.places(&shot, &target)?;
            let deposits = fields.deposits(&shot, &target, claim)?;
            Op::Publish { target, shot, places, deposits }
        }
        "make_link" => Op::MakeLink {
            home: fields.addr("home")?,
            from: fields.slotarg("from")?,
            to: fields.slotarg("to")?,
            ty: fields.slotarg("ty")?,
            replaces: fields.replaces()?,
        },
        "emit" => Op::Emit {
            home: fields.addr("home")?,
            ty: fields.endset("ty")?,
            from: fields.addr("from")?,
            to: fields.addrs("to")?,
        },
        "nullify" => Op::Nullify { home: fields.addr("home")?, target: fields.addr("target")? },
        "assert_sup" => Op::AssertSup {
            home: fields.addr("home")?,
            old: fields.addr("old")?,
            new: fields.addr("new")?,
        },
        "edit_link" => Op::EditLink {
            original: fields.addr("original")?,
            successor: fields.successor("successor")?,
            d_s: fields.addr("d_s")?,
            d_a: fields.addr("d_a")?,
        },
        "read_link" => Op::ReadLink { a: fields.addr("a")? },
        "follow_link" => Op::FollowLink { a: fields.addr("a")?, slot: fields.usize("slot")? },
        "retrieve_v" => Op::RetrieveV { specs: fields.specs("specs")? },
        // The read by identity and the content-frontier read (AUTH-6.38–6.40;
        // wire.md §Content & provenance reads) — an interim grammar: a span
        // is `{"start": <address>, "width": <nat>}`, its document derived,
        // never named; the frontier read names its `doc`.
        "retrieve_i" => Op::RetrieveI { spans: fields.ispans("spans")? },
        "content_frontier" => Op::ContentFrontier { doc: fields.addr("doc")? },
        "retrieve_doc_v_span" => Op::RetrieveDocVSpan { doc: fields.addr("doc")? },
        "retrieve_doc_v_span_set" => Op::RetrieveDocVSpanSet { doc: fields.addr("doc")? },
        "show_origin" => Op::ShowOrigin { doc: fields.addr("doc")?, span: fields.span("span")? },
        "show_deletions" => {
            Op::ShowDeletions { d_a: fields.addr("d_a")?, d_b: fields.addr("d_b")? }
        }
        "compare" => Op::Compare { rho1: fields.regions("rho1")?, rho2: fields.regions("rho2")? },
        "find_docs_containing" => Op::FindDocsContaining { regions: fields.regions("regions")? },
        "image" => Op::Image { d: fields.addr("d")?, region: fields.spans("region")? },
        "find_links_v" => Op::FindLinksV { d: fields.addr("d")?, region: fields.spans("region")? },
        "find_links_ftt" => Op::FindLinksFtt { q: fields.fourset("q")? },
        "count_v" => Op::CountV { d: fields.addr("d")?, region: fields.spans("region")? },
        "count_ftt" => Op::CountFtt { q: fields.fourset("q")? },
        "window_v" => Op::WindowV {
            d: fields.addr("d")?,
            region: fields.spans("region")?,
            cur: fields.cursor("cur")?,
            n: fields.usize("n")?,
        },
        "window_ftt" => Op::WindowFtt {
            q: fields.fourset("q")?,
            cur: fields.cursor("cur")?,
            n: fields.usize("n")?,
        },
        // The count by home (wire.md §Link discovery reads): `d` and `region`
        // as `count_v`'s, the budget `n` as `window_v`'s, and `except` one
        // wire list of home addresses under the list cap, absent and `null`
        // alike the empty list.
        "count_v_by_home" => Op::CountVByHome {
            d: fields.addr("d")?,
            region: fields.spans("region")?,
            n: fields.usize("n")?,
            except: fields.addrs_opt("except")?,
        },
        // The retracted-links read (wire.md §Link discovery reads): `d`,
        // `region`, `cur` and `n` as `window_v`'s, the view the read's own.
        "find_links_v_history" => Op::FindLinksVHistory {
            d: fields.addr("d")?,
            region: fields.spans("region")?,
            cur: fields.cursor("cur")?,
            n: fields.usize("n")?,
        },
        "retrieve_endsets" => {
            Op::RetrieveEndsets { d: fields.addr("d")?, region: fields.spans("region")? }
        }
        "project" => {
            Op::Project { a: fields.addr("a")?, slot: fields.usize("slot")?, d: fields.addr("d")? }
        }
        "discoverable_from" => Op::DiscoverableFrom { a: fields.addr("a")?, d: fields.addr("d")? },
        "delete_orphans" => Op::DeleteOrphans {
            d: fields.addr("d")?,
            p: fields.vpos("p")?,
            width: fields.nat("width")?,
        },
        "in_claims" => Op::InClaims { y: fields.addr("y")?, view: fields.view("view")? },
        "out_claims" => Op::OutClaims { x: fields.addr("x")?, view: fields.view("view")? },
        "edition_claims" => Op::EditionClaims { target: fields.addr("target")? },
        // No argument (PUB-8.47): `finish` refuses any field beside `op` and
        // the idempotency `id`, as everywhere.
        "universal_grants" => Op::UniversalGrants,
        other => return Err(PErr(format!("unknown op '{}'", bounded(other))).into()),
    })
}

/// Returns whether `kind` is of the checked set.
///
/// The checked set is the op kinds the write-path check reaches, and so the
/// ops an entry frame is composed for: the ten publish-class kinds (the ten
/// cells signed-ops D24 pins) — `create_new_document`, `fork`, `version`,
/// `insert`, `publish`, `make_link`, `emit`, `nullify`, `assert_sup`,
/// `edit_link`. The four other publish-class-capable kinds — `delete`,
/// `copy`, `reinstate`, `rearrange` — have no cell: the store refuses every
/// one of them into a published document (`published_target`) and no
/// publish-class write of their kind commits above the claim, so the gate's
/// fourteen inputs are the check's ten. This is the daemon's one statement
/// of it: the codec admits a request's `attest` member exactly on these, the
/// check demands and verifies one exactly on these, and `auth::entry::compose`
/// has an arm exactly for these. The acting hand *attests*; the check admits
/// or refuses, and signs nothing. The three must agree in both directions — a
/// member the codec admits and the check never demands is a signature
/// parsed and silently dropped, the commit landing with its marker slot
/// empty; one the check demands and the codec refuses is a write no signed
/// session can make on a claimed board — so a widening is one edit here and
/// one arm in `auth::entry::compose`, whose wildcard stops loudly in every
/// build: a widening that forgets the arm answers `500 internal_panic` on
/// each such write, and never commits one with its marker slot empty.
pub(crate) fn in_checked_set(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::CreateNewDocument
            | OpKind::Fork
            | OpKind::Version
            | OpKind::Insert
            | OpKind::Publish
            | OpKind::MakeLink
            | OpKind::Emit
            | OpKind::Nullify
            | OpKind::AssertSup
            | OpKind::EditLink
    )
}

/// The request object being consumed, its known fields taken out.
///
/// Anything left at [`Fields::finish`] is an unknown field and fails the
/// parse.
#[derive(Debug)]
struct Fields(Map<String, Value>);

impl Fields {
    fn take(&mut self, k: &'static str) -> PResult<Value> {
        self.0.remove(k).ok_or_else(|| PErr(format!("missing field '{k}'")))
    }

    /// Takes field `k`, absent and explicit `null` being the same absence.
    fn take_opt(&mut self, k: &'static str) -> Option<Value> {
        match self.0.remove(k) {
            None | Some(Value::Null) => None,
            Some(v) => Some(v),
        }
    }

    fn finish(self) -> PResult<()> {
        match self.0.keys().next() {
            Some(k) => Err(PErr(format!("unknown field '{}'", bounded(k)))),
            None => Ok(()),
        }
    }

    fn field<T>(&mut self, k: &'static str, f: impl FnOnce(&Value) -> PResult<T>) -> PResult<T> {
        let v = self.take(k)?;
        f(&v).map_err(|e| PErr(format!("field '{k}': {e}")))
    }

    fn string(&mut self, k: &'static str) -> PResult<String> {
        self.field(k, p_string)
    }

    /// Takes the frame's idempotency id, capped *before* the copy.
    ///
    /// That is the discipline [`room`] states and [`hex_values`] follows. A
    /// [`MAX_REQ_ID_BYTES`] cap enforced after the string has been copied out
    /// of the tree copies up to a whole request body to refuse 257 bytes.
    ///
    /// # Errors
    ///
    /// A [`PErr`] where the `id` is no string, or is longer than
    /// [`MAX_REQ_ID_BYTES`] bytes.
    fn req_id(&mut self) -> PResult<Option<ReqId>> {
        let Some(v) = self.take_opt("id") else { return Ok(None) };
        let s = v.as_str().ok_or_else(|| PErr("field 'id': expected a JSON string".into()))?;
        if s.len() > MAX_REQ_ID_BYTES {
            return Err(PErr(format!(
                "id is {} bytes, past the {MAX_REQ_ID_BYTES}-byte wire cap",
                s.len()
            )));
        }
        Ok(Some(ReqId(s.as_bytes().to_vec())))
    }

    fn u64(&mut self, k: &'static str) -> PResult<u64> {
        self.field(k, p_u64)
    }

    /// Takes the optional top-level `attest` member on a checked-set op.
    ///
    /// On an op of the checked set ([`in_checked_set`]) absent and explicit
    /// `null` alike read `None`; on any other op it is not taken at all, so
    /// `finish` refuses it as the unknown field it is there. The checked set
    /// is one statement and it is the codec's — the wire grammar's — because
    /// what it states is which ops carry `attest` on the wire (M10's interface
    /// calls it skepd's `JsonCodec`'s); the composer (`auth/entry`) and the
    /// policy *read* it from here.
    ///
    /// # Errors
    ///
    /// A [`PErr`] where the member, on an op of the checked set, is refused
    /// ([`p_attest`]).
    fn attest(&mut self, kind: OpKind) -> PResult<Option<Attestation>> {
        if !in_checked_set(kind) {
            return Ok(None);
        }
        match self.take_opt("attest") {
            None => Ok(None),
            Some(v) => p_attest(&v).map(Some).map_err(|e| PErr(format!("field 'attest': {e}"))),
        }
    }

    /// Takes `delegate`'s `new_id`, the wire's one principal id that *mints*.
    ///
    /// So it is the one held to [`MAX_MINTED_PRINCIPAL_ID`] at this door.
    /// Every other id field only *names* a principal: one some `delegate`
    /// registered is inside the range by this bound, and one nobody
    /// registered answers absent.
    ///
    /// # Errors
    ///
    /// A [`PErr`] where the field is missing or refused ([`p_minted_id`]).
    fn minted_id(&mut self, k: &'static str) -> PResult<u64> {
        self.field(k, p_minted_id)
    }

    fn usize(&mut self, k: &'static str) -> PResult<usize> {
        self.field(k, p_usize)
    }

    fn nat(&mut self, k: &'static str) -> PResult<Nat> {
        self.field(k, p_nat)
    }

    fn tum(&mut self, k: &'static str) -> PResult<Tumbler> {
        self.field(k, p_tum)
    }

    fn addr(&mut self, k: &'static str) -> PResult<Address> {
        self.field(k, p_addr)
    }

    fn addrs(&mut self, k: &'static str) -> PResult<Vec<Address>> {
        self.field(k, |v| p_list(v, p_addr))
    }

    /// Takes an optional list of addresses: absent and explicit `null`
    /// alike are the empty list (`take_opt`'s rule), and a present one is a
    /// wire list under [`MAX_WIRE_LIST`] — `count_v_by_home`'s `except`.
    ///
    /// # Errors
    ///
    /// A [`PErr`] where a present value is no array, is past the cap, or
    /// holds an element that is no address ([`p_list`], [`p_addr`]).
    fn addrs_opt(&mut self, k: &'static str) -> PResult<Vec<Address>> {
        match self.take_opt(k) {
            None => Ok(Vec::new()),
            Some(v) => p_list(&v, p_addr).map_err(|e| PErr(format!("field '{k}': {e}"))),
        }
    }

    fn span(&mut self, k: &'static str) -> PResult<Span> {
        self.field(k, p_span)
    }

    fn spans(&mut self, k: &'static str) -> PResult<Vec<Span>> {
        self.field(k, |v| p_list(v, p_span))
    }

    fn vpos(&mut self, k: &'static str) -> PResult<VPos> {
        self.field(k, p_vpos)
    }

    fn vposes(&mut self, k: &'static str) -> PResult<Vec<VPos>> {
        self.field(k, |v| p_list(v, p_vpos))
    }

    fn vspecs(&mut self, k: &'static str) -> PResult<Vec<VSpec>> {
        self.field(k, |v| p_list(v, p_vspec))
    }

    /// Takes a `reinstate`'s runs, in the shot's run form.
    ///
    /// They are one list under the wire's list cap.
    ///
    /// # Errors
    ///
    /// A [`PErr`] where the field is missing, or its list or a run in it is
    /// refused ([`p_list`], [`p_shot_run`]).
    fn shot_runs(&mut self, k: &'static str) -> PResult<Vec<ShotRun>> {
        self.field(k, |v| p_list(v, p_shot_run))
    }

    fn slotarg(&mut self, k: &'static str) -> PResult<SlotArg> {
        self.field(k, p_slotarg)
    }

    fn specs(&mut self, k: &'static str) -> PResult<Vec<Spec>> {
        self.field(k, |v| p_list(v, p_spec))
    }

    fn ispans(&mut self, k: &'static str) -> PResult<Vec<ISpan>> {
        self.field(k, |v| p_list(v, p_ispan))
    }

    fn regions(&mut self, k: &'static str) -> PResult<Vec<RegionSpec>> {
        self.field(k, |v| p_list(v, p_region))
    }

    fn vals(&mut self, k: &'static str) -> PResult<Vec<Val>> {
        self.field(k, p_values)
    }

    fn endset(&mut self, k: &'static str) -> PResult<Endset> {
        self.field(k, p_endset)
    }

    fn view(&mut self, k: &'static str) -> PResult<View> {
        self.field(k, p_view)
    }

    fn fourset(&mut self, k: &'static str) -> PResult<FourSet> {
        self.field(k, p_fourset)
    }

    /// Takes the three-valued publication flag on the minting ops (PUB-8.16).
    ///
    /// It is `absent | true | false`, with absent and explicit `null` reading
    /// the same absence (`take_opt`'s rule) → `None`.
    ///
    /// # Errors
    ///
    /// A [`PErr`] for any non-boolean value: a parse fault, never silently
    /// coerced.
    fn published(&mut self) -> PResult<Option<bool>> {
        match self.take_opt("published") {
            None => Ok(None),
            Some(v) => v
                .as_bool()
                .map(Some)
                .ok_or_else(|| PErr("field 'published': expected true or false".into())),
        }
    }

    /// Takes `insert`'s deposit declaration.
    ///
    /// It is PUB-9.13's declared horn (PUB-2.63): the field's value is the
    /// record class's type (PUB-2.64; RES-249), an address string, and absent
    /// — the field not sent — is the one spelling of `Undeclared`, an ordinary
    /// edit. So this field does not go through [`take_opt`](Self::take_opt):
    /// an explicit `null` is a declaration with nothing in it. Which types the
    /// deposit class holds is not this parse's to know: any T4-valid address
    /// declares, and M5's door tests it (`published_target` for a type the
    /// class does not hold). Both arms are written out, which is where M5 asks
    /// a reader to see which one is declared.
    ///
    /// # Errors
    ///
    /// A [`PErr`] for that explicit `null` and, like it, for `true` / `false`
    /// and any other non-address: a parse fault, never coerced to either arm.
    fn deposit(&mut self) -> PResult<Deposit> {
        match self.0.remove("deposit") {
            None => Ok(Deposit::Undeclared),
            Some(v) => {
                p_addr(&v).map(Deposit::Declared).map_err(|e| PErr(format!("field 'deposit': {e}")))
            }
        }
    }

    /// Takes `make_link`'s `replaces` member (PUB-5.15 (iii), (iv); RES-308).
    ///
    /// It is the state the record *replaces*, an address string — at the
    /// grant, the revocation a re-share follows — and absent, the field not
    /// sent, is the one spelling of the empty state, a first share's. So, as
    /// `deposit`, this does not go through [`take_opt`](Self::take_opt): an
    /// explicit `null` would be a member *present* with nothing in it, the one
    /// shape the entry frame's `replaces` row keeps apart from absent. Which
    /// address names the key's current state is not this parse's to know: any
    /// T4-valid address is a member, and the grant fold decides what it
    /// honors.
    ///
    /// # Errors
    ///
    /// A [`PErr`] for that explicit `null` — a parse fault, never coerced to
    /// either — and for any other value that is no wire address.
    fn replaces(&mut self) -> PResult<Option<Address>> {
        match self.0.remove("replaces") {
            None => Ok(None),
            Some(v) => p_addr(&v).map(Some).map_err(|e| PErr(format!("field 'replaces': {e}"))),
        }
    }

    /// Takes the cursor `k`: absent ≡ null ≡ ⊥ (start of the enumeration).
    ///
    /// # Errors
    ///
    /// A [`PErr`] where the cursor is present and no wire address
    /// ([`Fields::opt_addr`]).
    fn cursor(&mut self, k: &'static str) -> PResult<Option<Address>> {
        self.opt_addr(k)
    }

    /// Takes an optional address field.
    ///
    /// Absent and explicit `null` alike read `None`.
    ///
    /// # Errors
    ///
    /// A [`PErr`] where the field is present and does not parse as an
    /// address.
    fn opt_addr(&mut self, k: &'static str) -> PResult<Option<Address>> {
        match self.take_opt(k) {
            None => Ok(None),
            Some(v) => p_addr(&v).map(Some).map_err(|e| PErr(format!("field '{k}': {e}"))),
        }
    }

    /// Takes the publish shot's own fields (wire v7.3, PUB-8.1; the link-sets
    /// design §5.7, THE REQUEST).
    ///
    /// `base` and `base_extent` travel together — a base without the extent
    /// its copy took is a base the composite cannot compose against
    /// (PUB-2.42), and an extent without a base measures nothing — so either
    /// both are present or neither is (the birth version, PUB-2.34); `draft`
    /// is optional, the rendering draft; `also` is optional, the family's
    /// other drafts whose identity the shot re-mints beside it (the Nelson
    /// way, B3-S10) — a wire list of addresses under [`MAX_WIRE_LIST`],
    /// distinct, none the `draft` itself, and carried only beside a `draft`,
    /// since a shot naming no rendering draft re-mints nothing; absent and
    /// the empty list alike are the one-draft shot, the form the marshal
    /// writes back; `runs` is the client-rendered arrangement, each run its
    /// origin, its start and its width.
    ///
    /// # Errors
    ///
    /// A [`Refusal`] where `base`, `base_extent`, `draft` or `also` is
    /// present and refused, where one of `base` and `base_extent` comes
    /// without the other, where `also` is carried without `draft`, or where
    /// `runs` is missing or refused; the two shapes of `also` judged entry by
    /// entry — an entry that is the `draft` itself, an entry repeating an
    /// earlier one — name the entry at fault in the `malformed` rejection's
    /// `site.index`, as [`Fields::places`] names its.
    fn shot(&mut self) -> Result<Shot, Refusal> {
        let member = self.opt_addr("base")?;
        let extent = match self.take_opt("base_extent") {
            None => None,
            Some(v) => Some(p_nat(&v).map_err(|e| PErr(format!("field 'base_extent': {e}")))?),
        };
        let base = match (member, extent) {
            (Some(member), Some(extent)) => Some(Base { member, extent }),
            (None, None) => None,
            (Some(_), None) => {
                return Err(PErr("field 'base_extent': required beside 'base'".into()).into())
            }
            (None, Some(_)) => {
                return Err(PErr("field 'base_extent': carried without 'base'".into()).into())
            }
        };
        let draft = self.opt_addr("draft")?;
        // The family's other drafts, entry by entry, so an entry that is no
        // address names itself in `site.index` as the two shapes below do.
        let also: Vec<Address> = match self.take_opt("also") {
            None => Vec::new(),
            Some(v) => {
                let arr = v.as_array().ok_or_else(|| PErr("field 'also': expected a JSON array".into()))?;
                if arr.len() > MAX_WIRE_LIST {
                    return Err(PErr(format!(
                        "field 'also': array has {} elements, past the {MAX_WIRE_LIST}-element wire cap",
                        arr.len()
                    ))
                    .into());
                }
                arr.iter()
                    .enumerate()
                    .map(|(index, entry)| {
                        p_addr(entry).map_err(|e| Refusal(format!("field 'also': [{index}]: {e}"), Some(index)))
                    })
                    .collect::<Result<Vec<Address>, Refusal>>()?
            }
        };
        if !also.is_empty() && draft.is_none() {
            return Err(PErr(
                "field 'also': the family's other drafts are named beside the rendering draft, so 'draft' is required beside it"
                    .into(),
            )
            .into());
        }
        for (index, entry) in also.iter().enumerate() {
            if draft.as_ref() == Some(entry) {
                return Err(Refusal(
                    format!("field 'also': [{index}]: names the 'draft' itself; 'also' names the family's OTHER drafts"),
                    Some(index),
                ));
            }
            if also[..index].contains(entry) {
                return Err(Refusal(
                    format!("field 'also': [{index}]: repeats an earlier entry; each draft is named once"),
                    Some(index),
                ));
            }
        }
        let runs = self.field("runs", |v| p_list(v, p_shot_run))?;
        Ok(Shot { base, draft, also, runs })
    }

    /// Takes the publish shot's kept places (the link-sets design §5.7).
    ///
    /// `places` is a list parallel to `runs` by index — each entry a
    /// V-position as `reinstate`'s `at` is spelled, the place the run held
    /// in the staging draft when the client composed the request, or `null`
    /// for a run with none. Absent, or every entry `null`, is today's shot
    /// and reads as the empty list; a shorter list is padded with `null` to
    /// `runs`' length — so the value handed on is either empty or exactly as
    /// long as `runs`, with a place in it, the form the marshal writes back.
    /// Outside the signed preimage, as `draft` is: the composer reads the
    /// shot alone, and this is read after it, against the runs it took.
    ///
    /// A place stands beside a run of either kind the re-window has words
    /// for: a run of THE RENDERING DRAFT's own identity, whose stated
    /// `origin` projects to the request's `draft`, and a STRAY run, one of
    /// the document's own identity — its `origin` projecting to the trunk of
    /// `doc` — which the client re-composed by reference to a correspondence
    /// record's published words where the draft still arranges the record's
    /// draft words (the design's "AND THE STRAY PLACES WITH THEM"); a run of
    /// a draft `also` names takes no place — those drafts are left as they
    /// stand, the rendering draft alone re-windowed (B3-S11 P5) — a window
    /// onto any other document is never re-windowed, and at the mint form
    /// the edition has no identity before the commit, so no run is its own.
    ///
    /// # Errors
    ///
    /// A [`Refusal`] where the member is no array; and, naming the entry in
    /// its `index` — the `malformed` rejection's `site.index` — where the
    /// list is longer than `runs` (the first entry past them), where a
    /// non-null entry is no V-position, lies outside the content subspace
    /// (a kept place is a content position), or sits beside a run whose
    /// stated `origin` projects to neither the request's `draft` nor the
    /// trunk of its `doc` — a run of a draft `also` names among them: a
    /// place belongs to a run of the rendering draft's identity or a stray
    /// run of the document's own identity, and a request naming no draft
    /// has none.
    fn places(&mut self, shot: &Shot, target: &PublishTarget) -> Result<Vec<Option<VPos>>, Refusal> {
        let Some(v) = self.take_opt("places") else { return Ok(Vec::new()) };
        let arr =
            v.as_array().ok_or_else(|| PErr("field 'places': expected a JSON array".into()))?;
        if arr.len() > shot.runs.len() {
            return Err(Refusal(
                format!("field 'places': {} entries beside {} runs", arr.len(), shot.runs.len()),
                Some(shot.runs.len()),
            ));
        }
        let draft = shot.draft_document();
        // The document's own trunk at the document form; the account at the
        // mint form, which no run's origin projects to.
        let own = target.term();
        let at = |index: usize, fault: &str| {
            Refusal(format!("field 'places': [{index}]: {fault}"), Some(index))
        };
        let mut out: Vec<Option<VPos>> = Vec::with_capacity(shot.runs.len());
        for (index, (entry, run)) in arr.iter().zip(&shot.runs).enumerate() {
            if entry.is_null() {
                out.push(None);
                continue;
            }
            let place = p_vpos(entry).map_err(|e| at(index, &e.0))?;
            if !place.is_content() {
                return Err(at(index, "a kept place is a content position"));
            }
            let origin = trunk_of(&run.origin);
            if draft.is_none() || (draft.as_ref() != Some(&origin) && origin != own) {
                return Err(at(
                    index,
                    "a kept place belongs to a run of the rendering draft's own identity, whose origin is the request's 'draft', or to a stray run of the document's own identity; a run of a draft 'also' names takes no place, and a window onto another document is never re-windowed",
                ));
            }
            out.push(Some(place));
        }
        if out.iter().all(Option::is_none) {
            return Ok(Vec::new());
        }
        out.resize(shot.runs.len(), None);
        Ok(out)
    }

    fn successor(&mut self, k: &'static str) -> PResult<SuccessorSpec> {
        self.field(k, p_successor)
    }

    /// Takes a `publish`'s target (the link-sets design §5.7, THE REQUEST):
    /// the document form or the mint form.
    ///
    /// The document form is `doc`, the published document the shot appends;
    /// the mint form is `mint: true` with `account`, the parent account the
    /// commit mints the edition under, `doc` ABSENT. `mint` is a flag:
    /// absent, `null` and `false` alike are the flag unset, which is the one
    /// spelling the marshal writes back for it. The edition claim's flag,
    /// `claim`, is no part of the target: it rides either form (skep #692)
    /// and the `publish` arm reads it into the deposits.
    ///
    /// # Errors
    ///
    /// A [`PErr`] where `mint` is no boolean, where `doc` or `account` is no
    /// address, and for the shapes that name no one form: `doc` beside
    /// `mint`, `account` without `mint`, `mint` without `account`, neither
    /// `doc` nor `account`.
    fn publish_target(&mut self) -> PResult<PublishTarget> {
        let mint = self.flag("mint")?;
        let doc = self.opt_addr("doc")?;
        let account = self.opt_addr("account")?;
        match (mint, doc, account) {
            (false, Some(doc), None) => Ok(PublishTarget::Document(doc)),
            (true, None, Some(account)) => Ok(PublishTarget::Mint { account }),
            (false, None, Some(_)) => Err(PErr("field 'account': carried without 'mint': true".into())),
            (false, None, None) => Err(PErr("missing field 'doc'".into())),
            (false, Some(_), Some(_)) => {
                Err(PErr("field 'account': carried beside 'doc'; the mint form names 'account' alone".into()))
            }
            (true, Some(_), _) => {
                Err(PErr("field 'doc': carried beside 'mint': true; the mint form names 'account' alone".into()))
            }
            (true, None, None) => Err(PErr("field 'account': required beside 'mint': true".into())),
        }
    }

    /// Takes a boolean flag: absent, `null` and `false` alike are unset.
    ///
    /// # Errors
    ///
    /// A [`PErr`] for any other non-boolean value.
    fn flag(&mut self, k: &'static str) -> PResult<bool> {
        match self.take_opt(k) {
            None => Ok(false),
            Some(v) => v.as_bool().ok_or_else(|| PErr(format!("field '{k}': expected true or false"))),
        }
    }

    /// Takes a `publish`'s three deposit lists (the link-sets design §5.7):
    /// `links`, `retract` and `read_with`, each optional and read as the
    /// empty list where absent — and carries `claim`, the edition claim's
    /// flag the `publish` arm read ahead of the shot, beside them.
    ///
    /// Each list is one wire list under [`MAX_WIRE_LIST`]. A `links` entry
    /// is `{home, ty, from, to, old?}` ([`p_link_entry`]); a `retract` entry
    /// a link address; a `read_with` entry a document address. The tags
    /// `member` and `edition` are admitted where an address is expected
    /// inside an entry — a home, an element of an address-form end —
    /// `edition` at the mint form alone; the member-position end form is
    /// read against the shot's runs ([`p_end`]).
    ///
    /// # Errors
    ///
    /// A [`Refusal`] where a list is no array or is past the cap (no
    /// index), and naming the entry in its `index` — the `malformed`
    /// rejection's `site.index` — where an entry is refused.
    fn deposits(&mut self, shot: &Shot, target: &PublishTarget, claim: bool) -> Result<PublishDeposits, Refusal> {
        let image = request_image(shot);
        let mints = target.mints();
        let links = match self.take_opt("links") {
            None => Vec::new(),
            Some(v) => indexed_list(&v, "links", |entry| p_link_entry(entry, mints, &image))?,
        };
        let retract = match self.take_opt("retract") {
            None => Vec::new(),
            Some(v) => indexed_list(&v, "retract", p_addr)?,
        };
        let read_with = match self.take_opt("read_with") {
            None => Vec::new(),
            Some(v) => indexed_list(&v, "read_with", p_addr)?,
        };
        Ok(PublishDeposits { claim, links, retract, read_with })
    }
}

/// Parses one wire list whose entries' refusals name their index.
///
/// It is [`p_list`] — the one cap, counted before any element is parsed —
/// for the lists of a request that answer a refused entry by its position:
/// the fault carries the entry's index as the [`Refusal`]'s site, which
/// reaches the `malformed` rejection's `site.index`.
///
/// # Errors
///
/// A [`Refusal`] with no index where `v` is no array or is past
/// [`MAX_WIRE_LIST`], and with the entry's index where `f` refuses an
/// element.
fn indexed_list<T>(v: &Value, k: &str, f: impl Fn(&Value) -> PResult<T>) -> Result<Vec<T>, Refusal> {
    let arr = v.as_array().ok_or_else(|| PErr(format!("field '{k}': expected a JSON array")))?;
    if arr.len() > MAX_WIRE_LIST {
        return Err(PErr(format!(
            "field '{k}': array has {} elements, past the {MAX_WIRE_LIST}-element wire cap",
            arr.len()
        ))
        .into());
    }
    arr.iter()
        .enumerate()
        .map(|(i, x)| f(x).map_err(|e| Refusal(format!("field '{k}': [{i}]: {e}"), Some(i))))
        .collect()
}

/// Parses one `links` entry of a `publish` (the link-sets design §5.7):
/// `{"home": …, "ty": …, "from": …, "to": …, "old"?: …}`.
///
/// `home` is the tag `member` or an address; `ty` an end in the address form
/// over addresses alone or the I-span form — a type names no address the
/// commit mints and no member position; `from` and `to` ends in any of the
/// three forms ([`p_end`]); `old` the original's address, absent for an
/// entry with none (an explicit `null` is refused, as `make_link`'s
/// `replaces` refuses one).
///
/// # Errors
///
/// A [`PErr`] where the entry is no object of those keys, a member is
/// missing or refused, `home` is the tag `edition` at the document form,
/// or `ty` carries a tag or the member-position form.
fn p_link_entry(v: &Value, mints: bool, image: &[Run]) -> PResult<LinkEntry> {
    let m = p_obj(v, &["home", "ty", "from", "to", "old"])?;
    let home = field(m, "home", |v| p_named(v, mints))?;
    let ty = field(m, "ty", |v| p_end(v, mints, image))?;
    match &ty {
        EndArg::Addrs(named) if named.iter().any(|n| !matches!(n, NamedAddress::Address(_))) => {
            return Err(PErr("ty: a type slot names no address the commit mints (no tag)".into()));
        }
        EndArg::Member(_) => {
            return Err(PErr("ty: a type slot takes no member-position form".into()));
        }
        EndArg::Addrs(_) | EndArg::Spans(_) => {}
    }
    let from = field(m, "from", |v| p_end(v, mints, image))?;
    let to = field(m, "to", |v| p_end(v, mints, image))?;
    let old = match m.get("old") {
        None => None,
        Some(v) => Some(p_addr(v).map_err(|e| PErr(format!("old: {e}")))?),
    };
    Ok(LinkEntry { home, from, to, ty, old })
}

/// Parses an address or a tag standing for one the commit mints: the string
/// `member`, the string `edition` (at the mint form alone), else a wire
/// address.
///
/// # Errors
///
/// A [`PErr`] where `v` is the tag `edition` and the request mints no
/// edition, or is neither tag nor a wire address.
fn p_named(v: &Value, mints: bool) -> PResult<NamedAddress> {
    match v.as_str() {
        Some("member") => Ok(NamedAddress::Member),
        Some("edition") if mints => Ok(NamedAddress::Edition),
        Some("edition") => {
            Err(PErr("the tag 'edition' names the edition the request mints; this request mints none".into()))
        }
        _ => p_addr(v).map(NamedAddress::Address),
    }
}

/// Parses one end of a `links` entry (the link-sets design §5.7): the
/// address form `{"addrs": [addresses or tags…]}`, the I-span form
/// `{"spans": [i-spans…]}` ([`p_ispan_slot`]), or THE MEMBER-POSITION FORM
/// `{"member": [{"ordinal": n, "width": w}, …]}` — spans of the member's
/// positions inside `[1, placed]`, 1-based, each a natural as `reinstate`'s
/// `at` spells one — which must be CANONICAL: the lowest member positions
/// holding each value, consecutive positions merged, as M7's own
/// [`member_end`] spells them over the request's runs, so one signed row
/// stands against one request.
///
/// A V-spec array is admitted in no entry (the survey's ruling 7): the
/// ceremony sends I-spans or addresses, and the form is refused here.
///
/// # Errors
///
/// A [`PErr`] where `v` is a V-spec array or no object of exactly one of
/// the three keys, where the list under it is refused, where a member span
/// has a zero ordinal or width, lies outside the runs' positions, or
/// passes `u64`, and where the member-position row is not its canonical
/// spelling — the refusal naming the spelling the request owes.
fn p_end(v: &Value, mints: bool, image: &[Run]) -> PResult<EndArg> {
    if v.is_array() {
        return Err(PErr(
            "a V-spec array is admitted in no publication entry: send {\"addrs\": […]}, {\"spans\": […]} or {\"member\": […]}".into(),
        ));
    }
    let m = p_obj(v, &["addrs", "spans", "member"])?;
    match (m.get("addrs"), m.get("spans"), m.get("member")) {
        (Some(a), None, None) => {
            Ok(EndArg::Addrs(p_list(a, |v| p_named(v, mints)).map_err(|e| PErr(format!("addrs: {e}")))?))
        }
        (None, Some(s), None) => {
            Ok(EndArg::Spans(p_ispan_slot(s).map_err(|e| PErr(format!("spans: {e}")))?))
        }
        (None, None, Some(p)) => {
            let spans = p_list(p, p_member_span).map_err(|e| PErr(format!("member: {e}")))?;
            let end = member_end(image, &spans).ok_or_else(|| {
                PErr("member: a span of the member's positions has a zero ordinal or width, or reaches past the positions the runs place".into())
            })?;
            if end.canonical != spans {
                let owed = end
                    .canonical
                    .iter()
                    .map(|s| format!("{{\"ordinal\":\"{}\",\"width\":\"{}\"}}", s.ordinal, s.width))
                    .collect::<Vec<_>>()
                    .join(",");
                return Err(PErr(format!(
                    "member: not the canonical spelling — the lowest member positions holding each value, consecutive positions merged: [{owed}]"
                )));
            }
            Ok(EndArg::Member(spans))
        }
        _ => Err(PErr("expected exactly one of 'addrs', 'spans' or 'member'".into())),
    }
}

/// Parses one span of the member-position form: `{"ordinal": n, "width": w}`,
/// each a natural spelled as `reinstate`'s `at` spells one, within `u64`.
///
/// # Errors
///
/// A [`PErr`] where `v` is no object of the two keys, a key is missing or
/// refused, or a value passes `u64`.
fn p_member_span(v: &Value) -> PResult<MemberSpan> {
    let m = p_obj(v, &["ordinal", "width"])?;
    let bounded = |n: Nat| u64::try_from(&n).map_err(|_| PErr("past 2^64 − 1".into()));
    let ordinal = field(m, "ordinal", |v| p_nat(v).and_then(bounded))?;
    let width = field(m, "width", |v| p_nat(v).and_then(bounded))?;
    Ok(MemberSpan { ordinal, width })
}

// ── leaf parsers, M1's values each through its validating constructors ──

/// Returns the offending text, bounded.
///
/// A refusal must not be a copy of the input it refuses. The wire-supplied
/// strings echoed below are bounded only by the request body, and a parse
/// fault is wrapped by each enclosing field, element and region on the way
/// out, so an unbounded echo is copied once per level and then again into
/// the response.
///
/// The cut is on a *character* boundary: the argument is arbitrary UTF-8 from
/// the wire, and a byte-index slice would panic on one. Applied where the
/// echoed value is wire-supplied and unbounded, and to every key
/// [`check_keys`] refuses, whatever its source; the transport's own echoes (a
/// path, a query parameter, a header line) are already bounded by the
/// request-head cap and are left as they are.
fn bounded(s: &str) -> String {
    const MAX: usize = 64;
    match s.char_indices().nth(MAX) {
        None => s.to_string(),
        Some((i, _)) => format!("{}… ({} bytes)", &s[..i], s.len()),
    }
}

/// Borrows a JSON string from the tree, for a caller that only reads the text.
///
/// So the hex forms decode off the frame's own bytes rather than off a copy
/// of them. [`p_string`] is this plus the copy, for the callers that keep
/// the text past `field`'s closure.
///
/// # Errors
///
/// A [`PErr`] where `v` is no string.
fn p_str(v: &Value) -> PResult<&str> {
    v.as_str().ok_or_else(|| PErr("expected a JSON string".into()))
}

fn p_string(v: &Value) -> PResult<String> {
    p_str(v).map(str::to_owned)
}

fn p_u64(v: &Value) -> PResult<u64> {
    v.as_u64().ok_or_else(|| PErr("expected a non-negative JSON integer".into()))
}

fn p_usize(v: &Value) -> PResult<usize> {
    usize::try_from(p_u64(v)?).map_err(|_| PErr("integer exceeds this platform's usize".into()))
}

/// Parses a principal id about to be *registered*.
///
/// It is held to the wire's exactly-representable range
/// ([`MAX_MINTED_PRINCIPAL_ID`]).
///
/// # Errors
///
/// A [`PErr`] where `v` is no non-negative integer or is past
/// [`MAX_MINTED_PRINCIPAL_ID`]: a parse fault like every other malformed
/// field — the ordinary `unparseable` rejection, no new code and no new
/// token — so the frame reaches no session gate, no lock and no store, and
/// nothing commits.
fn p_minted_id(v: &Value) -> PResult<u64> {
    let id = p_u64(v)?;
    if id > MAX_MINTED_PRINCIPAL_ID {
        return Err(PErr(format!(
            "{id} is past {MAX_MINTED_PRINCIPAL_ID} (2^53 - 1), the largest principal id a \
             JSON number carries exactly"
        )));
    }
    Ok(id)
}

/// Parses an ℕ value: canonically a decimal string.
///
/// A non-negative JSON integer is accepted leniently (canonical output is
/// always the string form).
///
/// # Errors
///
/// A [`PErr`] where `v` is neither a string nor a non-negative integer, or
/// is a string [`p_nat_str`] refuses.
fn p_nat(v: &Value) -> PResult<Nat> {
    match v {
        Value::Number(_) => p_u64(v).map(Nat::from),
        Value::String(s) => p_nat_str(s),
        _ => Err(PErr("expected a decimal string or non-negative integer".into())),
    }
}

/// Parses one decimal natural: a tumbler component or a natural field.
///
/// The [`MAX_NAT_DIGITS`] refusal comes *before* the radix conversion, so a
/// hostile digit run is never converted — the conversion is the expensive
/// half, and refusing after it would pay exactly the cost the cap exists to
/// avoid.
///
/// # Errors
///
/// A [`PErr`] where `s` is empty or holds a non-digit, then where it has
/// more than [`MAX_NAT_DIGITS`] digits, then where the conversion refuses
/// it.
fn p_nat_str(s: &str) -> PResult<Nat> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PErr(format!("'{}' is not a decimal natural", bounded(s))));
    }
    if s.len() > MAX_NAT_DIGITS {
        return Err(PErr(format!(
            "natural has {} digits, past the {MAX_NAT_DIGITS}-digit wire cap",
            s.len()
        )));
    }
    Nat::from_str(s).map_err(|e| PErr(format!("'{}': {e}", bounded(s))))
}

/// Parses a dotted-decimal tumbler under both of this codec's tumbler caps.
///
/// It is *the* bounded parse off the wire, and what makes
/// `MAX_NAT_DIGITS`'s "this is that place" true of every wire tumbler rather
/// than of frames alone. A route that takes one from a query string meets
/// the door a frame's tumbler meets, instead of reassembling it from this
/// module's two constants and another module's uncapped grammar. Both caps
/// are applied before the component they bound is converted (see
/// `p_nat_str`).
///
/// # Errors
///
/// `Err` carries the detail text; a caller wraps it in its own field name.
/// It names more than `MAX_TUMBLER_COMPONENTS` components, then a component
/// that is no decimal natural or has more than `MAX_NAT_DIGITS` digits, then
/// a component sequence the tumbler's own constructor refuses.
pub fn wire_tumbler(s: &str) -> Result<Tumbler, String> {
    let depth = s.split('.').count();
    if depth > MAX_TUMBLER_COMPONENTS {
        return Err(format!(
            "tumbler has {depth} components, past the \
             {MAX_TUMBLER_COMPONENTS}-component wire cap"
        ));
    }
    let comps = s.split('.').map(p_nat_str).collect::<PResult<Vec<Nat>>>().map_err(|e| e.0)?;
    Tumbler::new(comps).map_err(|e| format!("'{}': {e}", bounded(s)))
}

/// Parses a dotted-decimal address off the wire.
///
/// It is [`wire_tumbler`]'s capped parse refined by M1's `validate` — *the*
/// address door, as that function is the tumbler's, so the two steps that
/// make a wire address are composed once and a caller adds only the field
/// name its own grammar gives it.
///
/// The uncapped twin is `commits::classify::parse_dotted`, which refines its
/// own grammar the same way and states why a name that reached a *file* is
/// already past the budgets a client meets.
///
/// # Errors
///
/// `Err` carries the detail text: [`wire_tumbler`]'s refusals, then
/// `not a T4-valid address: …` for a tumbler `validate` refuses.
pub fn wire_address(s: &str) -> Result<Address, String> {
    validate(wire_tumbler(s)?).map_err(|e| format!("not a T4-valid address: {e}"))
}

/// Parses a tumbler from a JSON string, through [`wire_tumbler`].
///
/// It is the frame side's face of the one bounded parse.
///
/// # Errors
///
/// A [`PErr`] where `v` is no string, or [`wire_tumbler`] refuses it.
fn p_tum(v: &Value) -> PResult<Tumbler> {
    let s = v.as_str().ok_or_else(|| PErr("expected a dotted-decimal string".into()))?;
    wire_tumbler(s).map_err(PErr)
}

/// Parses an address from a JSON string, through [`wire_address`].
///
/// It is the frame side's face, as [`p_tum`] is [`wire_tumbler`]'s. The
/// non-string fault is `p_tum`'s verbatim: the two faces refuse the same
/// shape for the same reason.
///
/// # Errors
///
/// A [`PErr`] where `v` is no string, or [`wire_address`] refuses it.
fn p_addr(v: &Value) -> PResult<Address> {
    let s = v.as_str().ok_or_else(|| PErr("expected a dotted-decimal string".into()))?;
    wire_address(s).map_err(PErr)
}

/// Guards which keys a sub-object may carry.
///
/// # Errors
///
/// A [`PErr`] where `v` is no object, or carries a key outside `allowed`:
/// unknown keys fail like unknown envelope fields do.
fn p_obj<'a>(v: &'a Value, allowed: &[&str]) -> PResult<&'a Map<String, Value>> {
    let m = v.as_object().ok_or_else(|| PErr("expected a JSON object".into()))?;
    check_keys(m, allowed).map_err(PErr)?;
    Ok(m)
}

/// Refuses any key outside `allowed`: *the* never-silent device.
///
/// It is applied wherever this crate accepts a JSON object it did not write
/// itself, the request envelope aside, whose leftover fields
/// `Fields::finish` refuses alike: a client's typo is a named failure, never
/// a field quietly ignored.
///
/// # Errors
///
/// `unknown field '…'`, naming a key outside `allowed`. It errors as a bare
/// `String` so the transport envelopes (whose faults are not `ParseError`s)
/// share it.
pub fn check_keys(m: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    match m.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(format!("unknown field '{}'", bounded(k))),
        None => Ok(()),
    }
}

fn need<'a>(m: &'a Map<String, Value>, k: &'static str) -> PResult<&'a Value> {
    m.get(k).ok_or_else(|| PErr(format!("missing field '{k}'")))
}

fn field<T>(
    m: &Map<String, Value>,
    k: &'static str,
    f: impl FnOnce(&Value) -> PResult<T>,
) -> PResult<T> {
    f(need(m, k)?).map_err(|e| PErr(format!("{k}: {e}")))
}

/// Parses one wire list, *the* place [`MAX_WIRE_LIST`] is enforced.
///
/// Every list on the request surface but `insert`'s `values` ([`p_values`])
/// passes here. The elements are counted before any is parsed, so an
/// over-length array is refused without building what it asked for.
///
/// # Errors
///
/// A [`PErr`] where `v` is no array, where it holds more than
/// [`MAX_WIRE_LIST`] elements, or where `f` refuses an element, the fault
/// prefixed with the element's index.
fn p_list<T>(v: &Value, f: impl Fn(&Value) -> PResult<T>) -> PResult<Vec<T>> {
    let arr = v.as_array().ok_or_else(|| PErr("expected a JSON array".into()))?;
    if arr.len() > MAX_WIRE_LIST {
        return Err(PErr(format!(
            "array has {} elements, past the {MAX_WIRE_LIST}-element wire cap",
            arr.len()
        )));
    }
    arr.iter().enumerate().map(|(i, x)| f(x).map_err(|e| PErr(format!("[{i}]: {e}")))).collect()
}

fn p_span(v: &Value) -> PResult<Span> {
    let m = p_obj(v, &["start", "width"])?;
    let start = field(m, "start", p_tum)?;
    let width = field(m, "width", p_tum)?;
    Span::new(start, width).map_err(|e| PErr(format!("ill-formed span: {e}")))
}

fn p_vpos(v: &Value) -> PResult<VPos> {
    let m = p_obj(v, &["ordinal", "subspace"])?;
    Ok(VPos { subspace: field(m, "subspace", p_nat)?, ordinal: field(m, "ordinal", p_nat)? })
}

fn p_vspec(v: &Value) -> PResult<VSpec> {
    let m = p_obj(v, &["source", "span"])?;
    Ok(VSpec { source: field(m, "source", p_addr)?, span: field(m, "span", p_span)? })
}

/// Parses one run of a publish shot (wire.md §Arrangement, `publish`).
///
/// The run is the origin document, the run's start, and its width — through
/// M5's own `Run::new`, so no zero-width run and no start that is not a full
/// element position survives the trust boundary.
///
/// # Errors
///
/// A [`PErr`] where `v` is no object of `i_start`, `origin` and `width`
/// alone, where one of the three is missing or refused, or where `Run::new`
/// refuses the run, its message passed on whole.
fn p_shot_run(v: &Value) -> PResult<ShotRun> {
    let m = p_obj(v, &["i_start", "origin", "width"])?;
    let origin = field(m, "origin", p_addr)?;
    let i_start = field(m, "i_start", p_addr)?;
    let width = field(m, "width", p_nat)?;
    // M5's verdict is a whole message already — the clause broken, under the
    // run's own prefix ("run: …") — so the codec adds no frame of its own.
    let run = Run::new(i_start, width).map_err(|e| PErr(e.to_string()))?;
    Ok(ShotRun { origin, run })
}

/// Parses a `make_link` endset slot (wire v5; the I-span form, W6 (a)).
///
/// It is a V-spec array (content-resolved, byte-identical to v4),
/// `{"addrs": [addresses…]}` — the names recorded verbatim, the same
/// addrs-object encoding as `edit_link`'s successor `ty` — or
/// `{"spans": [i-spans…]}`, content I-spans recorded verbatim
/// ([`p_ispan_slot`]).
///
/// # Errors
///
/// A [`PErr`] where `v` is neither an array nor an object, where the object
/// holds other than exactly one of `addrs` and `spans`, or where the array,
/// the `addrs` list or the `spans` list is refused.
fn p_slotarg(v: &Value) -> PResult<SlotArg> {
    match v {
        Value::Array(_) => Ok(SlotArg::Resolve(p_list(v, p_vspec)?)),
        Value::Object(_) => {
            let m = p_obj(v, &["addrs", "spans"])?;
            match (m.get("addrs"), m.get("spans")) {
                (Some(a), None) => {
                    Ok(SlotArg::Addrs(p_list(a, p_addr).map_err(|e| PErr(format!("addrs: {e}")))?))
                }
                (None, Some(s)) => {
                    Ok(SlotArg::Spans(p_ispan_slot(s).map_err(|e| PErr(format!("spans: {e}")))?))
                }
                _ => Err(PErr("expected exactly one of 'addrs' or 'spans'".into())),
            }
        }
        _ => Err(PErr(
            "expected a v-spec array, {\"addrs\": [addresses…]} or {\"spans\": [i-spans…]}".into(),
        )),
    }
}

/// Parses an I-span slot's list: `retrieve_i`'s I-spans, each as the span
/// the store holds (wire.md §Links (writes), the I-span form).
///
/// The list is one wire list ([`p_list`], the cap M7's slot budget); each
/// element is [`p_ispan`]'s `{start, width}` turned into its span by
/// [`ispan_extent`]. The shape the store demands of the span — a
/// content-subspace element start, the content clause — is M7's refusal
/// (`not_content_subspace`, by slot and index), not this parse's, as the
/// read by identity's shape is M10's: a span is well-formed here whatever
/// document it names.
///
/// # Errors
///
/// A [`PErr`] where `v` is no array, past the cap, or an element is refused
/// — its index prefixed.
fn p_ispan_slot(v: &Value) -> PResult<Vec<Span>> {
    p_list(v, |v| ispan_extent(&p_ispan(v)?))
}

/// Returns the span an I-span names: `width` positions from `start`.
///
/// It is the extent `Run::iextent` yields for the run of that start and
/// width — the start's tumbler, and the ordinal displacement at the start's
/// own length with `width` as its last component — built by arithmetic on
/// the two fields and no address check: a start that is no content element
/// position makes a span the store refuses by index, never a parse failure,
/// so a malformed slot answers the same classified bytes whatever its
/// document holds.
///
/// # Errors
///
/// A [`PErr`] where `width` is zero: a span over no position, which no
/// stored slot holds — M1's span constructor refuses the zero displacement
/// — so the form refuses it where a zero-width V-span is refused, at the
/// parse.
fn ispan_extent(s: &ISpan) -> PResult<Span> {
    let start = s.start.tumbler().clone();
    let zeros = (1..start.len()).map(|_| Nat::from(0u32));
    let width = Tumbler::new(zeros.chain([s.width.clone()]))
        .expect("a width as long as its start is nonempty");
    Span::new(start, width).map_err(|_| PErr("width must be at least 1".into()))
}

fn p_spec(v: &Value) -> PResult<Spec> {
    let m = p_obj(v, &["doc", "span"])?;
    Ok(Spec { doc: field(m, "doc", p_addr)?, span: field(m, "span", p_span)? })
}

/// Parses one I-span of `retrieve_i` (wire.md §Content & provenance reads).
///
/// It is an I-address and a width — through M1's address door and the
/// natural's, so no malformed address survives the trust boundary. Its
/// shape — an element position at the start, a width of at least one — is
/// M10's own refusal (`not_content_subspace`, `empty_width`, by the span's
/// index), not this parse's: a span is well-formed here whatever document
/// it derives, and what it derives is M10's to judge.
///
/// # Errors
///
/// A [`PErr`] where `v` is no object of `start` and `width` alone, or where
/// either is missing or refused.
fn p_ispan(v: &Value) -> PResult<ISpan> {
    let m = p_obj(v, &["start", "width"])?;
    Ok(ISpan { start: field(m, "start", p_addr)?, width: field(m, "width", p_nat)? })
}

fn p_region(v: &Value) -> PResult<RegionSpec> {
    let m = p_obj(v, &["doc", "spans"])?;
    Ok(RegionSpec {
        doc: field(m, "doc", p_addr)?,
        spans: field(m, "spans", |v| p_list(v, p_span))?,
    })
}

/// Parses the `values` array of `insert`.
///
/// Each element is one of the four write forms (wire.md §Content values),
/// contributing zero or more values that concatenate in order.
///
/// What bounds the values the whole array mints is [`MAX_INSERT_VALUES`],
/// which [`p_val_form`] enforces against this accumulator before each element
/// mints into it — the array's element count bounds nothing on its own, since
/// one per-byte string mints one value per byte.
///
/// # Errors
///
/// A [`PErr`] where `v` is no array, or where [`p_val_form`] refuses an
/// element, the fault prefixed with the element's index.
fn p_values(v: &Value) -> PResult<Vec<Val>> {
    let arr = v.as_array().ok_or_else(|| PErr("expected a JSON array".into()))?;
    let mut out = Vec::new();
    for (i, x) in arr.iter().enumerate() {
        p_val_form(x, &mut out).map_err(|e| PErr(format!("[{i}]: {e}")))?;
    }
    Ok(out)
}

/// Checks there is room for what an element is *about* to mint.
///
/// It is *the* place [`MAX_INSERT_VALUES`] is enforced, and enforced ahead
/// of the mint rather than behind it. An element's whole contribution is
/// added in one call — one `extend`, or one `push` for an atom — so a check
/// that runs once the element has returned has already paid the peak the
/// cap exists to prevent: an 8 MiB per-byte string mints 8.4M [`Val`]s, each
/// its own `Arc` allocation, order 400 MB of live heap, for a frame that is
/// then refused. Asked in values — the unit the cap counts — and measured
/// against the accumulator, so an element's own length is never mistaken
/// for the budget it consumes.
///
/// # Errors
///
/// A [`PErr`] where `out` with `adding` more would pass
/// [`MAX_INSERT_VALUES`].
fn room(out: &[Val], adding: usize) -> PResult<()> {
    if out.len().saturating_add(adding) > MAX_INSERT_VALUES {
        return Err(PErr(format!(
            "values mint more than the {MAX_INSERT_VALUES}-value cap on one insert"
        )));
    }
    Ok(())
}

/// Returns the values one hex field will mint, read from its encoded text.
///
/// It reads the text without copying or decoding it, so [`room`] can refuse
/// before either. A non-string field needs no room; `field` below reports
/// its own fault.
///
/// # Errors
///
/// A [`PErr`] where the field `k` is missing.
fn hex_values(m: &Map<String, Value>, k: &'static str) -> PResult<usize> {
    Ok(need(m, k)?.as_str().map_or(0, |s| s.len() / 2))
}

/// Parses one element of `values` into `out`.
///
/// The per-byte forms (`"str"`, `{"hex"}`) mint one single-byte value per
/// byte — the substrate's text discipline, under which every interior byte
/// stays addressable — and admit the vacuous `""`. The atom forms
/// (`{"atom"}`, `{"atom_hex"}`) mint *one* composite value of all the bytes:
/// coarse granularity must be said, never fallen into; a zero-byte atom is
/// not expressible.
///
/// Every arm asks [`room`] for what it is about to add before it adds it, so
/// an over-budget element mints nothing — and on the hex path is never even
/// decoded. An atom asks for *one* value whatever its byte count, which is
/// what a composite value is.
///
/// # Errors
///
/// A [`PErr`] where `v` is neither a string nor an object of exactly one of
/// `hex`, `atom` and `atom_hex`, where [`room`] refuses what it would mint,
/// where the form's text is no string or no even-length hex, or where an
/// atom has zero bytes.
fn p_val_form(v: &Value, out: &mut Vec<Val>) -> PResult<()> {
    let m = match v {
        Value::String(s) => {
            room(out, s.len())?;
            out.extend(s.bytes().map(|b| Val::new(vec![b])));
            return Ok(());
        }
        Value::Object(_) => p_obj(v, &["atom", "atom_hex", "hex"])?,
        _ => {
            return Err(PErr(
                "expected a string or an object with one of 'hex', 'atom', 'atom_hex'".into(),
            ))
        }
    };
    if m.len() != 1 {
        return Err(PErr("expected exactly one of 'hex', 'atom', or 'atom_hex'".into()));
    }
    if m.contains_key("hex") {
        room(out, hex_values(m, "hex")?)?;
        let bytes = field(m, "hex", |v| p_hex(p_str(v)?))?;
        out.extend(bytes.into_iter().map(|b| Val::new(vec![b])));
    } else if m.contains_key("atom") {
        room(out, 1)?;
        let s = field(m, "atom", p_string)?;
        if s.is_empty() {
            return Err(PErr("atom: a zero-byte atom is not expressible".into()));
        }
        out.push(Val::new(s.into_bytes()));
    } else {
        room(out, 1)?;
        let bytes = field(m, "atom_hex", |v| p_hex(p_str(v)?))?;
        if bytes.is_empty() {
            return Err(PErr("atom_hex: a zero-byte atom is not expressible".into()));
        }
        out.push(Val::new(bytes));
    }
    Ok(())
}

fn p_hex(s: &str) -> PResult<Vec<u8>> {
    // The odd-length refusal comes first, because the pairing below drops
    // a trailing half-byte in silence — exactly the reading this check
    // exists to refuse.
    if !s.len().is_multiple_of(2) {
        return Err(PErr("hex string has odd length".into()));
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(hex_digit(pair[0])? * 16 + hex_digit(pair[1])?))
        .collect()
}

/// Parses any whole number of bytes of lowercase hex, or answers `None`.
///
/// It is [`parse_lower_hex`](skep_util::json::parse_lower_hex)'s
/// variable-width twin under the same case policy: the parse of the attest
/// store's `sig` (`feed-attest.log`), which this crate reads back only as
/// [`hex_string`](skep_util::json::hex_string) wrote it. An odd length is
/// refused ahead of the pairing, so no trailing half-byte is dropped in
/// silence.
pub(crate) fn parse_lower_hex_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Some((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

/// Parses one hex character, case *folded*: the frame's hex policy.
///
/// `{"hex"}`, `{"atom_hex"}` and the `attest` member's `sig` are decoded to
/// bytes and never framed, so an uppercase digit means what a lowercase one
/// means.
///
/// # Errors
///
/// A [`PErr`] naming a character that is no hex digit in either case.
fn hex_digit(c: u8) -> PResult<u8> {
    hex_nibble(c.to_ascii_lowercase())
        .ok_or_else(|| PErr(format!("invalid hex digit '{}'", c as char)))
}

fn p_endset(v: &Value) -> PResult<Endset> {
    Ok(Endset::from_spans(p_list(v, p_span)?))
}

fn p_view(v: &Value) -> PResult<View> {
    match v.as_str() {
        Some("audit") => Ok(View::Audit),
        Some("active") => Ok(View::Active),
        Some("default") => Ok(View::Default),
        _ => Err(PErr("expected \"audit\", \"active\", or \"default\"".into())),
    }
}

/// Parses a slot constraint: `"any"`, `"empty"`, or a span array.
///
/// `"any"` drops out and `"empty"` annihilates. An empty array *is* the
/// empty constraint and normalizes onto `"empty"` — M8 documents the empty
/// endset as exactly that zero.
///
/// # Errors
///
/// A [`PErr`] where `v` is none of the three, or where the span array is
/// refused ([`p_list`]).
fn p_slotspec(v: &Value) -> PResult<SlotSpec> {
    match v {
        Value::String(s) if s == "any" => Ok(SlotSpec::Any),
        Value::String(s) if s == "empty" => Ok(SlotSpec::Empty),
        Value::Array(_) => {
            let spans = p_list(v, p_span)?;
            if spans.is_empty() {
                Ok(SlotSpec::Empty)
            } else {
                Ok(SlotSpec::Spans(Endset::from_spans(spans)))
            }
        }
        _ => Err(PErr("expected \"any\", \"empty\", or a span array".into())),
    }
}

fn p_fourset(v: &Value) -> PResult<FourSet> {
    let m = p_obj(v, &["from", "home", "to", "ty"])?;
    Ok(FourSet {
        home: field(m, "home", p_slotspec)?,
        from: field(m, "from", p_slotspec)?,
        to: field(m, "to", p_slotspec)?,
        ty: field(m, "ty", p_slotspec)?,
    })
}

/// Parses EditLink's successor: its two ends, and the type slot.
///
/// `from` and `to` are each a V-spec array (content-resolved) or
/// `{"spans": […]}` (content I-spans, recorded verbatim — W6 (a)); the type
/// slot is exactly one of `{"addrs": […]}` (address-denoting — the
/// identical encoding of `make_link`'s addrs form), `{"resolve": […]}`
/// (content-resolved) or `{"spans": […]}`, mirroring M10's `SlotArg`. An
/// `addrs` object on `from` or `to` is refused here: the narrowing M10's
/// successor keeps — an address-denoting successor end is not sent.
///
/// # Errors
///
/// A [`PErr`] where `v` is no object of `from`, `to` and `ty` alone, where
/// one of the three is missing or refused, where `from` or `to` is neither
/// an array nor a `spans` object, or where `ty` holds other than exactly one
/// of `addrs`, `resolve` and `spans`.
fn p_successor(v: &Value) -> PResult<SuccessorSpec> {
    let m = p_obj(v, &["from", "to", "ty"])?;
    Ok(SuccessorSpec {
        from: field(m, "from", p_successor_end)?,
        to: field(m, "to", p_successor_end)?,
        ty: field(m, "ty", p_successor_ty)?,
    })
}

/// Parses a successor's `from` or `to`: V-specs, or I-spans.
///
/// # Errors
///
/// A [`PErr`] where `v` is neither an array nor an object of `spans` alone,
/// or where the list is refused.
fn p_successor_end(v: &Value) -> PResult<SlotArg> {
    match v {
        Value::Array(_) => Ok(SlotArg::Resolve(p_list(v, p_vspec)?)),
        Value::Object(_) => {
            let m = p_obj(v, &["spans"])?;
            Ok(SlotArg::Spans(field(m, "spans", p_ispan_slot)?))
        }
        _ => Err(PErr("expected a v-spec array or {\"spans\": [i-spans…]}".into())),
    }
}

fn p_successor_ty(v: &Value) -> PResult<SlotArg> {
    let m = p_obj(v, &["addrs", "resolve", "spans"])?;
    match (m.get("addrs"), m.get("resolve"), m.get("spans")) {
        (Some(a), None, None) => {
            Ok(SlotArg::Addrs(p_list(a, p_addr).map_err(|e| PErr(format!("addrs: {e}")))?))
        }
        (None, Some(r), None) => {
            Ok(SlotArg::Resolve(p_list(r, p_vspec).map_err(|e| PErr(format!("resolve: {e}")))?))
        }
        (None, None, Some(s)) => {
            Ok(SlotArg::Spans(p_ispan_slot(s).map_err(|e| PErr(format!("spans: {e}")))?))
        }
        _ => Err(PErr("expected exactly one of 'addrs', 'resolve' or 'spans'".into())),
    }
}

#[cfg(test)]
mod tests;
