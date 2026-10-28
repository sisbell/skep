//! The codec's marshal side: the operation channel's shapes and name tables.
//!
//! It holds every shape this crate renders on the operation channel —
//! M10's `Response`s, the canonical request encoding
//! `JsonCodec::marshal_request` writes, the daemon's own rejections
//! (`credential_refused_reply`, `registry_refused_reply`, the `key_set` row)
//! — and the two name tables (`op_name`, `code_name`) both directions spell
//! the wire through. Every object goes through [`obj`].

use serde_json::Value;
use skep_address::{Address, Nat, Span, SpanSet, Tumbler};
use skep_arrangement::{Run, ShotRun, VPos, VSpec};
use skep_content::Val;
use skep_discovery::{FourSet, SlotSpec, SupClaim, Window};
use skep_febe::{
    Deposit, Disposition, EditionClaim, FaultSite, IItem, ISpan, MintTime, Op, OpKind, RejectCode,
    Rejection, Response, SlotArg, SuccessorSpec, TimeSource, UniversalGrant,
};
use skep_identity::{KeySet, SigAlgRow};
use skep_kernel::{Attestation, Seq};
use skep_links::{EndArg, Endset, Invalid, Link, LinkEntry, NamedAddress, PublishTarget, View};
use skep_retrieval::{CorrPair, Deletions, DeliveryItem, Operand, RegionSpec, SpanFault, Spec};
use skep_util::json::{hex_string, obj};

use super::to_bytes;

/// A rejection the *daemon* originates, in the wire's one rejection shape.
///
/// It is the `credential_refused` and `registry_refused` families, and the
/// `key_set` row's `not_an_account`, byte-shaped exactly as [`j_rejection`]
/// marshals M10's: `{"code","disposition","op","resp"}` plus the optional
/// `detail`. The daemon cannot construct M10's `Rejection` for codes M10
/// does not carry (the `RejectCode` delta lies upstream), so the wire shape
/// is built here — one shape on the wire either way.
///
/// One value rather than three adjacent `&str`s: `op` and `code` are the
/// same type and mean opposite things, so as arguments they would sit one
/// transposition away from a well-formed rejection naming the code as its
/// op — the same reason `skepd::HttpRequest` is one value rather than
/// seven. `disposition` is typed because [`disposition_name`] is the table
/// that spells it, and `code` takes [`code_name`]'s output wherever M10
/// carries the code.
struct DaemonRejection<'a> {
    /// The refused op's wire name.
    ///
    /// It is [`op_name`]'s output, or the daemon's own name for a row M10
    /// has no `OpKind` for.
    op: &'a str,
    /// [`code_name`]'s output, or a code M10 does not carry.
    ///
    /// Those codes are [`CREDENTIAL_REFUSED`] and [`REGISTRY_REFUSED`].
    code: &'a str,
    disposition: Disposition,
    detail: Option<String>,
}

fn daemon_rejected(r: DaemonRejection<'_>) -> Vec<u8> {
    let mut pairs = vec![
        ("resp", Value::String("rejected".into())),
        ("op", Value::String(r.op.into())),
        ("code", Value::String(r.code.into())),
        ("disposition", Value::String(disposition_name(r.disposition).into())),
    ];
    if let Some(d) = r.detail {
        pairs.push(("detail", Value::String(d)));
    }
    to_bytes(&obj(pairs))
}

/// Marshals the `key_set` answer (AUTH-6.18–6.20).
///
/// It is the daemon's own operation-channel shape, rendered here because
/// this is where that channel's shapes are rendered (the codec's module doc
/// draws the line, and the transport's own shapes sit on the other side of
/// it).
///
/// `set` is [`crate::auth::key_set_of`]'s answer over the world the
/// route holds, read off that world's own identity slice: `None` is the
/// not-an-account case and answers the existing code `not_an_account`; a
/// keyless account answers empty lists. Entries ride in the key set's own
/// fingerprint order.
///
/// `as_of` is a stamp *and* a bound: every entry is the account's set as of
/// that position, since the world the route holds carries its table
/// (AUTH-2.79) and the caller stamps the answer with that world's own
/// coordinate — the head snapshot's `seq` on `/op`, the requested position on
/// `/op-at` — which is what lets a client correlate the answer with
/// `/changes` and re-read it at `/op-at`. The caller owes stamping the
/// position of the world it handed [`crate::auth::key_set_of`]; this
/// function cannot check it.
pub fn key_set_reply(as_of: Seq, set: Option<&KeySet>) -> Vec<u8> {
    let Some(set) = set else {
        // M10's own code, so M10's own advice: the table is asked rather than
        // its row transcribed, since one code advised two ways on one wire is
        // a divergence nothing would fail on.
        return daemon_rejected(DaemonRejection {
            op: "key_set",
            code: code_name(RejectCode::NotAnAccount),
            disposition: RejectCode::NotAnAccount.disposition(),
            detail: None,
        });
    };
    let enrolled: Vec<Value> = set
        .enrolled()
        .map(|(fp, e)| {
            obj(vec![
                ("alg", Value::String(e.key.alg().into())),
                ("anchor", Value::Bool(e.anchor)),
                ("fingerprint", Value::String(fp.to_hex())),
                ("key", Value::String(e.key.to_hex())),
            ])
        })
        .collect();
    let retired: Vec<Value> = set
        .retired()
        .map(|(fp, anchor)| {
            obj(vec![("anchor", Value::Bool(anchor)), ("fingerprint", Value::String(fp.to_hex()))])
        })
        .collect();
    to_bytes(&obj(vec![
        ("as_of", Value::Number(as_of.0.into())),
        ("enrolled", Value::Array(enrolled)),
        ("resp", Value::String("key_set".into())),
        ("retired", Value::Array(retired)),
    ]))
}

/// Marshals one daemon-originated credential refusal (AUTH-3.53–3.54).
///
/// Its fields: `code: credential_refused` always; `detail` the machine token
/// the refusal names itself by; `disposition` the class it names for itself
/// — `permanent` for the family, the attestation codes' own and the media
/// door's `index_rebuilding`, `retry`, beside it; and `op` the refused op's
/// own wire name, lowered from its `OpKind` through [`op_name`]'s table so
/// no caller holds one to pass on.
///
/// Here rather than at the route, for [`key_set_reply`]'s reason: this is
/// the family's wire shape and this is where those shapes are rendered. The
/// `code` is the one field the spec fixes, so choosing it here leaves a
/// caller the three that vary and leaves `CREDENTIAL_REFUSED`,
/// `DaemonRejection` and `daemon_rejected` with no reader outside this
/// module.
///
/// The token rides as an owned `String` — a credential refusal's own
/// `token()` answer, moved rather than copied, or a media door refusal's
/// token, copied in by its caller — so this module renders the family's
/// vocabulary without depending on the types that enumerate it, the
/// arrangement [`key_set_reply`] has with the identity slice.
pub fn credential_refused_reply(
    op: OpKind,
    token: String,
    disposition: Disposition,
) -> Vec<u8> {
    daemon_rejected(DaemonRejection {
        op: op_name(op),
        code: CREDENTIAL_REFUSED,
        // `Permanent` for the whole family but the two attestation codes
        // (signed ops; the design record §7.3 (iii)) and the media door's
        // `index_rebuilding`, `Retry`: the refusal names its own class, so the
        // family's uniformity is the producers' and not this renderer's.
        disposition,
        detail: Some(token),
    })
}

/// Marshals one registry-sequence refusal (wire.md §Registry).
///
/// The sequence is the record grade for registry records (2b). The refusal
/// is the credential family's row under a code of its own,
/// `REGISTRY_REFUSED`, so a client tells the two families apart — `detail`
/// the refusal's one token, `disposition` its own class, `op` lowered
/// through [`op_name`]. Here for [`credential_refused_reply`]'s reason: the
/// family's wire shape is rendered where every operation-channel shape is,
/// through `daemon_rejected`.
pub fn registry_refused_reply(
    op: OpKind,
    token: String,
    disposition: Disposition,
) -> Vec<u8> {
    daemon_rejected(DaemonRejection {
        op: op_name(op),
        code: REGISTRY_REFUSED,
        disposition,
        detail: Some(token),
    })
}

/// Renders an attestation as the wire's `attest` member.
///
/// It is [`p_attest`](super::p_attest)'s inverse: the tag back to its token,
/// the blob to hex — the request's `attest` member, and (wire v7.11) the
/// change feed's, rendered from the marker slot the attest store mirrors, so
/// the two are one spelling.
pub(crate) fn j_attest(a: &Attestation) -> Value {
    let alg = SigAlgRow::of_tag(a.sig_alg())
        .map_or_else(|| format!("<unknown tag {}>", a.sig_alg()), |row| row.token.to_string());
    obj(vec![("alg", Value::String(alg)), ("sig", Value::String(hex_string(a.sig())))])
}

// ── marshal (Request → wire, the canonical inverse) ──────────────────────

/// Returns the optional `published` pair on a minting op.
///
/// It is emitted only when the flag is present (PUB-8.16 — absent is the
/// wire default, so a `None` marshals to no field and `parse ∘ marshal` is a
/// fixpoint). `Some` renders the bare boolean.
fn published_pair(published: &Option<bool>) -> Vec<(&'static str, Value)> {
    match published {
        Some(b) => vec![("published", Value::Bool(*b))],
        None => Vec::new(),
    }
}

/// Returns an op's wire name and member pairs, one arm per `Op` variant.
///
/// The name comes from the *same* [`op_name`] table the rejection marshal
/// uses, so the two directions cannot drift.
pub(super) fn req_pairs(op: &Op) -> (&'static str, Vec<(&'static str, Value)>) {
    match op {
        Op::CreateNewDocument { account, published } => {
            let mut pairs = vec![("account", j_addr(account))];
            pairs.extend(published_pair(published));
            (op_name(OpKind::CreateNewDocument), pairs)
        }
        Op::Delegate { new_prefix, new_id } => (
            op_name(OpKind::Delegate),
            vec![("new_prefix", j_tum(new_prefix)), ("new_id", j_u64(new_id.0))],
        ),
        Op::RegisterNode { addr } => (op_name(OpKind::RegisterNode), vec![("addr", j_tum(addr))]),
        Op::Fork { published } => (op_name(OpKind::Fork), published_pair(published)),
        Op::NextAccountPrefix { parent } => {
            (op_name(OpKind::NextAccountPrefix), vec![("parent", j_addr(parent))])
        }
        Op::PrincipalPrefix { id } => {
            (op_name(OpKind::PrincipalPrefix), vec![("principal", j_u64(id.0))])
        }
        Op::EffectiveOwner { addr } => {
            (op_name(OpKind::EffectiveOwner), vec![("addr", j_addr(addr))])
        }
        Op::DocMetadata { doc } => (op_name(OpKind::DocMetadata), vec![("doc", j_addr(doc))]),
        Op::Insert { doc, at, values, deposit } => {
            let mut pairs =
                vec![("doc", j_addr(doc)), ("at", j_vpos(at)), ("values", j_values(values))];
            // Canonical: the declaration rides only when made, as the class
            // type it names (PUB-2.64) — absent *is* `Undeclared` on the wire,
            // so an undeclared insert marshals to no field and
            // `parse ∘ marshal` is a fixpoint.
            match deposit {
                Deposit::Declared(ty) => pairs.push(("deposit", j_addr(ty))),
                Deposit::Undeclared => {}
            }
            (op_name(OpKind::Insert), pairs)
        }
        Op::Delete { doc, p, width } => (
            op_name(OpKind::Delete),
            vec![("doc", j_addr(doc)), ("p", j_vpos(p)), ("width", j_nat(width))],
        ),
        Op::Copy { doc, at, specs } => (
            op_name(OpKind::Copy),
            vec![("doc", j_addr(doc)), ("at", j_vpos(at)), ("specs", j_vspecs(specs))],
        ),
        Op::Reinstate { doc, at, runs } => (
            op_name(OpKind::Reinstate),
            vec![("doc", j_addr(doc)), ("at", j_vpos(at)), ("runs", j_shot_runs(runs))],
        ),
        Op::Rearrange { doc, cuts } => {
            (op_name(OpKind::Rearrange), vec![("doc", j_addr(doc)), ("cuts", j_vposes(cuts))])
        }
        Op::Version { d_src, published } => {
            let mut pairs = vec![("d_src", j_addr(d_src))];
            pairs.extend(published_pair(published));
            (op_name(OpKind::Version), pairs)
        }
        // Canonical: `base`/`base_extent` and `draft` ride only when present,
        // so an absent one marshals to no field and `parse ∘ marshal` is a
        // fixpoint — and so do the kept places: `places` rides only where
        // one is present, the list `runs`' length with `null` at a run with
        // none, the form the parse pads a shorter list to — and so do the
        // deposits (the link-sets design §5.7): the target in its one form
        // (`doc`, or `account` with `mint: true` and, where set, `claim:
        // true`; an unset flag is no field), and each of `links`, `retract`
        // and `read_with` only where it holds an entry.
        Op::Publish { target, shot, places, deposits } => {
            let mut pairs = match target {
                PublishTarget::Document(doc) => vec![("doc", j_addr(doc))],
                PublishTarget::Mint { account, claim } => {
                    let mut pairs = vec![("account", j_addr(account)), ("mint", Value::Bool(true))];
                    if *claim {
                        pairs.push(("claim", Value::Bool(true)));
                    }
                    pairs
                }
            };
            pairs.push(("runs", j_shot_runs(&shot.runs)));
            if let Some(base) = &shot.base {
                pairs.push(("base", j_addr(&base.member)));
                pairs.push(("base_extent", j_nat(&base.extent)));
            }
            if let Some(draft) = &shot.draft {
                pairs.push(("draft", j_addr(draft)));
            }
            if places.iter().any(Option::is_some) {
                let places = places.iter().map(|p| p.as_ref().map_or(Value::Null, j_vpos));
                pairs.push(("places", Value::Array(places.collect())));
            }
            if !deposits.links.is_empty() {
                pairs.push(("links", Value::Array(deposits.links.iter().map(j_link_entry).collect())));
            }
            if !deposits.retract.is_empty() {
                pairs.push(("retract", j_addrs(&deposits.retract)));
            }
            if !deposits.read_with.is_empty() {
                pairs.push(("read_with", j_addrs(&deposits.read_with)));
            }
            (op_name(OpKind::Publish), pairs)
        }
        Op::MakeLink { home, from, to, ty, replaces } => {
            let mut pairs = vec![
                ("home", j_addr(home)),
                ("from", j_slotarg(from)),
                ("to", j_slotarg(to)),
                ("ty", j_slotarg(ty)),
            ];
            // Canonical: the `replaces` member rides only when present —
            // absent *is* the empty state on the wire — so a member-less
            // `make_link` marshals to no field and `parse ∘ marshal` is a
            // fixpoint.
            if let Some(named) = replaces {
                pairs.push(("replaces", j_addr(named)));
            }
            (op_name(OpKind::MakeLink), pairs)
        }
        Op::Emit { home, ty, from, to } => (
            op_name(OpKind::Emit),
            vec![
                ("home", j_addr(home)),
                ("ty", j_endset(ty)),
                ("from", j_addr(from)),
                ("to", j_addrs(to)),
            ],
        ),
        Op::Nullify { home, target } => {
            (op_name(OpKind::Nullify), vec![("home", j_addr(home)), ("target", j_addr(target))])
        }
        Op::AssertSup { home, old, new } => (
            op_name(OpKind::AssertSup),
            vec![("home", j_addr(home)), ("old", j_addr(old)), ("new", j_addr(new))],
        ),
        Op::EditLink { original, successor, d_s, d_a } => (
            op_name(OpKind::EditLink),
            vec![
                ("original", j_addr(original)),
                ("successor", j_successor(successor)),
                ("d_s", j_addr(d_s)),
                ("d_a", j_addr(d_a)),
            ],
        ),
        Op::ReadLink { a } => (op_name(OpKind::ReadLink), vec![("a", j_addr(a))]),
        Op::FollowLink { a, slot } => {
            (op_name(OpKind::FollowLink), vec![("a", j_addr(a)), ("slot", j_usize(*slot))])
        }
        Op::RetrieveV { specs } => (op_name(OpKind::RetrieveV), vec![("specs", j_specs(specs))]),
        Op::RetrieveI { spans } => (op_name(OpKind::RetrieveI), vec![("spans", j_ispans(spans))]),
        Op::ContentFrontier { doc } => {
            (op_name(OpKind::ContentFrontier), vec![("doc", j_addr(doc))])
        }
        Op::RetrieveDocVSpan { doc } => {
            (op_name(OpKind::RetrieveDocVSpan), vec![("doc", j_addr(doc))])
        }
        Op::RetrieveDocVSpanSet { doc } => {
            (op_name(OpKind::RetrieveDocVSpanSet), vec![("doc", j_addr(doc))])
        }
        Op::ShowOrigin { doc, span } => {
            (op_name(OpKind::ShowOrigin), vec![("doc", j_addr(doc)), ("span", j_span(span))])
        }
        Op::ShowDeletions { d_a, d_b } => {
            (op_name(OpKind::ShowDeletions), vec![("d_a", j_addr(d_a)), ("d_b", j_addr(d_b))])
        }
        Op::Compare { rho1, rho2 } => {
            (op_name(OpKind::Compare), vec![("rho1", j_regions(rho1)), ("rho2", j_regions(rho2))])
        }
        Op::FindDocsContaining { regions } => {
            (op_name(OpKind::FindDocsContaining), vec![("regions", j_regions(regions))])
        }
        Op::Image { d, region } => {
            (op_name(OpKind::Image), vec![("d", j_addr(d)), ("region", j_spans(region))])
        }
        Op::FindLinksV { d, region } => {
            (op_name(OpKind::FindLinksV), vec![("d", j_addr(d)), ("region", j_spans(region))])
        }
        Op::FindLinksFtt { q } => (op_name(OpKind::FindLinksFtt), vec![("q", j_fourset(q))]),
        Op::CountV { d, region } => {
            (op_name(OpKind::CountV), vec![("d", j_addr(d)), ("region", j_spans(region))])
        }
        Op::CountFtt { q } => (op_name(OpKind::CountFtt), vec![("q", j_fourset(q))]),
        Op::WindowV { d, region, cur, n } => (
            op_name(OpKind::WindowV),
            vec![
                ("d", j_addr(d)),
                ("region", j_spans(region)),
                ("cur", j_cursor(cur)),
                ("n", j_usize(*n)),
            ],
        ),
        Op::WindowFtt { q, cur, n } => (
            op_name(OpKind::WindowFtt),
            vec![("q", j_fourset(q)), ("cur", j_cursor(cur)), ("n", j_usize(*n))],
        ),
        Op::RetrieveEndsets { d, region } => {
            (op_name(OpKind::RetrieveEndsets), vec![("d", j_addr(d)), ("region", j_spans(region))])
        }
        Op::Project { a, slot, d } => (
            op_name(OpKind::Project),
            vec![("a", j_addr(a)), ("slot", j_usize(*slot)), ("d", j_addr(d))],
        ),
        Op::DiscoverableFrom { a, d } => {
            (op_name(OpKind::DiscoverableFrom), vec![("a", j_addr(a)), ("d", j_addr(d))])
        }
        Op::DeleteOrphans { d, p, width } => (
            op_name(OpKind::DeleteOrphans),
            vec![("d", j_addr(d)), ("p", j_vpos(p)), ("width", j_nat(width))],
        ),
        Op::InClaims { y, view } => {
            (op_name(OpKind::InClaims), vec![("y", j_addr(y)), ("view", j_view(*view))])
        }
        Op::OutClaims { x, view } => {
            (op_name(OpKind::OutClaims), vec![("x", j_addr(x)), ("view", j_view(*view))])
        }
        Op::EditionClaims { target } => {
            (op_name(OpKind::EditionClaims), vec![("target", j_addr(target))])
        }
        Op::UniversalGrants => (op_name(OpKind::UniversalGrants), Vec::new()),
    }
}

// ── marshal (Response → wire) ────────────────────────────────────────────

pub(super) fn j_response(r: &Response) -> Value {
    let (name, mut pairs): (&'static str, Vec<(&'static str, Value)>) = match r {
        Response::Ack { at } => ("ack", vec![("at", j_seq(*at))]),
        Response::AckAddr { addr, at } => {
            ("ack_addr", vec![("addr", j_addr(addr)), ("at", j_seq(*at))])
        }
        Response::AckEdit { successor, claim, at } => (
            "ack_edit",
            vec![("successor", j_addr(successor)), ("claim", j_addr(claim)), ("at", j_seq(*at))],
        ),
        Response::Delivery { items, as_of } => {
            ("delivery", vec![("items", j_items(&items.0)), ("as_of", j_seq(*as_of))])
        }
        // The read by identity (AUTH-6.38–6.40): one object per I-position
        // asked, `at` the address and `value` the value as the delivery
        // renders one value — or `null`, a payload option, where the
        // position holds none.
        Response::IDelivery { items, as_of } => {
            ("i_delivery", vec![("items", j_iitems(items)), ("as_of", j_seq(*as_of))])
        }
        // The content-frontier read: `next`, the next unminted content
        // ordinal, a natural as every ordinal rides.
        Response::Frontier { next, as_of } => {
            ("frontier", vec![("next", j_nat(next)), ("as_of", j_seq(*as_of))])
        }
        Response::SpanSet { set, as_of } => {
            ("span_set", vec![("set", j_spanset(set)), ("as_of", j_seq(*as_of))])
        }
        Response::Addrs { addrs, as_of } => {
            ("addrs", vec![("addrs", j_addrs(addrs)), ("as_of", j_seq(*as_of))])
        }
        // The payload option: always present, null = absent/ineligible.
        Response::MaybeAddr { addr, as_of } => (
            "maybe_addr",
            vec![
                ("addr", addr.as_ref().map(j_addr).unwrap_or(Value::Null)),
                ("as_of", j_seq(*as_of)),
            ],
        ),
        // The owner-of-address answer (AUTH-6.37): ω *unprojected*. `prefix`
        // and `principal` are two wire keys over *one* optional value — M3's
        // own registry entry — so they are always present and null together,
        // exactly where no registered principal's prefix contains the address
        // asked (`doc_metadata`'s `birth`/`birth_extent` pairing, and for its
        // reason). Allocated iff `prefix` equals the address asked: that test
        // is the caller's, and nothing here pre-draws it.
        Response::EffectiveOwner { owner, as_of } => (
            "effective_owner",
            vec![
                ("prefix", owner.as_ref().map(|(p, _)| j_addr(p)).unwrap_or(Value::Null)),
                ("principal", owner.as_ref().map(|(_, id)| j_u64(id.0)).unwrap_or(Value::Null)),
                ("as_of", j_seq(*as_of)),
            ],
        ),
        Response::Count { n, as_of } => {
            ("count", vec![("n", j_usize(*n)), ("as_of", j_seq(*as_of))])
        }
        Response::Page { window, as_of } => {
            ("page", vec![("window", j_window(window)), ("as_of", j_seq(*as_of))])
        }
        Response::Endsets { pairs: ps, as_of } => {
            ("endsets", vec![("pairs", j_endset_pairs(ps)), ("as_of", j_seq(*as_of))])
        }
        Response::Runs { runs, as_of } => {
            ("runs", vec![("runs", j_runs(runs)), ("as_of", j_seq(*as_of))])
        }
        Response::Bool { val, as_of } => {
            ("bool", vec![("val", Value::Bool(*val)), ("as_of", j_seq(*as_of))])
        }
        // The payload option: null = ⊥ (no link at that address). The link's
        // age beside it (wire.md §Links (raw reads)): `at`, the position of
        // the commit that minted it, and `time` with `time_from` — three wire
        // keys over two optional values, `time` and `time_from` null together
        // where no testimony holds a reading, all three null where the
        // position is unknown or the link reads as absent.
        Response::LinkValue { link, at, time, as_of } => (
            "link_value",
            vec![
                ("link", link.as_ref().map(j_link).unwrap_or(Value::Null)),
                ("at", at.map(j_seq).unwrap_or(Value::Null)),
                ("time", time.map(j_mint_time).unwrap_or(Value::Null)),
                ("time_from", time.map(j_time_from).unwrap_or(Value::Null)),
                ("as_of", j_seq(*as_of)),
            ],
        ),
        Response::Follow { result, as_of } => {
            ("follow", vec![("result", j_follow_result(result)), ("as_of", j_seq(*as_of))])
        }
        Response::Deletions { rep, as_of } => {
            ("deletions", vec![("rep", j_deletions(rep)), ("as_of", j_seq(*as_of))])
        }
        Response::Compare { rep, as_of } => {
            ("compare", vec![("pairs", j_corrs(&rep.0)), ("as_of", j_seq(*as_of))])
        }
        Response::Orphans { report, as_of } => {
            ("orphans", vec![("orphaned", j_addrs(&report.orphaned)), ("as_of", j_seq(*as_of))])
        }
        Response::Claims { claims, as_of } => {
            ("claims", vec![("claims", j_claims(claims)), ("as_of", j_seq(*as_of))])
        }
        // The doc-metadata answer (wire v7.6, PUB-8.12): the trunk document,
        // its publication bit, its owner account, its birth version with
        // that version's base extent, and — the signed-ops design record's
        // D25 — the shot terms of the address named. `owner` is a payload
        // option — null stands only so the shape never invents an account; a
        // registered document always carries one. `birth` and
        // `birth_extent` are two wire keys over *one* optional value, so they
        // are null together while the document has no member yet and carried
        // together once it has. `placed` and `base_extent` are two wire keys
        // over the terms: both null where the address named carries none (a
        // trunk, a version-minted birth, a member minted without terms);
        // `placed` carried and `base_extent` null for a member the birth shape
        // minted — the null *is* the birth bit there; both carried otherwise.
        // `source` (the fork-source design record) is a payload option over
        // the fork source of the address named: the member or bare document a
        // `version` snapshotted into it, null where no `version` minted it.
        // `at`, `time` and `time_from` are the age of the address named, as
        // `link_value` carries a link's: the mint position off the world's
        // map, null for an address a build before it minted; the time and
        // its source null together where no testimony holds a reading.
        Response::DocMetadata { doc, published, owner, birth, terms, source, at, time, as_of } => (
            "doc_metadata",
            vec![
                ("doc", j_addr(doc)),
                ("published", Value::Bool(*published)),
                ("owner", owner.as_ref().map(j_addr).unwrap_or(Value::Null)),
                ("birth", birth.as_ref().map(|b| j_addr(&b.addr)).unwrap_or(Value::Null)),
                ("birth_extent", birth.as_ref().map(|b| j_nat(&b.extent)).unwrap_or(Value::Null)),
                ("placed", terms.as_ref().map(|t| j_nat(&t.placed)).unwrap_or(Value::Null)),
                (
                    "base_extent",
                    terms
                        .as_ref()
                        .and_then(|t| t.base_extent.as_ref())
                        .map(j_nat)
                        .unwrap_or(Value::Null),
                ),
                ("source", source.as_ref().map(j_addr).unwrap_or(Value::Null)),
                ("at", at.map(j_seq).unwrap_or(Value::Null)),
                ("time", time.map(j_mint_time).unwrap_or(Value::Null)),
                ("time_from", time.map(j_time_from).unwrap_or(Value::Null)),
                ("as_of", j_seq(*as_of)),
            ],
        ),
        // The audit-view edition-claim lookup (wire v7.6, PUB-8.46): one row
        // per admitted, unsuperseded claim, retracted or not.
        Response::EditionClaims { claims, as_of } => {
            ("edition_claims", vec![("claims", j_edition_claims(claims)), ("as_of", j_seq(*as_of))])
        }
        // The any-principal discovery read (PUB-8.47): one row per covered
        // content prefix with the issuers who granted it, in prefix order;
        // `rows` is always present and empty for the guest — an answer.
        Response::UniversalGrants { rows, as_of } => {
            ("universal_grants", vec![("rows", j_universal_grants(rows)), ("as_of", j_seq(*as_of))])
        }
        Response::Rejected(rej) => return j_rejection(rej),
    };
    pairs.push(("resp", Value::String(name.into())));
    obj(pairs)
}

fn j_rejection(rej: &Rejection) -> Value {
    let mut pairs = vec![
        ("resp", Value::String("rejected".into())),
        ("op", Value::String(op_name(rej.op).into())),
        ("code", Value::String(code_name(rej.code).into())),
        ("disposition", Value::String(disposition_name(rej.disposition).into())),
    ];
    // Diagnostic options are omitted when absent (payload options are null).
    if let Some(site) = &rej.site {
        pairs.push(("site", j_site(site)));
    }
    if let Some(d) = &rej.detail {
        pairs.push(("detail", Value::String(d.clone())));
    }
    obj(pairs)
}

fn j_site(s: &FaultSite) -> Value {
    let mut pairs: Vec<(&'static str, Value)> = Vec::new();
    if let Some(o) = s.operand {
        let name = match o {
            Operand::First => "first",
            Operand::Second => "second",
        };
        pairs.push(("operand", Value::String(name.into())));
    }
    if let Some(r) = s.region {
        pairs.push(("region", j_usize(r)));
    }
    if let Some(sl) = s.slot {
        pairs.push(("slot", j_usize(sl)));
    }
    if let Some(i) = s.index {
        pairs.push(("index", j_usize(i)));
    }
    if let Some(f) = s.fault {
        pairs.push(("fault", Value::String(fault_name(f).into())));
    }
    if let Some(a) = &s.addr {
        pairs.push(("addr", j_addr(a)));
    }
    obj(pairs)
}

// ── leaf marshalers ──

fn j_seq(s: Seq) -> Value {
    j_u64(s.0)
}

fn j_u64(n: u64) -> Value {
    Value::Number(n.into())
}

/// Renders an age read's `time`: the testimony's unix milliseconds.
fn j_mint_time(t: MintTime) -> Value {
    j_u64(t.millis)
}

/// Renders an age read's `time_from`: which testimony the time is.
///
/// `"feed"` is the change feed's own line for the position, exact to the
/// minute; `"anchor"` the newest hourly `skep-time` record at or below it
/// (wire.md §Links (raw reads)). The two spellings are the wire's, pinned by
/// the wire doc's examples.
fn j_time_from(t: MintTime) -> Value {
    Value::String(
        match t.source {
            TimeSource::Feed => "feed",
            TimeSource::Anchor => "anchor",
        }
        .to_string(),
    )
}

fn j_usize(n: usize) -> Value {
    j_u64(n as u64)
}

fn j_nat(n: &Nat) -> Value {
    Value::String(n.to_string())
}

/// Renders a tumbler in its wire form.
///
/// The form is dotted-decimal, zeros explicit, components canonical decimal
/// — M1's own `Display`, so the wire form and a tumbler's canonical text are
/// *one* rendering rather than two that must be kept equal. (The conformance
/// goldens read the same encoding.)
fn j_tum(t: &Tumbler) -> Value {
    Value::String(t.to_string())
}

fn j_addr(a: &Address) -> Value {
    j_tum(a.tumbler())
}

fn j_addrs(addrs: &[Address]) -> Value {
    Value::Array(addrs.iter().map(j_addr).collect())
}

fn j_span(s: &Span) -> Value {
    obj(vec![("start", j_tum(s.start())), ("width", j_tum(s.width()))])
}

fn j_spans(spans: &[Span]) -> Value {
    Value::Array(spans.iter().map(j_span).collect())
}

fn j_spanset(s: &SpanSet) -> Value {
    Value::Array(s.iter().map(j_span).collect())
}

fn j_endset(e: &Endset) -> Value {
    Value::Array(e.spans().map(j_span).collect())
}

fn j_vpos(u: &VPos) -> Value {
    obj(vec![("subspace", j_nat(&u.subspace)), ("ordinal", j_nat(&u.ordinal))])
}

fn j_vposes(us: &[VPos]) -> Value {
    Value::Array(us.iter().map(j_vpos).collect())
}

fn j_vspec(v: &VSpec) -> Value {
    obj(vec![("source", j_addr(&v.source)), ("span", j_span(&v.span))])
}

fn j_vspecs(vs: &[VSpec]) -> Value {
    Value::Array(vs.iter().map(j_vspec).collect())
}

/// Renders a shot run: the origin, the run's start and its width.
///
/// It is [`p_shot_run`](super::p_shot_run)'s inverse.
fn j_shot_run(r: &ShotRun) -> Value {
    obj(vec![
        ("origin", j_addr(&r.origin)),
        ("i_start", j_addr(r.run.i_start())),
        ("width", j_nat(r.run.width())),
    ])
}

fn j_shot_runs(rs: &[ShotRun]) -> Value {
    Value::Array(rs.iter().map(j_shot_run).collect())
}

/// Renders a slot argument, [`p_slotarg`](super::p_slotarg)'s inverse.
///
/// The Resolve form is the bare v-spec array (byte-identical to v4), the
/// Addrs form and the Spans form each their tagged object.
fn j_slotarg(s: &SlotArg) -> Value {
    match s {
        SlotArg::Resolve(v) => j_vspecs(v),
        SlotArg::Addrs(a) => obj(vec![("addrs", j_addrs(a))]),
        SlotArg::Spans(spans) => obj(vec![("spans", j_ispan_slot(spans))]),
    }
}

/// Renders one `links` entry of a `publish` (the link-sets design §5.7) —
/// [`p_link_entry`](super::p_link_entry)'s inverse: `home`, `ty`, `from`,
/// `to`, and `old` only where the entry names one.
fn j_link_entry(entry: &LinkEntry) -> Value {
    let mut pairs = vec![
        ("home", j_named(&entry.home)),
        ("ty", j_end(&entry.ty)),
        ("from", j_end(&entry.from)),
        ("to", j_end(&entry.to)),
    ];
    if let Some(old) = &entry.old {
        pairs.push(("old", j_addr(old)));
    }
    obj(pairs)
}

/// Renders an address or a tag standing for one the commit mints —
/// [`p_named`](super::p_named)'s inverse: the string `member`, the string
/// `edition`, or the address.
fn j_named(named: &NamedAddress) -> Value {
    match named {
        NamedAddress::Member => Value::String("member".into()),
        NamedAddress::Edition => Value::String("edition".into()),
        NamedAddress::Address(a) => j_addr(a),
    }
}

/// Renders one end of a `links` entry — [`p_end`](super::p_end)'s inverse:
/// the address form, the I-span form, or the member-position form, each its
/// tagged object; a member span's `ordinal` and `width` as decimal strings,
/// as `reinstate`'s `at` spells its naturals.
fn j_end(end: &EndArg) -> Value {
    match end {
        EndArg::Addrs(named) => obj(vec![("addrs", Value::Array(named.iter().map(j_named).collect()))]),
        EndArg::Spans(spans) => obj(vec![("spans", j_ispan_slot(spans))]),
        EndArg::Member(spans) => obj(vec![(
            "member",
            Value::Array(
                spans
                    .iter()
                    .map(|s| {
                        obj(vec![
                            ("ordinal", Value::String(s.ordinal.to_string())),
                            ("width", Value::String(s.width.to_string())),
                        ])
                    })
                    .collect(),
            ),
        )]),
    }
}

/// Renders an I-span slot's spans as the I-spans they were sent as —
/// [`p_ispan_slot`](super::p_ispan_slot)'s inverse: each span's start as an
/// address and its width's last component as the count, `retrieve_i`'s
/// I-span shape.
///
/// Exact for every span the parse admits (a start of any shape, a width
/// `0…0.n` at the start's length): what a caller rebuilt some other way
/// renders by the same two fields.
fn j_ispan_slot(spans: &[Span]) -> Value {
    Value::Array(
        spans
            .iter()
            .map(|s| {
                // The width's last component (`Tumbler::get` is 1-based).
                let width = s.width();
                let count = width.get(width.len()).expect("a tumbler is nonempty");
                obj(vec![("start", j_tum(s.start())), ("width", j_nat(count))])
            })
            .collect(),
    )
}

fn j_spec(s: &Spec) -> Value {
    obj(vec![("doc", j_addr(&s.doc)), ("span", j_span(&s.span))])
}

fn j_specs(ss: &[Spec]) -> Value {
    Value::Array(ss.iter().map(j_spec).collect())
}

/// Renders an I-span: the span's start address and its width.
///
/// It is [`p_ispan`](super::p_ispan)'s inverse.
fn j_ispan(s: &ISpan) -> Value {
    obj(vec![("start", j_addr(&s.start)), ("width", j_nat(&s.width))])
}

fn j_ispans(ss: &[ISpan]) -> Value {
    Value::Array(ss.iter().map(j_ispan).collect())
}

fn j_region(r: &RegionSpec) -> Value {
    obj(vec![("doc", j_addr(&r.doc)), ("spans", j_spans(&r.spans))])
}

fn j_regions(rs: &[RegionSpec]) -> Value {
    Value::Array(rs.iter().map(j_region).collect())
}

/// The canonical rendering of a position-value sequence into wire items.
///
/// The items are a request's `values` array or a delivery's `items` array,
/// and this is the one place the rendering's rule lives: consecutive
/// single-byte values accumulate into a run rendered as *one* item (UTF-8
/// judged on the whole run, else `{"hex"}`); a composite value flushes the
/// run and renders as its own atom item, never coalesced with a neighbor; a
/// delivery's byte-run item, M6's `Bytes` — a maximal run of single-byte
/// positions read out of one stored stretch — feeds the pending run byte by
/// byte, so the wire item is the same whether the store held the run as one
/// entry or as one value per byte. Maximal runs are what make the rendering
/// injective — two distinct position-value sequences never render alike —
/// and what re-canonicalize the parse-side normalizations (element
/// boundaries between adjacent per-byte forms, one-byte atoms), so
/// `parse(marshal_request(r))` reproduces `r`.
///
/// `utf8` is the only thing the two renderings differ by: a request
/// `values` element is the bare string, a delivery item is
/// `{"content": …}`.
#[derive(Debug)]
struct ValueItems {
    out: Vec<Value>,
    byte_run: Vec<u8>,
    utf8: fn(String) -> Value,
}

impl ValueItems {
    fn new(utf8: fn(String) -> Value) -> ValueItems {
        ValueItems { out: Vec::new(), byte_run: Vec::new(), utf8 }
    }

    /// Adds one position's value to the items.
    ///
    /// A single-byte value joins the pending run, a composite one breaks it
    /// and becomes its own atom item.
    fn value(&mut self, v: &Val) {
        if let [b] = v.as_bytes() {
            self.byte_run.push(*b);
        } else {
            self.flush();
            self.out.push(j_atom(v));
        }
    }

    /// Adds a run of single-byte positions, one delivery item.
    ///
    /// Every byte joins the pending run — the run a one-byte value joins — so
    /// the item rendered is the one a per-value delivery renders, and a run
    /// that meets a one-byte value at its edge coalesces with it.
    fn bytes(&mut self, run: &[u8]) {
        self.byte_run.extend_from_slice(run);
    }

    /// Adds a rendered item that is not a content value.
    ///
    /// It is a delivery `{"ref"}` or `{"withheld"}`, and it breaks the run,
    /// since a run is consecutive by definition.
    fn item(&mut self, v: Value) {
        self.flush();
        self.out.push(v);
    }

    /// Emits the pending run, if any.
    ///
    /// The item is `utf8`'s form when the whole run decodes, else `{"hex"}`
    /// over its raw bytes.
    fn flush(&mut self) {
        if self.byte_run.is_empty() {
            return;
        }
        let item = match String::from_utf8(std::mem::take(&mut self.byte_run)) {
            Ok(s) => (self.utf8)(s),
            Err(e) => obj(vec![("hex", Value::String(hex_string(e.as_bytes())))]),
        };
        self.out.push(item);
    }

    fn finish(mut self) -> Value {
        self.flush();
        Value::Array(self.out)
    }
}

/// Renders the canonical `values` encoding.
///
/// It is [`p_values`](super::p_values)'s inverse, under [`ValueItems`]' rule
/// with the bare-string run form.
fn j_values(vs: &[Val]) -> Value {
    let mut out = ValueItems::new(Value::String);
    for v in vs {
        out.value(v);
    }
    out.finish()
}

/// Renders one composite value as its atom item.
///
/// The item is `{"atom"}` when its bytes are UTF-8, else `{"atom_hex"}` —
/// exactly one value per item, never coalesced with its neighbors.
fn j_atom(v: &Val) -> Value {
    match std::str::from_utf8(v.as_bytes()) {
        Ok(s) => obj(vec![("atom", Value::String(s.to_owned()))]),
        Err(_) => obj(vec![("atom_hex", Value::String(hex_string(v.as_bytes())))]),
    }
}

fn j_view(v: View) -> Value {
    Value::String(
        match v {
            View::Audit => "audit",
            View::Active => "active",
            View::Default => "default",
        }
        .into(),
    )
}

fn j_slotspec(s: &SlotSpec) -> Value {
    match s {
        SlotSpec::Any => Value::String("any".into()),
        SlotSpec::Empty => Value::String("empty".into()),
        SlotSpec::Spans(e) => j_endset(e),
    }
}

fn j_fourset(q: &FourSet) -> Value {
    obj(vec![
        ("home", j_slotspec(&q.home)),
        ("from", j_slotspec(&q.from)),
        ("to", j_slotspec(&q.to)),
        ("ty", j_slotspec(&q.ty)),
    ])
}

fn j_cursor(c: &Option<Address>) -> Value {
    c.as_ref().map(j_addr).unwrap_or(Value::Null)
}

fn j_window(w: &Window) -> Value {
    obj(vec![
        ("batch", j_addrs(&w.batch)),
        ("next", j_cursor(&w.next)),
        ("exhausted", Value::Bool(w.exhausted)),
    ])
}

/// Renders a delivery's items.
///
/// They follow [`ValueItems`]' rule with the `{"content"}` run form, plus
/// link positions as `{"ref"}` and withheld runs as `{"withheld"}`. The item
/// key names the granularity, so a client always knows which world it is
/// looking at.
fn j_items(items: &[DeliveryItem]) -> Value {
    let mut out = ValueItems::new(|s| obj(vec![("content", Value::String(s))]));
    for it in items {
        match it {
            DeliveryItem::Content(v) => out.value(v),
            DeliveryItem::Bytes(run) => out.bytes(run),
            DeliveryItem::Ref(a) => out.item(obj(vec![("ref", j_addr(a))])),
            // The withheld arm (PUB-6.41): one item per masked *run* at its
            // own position, `{"withheld": {"origin", "width"}}` — `out.item`
            // breaks the pending run, so it is never coalesced with a
            // neighbour (PUB-6.58).
            DeliveryItem::Withheld { origin, width } => out.item(obj(vec![(
                "withheld",
                obj(vec![("origin", j_addr(origin)), ("width", j_nat(width))]),
            )])),
        }
    }
    out.finish()
}

/// Renders the items of the read by identity, `i_delivery`.
///
/// They are one object per I-position asked (wire.md §The response
/// envelope): `at` its address and `value` the value M4 holds there —
/// rendered as the delivery renders *one* value, [`ValueItems`]' rule over
/// a run of one: `{"content"}` or `{"hex"}` for a single-byte value,
/// `{"atom"}` or `{"atom_hex"}` for a composite — or `null`, a payload
/// option, where the position holds none. Never coalesced across positions:
/// the items are the request's positions, one each, so a client reads a
/// value at the address it asked.
///
/// # Panics
///
/// Panics if a value renders as no item, which it cannot: [`ValueItems`]
/// renders one value as exactly one item.
fn j_iitems(items: &[IItem]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|item| {
                let value = match &item.value {
                    Some(v) => {
                        let mut one = ValueItems::new(|s| obj(vec![("content", Value::String(s))]));
                        one.value(v);
                        match one.finish() {
                            Value::Array(mut rendered) => rendered.remove(0),
                            other => other,
                        }
                    }
                    None => Value::Null,
                };
                obj(vec![("at", j_addr(&item.at)), ("value", value)])
            })
            .collect(),
    )
}

/// Renders a link as its positional slots, 1-based on the wire as in M7.
///
/// The slots are 1 = from, 2 = to, 3 = type.
fn j_link(l: &Link) -> Value {
    let slots: Vec<Value> = l.slots().map(j_endset).collect();
    obj(vec![("slots", Value::Array(slots))])
}

fn j_run(r: &Run) -> Value {
    obj(vec![("i_start", j_addr(r.i_start())), ("width", j_nat(r.width()))])
}

fn j_runs(rs: &[Run]) -> Value {
    Value::Array(rs.iter().map(j_run).collect())
}

fn j_corr(p: &CorrPair) -> Value {
    obj(vec![
        ("d1", j_addr(&p.d1)),
        ("u1", j_vpos(&p.u1)),
        ("d2", j_addr(&p.d2)),
        ("u2", j_vpos(&p.u2)),
        ("width", j_nat(&p.width)),
    ])
}

fn j_corrs(ps: &[CorrPair]) -> Value {
    Value::Array(ps.iter().map(j_corr).collect())
}

fn j_claim(c: &SupClaim) -> Value {
    obj(vec![
        ("claim", j_addr(&c.claim)),
        ("old", j_addr(&c.old)),
        ("new", j_addr(&c.new)),
        ("home", j_addr(&c.home)),
        ("active", Value::Bool(c.active)),
    ])
}

fn j_claims(cs: &[SupClaim]) -> Value {
    Value::Array(cs.iter().map(j_claim).collect())
}

/// Renders one edition-claim row (wire.md §edition_claims).
///
/// The row is the claim's address, its home (the edition), its `to` endset
/// as deposited, and whether it is active — `false` names a retracted claim
/// the audit view still lists.
fn j_edition_claim(c: &EditionClaim) -> Value {
    obj(vec![
        ("claim", j_addr(&c.claim)),
        ("home", j_addr(&c.home)),
        ("to", j_endset(&c.to)),
        ("active", Value::Bool(c.active)),
    ])
}

fn j_edition_claims(cs: &[EditionClaim]) -> Value {
    Value::Array(cs.iter().map(j_edition_claim).collect())
}

/// Renders one row of the any-principal discovery read.
///
/// The row (wire.md §universal_grants) is the covered content prefix — the
/// stored prefix where the registry's `effective_owner` answers the issuer
/// for it, or the issuer's own account where the stored prefix is wider
/// (PUB-8.47; RES-298), so every issuer listed owns it — and the issuing
/// accounts, in address order: the set's own iteration order, rendered as
/// the list the shape rules.
fn j_universal_grant(g: &UniversalGrant) -> Value {
    obj(vec![
        ("prefix", j_addr(&g.prefix)),
        ("issuers", Value::Array(g.issuers.iter().map(j_addr).collect())),
    ])
}

fn j_universal_grants(gs: &[UniversalGrant]) -> Value {
    Value::Array(gs.iter().map(j_universal_grant).collect())
}

/// Renders one `retrieve_endsets` pair: the 1-based slot and its endset.
fn j_endset_pair(slot: usize, e: &Endset) -> Value {
    obj(vec![("slot", j_usize(slot)), ("endset", j_endset(e))])
}

fn j_endset_pairs(ps: &[(usize, Endset)]) -> Value {
    Value::Array(ps.iter().map(|(slot, e)| j_endset_pair(*slot, e)).collect())
}

/// Renders `show_deletions`' two directions, each an address list.
///
/// The wire keys are `a_with_b`/`b_with_a` (wire.md §showdeletions), the
/// contracted spelling of M6's
/// `deleted_from_a_with_b`/`deleted_from_b_with_a`.
fn j_deletions(d: &Deletions) -> Value {
    obj(vec![
        ("a_with_b", j_addrs(&d.deleted_from_a_with_b)),
        ("b_with_a", j_addrs(&d.deleted_from_b_with_a)),
    ])
}

/// Renders `follow_link`'s in-band `Result`.
///
/// The empty span set is a defined answer, so ⟨⟩ and ⊥ are distinct wire
/// shapes rather than one nullable field.
fn j_follow_result(r: &Result<SpanSet, Invalid>) -> Value {
    match r {
        Ok(set) => obj(vec![("ok", j_spanset(set))]),
        Err(_) => obj(vec![("err", Value::String("invalid".into()))]),
    }
}

fn j_successor(s: &SuccessorSpec) -> Value {
    obj(vec![
        ("from", j_successor_end(&s.from)),
        ("to", j_successor_end(&s.to)),
        ("ty", j_successor_ty(&s.ty)),
    ])
}

/// Renders a successor's `from` or `to`,
/// [`p_successor_end`](super::p_successor_end)'s inverse: the bare v-spec
/// array, or the `spans` object. An address-form end renders as its `addrs`
/// object, which the parse refuses — the narrowing M10 keeps, stated at the
/// parse and not here.
fn j_successor_end(e: &SlotArg) -> Value {
    j_slotarg(e)
}

fn j_successor_ty(t: &SlotArg) -> Value {
    match t {
        SlotArg::Addrs(a) => obj(vec![("addrs", j_addrs(a))]),
        SlotArg::Resolve(v) => obj(vec![("resolve", j_vspecs(v))]),
        SlotArg::Spans(spans) => obj(vec![("spans", j_ispan_slot(spans))]),
    }
}

// ── the two name tables (marshal-side; parse mirrors op_name) ──

/// Returns an `OpKind` variant's name in snake_case, its wire name.
///
/// It is the request tag *and* the rejection's `op` field, one table for
/// both.
pub fn op_name(k: OpKind) -> &'static str {
    match k {
        OpKind::CreateNewDocument => "create_new_document",
        OpKind::Delegate => "delegate",
        OpKind::RegisterNode => "register_node",
        OpKind::Fork => "fork",
        OpKind::NextAccountPrefix => "next_account_prefix",
        OpKind::PrincipalPrefix => "principal_prefix",
        OpKind::EffectiveOwner => "effective_owner",
        OpKind::DocMetadata => "doc_metadata",
        OpKind::Insert => "insert",
        OpKind::Delete => "delete",
        OpKind::Copy => "copy",
        OpKind::Reinstate => "reinstate",
        OpKind::Rearrange => "rearrange",
        OpKind::Version => "version",
        OpKind::Publish => "publish",
        OpKind::MakeLink => "make_link",
        OpKind::Emit => "emit",
        OpKind::Nullify => "nullify",
        OpKind::AssertSup => "assert_sup",
        OpKind::EditLink => "edit_link",
        OpKind::ReadLink => "read_link",
        OpKind::FollowLink => "follow_link",
        OpKind::RetrieveV => "retrieve_v",
        OpKind::RetrieveI => "retrieve_i",
        OpKind::ContentFrontier => "content_frontier",
        OpKind::RetrieveDocVSpan => "retrieve_doc_v_span",
        OpKind::RetrieveDocVSpanSet => "retrieve_doc_v_span_set",
        OpKind::ShowOrigin => "show_origin",
        OpKind::ShowDeletions => "show_deletions",
        OpKind::Compare => "compare",
        OpKind::FindDocsContaining => "find_docs_containing",
        OpKind::Image => "image",
        OpKind::FindLinksV => "find_links_v",
        OpKind::FindLinksFtt => "find_links_ftt",
        OpKind::CountV => "count_v",
        OpKind::CountFtt => "count_ftt",
        OpKind::WindowV => "window_v",
        OpKind::WindowFtt => "window_ftt",
        OpKind::RetrieveEndsets => "retrieve_endsets",
        OpKind::Project => "project",
        OpKind::DiscoverableFrom => "discoverable_from",
        OpKind::DeleteOrphans => "delete_orphans",
        OpKind::InClaims => "in_claims",
        OpKind::OutClaims => "out_claims",
        OpKind::EditionClaims => "edition_claims",
        OpKind::UniversalGrants => "universal_grants",
        OpKind::Unparseable => "unparseable",
    }
}

fn disposition_name(d: Disposition) -> &'static str {
    match d {
        Disposition::Permanent => "permanent",
        Disposition::Reorder => "reorder",
        Disposition::Retry => "retry",
        Disposition::Halt => "halt",
    }
}

fn fault_name(f: SpanFault) -> &'static str {
    match f {
        SpanFault::NotOrdinalLevel => "not_ordinal_level",
        SpanFault::NotLevelUniform => "not_level_uniform",
        SpanFault::StartNotZeroFree => "start_not_zero_free",
        SpanFault::StartTooShallow => "start_too_shallow",
    }
}

/// The code of AUTH's credential family, spelled by hand.
///
/// The rejection codes M10 does not carry are the ones this crate spells by
/// hand rather than through [`code_name`] (wire.md §Credential refusals,
/// §Registry): AUTH's credential family's, and the registry sequence's.
/// Each retires the day `RejectCode` grows a variant for it.
const CREDENTIAL_REFUSED: &str = "credential_refused";
/// The registry sequence's code — [`CREDENTIAL_REFUSED`]'s sibling.
const REGISTRY_REFUSED: &str = "registry_refused";

/// Returns a `RejectCode` variant's wire name, its name in snake_case.
///
/// The one variant spelled otherwise is `NotOrdinalVSpan`, whose `VSpan` is
/// one word (`not_ordinal_vspan`). Exhaustive, so a new code cannot ship
/// without a wire name.
fn code_name(c: RejectCode) -> &'static str {
    match c {
        RejectCode::Unauthenticated => "unauthenticated",
        RejectCode::Malformed => "malformed",
        RejectCode::Durability => "durability",
        RejectCode::TxnUnencodable => "txn_unencodable",
        RejectCode::TxnOverBudget => "txn_over_budget",
        RejectCode::Poisoned => "poisoned",
        RejectCode::HomeNotRegistered => "home_not_registered",
        RejectCode::DocNotRegistered => "doc_not_registered",
        RejectCode::SourceNotRegistered => "source_not_registered",
        RejectCode::ParentNotRegistered => "parent_not_registered",
        RejectCode::NotRegistered => "not_registered",
        RejectCode::OriginalNotResident => "original_not_resident",
        RejectCode::EndpointNotResident => "endpoint_not_resident",
        RejectCode::NotOwner => "not_owner",
        RejectCode::NotAnAccount => "not_an_account",
        RejectCode::Gate => "gate",
        RejectCode::DelegatorUnknown => "delegator_unknown",
        RejectCode::DuplicateId => "duplicate_id",
        RejectCode::NotAncestor => "not_ancestor",
        RejectCode::NotAuthorized => "not_authorized",
        RejectCode::NotAccountTier => "not_account_tier",
        RejectCode::NotTopDown => "not_top_down",
        RejectCode::NotNextForm => "not_next_form",
        RejectCode::NotValid => "not_valid",
        RejectCode::NotNode => "not_node",
        RejectCode::TooDeep => "too_deep",
        RejectCode::NotDescendantOfBootstrap => "not_descendant_of_bootstrap",
        RejectCode::NotFresh => "not_fresh",
        RejectCode::EmptyContent => "empty_content",
        RejectCode::Content => "content",
        RejectCode::EmptySource => "empty_source",
        RejectCode::NotOrdinalVSpan => "not_ordinal_vspan",
        RejectCode::DanglingSource => "dangling_source",
        RejectCode::TooManyRuns => "too_many_runs",
        // The publish shot's re-insert budget (M5's `MAX_REINSERTED_VALUES`),
        // beside the run budget it is not.
        RejectCode::TooManyValues => "too_many_values",
        RejectCode::EmptyResult => "empty_result",
        RejectCode::NotArranged => "not_arranged",
        RejectCode::OutOfBounds => "out_of_bounds",
        RejectCode::EmptyWidth => "empty_width",
        RejectCode::BadCutCount => "bad_cut_count",
        RejectCode::NotAscending => "not_ascending",
        RejectCode::EmptyContentSubspace => "empty_content_subspace",
        RejectCode::NotAPrincipal => "not_a_principal",
        RejectCode::NodeTierCrossOwner => "node_tier_cross_owner",
        RejectCode::NotLinkAddress => "not_link_address",
        RejectCode::NotHomeLink => "not_home_link",
        RejectCode::AlreadySeated => "already_seated",
        RejectCode::NotContentSubspace => "not_content_subspace",
        // The version-chain model's three write-path refusals (PUB-8.2's
        // routed item; PUB-kickoff D2b) — the wire's own tokens, tabled with
        // their dispositions and faces in §The version-chain refusals.
        RejectCode::PublishedTarget => "published_target",
        RejectCode::PrivateVersionOfPublished => "private_version_of_published",
        RejectCode::PrivateSourceVersionless => "private_source_versionless",
        // The publish shot's codes: `withheld` is PUB-8.4's pinned token, and
        // the four beside it are the wire's own, tabled with their
        // dispositions in §The publish shot and head-float.
        RejectCode::Withheld => "withheld",
        RejectCode::BadRun => "bad_run",
        RejectCode::BaseNotInChain => "base_not_in_chain",
        RejectCode::BaseSuperseded => "base_superseded",
        RejectCode::BaseExtentTooLarge => "base_extent_too_large",
        // The publication's twin fence and its re-window's check (the
        // link-sets design §5.7), tabled with the shot's codes in §The publish
        // shot and head-float.
        RejectCode::AlreadyPublished => "already_published",
        RejectCode::KeptPlaceMoved => "kept_place_moved",
        RejectCode::IllFormedSpec => "ill_formed_spec",
        RejectCode::SlotTooLarge => "slot_too_large",
        RejectCode::EmptyTypeResolution => "empty_type_resolution",
        RejectCode::ShapeViolation => "shape_violation",
        RejectCode::RetractionClass => "retraction_class",
        RejectCode::NonAddressDenotingType => "non_address_denoting_type",
        RejectCode::BadTarget => "bad_target",
        RejectCode::SelfSupersession => "self_supersession",
        RejectCode::IllFormedSuccessor => "ill_formed_successor",
        RejectCode::DcViolation => "dc_violation",
        // The publication's deposits (the link-sets design §5.7; lane S3):
        // six tokens, tabled in §Rejection codes.
        RejectCode::LinkHomeRefused => "link_home_refused",
        RejectCode::OldRefused => "old_refused",
        RejectCode::DuplicateOriginal => "duplicate_original",
        RejectCode::ReadWithInLinks => "read_with_in_links",
        RejectCode::RetractRefused => "retract_refused",
        RejectCode::ReadWithRefused => "read_with_refused",
        RejectCode::NoSuchSubspace => "no_such_subspace",
        RejectCode::EmptySubspace => "empty_subspace",
        RejectCode::DepthIncompatible => "depth_incompatible",
        RejectCode::RangeNotPresent => "range_not_present",
        RejectCode::MalformedSpan => "malformed_span",
        RejectCode::TooManyBlocks => "too_many_blocks",
        RejectCode::TooManyPairs => "too_many_pairs",
        RejectCode::TooMuchCoverage => "too_much_coverage",
        RejectCode::TooManyItems => "too_many_items",
        RejectCode::NotALink => "not_a_link",
        RejectCode::BadRegion => "bad_region",
        RejectCode::ImageTooLarge => "image_too_large",
        RejectCode::EndsetsTooLarge => "endsets_too_large",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{p_hex, p_slotspec, p_val_form, p_view};

    /// Checks value granularity at the leaf.
    ///
    /// Per-byte forms mint one single-byte value per byte, atom forms one
    /// composite value; the canonical marshal coalesces maximal per-byte runs
    /// (UTF-8 judged on the whole run) and never coalesces atoms.
    #[test]
    fn value_forms_parse_per_byte_and_atoms_marshal_apart() {
        let mut vs: Vec<Val> = Vec::new();
        p_val_form(&Value::String("hé".into()), &mut vs).expect("a string value form parses");
        assert_eq!(vs.len(), 3, "'h' plus the two bytes of 'é'");
        assert!(vs.iter().all(|v| v.len() == 1));
        p_val_form(&obj(vec![("atom", Value::String("hé".into()))]), &mut vs)
            .expect("an atom value form parses");
        assert_eq!(vs.len(), 4);
        assert_eq!(vs[3].as_bytes(), "hé".as_bytes());
        // Canonical inverse: the run reassembles, the atom stays its own form.
        let canon = j_values(&vs);
        let expect: Value = serde_json::from_str(r#"["hé",{"atom":"hé"}]"#).unwrap();
        assert_eq!(canon, expect);
        // Empty per-byte forms are vacuous; empty atoms are inexpressible;
        // multi-key objects and non-string/object elements are malformed.
        let mut none: Vec<Val> = Vec::new();
        p_val_form(&Value::String(String::new()), &mut none).expect("\"\" is vacuous");
        p_val_form(&obj(vec![("hex", Value::String(String::new()))]), &mut none)
            .expect("an empty hex string is vacuous");
        assert!(none.is_empty());
        for bad in [
            obj(vec![("atom", Value::String(String::new()))]),
            obj(vec![("atom_hex", Value::String(String::new()))]),
            obj(vec![("atom", Value::String("a".into())), ("hex", Value::String("00".into()))]),
            Value::Bool(true),
        ] {
            assert!(p_val_form(&bad, &mut none).is_err(), "{bad} must not parse");
        }
        assert!(p_hex("abc").is_err()); // odd length
        assert!(p_hex("zz").is_err());
    }

    /// Checks that all three documented view values round-trip.
    ///
    /// They are wire.md §Value encodings' `"audit"`, `"active"` and
    /// `"default"`. The request fixtures carry all three
    /// (`tests/it/codec_roundtrip.rs`), and this test holds each value's parse
    /// arm and marshal arm to its documented name: a typo in either makes a
    /// frame the document offers a client come back `unparseable`, which tells
    /// them their frame is malformed when the value is one wire.md invited.
    #[test]
    fn every_documented_view_value_round_trips() {
        for name in ["audit", "active", "default"] {
            let v = p_view(&Value::String(name.into()))
                .unwrap_or_else(|e| panic!("'{name}' is a documented view: {e}"));
            assert_eq!(j_view(v), Value::String(name.into()), "'{name}' must be its own inverse");
        }
        for bad in ["Audit", "", "all", "actives"] {
            assert!(p_view(&Value::String(bad.into())).is_err(), "'{bad}' must not parse");
        }
    }

    /// Checks that an empty slot constraint normalizes to its canonical name.
    ///
    /// It is the one parse-side normalization
    /// [`JsonCodec::marshal_request`]'s precondition names rather than
    /// excludes: an empty span array *is* the empty constraint (M8 documents
    /// the empty endset as exactly that zero), so it reads back under the
    /// canonical name and a `SlotSpec::Spans` over an empty endset
    /// round-trips *equal* rather than identical. Nothing else pins that the
    /// two spellings meet.
    #[test]
    fn an_empty_slot_constraint_normalizes_onto_its_canonical_name() {
        assert!(
            matches!(p_slotspec(&Value::Array(vec![])), Ok(SlotSpec::Empty)),
            "an empty span array is the empty constraint, not an empty span list"
        );
        assert_eq!(
            j_slotspec(&SlotSpec::Spans(Endset::from_spans([]))),
            Value::Array(vec![]),
            "which is the form an empty Spans marshals as"
        );
        assert_eq!(j_slotspec(&SlotSpec::Empty), Value::String("empty".into()));
    }
}
