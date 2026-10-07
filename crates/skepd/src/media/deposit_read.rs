//! THE DEPOSIT READ (`media.md` Op inventory 1, "THE DEPOSITOR CAN READ
//! THEIR OWN DEPOSIT RECORD, AND THE RESUME NAMES ONE ACT PER RESIDUE"; "IT
//! ANSWERS THE REQUESTER's OWN USAGE BESIDE THEM"; the register M-I5 (c),
//! M-I2 (e), M-I6 (a), (b)): one read of the asking principal's OWN records
//! — its standing deposits (hash, size, expiry; a live lease over a file
//! that is not there marked LAPSED, at this read as at the `insert`), its
//! standing uploads (identifier, the offset a resume continues from, the
//! length, the expiry), its usage as two figures — the BASE, the cell
//! index's number for its account (the distinct hashes its cells name, at
//! their size), and its PENDING bytes (its live leases on hashes none of
//! its cells names, and its uploads' bytes received) — the limits
//! record's address as installed, or `null` where none is — and THE
//! PER-ACCOUNT LIMIT IN FORCE, `per_account`, whatever its source: the
//! daemon's default where no record is installed, echoed as a written
//! limit is, so R68's read-before-refusal holds under the default (P37; the
//! register M-I6 (b), (d)); `null` only where a written record sets none.
//!
//! NO SURFACE OF ITS OWN (m-Q10, RULED): it is the resumable PUT's own
//! state made readable, served on the upload's path family (`GET
//! /blob/upload`, `server/blob_routes.rs`) and priced with the transport
//! delta. It is keyed to the asking principal's own record and never to a
//! file's presence beyond that record's live lease: it lists no deposit of
//! another's, and answers "this board holds these bytes" of nothing a
//! principal did not deposit itself. Its base is one of the index's three
//! readers: the route refuses it `index_rebuilding` until the walk at open
//! completes (ms5-R). The sweep-3 subtraction of this read was DECLINED
//! (sm-Q10): the records exist for the resume and the binding, and the
//! listing is this one function over them.

use serde_json::Value;
use skep_namespace::PrincipalId;

use super::gate::MediaGate;
use crate::codec::obj;

/// The read, as its JSON object, off `media_gate`, the media gate whose store
/// holds the records. The caller has read the index's readiness: the base
/// here is the index's number.
pub(crate) fn deposit_read(media_gate: &MediaGate, principal: PrincipalId) -> Value {
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
