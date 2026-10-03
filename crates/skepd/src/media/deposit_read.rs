//! THE DEPOSIT READ (media lane B; `media.md` Op inventory 1, "THE DEPOSITOR
//! CAN READ THEIR OWN DEPOSIT RECORD, AND THE RESUME NAMES ONE ACT PER
//! RESIDUE"; "IT ANSWERS THE REQUESTER's OWN USAGE BESIDE THEM"; the
//! register M-I5 (c), M-I2 (e)): one read of the asking principal's OWN
//! records — its standing deposits (hash, size, expiry; a live lease over a
//! file that is not there marked LAPSED, at this read as at the `insert`),
//! its standing uploads (identifier, the offset a resume continues from,
//! the length, the expiry), its usage as two figures (the BASE, zero at
//! lane B — the cell index is lane C's — and its PENDING bytes), and the
//! limits record's address as installed, or `null` where none is.
//!
//! NO SURFACE OF ITS OWN (m-Q10, RULED): it is the resumable PUT's own
//! state made readable, served on the upload's path family (`GET
//! /blob/upload`, `server/blob_routes.rs`) and priced with the transport
//! delta. It is keyed to the asking principal's own record and never to a
//! file's presence beyond that record's live lease: it lists no deposit of
//! another's, and answers "this board holds these bytes" of nothing a
//! principal did not deposit itself. The sweep-3 subtraction of this read
//! was DECLINED (sm-Q10): the records exist for the resume and the binding,
//! and the listing is this one function over them.

use serde_json::Value;
use skep_namespace::PrincipalId;

use super::gate::MediaGate;
use crate::codec::obj;

/// The read, as its JSON object.
pub(crate) fn deposit_read(gate: &MediaGate, principal: PrincipalId) -> Value {
    let key = MediaGate::key(principal);
    let now = gate.now_ms();
    let store = gate.store();
    let deposits: Vec<Value> = store
        .leases_of(&key, now)
        .into_iter()
        .map(|l| {
            // Exact of what is on disk: a lease over a file that is absent
            // or not whole reads as LAPSED here as at the insert.
            let whole = store.blob_len(&l.designation, &l.hex) == Some(l.size);
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
    let limits = gate.limits();
    obj(vec![
        // The base is journal-derived and zero until the cell index (lane
        // C) counts the account's distinct hashes.
        ("base", Value::Number(0u64.into())),
        ("deposits", Value::Array(deposits)),
        ("limits", limits.address.map_or(Value::Null, Value::String)),
        ("pending", Value::Number(store.pending_bytes(&key, now).into())),
        ("uploads", Value::Array(uploads)),
    ])
}
