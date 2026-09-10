//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Nothing but module declarations belongs here.

mod auth_wire;
mod authz;
mod cascade;
mod changes;
mod client;
mod codec_roundtrip;
mod common;
mod cors;
mod dedup_class;
mod events;
mod feed_class;
mod fuzz_codec;
// Shared plumbing, not a suite: each fuzz suite uses a subset, so the allow
// that was this file's own crate-level attribute rides its `mod` line here.
#[allow(dead_code)]
mod fuzz_common;
mod fuzz_envelope;
mod fuzz_http;
mod h1_residue;
mod hazard;
mod history;
mod http_lifecycle;
mod nullify_class;
mod ownership;
mod properties;
mod publication_reads;
mod publish;
mod read_surface;
mod register;
mod restart;
mod scan_bound;
mod source_gate;
mod transport;
mod vectors;
mod version_chain;
mod wire_doc;
