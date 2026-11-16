//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own. The core's socket-bound suites —
//! the session layer, the commits and the head over a served daemon — are
//! `skepd`'s (`crates/skepd/tests/it`), which spawn the daemon they drive;
//! what stands here is what reads this crate alone: the codec's round trips
//! and the layering — and the admission frame's signature, checked here
//! because this crate links the three crates it takes: the frame's syntax,
//! the request's body and the signature library. Nothing but module
//! declarations belongs here.

mod admission_frame;
mod codec_roundtrip;
mod tidy;
