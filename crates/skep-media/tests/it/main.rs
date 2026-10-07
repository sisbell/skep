//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own. The media resource's own suites —
//! the upload, the fetch, the door and the pruner over a served daemon — are
//! `skepd`'s (`crates/skepd/tests/it`), which spawn the daemon they drive;
//! what stands here is what reads this crate's source alone. Nothing but
//! module declarations belongs here.

mod tidy;
