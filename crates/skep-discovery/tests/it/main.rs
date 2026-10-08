//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. `common` is the minimal engine assembly the
//! composition contract prescribes and the fixtures every suite shares;
//! `tidy` holds every check that reads the crate's own source — the module
//! map `src/lib.rs` declares, that every file of this tree and of `src/` is
//! declared (a suite file no `mod` line names never runs), that `home.rs`
//! alone asks the reader's predicate, that the `_on` suffix marks exactly the
//! functions over a snapshot, and that the crate doc's `## Cost` section
//! keeps its heading and names every read; each other module is one § of the
//! read surface — a family, a pair, the preview — or one law that crosses
//! them (`home_rule`, `consumer`), and the module names are the table of
//! contents. Nothing but module declarations belongs here.

mod common;

mod consumer;
mod descriptor;
mod endsets;
mod home_rule;
mod lineage;
mod pointwise;
mod region;
mod survival;
mod tidy;
mod window;
