//! The crate's one integration-test target: every suite below is a module of
//! this binary. Each spawns skepd in-process and drives the built `skep`
//! binary through its argv, stdin and stdout.

mod ceremonies;
mod cli;
mod common;
