//! The crate's one integration-test target: the suites below are modules of
//! this binary, so the gate links these tests once. Each spawns skepd
//! IN-PROCESS on an ephemeral port and drives THE BUILT `skep` BINARY
//! through its argv, stdin and stdout.

mod cli;
mod common;
