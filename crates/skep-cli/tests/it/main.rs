//! The crate's one integration-test target: every suite below is a module of
//! this binary. `cli` and `ceremonies` spawn skepd in-process and drive the
//! built `skep` binary through its argv, stdin and stdout; `hostile` drives
//! it with what arrives from outside the person's trust — a board's bytes, a
//! third party's reply, a payload's length; `tidy` reads the crate's own
//! source for the arrangement `ARCHITECTURE.md` §The command states.

mod ceremonies;
mod cli;
mod common;
mod hostile;
mod tidy;
