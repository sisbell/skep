//! The crate's one integration-test target: every suite below is a module of
//! this binary. `cli` and `ceremonies` spawn skepd in-process and drive the
//! built `skep` binary through its argv, stdin and stdout; `hostile` drives
//! it with what arrives from outside the person's trust — a board's bytes, a
//! third party's reply, a payload's length; `dev` spawns and claims a board
//! and drives the built `skep-dev` against a corpus it builds under the
//! system temp dir; `merge` seeds a claimed board with a document's
//! versions by hand and drives the fourteenth command, `skep merge`,
//! against them; `share` drives the fifteenth, `skep share` — the usage
//! forms against a dead port, then the share, the revoke, the re-share, the
//! privash and the lists on a claimed board; `restore` drives the
//! sixteenth, `skep restore` — the usage forms against a dead port, then a
//! draft put back to a past state on a claimed board over the merge
//! suite's rig; `hint` drives the seventeenth, `skep hint` — a claimed
//! board's root hint printed as one line, its origins in order and its
//! realm the genesis set's, then each refusal, an unclaimed board's and a
//! scripted board's among them; `resolve` drives the eighteenth, `skep
//! resolve` — each refusal, then an address resolved against a claimed
//! board as its registry, the root hint read from its flag and from its
//! variable, the mirror kept beside the keys and the store's own files
//! untouched; `tidy` reads the crate's own source for the arrangement
//! `ARCHITECTURE.md` §The command states.

mod ceremonies;
mod cli;
mod common;
mod dev;
mod hint;
mod hostile;
mod merge;
mod resolve;
mod restore;
mod serve;
mod share;
mod tidy;
