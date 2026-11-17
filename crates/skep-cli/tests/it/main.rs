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
//! untouched; `deposit` drives the nineteenth, `skep deposit` — on an
//! enforcing board, a node account made by the suite's own hands: the real
//! `skep bind` minting its doc 1 from its first signed session, the command
//! minting a missing home and depositing the endpoint a verifying mirror
//! reads current, a later deposit naming the one it replaces, and each
//! refusal; `hire` drives the twentieth, `skep hire` — its line read whole
//! ahead of its door, the door refused without a terminal, one run typed at
//! a pseudo-terminal from the standing statements to the agent's principal,
//! and `skep bind` refused at the account a hire made; `register` drives
//! the twenty-first, `skep register`, with no daemon at all — its line read
//! ahead of its door, the door refused without a terminal, a door
//! identifier that is none halting before anything is asked or written, one
//! fresh registration typed at a pseudo-terminal from an empty store to the
//! request on stdout, verified as a reader verifies it, the board that
//! carries on, and `skep keygen --anchors` unchanged beside it; `console`
//! drives the twenty-second to the twenty-fifth, the registrar's `skep
//! review`, `skep approve`, `skep deny` and `skep set-policy` — on an
//! enforcing board its registrar claimed, an intake home beside it writing
//! each request: the four end to end with what each prints, the three
//! person doors refused on a pipe, the unattended hand on pipes from its
//! refusal to start through its first pass to its stop between two requests
//! and its stop with an approval under way, the policy's four acts and the
//! files it refuses, and a door with no policy; `tidy` reads
//! the crate's own source for the arrangement
//! `ARCHITECTURE.md` §The command states.

mod ceremonies;
mod cli;
mod common;
mod console;
mod deposit;
mod dev;
mod hint;
mod hire;
mod hostile;
mod merge;
mod register;
mod resolve;
mod restore;
mod serve;
mod share;
mod tidy;
