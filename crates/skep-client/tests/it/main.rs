//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Nothing but module declarations belongs here.
//!
//! The suites spawn skepd IN-PROCESS on an ephemeral port over a temp data
//! dir, as skep-mcp's suite does, and drive THE LIBRARY — the walks with the
//! scripted `Person`, the compositions by their own calls; another hand is
//! the wire transcript re-driven (`common`'s `wire_*`), never a ceremony.
//! Three need no daemon: `backup`, the moment alone; `registration`, the
//! applicant's registration request — the door identifier judged first, the
//! device key named or generated, the moment's node arm, the enrolments and
//! the one signature over the frame — which reads and writes no board; and
//! `tidy`, which reads
//! the crate's own source for the arrangement it promises. `search` drives
//! the `search` module — the feature the self dev-dependency turns on —
//! over a claimed board, its fixture its own; `merge` drives the `merge`
//! module's one whole merge over a claimed permissive board; `share` drives
//! the `share` module — the share, the revoke, the re-share, the privash and
//! the lost answer — over three keyed siblings on a claimed permissive board;
//! `removals` drives the ceremonies' removals of anchor files against a
//! directory that refuses the unlink, over the loss arm, and `cut_short`
//! the face a cut-short anchor file meets at the import; `publication`
//! drives the `publication` module — the enumeration against the daemon's
//! own filter, the one request, the acknowledgment, the twin, a moved place
//! and a cut connection — over a claimed permissive board; `restore` drives
//! the `history` module — a draft put back to a past state, the records'
//! mapping across a publication, the refusals at a moved draft, a reclaimed
//! position and a marked draft — over the merge suite's rig; `hire` drives
//! the hire's owner side on an enforcing board — the standing statements
//! placed against the `delegate`, the custody pair or its decline, the
//! paste's tests, the owner's own genesis, the mint and the principal, each
//! resume, the re-hire — and beside it the agent's own sessions, a rotation
//! at the agent and the stop at an account a hire made; `well_known` drives
//! the creation of an account's well-known documents on an enforcing board
//! — each slot in its own state, the published three signed, once apiece —
//! and the refusals that reach its caller; `console` drives the registrar's
//! console and the door's policy on an enforcing board — the policy's four
//! acts at well-known document 5, the queue read from admitted homes alone,
//! the framing re-check and the refused answer, the approval in its order
//! and resumed from a stop after each write, the read-back under a lost
//! race, next-form, the denial, the unattended hand under each policy, the
//! three derived lists and a door with no policy.

mod backup;
mod claim;
mod common;
mod console;
mod cut_short;
mod enroll;
mod handoff;
mod handshake;
mod hire;
mod hosted;
mod loss;
mod merge;
mod publication;
mod recover;
mod registration;
mod removals;
mod restore;
mod retire;
mod rotate;
mod search;
mod share;
mod tidy;
mod verifier;
mod well_known;
