//! The ceremonies (`client.md` §1.1's `ceremony` row): the claim as a state
//! machine — the notebook walk (§4.1) and the hosted arm (§4.5) — the
//! compositions every later ceremony runs over (P28), each ONE in-crate home
//! holding its frames, its reads, its armed refusals and its order, every
//! site stating only what it adds, and the ceremonies over them:
//!
//! * [`handshake`] — the one session-open composition: AUTH-5.65's pre-check
//!   ahead of the `/challenge`, the challenge with its `ttl_ms` read off the
//!   body, the framing by scope, the ONE re-challenge on `session_rejected`,
//!   and the three answers with their faces.
//! * [`deposit`] — the one credential-write composition: above the claim
//!   THE RECORD GRADE (the sig-less record, its `record` frame, the hand's
//!   `sig` at the act's grade), then the insert, the re-read `from`, the
//!   link, AUTH-5.6's `id`, AUTH-5.17's reconcile and the base armed set.
//! * [`first_session`] — the one first-signed-session composition
//!   (AUTH-5.90 (iii); AUTH-5.87): two states, each resumed by reading.
//! * [`backup`] — the backup moment in AUTH-5.54's order (§4.2), at its
//!   three sites (the claim, the door-side form, the handoff's recipient)
//!   and the LOSS arm's cited steps 1–3.
//! * [`preview`] — `preview(removed)`, the one retirement preview (AUTH-5.46).
//! * [`enumerate`] — the head invariant's enumeration (AUTH-5.59's head) and
//!   the by-reference cone (AUTH-5.89).
//! * [`trail`] — the supersession trail, `assert_sup` with its attest
//!   (AUTH-5.59 step 2), resumed by reading.
//! * [`import`] — the anchor import step (§4a.2 R1), never a command.
//! * [`reads`] — R0's reads, shared by the recovery family, and the A4 cell.
//! * [`enroll`] — AUTH-5.32's hop, the signed-in half (§2.2).
//! * [`recover`] — the device arm with its STOLEN order (§4a.2 R0–R6) and
//!   the LOSS arm (§4a.6 L0–L7).
//! * [`retire`] — the device-key retirement (§4a.4; §2.2).
//! * [`rotate`] — AUTH-5.59's device arm as one gesture, with its trail
//!   (§4a.8 T0–T5).
//! * [`handoff`] — the giver's walk, G0–G6 (§4c.2).
//! * [`accept`] — the recipient's beat (§4c.1).
//!
//! No journal: every walk resumes by READING the board (§4.4; P4).

pub mod accept;
pub mod backup;
pub mod claim;
pub mod deposit;
pub mod enroll;
pub mod enumerate;
pub mod first_session;
pub mod handoff;
pub mod handshake;
pub mod import;
pub mod preview;
pub mod reads;
pub mod recover;
pub mod retire;
pub mod rotate;
pub mod trail;

pub use backup::{backup_moment, AnchorArtifact, BackupOptions, BackupOutcome, Venue};
pub use deposit::{deposit, Deposit, DepositKind, DepositOutcome, Grade};
pub use first_session::{first_session, FirstSessionDone, FirstSessionReads};
pub use handshake::{handshake, handshake_prechecked, Session, Site};
pub use preview::{preview, Preview, PreviewSite, Previewed, Row};
