//! The ceremonies (`client.md` §1.1's `ceremony` row): the claim as a state
//! machine — the notebook walk (§4.1) and the hosted arm (§4.5) — and the
//! compositions every later ceremony runs over (P28), each ONE in-crate home
//! holding its frames, its reads, its armed refusals and its order, every
//! site stating only what it adds:
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
//! * [`backup`] — the backup moment in AUTH-5.54's order (§4.2).
//!
//! No journal: every walk resumes by READING the board (§4.4; P4).

pub mod backup;
pub mod claim;
pub mod deposit;
pub mod first_session;
pub mod handshake;

pub use backup::{backup_moment, AnchorArtifact, BackupOptions, BackupOutcome, Venue};
pub use deposit::{deposit, Deposit, DepositKind, DepositOutcome, Grade};
pub use first_session::{first_session, FirstSessionDone, FirstSessionReads};
pub use handshake::{handshake, handshake_prechecked, Session, Site};
