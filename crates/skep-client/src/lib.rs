//! # skep-client — the library every acting client embeds
//!
//! The design is `client.md` (the skep-ux-design repo, lane 5.1a): what a
//! person's own client — the `skep` command, the bundled app's shell, the
//! attendant — needs to claim a board, open a signed session, keep its keys
//! and check what a board holds for it, and nothing a frontend needs. The
//! modules are §1.1's table, one each, listed bottom-up; `ARCHITECTURE.md`
//! §The client draws how they fit and the rules that cross them.
//!
//! The READING half, in every build — all a daemon embedding the dialer
//! takes:
//!
//! * [`origin`] — the canonical web origin, this crate's OWN reproduction of
//!   the daemon's grammar (AUTH-4.2; AUTH RES-61) under a vector-agreement
//!   test over the daemon's own admitted and refused strings (P5).
//! * [`address`] — the address grammar over the wire's dotted spelling: an
//!   account's parent, first child and doc 1, the document an address lies
//!   in, the parse into `skep_address`'s `Address`.
//! * `hex` (private) — lowercase hex, the one spelling every hex this crate
//!   emits takes.
//! * [`dial`] — the ONE outbound dialer (`Dialer`) and its plain-HTTP arm:
//!   one `TcpStream` per request, `Connection: close`, `Content-Length`
//!   checked, no redirects, no proxy environment (wire.md §Transport); the
//!   streamed form for the blob routes and `/events`; `https://` behind the
//!   `tls` feature.
//! * [`halt`] — the one error family: `Halt`, `Refused`, `Blocked`, `Dial`,
//!   with §2.3's exit codes as the binary's mapping (AUTH-5.66).
//! * [`board`] — `Board { dialed, signed, dialer }`: the wire's endpoints,
//!   every token-bearing dial through ONE `authed` exchange, the one reader
//!   of `Skepd-Session: closed` (P28), and `H.1`'s pair read once per board
//!   (D13); its child `frames` spells every frame this crate sends.
//! * [`derive`](mod@derive) — the pure derivations over board reads: the
//!   MODE off `/health`'s pair (AUTH-5.86), AUTH-5.65's pre-check, the
//!   three-state key diagnosis at the set AUTH-5.21's walk reaches
//!   (AUTH-4.30 (i)), the principal of an address (AUTH-6.37), AUTH-5.66's
//!   `closed` predicate, and — behind `acting` — `derive::records`, the one
//!   admitted read of an account's credential records (AUTH-5.68,
//!   AUTH-2.113).
//!
//! Behind the default-on `acting` feature — everything that signs or holds a
//! key:
//!
//! * [`sign`] — the `Signer` seam over `skep_signature::HybridSigner`, and
//!   the bytes a signer signs: the session payload under `SESSION_TAG` /
//!   `SESSION_TAG_V2` (AUTH-6.4) and a credential record's `record` frame.
//! * [`sheet`] — the key file's one JSON spelling and its refusals,
//!   `KeyFileError` (§3.2), the R42 grouping (AUTH-5.1) and the sheet's
//!   field list (AUTH-5.38).
//! * [`store`] — the `KeyStore` seam and `FileStore` (§3), and the halts the
//!   store's refusals render as (AUTH-5.67).
//! * [`person`] — the `Person` seam: the human moments in three classes,
//!   SECRET, CONSENT and PUBLIC, as types; behind `test-hooks`,
//!   `person::scripted`, the scripted person a test drives.
//! * [`verify`] — the READER's verifier: a committed signature judged against
//!   the signature-FILTERED key set as of the entry's base (AUTH-2.94;
//!   D14), a pure function of its caller's reads.
//! * [`resolve`] — `skep_resolve::Transport` over this crate's dialer.
//! * [`ceremony`] — the ceremonies in two layers: the COMPOSITIONS every
//!   walk runs over (P28) — `handshake`, `deposit`, `first_session`,
//!   `backup`, `payload`, `preview`, `enumerate`, `trail`, `import`, `reads`
//!   — and the WALKS over them — `claim`, `enroll`, `recover`, `retire`,
//!   `rotate`, `handoff`, `accept`. A walk names compositions and never
//!   another walk.
//!
//! No async runtime, no HTTP crate, no argument-parsing crate (§1.1's
//! dependency paragraph). The fence (§1.1): this crate reads no content save
//! the credential records the admitted read names and `H.1`'s pair;
//! `Board::op` is a general frame pipe for its embedders.

#![forbid(unsafe_code)]

pub mod address;
pub mod board;
pub mod derive;
pub mod dial;
pub mod halt;
pub mod origin;

mod hex;

#[cfg(feature = "acting")]
pub mod ceremony;
#[cfg(feature = "acting")]
pub mod person;
#[cfg(feature = "acting")]
pub mod resolve;
#[cfg(feature = "acting")]
pub mod sheet;
#[cfg(feature = "acting")]
pub mod sign;
#[cfg(feature = "acting")]
pub mod store;
#[cfg(feature = "acting")]
pub mod verify;

pub use board::{Board, Health, KeySet, Token};
pub use dial::{DialError, Dialer, PlainHttp, Request, Response};
pub use halt::{Blocked, Face, Halt, Refused};
pub use origin::{NotCanonical, Origin};

/// The auto-traits this crate promises without saying so: a shell holds a
/// `Board` across threads, and a halt crosses to whichever thread reports
/// it. A private field that revoked either would compile here and break an
/// embedder's build naming nothing — so it fails to compile here instead.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Board>();
    assert_send_sync::<Halt>();
    assert_send_sync::<PlainHttp>();
    assert_send_sync::<Origin>();
};
