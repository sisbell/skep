//! # skep-http — the plain HTTP/1.1 subset two programs speak
//!
//! THE SUBSET, written once: the HTTP/1.1 a program in this workspace
//! speaks over a `TcpStream` when it answers a page or a form on loopback
//! and needs nothing more. ONE REQUEST PER CONNECTION. The head is read to
//! its `\r\n\r\n` terminator under a cap and parsed — the request line, its
//! method in uppercase letters, `HTTP/1.1` or `HTTP/1.0`, one header to a
//! line; the body is read to its `Content-Length` under a cap; a
//! `Transfer-Encoding` is refused by name, so no chunked body is ever
//! decoded; and every answer — the status line, the caller's headers, the
//! content type and length where known, `Cache-Control: no-store`, the
//! body — says `Connection: close`, the caller closing the stream behind
//! it. Both caps are the caller's, handed in at the read ([`Limits`]).
//!
//! WHO CALLS IT: the dev provider (`skep-dev serve`, a binary of
//! `skep-cli`), which serves the shell's core to a page in a browser, today;
//! and the provisioning service, which serves its sign-up form, next. The
//! daemon's own reader stays the daemon's (`skepd`'s `server/http.rs`, the
//! pattern the provider's copy followed): it carries sessions, the event
//! stream and a cap per route, and calls nothing here.
//!
//! * `read` — [`read_request`], the one read, under [`Limits`]; the
//!   [`Request`] it answers, with [`Request::header`] and
//!   [`Request::query_value`]; and [`Refused`], the subset's refusal or a
//!   body past the cap, whose words the caller answers with;
//! * `write` — [`write_response`], one whole answer, and [`write_head`],
//!   the head alone, for a caller that streams the body after it.
//!
//! ## The rule of membership
//!
//! An item lives here if and only if it is the plain subset: the request
//! read and the answer written as any program serving one request per
//! connection reads and writes them. What one caller alone speaks stays
//! that caller's — no CORS header (which page a program admits is its own
//! policy), no event stream (a framing the dev provider alone speaks), and
//! no cap VALUE: a cap is the caller's configuration, as `skep-util`'s rule
//! says of its own — "A constant is configuration, not a utility" — so
//! [`Limits`] has no default. The crate names nothing of skep and depends
//! on `std` alone, so a program takes it without taking anything else.
//! That rule is why the subset is a crate of its own and not a `skep-util`
//! module: `skep-util` holds what BOTH `skepd` and `skep-media` take and
//! what has no subject of its own, and this subset's callers are two other
//! programs, and its subject is HTTP.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod read;
mod write;

pub use read::{read_request, Limits, Refused, Request};
pub use write::{write_head, write_response};
