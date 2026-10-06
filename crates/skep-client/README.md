# skep-client

The library every acting skep client embeds — the `skep` command, the
bundled app's shell, the attendant. Its design is `client.md` in the
skep-ux-design repository (lane 5.1a); its rules are the AUTH spec's, cited
by id in every doc comment. How its modules fit, and the rules that cross
them, are in the workspace's `ARCHITECTURE.md` §The client.

## What it holds

The reading half, in every build:

| module | holds |
|---|---|
| `origin` | the canonical web origin, this crate's own reproduction of the daemon's grammar (AUTH-4.2), held equal to it by a vector-agreement test |
| `address` | the address grammar over the wire's dotted spelling: an account's parent, first child and doc 1, the document an address lies in, the parse into `skep_address`'s `Address` |
| `dial` | the one outbound `Dialer` and its plain-HTTP arm — one `TcpStream` per request, `Connection: close`, `Content-Length` checked, no redirects, no proxy environment — with a streamed form; `https://` behind the `tls` feature |
| `halt` | the one error family — `Halt`, `Refused`, `Blocked`, `Dial` — and the exit codes |
| `board` | `Board { dialed, signed, dialer }`: the wire's endpoints, the token-free registry reads, `H.1`'s pair, every token-bearing dial through one `authed` exchange, the one reader of `Skepd-Session: closed`; `board::frames`, every frame the crate sends |
| `derive` | the pure derivations over board reads: the mode, AUTH-5.65's pre-check, the three-state key diagnosis at the set AUTH-5.21's walk reaches, the `closed` predicate; behind `acting`, `derive::records`, the one admitted read of an account's credential records |

Behind `acting`:

| module | holds |
|---|---|
| `sign` | the `Signer` seam over `skep_signature::HybridSigner`; the session payload under both versioned layouts (AUTH-6.4) and a credential record's `record` frame |
| `sheet` | the key file's one JSON spelling and its refusals (`KeyFileError`), the R42 grouping, the sheet's field list |
| `store` | the `KeyStore` seam and `FileStore`: plain files with modes, the append-only bindings file in its two line forms, the lock; and the halts the store's refusals render as |
| `person` | the `Person` seam — SECRET, CONSENT and PUBLIC moments as types; behind `test-hooks`, `person::scripted`, the scripted person a test drives |
| `verify` | the reader's verifier: a committed signature judged against the signature-filtered key set as of the entry's base |
| `resolve` | `skep_resolve::Transport` over this crate's dialer |
| `ceremony` | the compositions every ceremony runs over — `handshake`, `deposit`, `first_session`, `backup`, `trail` public, the rest the crate's own — and the walks over them: `claim` (the notebook walk and the hosted arm), `enroll`, `recover` (the device and loss arms), `retire`, `rotate`, `handoff`, `accept` |

## Features

- `acting` (default on) — the acting half: `sign`, `store`, `ceremony`,
  `person`, `sheet`, `verify`, `resolve`. It alone turns `skep-signature`'s
  `sign` on; a daemon embedding the dialer takes this crate with
  `default-features = false` and holds no signer.
- `tls` (default off) — `https://` through rustls and the platform verifier;
  the `skep` binary turns it on.
- `test-hooks` (default off) — implies `acting`; `person::scripted`, the
  test support a suite drives a walk with. Every test build turns it on
  through the dev-dependencies; no shipped build does.

No async runtime, no HTTP crate, no argument-parsing crate.
