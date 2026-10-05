# skep-client

The library every acting skep client embeds — the `skep` command, the
bundled app's shell, the attendant. Its design is `client.md` in the
skep-ux-design repository (lane 5.1a); its rules are the AUTH spec's, cited
by id in every doc comment.

## What it holds

| module | holds |
|---|---|
| `origin` | the canonical web origin, this crate's own reproduction of the daemon's grammar (AUTH-4.2), held equal to it by a vector-agreement test |
| `dial` | the one outbound `Dialer` and its plain-HTTP arm — one `TcpStream` per request, `Connection: close`, `Content-Length` checked, no redirects, no proxy environment — with a streamed form; `https://` behind the `tls` feature |
| `board` | `Board { dialed, signed, dialer }`: the wire's endpoints, the token-free registry reads, every token-bearing dial through one `authed` exchange, the one reader of `Skepd-Session: closed` |
| `derive` | the pure derivations over board reads: the mode, AUTH-5.65's pre-check, the three-state key diagnosis at the set AUTH-5.21's walk reaches, the `closed` predicate; behind `acting`, the one admitted read of an account's credential records and `H.1`'s pair |
| `halt` | the one error family — `Halt`, `Refused`, `Blocked`, `Dial` — and the exit codes |
| `sign` | the `Signer` seam over `skep_signature::HybridSigner`; the session payload under both versioned layouts (AUTH-6.4) |
| `verify` | the reader's verifier: a committed signature judged against the signature-filtered key set as of the entry's base |
| `store` | the `KeyStore` seam and `FileStore`: plain files with modes, the append-only bindings file in its two line forms, the lock |
| `sheet` | the key file's one JSON spelling, the R42 grouping, the sheet's field list |
| `person` | the `Person` seam — SECRET, CONSENT and PUBLIC moments as types — and the scripted person a test drives |
| `ceremony` | the claim (the notebook walk and the hosted arm) and the compositions every ceremony runs over: `handshake`, `deposit`, `first_session`, `backup` |
| `resolve` | `skep_resolve::Transport` over this crate's dialer |

## Features

- `acting` (default on) — the acting half: `sign`, `store`, `ceremony`,
  `person`, `sheet`, `verify`, `resolve`. It alone turns `skep-signature`'s
  `sign` on; a daemon embedding the dialer takes this crate with
  `default-features = false` and holds no signer.
- `tls` (default off) — `https://` through rustls and the platform verifier;
  the `skep` binary turns it on.

No async runtime, no HTTP crate, no argument-parsing crate.
