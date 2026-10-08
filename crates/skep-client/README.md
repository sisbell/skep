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
| `dial` | the one outbound `Dialer` and its plain-HTTP arm — one `TcpStream` per request, `Connection: close`, `Content-Length` checked, no redirects, no proxy environment — with a streamed form; `https://` behind the `tls` feature; a dialer behind a reference, a box or an `Arc` is itself a `Dialer`, so one is shared by a `Board` and the resolver's transport |
| `halt` | the one error family — `Halt`, `Refused`, `Blocked`, `Dial` — and the exit codes |
| `board` | `Board { dialed, signed, dialer }`, its origins read through `Board::dialed` and `Board::signed`: the wire's endpoints, the token-free registry reads, `H.1`'s pair, every token-bearing dial through one `authed` exchange, the one reader of `Skepd-Session: closed`, every token-free read through `Board::guest`, which halts on that signal; `board::frames`, every frame the crate sends; `Rejection::key`, the one token a refusal is dispatched on |
| `derive` | the pure derivations over board reads: the mode, AUTH-5.65's pre-check, the three-state key diagnosis at the set AUTH-5.21's walk reaches, the `closed` predicate; behind `acting`, `derive::records`, the one admitted read of an account's credential records |

Behind `acting`:

| module | holds |
|---|---|
| `sign` | the `Signer` seam over `skep_signature::HybridSigner` — `Send + Sync`, lending its public key, a signer behind a box or a reference being one; the session payload under both versioned layouts (AUTH-6.4) and a credential record's `record` frame, `RecordFrame` |
| `sheet` | the key file's one JSON spelling and its refusals (`KeyFileError`), the byline `Label` and its domain, the `Seed` every secret is born into, the R42 grouping, the sheet's field list |
| `store` | the `KeyStore` seam and `FileStore`: plain files with modes, the append-only bindings file in its two line forms, the lock — a lookup answering a key's public facts (`KeyFacts`), a stored key signing through `KeyStore::signer` alone; the halts the store's refusals render as; and `Unappended`, the warning a binding line that cannot be appended answers |
| `person` | the `Person` seam — SECRET, CONSENT and PUBLIC moments as types, a SECRET payload printing no key material; behind `test-hooks`, `person::scripted`, the scripted person a test drives |
| `verify` | the reader's verifier: a committed signature judged against the signature-filtered key set as of the entry's base |
| `resolve` | `skep_resolve::Transport` over this crate's dialer |
| `ceremony` | the compositions every ceremony runs over — `handshake`, `deposit`, `first_session`, `backup`, `trail` public, the rest the crate's own — and the walks over them: `claim` (the notebook walk and the hosted arm), `enroll`, `recover` (the device and loss arms), `retire`, `rotate`, `handoff`, `accept` |

Behind `search` (default off) — THE SHELL's HALF of search (`client.md`
§4e), over `skep-search`, a library API an embedder calls (the `skep`
command one embedder, the frontend's shell the other) and nothing that
assumes a page:

| module | holds |
|---|---|
| `search::directory` | `SearchDir`, `<data>/index/`, and `BoardDir`, `<chain>/` keyed by `H.1`'s chain: `published.index`, `principal-<n>.index`, the document index's `published.places` and `principal-<n>.places` beside them, the feeder's `lock`; the modes `0700`/`0600` set at creation, the save by `<name>.tmp` written, synced and renamed over the old, the aside by a rename that never overwrites (`aside_name`), the `flock` held for the consumer's life |
| `search::consumer` | `Consumer`, one per board: the open with the aside check and the resume (`GET /chain?at` per saved pair, the `H.k` re-read, `Resume::judge`), `poll` — the `/health` pair before the drain, the published range as a guest, each supplement's ranges and the two discovery reads under the session's token, one read per changed document per poll in parts past `MAX_DELIVERY_ITEMS`, the trunk probed where the feed names no head, a straddled draft's join held pending, bare rows counted, refusals recorded, `held` the fenced pair — the save every `SAVE_EVERY_UNITS` or `SAVE_EVERY` and at `close`, compacting where due; the triggers `widen`, `narrow`, the refresh `reindex`, `orphans` and `forget`; `state`, `counts`; `events`, the `/events` stream's commit positions as the loop's input |
| `search::places` | `Places`, the document index's one part — addresses, first lines, the head member last read at, counts per account — one JSON line per document, the exact address and label matches |
| `search::state` | `State`, the `index` event's ten arms typed — `None`, `Building`, `Widening`, `Complete`, `AtTheFloor`, `ResumedFromTheFloor`, `Unplaced`, `PastTheCeiling`, `NewerSkep`, `Busy` — and `State::compose` over the pair's parts |
| `search::bridge` | `Consumer::search(who, query, opts) → SearchAnswer {hits, total, the four flags, places, state}`: the query bounded at `QUERY_BOUND` bytes (`QueryTooLong` echoing nothing), the pair by role with the header ranges and the honored set, `places` at the call's class with a standing at the document grain; `Who::{Guest, Session(SessionRef)}`, `SearchOpts`, `Place` |
| `search::jump` | `land(span, pairs) → Landing::{Carried, Partial, Absent}` over a `compare` answer's `Correspondence`s, and `landing_of`, the three budget refusals landing `Pinned` |

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
- `search` (default off) — implies `acting`; the `search` module over the
  optional `skep-search` dependency. OFF by default so the default build
  holds no feed consumer and makes no content read (`client.md` §1.1's
  fence as written); the frontend's shell and the `skep` command's search
  turn it on, as the shell turns `tls` on. The crate's own tests turn it on
  through the self dev-dependency.

No async runtime, no HTTP crate, no argument-parsing crate.
