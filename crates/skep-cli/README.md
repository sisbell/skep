# skep-cli — the `skep` command, and the dev binary `skep-dev`

The command over `skep-client` (`client.md` §1.2, §2), thirteen commands:
`keygen`, `claim`, `session`, `fingerprint`, `verify`, `health`, `bind`,
and the ceremonies `enroll`, `recover`, `retire`, `rotate`, `handoff`,
`accept`. Flag parsing by hand, one file per command, a `Person` over the
terminal, stdout DATA and stderr TALK, §2.3's exit codes (0 done, 1 the
board refused, 2 usage, 3 halt and surface, 4 transport).

`skep --help` lists each command's flags, and Settings, below, every
value the two programs run with — its variable, its default and where it
is read. The person doors, which refuse without a controlling terminal,
and how the files fit are in the workspace's `ARCHITECTURE.md` §The
command.

Beside it the crate builds `skep-dev`, a dev binary over the same
plumbing with two verbs. `skep-dev seed` dials a RUNNING board the
person started per `RUNBOOK.md` §3 and claimed with `skep claim`, opens
one content-scoped signed session under the person's key, and fills the
board from a git checkout of prose at a pinned commit (`--repo`, or
`SKEP_SEARCH_CORPUS`; `--pin`, by default the search budgets' commit):
the documents `skep-corpus` cuts (`--documents`; `--from` a subtree) as
editions a guest reads, the backticked `.md` cites among them as citation
links — a ghost document where the cited file is outside the set — a
second version of every k-th document (`--versions`; a paragraph
appended, a paragraph removed, a sentence changed, in rotation), drafts
past the tier (`--drafts`) with the first windowed by the first edition,
and a keyless second account with a draft the claimant cannot read. One
JSON object on stdout; a manifest beside the key store
(`<store>-seed/<chain>.jsonl`) makes a second run add nothing and a
killed run resume. The first run fixes the seed: the manifest's header
records the board, the account, the principal, the pin, the cut rule,
`--from` and the three counts, and a later run naming any other is
refused, naming each difference — a different seed takes a fresh board. A
resume makes again the one write the killed run had in flight — an
envelope id holds within one session alone — so a mint or a shot that
had landed lands twice, which the resumed run says as it opens the
manifest; where the board's exact shape matters, seed a fresh board
instead. A run that stops inside a write names it ahead of its halt, and
whether its frame was in flight; the resume names it again as it makes
it, so the two runs' stderr join on its envelope id. On stderr the seed
also names the board, the session's principal, account and key — the
fingerprint the board testifies each write by — each stall the board's
`write_busy` puts it through (as it begins, then at most once per ten
seconds), and at its end the frames sent and retried, the commits landed
since the run read its position, and the manifest lines this run
recorded.

`skep-dev serve` is THE DEV PROVIDER: the shell's core (`skep-shell`)
served to a page in a browser over loopback HTTP and server-sent events —
`POST /bridge/<call>` for the twenty-two calls of `client.md` §4b.1
(`{result}` or `{refused}` back, HTTP 200 either way; a 4xx is the
provider's own refusal), `GET /bridge/events` for the seven events of
§4b.2 (`event:` and `data:` lines, a `:ka` comment every fifteen seconds),
`POST /bridge/answer` and `/bridge/cancel` for a moment's two answers,
`GET /bridge/log` (every call the page made and every dial the provider
made), `GET /bridge/shapes` (the TypeScript declarations), `POST
/bridge/script` (the next answer of a call armed as a named refusal, an
event fired by hand), and `POST /bridge/fetch`, which streams a blob's
bytes. ONE page origin is admitted (`--page-origin`, required): every
request's `Origin` must equal it, `Host` must name the listen address
(`--listen`), the peer must be loopback, and the per-run secret must ride
the `Skep-Provider` header, or the event stream's URL as
`?provider=<secret>`, since an `EventSource` sends no custom header
(unverified here); the CORS answer names the one origin and never `*`.
The secret is `--secret`, one or more of `A-Z a-z 0-9 - . _ ~` — the
characters the page's URL and header carry unchanged — a fixed one
keeping the page's URL across restarts; else one is generated anew each
run. Either way it is printed once on stdout, its one carrier, no stderr
line naming it; and a command line is visible to every user of this
machine (`ps`), so where others use it, let the provider generate the
secret. The session is `--session bare` as the principal (`--principal`)
on the permissive board, or `--session signed` with the dev key in
`--dir`; `~/.skep` is never consulted, a key file (`--key`, `SKEP_KEY`) is
refused, and a bare run without `--dir` takes a throwaway directory under
the system temp dir. `--script <file>` answers the SECRET and CONSENT
moments from a script (`skep-shell`'s grammar), read once, at start —
an edit to it takes a restart, as the arm's start line says; absent, the
auto arm answers and says so on stderr. The board is `--board`, a daemon
already running, or — in a build with the `dev-hooks` feature, which no
shipped build enables — `--own --data-dir <dir> [--port <p>]`, the daemon
run in-process with its test hooks and its fault doors at `POST
/bridge/fault/<door>` (`write_busy`, `scan_busy`, `fetch_busy`,
`release`, `refuse_next_head`, `hold_feed_walk`, `release_feed_walk`,
`media_free_space`, `panic_checkpoint_thread`, `halt_writes`, `poison`).
The provider stops cleanly when stdin closes — Ctrl-D at a terminal —
saying why it stopped and what the run came to (the connections accepted,
the refusals by kind; sessions closed, the index saved — the stop's
seconds once it completes — the in-process daemon stopped, the throwaway
store removed), exit 0; an interrupt (Ctrl-C) ends it with none of that:
its sessions live at the board until it restarts, and a throwaway store
stays in place. Exit 2 is usage, exit 3 a halt before serving. A request
the provider refuses itself — a page from another origin, a wrong host,
no secret — is said on its stderr the first time each kind is met, with
the route it was met at, since a browser shows the page an origin refusal
only as a CORS failure, and every one is counted to the stop.

The thirteen commands stand: the dev binary is no command of `skep`, and
the sidecar image, built `--no-default-features --bin skep`, holds none of
it and no `skepd` (the default build neither: `dev-hooks` alone links the
daemon, which `scripts/gate-full.sh`'s isolation line and
`tests/it/serve.rs` hold).

## Settings

Every value the two programs run with, each read once per run: a change
takes the next run, and nothing re-reads one mid-run. A flag beats its
variable; a variable set empty is unset, and one whose value is not UTF-8
text is refused; a flag given an empty value, or another flag where its
value stands, is refused. Each refusal is exit 2, before any socket opens.
`src/args.rs`'s unit tests hold every flag below to the grammar that takes
it and every default to its constant, and `tests/it/tidy.rs` holds every
variable the source reads to a row here.

### `skep`

| setting | variable | default | checked | read at | what it sets |
|---|---|---|---|---|---|
| `--board` | `SKEP_BOARD` | none | a canonical origin, as the command reads it | every command but `keygen` and `fingerprint`; asked at `accept` where absent | the board; the store keys each binding by the origin as written, so `localhost` is another board than `127.0.0.1` |
| `--dir` | `SKEP_KEYSTORE` | `~/.skep`, under `HOME`, else `USERPROFILE` | the home an absolute path, else refused | every command but `health`, `claim --hosted` and `session --close` | the key store: `keys/` (each file 0600, the directory 0700), `bindings` and `lock`; `skep-dev seed`'s manifest in `<store>-seed/` beside it |
| `--key` | `SKEP_KEY` | none | the file, as the command reads it; an anchor's file refused where the key signs | `session`, `verify`, `bind`, `fingerprint`, `accept --reprint`; refused at `enroll` and `retire` | one key file, bypassing the store's lookup; at `fingerprint`, the one key listed |
| `--principal` | `SKEP_PRINCIPAL` (`skep-mcp` reads it too) | the store's one binding at the board; at `bind`, the reply's; at `claim`, `1` | an integer from 0 to 2^53 − 1, as the command reads it | `session`, `verify`, `enroll`, `recover`, `retire`, `rotate`, `handoff`, `bind`, `claim` | the principal; at `claim`, the new account's id |
| `--json` | — | off | — | `verify`, `health`, `fingerprint` | one JSON document on stdout |
| — | `SKEP_SESSION` | none | a session token, 32 lowercase hex | `session --close -` alone | the token to end; stdin is then not read |
| — | `HOME`, else `USERPROFILE` | — | an absolute path | where `--dir` and `SKEP_KEYSTORE` are absent | where the default store lives |
| — | `COMPUTERNAME`, `HOSTNAME` | `this-machine` | — | at an anchor's name box | the box's default name, beside today's date: the first that answers of the two, `/etc/hostname` and `hostname` on `PATH`, cut at its first dot and lowercased |

`--version`'s commit is the build's `SKEP_GIT_SHA`, compiled in:
`unknown` where the build set none, as a developer's own `cargo build`
does; `scripts/release-pack.sh` sets it for a release, and the
Dockerfile's builder from its `REVISION` build argument. `tls` is on by
default; the sidecar image builds `--no-default-features --bin skep`
without it, and an `https://` board is then a transport halt that names
the feature.

### `skep-dev`

| setting | variable | default | checked | read at | what it sets |
|---|---|---|---|---|---|
| `--board` | `SKEP_BOARD` | none | a canonical origin, before any socket opens | `seed`; `serve` without `--own` | the board dialed |
| `--dir` | `SKEP_KEYSTORE` | at `seed`, `~/.skep`; at `serve`, none — required under `--session signed`, else a throwaway under the system temp dir, removed at the clean stop | as `skep`'s | `seed`, `serve` | the key store; at `seed`, its manifest beside it |
| `--key` | `SKEP_KEY` | none | the file, an anchor's refused | `seed`; refused at `serve` | one key file, bypassing the store's lookup |
| `--principal` | `SKEP_PRINCIPAL` | at `seed`, the store's one binding at the board; at `serve`, `1` | an integer from 0 to 2^53 − 1 | `seed`, `serve` | the principal the session opens as |
| `--repo` | `SKEP_SEARCH_CORPUS` (`skep-search`'s budgets read it too) | none: required | a directory, then the corpus readable at the pin, before any socket opens | `seed`, through `git` on `PATH` | the checkout the corpus is cut from |
| `--pin` | — | `b17656e9` | the corpus readable at it | `seed` | the commit read |
| `--from` | — | the whole set (`cut-v1`) | — | `seed` | a subtree the cut reads alone, the rule then `cut-v2` |
| `--documents` | — | `1000` | a count of at least one | `seed` | the documents cut as editions |
| `--versions` | — | `20` | a count of at least one | `seed` | a second version of every k-th document |
| `--drafts` | — | `10` | a count of at least one | `seed` | the drafts past the tier, the first windowed |
| `--page-origin` | — | none: required | a canonical origin | `serve` | the one page origin admitted |
| `--session` | — | none: required | `bare` or `signed` | `serve` | the session mode |
| `--listen` | — | `8742` | a port from 1 to 65535 | `serve` | the provider's loopback port |
| `--secret` | — | one generated anew each run | one or more of `A-Z a-z 0-9 - . _ ~` | `serve` | the admission secret |
| `--script` | — | the auto arm | read and parsed once, at start | `serve` | the dev arm's answers |
| `--own` | — | off | a `dev-hooks` build; never beside `--board` | `serve` | the daemon run in-process |
| `--data-dir` | — | none: required with `--own` | — | `serve --own` | the in-process daemon's board directory |
| `--port` | — | `8642`; `0` a free port, named on stderr | a port | `serve --own` | the in-process daemon's port |
| `--no-local-trust` | — | local trust on | — | `serve --own` | local trust off |
| — | `TMPDIR` | the system temp dir | — | `serve` without `--dir` | where the throwaway store is made |

Not settings: the pins, carded constants a rebuild alone moves, each
stated once at its home — the payload cap (`MAX_PAYLOAD_BYTES`,
`src/commands.rs`) and the echo bound (`CLIPPED_CHARS`, `src/shared.rs`);
`skep-client`'s dial bounds (`CONNECT_TIMEOUT`, `IO_TIMEOUT`); the seed's
insert frame and its retry (`INSERT_CHUNK`, `WRITE_BUSY_BACKOFF_FIRST`,
`WRITE_BUSY_BACKOFF_CAP`, `WRITE_BUSY_PATIENCE`, `STALL_SAID_EVERY`,
`src/dev/board.rs`); and the provider's socket timeouts, request caps and
keep-alive (`src/dev/serve/http.rs`), its accept pause (`ACCEPT_PAUSE`,
`src/dev/serve.rs`) and its loopback-only bind.
