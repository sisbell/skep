# skep-cli — the `skep` command, and the dev binary `skep-dev`

The command over `skep-client` (`client.md` §1.2, §2), thirteen commands:
`keygen`, `claim`, `session`, `fingerprint`, `verify`, `health`, `bind`,
and the ceremonies `enroll`, `recover`, `retire`, `rotate`, `handoff`,
`accept`. Flag parsing by hand, one file per command, a `Person` over the
terminal, stdout DATA and stderr TALK, §2.3's exit codes (0 done, 1 the
board refused, 2 usage, 3 halt and surface, 4 transport).

`skep --help` lists each command's flags. The person doors, which refuse
without a controlling terminal, and how the files fit are in the
workspace's `ARCHITECTURE.md` §The command. The default store is
`~/.skep/` on every platform (`--dir`, `SKEP_KEYSTORE`). `tls` is on by
default here; the sidecar image builds `--no-default-features --bin skep`.

Beside it the crate builds `skep-dev`, a dev binary over the same
plumbing with two verbs. `skep-dev seed` dials a RUNNING board the
person started per `RUNBOOK.md` §3 and claimed with `skep claim`, opens
one content-scoped signed session under the person's key, and fills the
board from a git checkout of prose at a pinned commit (`--repo`, or
`SKEP_SEARCH_CORPUS`; `--pin`, default the search budgets' `b17656e9`):
the documents `skep-corpus` cuts (`--documents`, default 1000; `--from` a
subtree) as editions a guest reads, the backticked `.md` cites among them
as citation links — a ghost document where the cited file is outside the
set — a second version of every k-th document (`--versions`, default 20;
a paragraph appended, a paragraph removed, a sentence changed, in
rotation), drafts past the tier (`--drafts`, default 10) with the first
windowed by the first edition, and a keyless second account with a draft
the claimant cannot read. One JSON object on stdout; a manifest beside the
key store (`<store>-seed/<chain>.jsonl`) makes a second run add nothing
and a killed run resume.

`skep-dev serve` is THE DEV PROVIDER: the shell's core (`skep-shell`)
served to a page in a browser over loopback HTTP and server-sent events —
`POST /bridge/<call>` for the twenty-two calls of `client.md` §4b.1
(`{result}` or `{refused}` back, HTTP 200 either way; a 4xx is the
provider's own refusal), `GET /bridge/events` for the seven events of
§4b.2 (`event:` and
`data:` lines, a `:ka` comment every fifteen seconds), `POST /bridge/answer`
and `/bridge/cancel` for a moment's two answers, `GET /bridge/log` (every
call the page made and every dial the provider made), `GET /bridge/shapes`
(the TypeScript declarations), `POST /bridge/script` (the next answer of a
call armed as a named refusal, an event fired by hand), and `POST
/bridge/fetch`, which streams a blob's bytes. ONE page origin is admitted
(`--page-origin`, required): every request's `Origin` must equal it,
`Host` must name the listen address (`--listen`, default 8742), the peer
must be loopback, and the per-run secret — `--secret`, else generated and
printed once on stdout — must ride the `Skep-Provider` header, or the
event stream's URL as `?provider=<secret>`, since an `EventSource` sends no
custom header (unverified here); the CORS answer names the one origin and
never `*`. The session is `--session bare` as the principal (`--principal`,
default 1) on the permissive board, or `--session signed` with the dev key
in `--dir`; `~/.skep` is never consulted, and a bare run without `--dir`
takes a throwaway directory under the system temp dir. `--script <file>`
answers the SECRET and CONSENT moments from a script (`skep-shell`'s
grammar); absent, the auto arm answers and says so on stderr. The board is
`--board`, a daemon already running, or — in a build with the `dev-hooks`
feature, which no shipped build enables — `--own --data-dir <dir> [--port
<p>]`, the daemon run in-process with its test hooks and its fault doors at
`POST /bridge/fault/<door>` (`write_busy`, `scan_busy`, `fetch_busy`,
`release`, `refuse_next_head`, `hold_feed_walk`, `release_feed_walk`,
`media_free_space`, `panic_checkpoint_thread`). The provider stops cleanly
when stdin closes (sessions closed, the index saved), exit 0; exit 2 is
usage, exit 3 a halt before serving.

The thirteen commands stand: the dev binary is no command of `skep`, and
the sidecar image, built `--no-default-features --bin skep`, holds none of
it and no `skepd` (the default build neither: `dev-hooks` alone links the
daemon, which `scripts/gate-full.sh`'s isolation line and
`tests/it/serve.rs` hold).
