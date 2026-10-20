# skep-mcp

The MCP adapter: newline-delimited JSON-RPC over stdio on one side, the
shell's core — [skep-shell](../skep-shell), the engine the dev provider
and the desktop shell run on — on the other. It is how an agent runtime
speaks to a board: one process per agent, one board, ONE SIGNED SESSION
for the process's life.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

## What it does

- **A signed session, opened at startup.** Before the first tool call the
  adapter opens one content-scoped signed session for the configured
  principal with the key its store holds for it — the store's key for the
  principal, enrolled in the principal's account's set or the nearest set
  above it (a principal under a person's account signs by reference with a
  key enrolled in the person's set, until the hire ceremony lands). No
  key in the store, or a key the board refuses, stops the adapter before
  it serves, with the shell's face in plain words; no bare mode exists.
  The startup lines on stderr name every setting in force and where it
  came from, the board and its mode, the key and the account, and the
  person seam — and, for a board off this machine's loopback, the warning
  that its session's token rides in the clear unless a tunnel carries it,
  and the principal's held bursts an earlier run left at the board, or a
  held file the shell halted. Every line on
  stderr opens `skep-mcp: ` and the moment it was said: a C0 control, DEL or
  bidi control a board's text carries there is shown as its code point, and
  a line break in it continues the line indented.
- **Every tool is one call of the shell.** The wire operations of
  `docs/wire.md` §Operations are tools of their own names — the name is the
  frame's `op`, the arguments are the frame — the shell's own calls
  (`boards`, `health`, `probe`, `search`, `places`, `held`, `resolve`) are
  tools of theirs, and three are the adapter's apparatus: `session_info`,
  `changes_since` and `fetch`. The catalog an agent reads, `tools.json`
  beside `Cargo.toml`, is embedded and checked against that dispatch at
  startup.
- **A refusal as a result.** The board's verdict on a frame comes back as
  data, `isError: false`; `isError` means the shell could not get the
  board's verdict — among the causes, a board not answering and a frame the
  shell refused itself, nothing sent — or `fetch` declined a file.
- **The session's life.** A board restart is met by the shell's silent
  re-open, and the agent sees nothing. A death the shell does not re-open —
  the key retired, the prefix blocked, the account seeded, a re-open the
  board refused — stops the process with one plain line on stderr, as does
  the board's refusal of the session the adapter opens once a board that
  stopped answering answers again: the person stops an agent by retiring
  its key, and the adapter's end is what the agent's client sees. A sign-in
  the board did not accept at either open (`busy`: the board busy, or a
  third party evicting its nonces, transient either way) lapses the session
  instead, and a later call opens one. A board that stops answering once
  the adapter serves refuses each call `unreachable`, and the adapter stays
  up; one not answering at its start stops it, exit 1: start it again once
  the board answers.
- **No person at the seam.** The shell is opened with the refusing arm:
  every SECRET and CONSENT moment would be refused `person_required`, and
  no ceremony tool is offered (no `keygen`, `fingerprint`, `claim`,
  `enroll`, `bind`, `recover`, `rotate`, `retire`, `handoff`, `accept`);
  nor `upload` or `restore`, whose media walk the shell does not reach
  yet (skep #502). Nor does `search` take `opts.reindex`: the index's
  refresh, the person's act, re-reads every document the index holds while
  the call waits; the index follows the board's commits without it.
- **One call at a time.** Calls are served in arrival order, one at a time;
  a `fetch` of a large file, up to its body's deadline, or a `search` while
  the index is building holds the calls behind it, and the log says their
  wait. Stdin's end is the clean exit: the shell's stop closes the session
  at the board and saves the index, and the log says how long it took. A
  signal ends the process with neither — the session then lives on at the
  board until it restarts.
- **Deliberately dependency-light** — the shell's core, `skep-client` for
  the types the shell's surface names, the inert rendering a key's label
  and every log line take, and the plaintext warning the start says, and
  `serde_json`; the stdio framing, the log's writer, the type sniff and the
  base64 are this crate's own.

Each rule above is stated in full where its reader looks: what an agent is
told — every tool's arguments and answers, the held bursts, which refused
writes may still have committed, the fetch's cap — in the catalog's
instructions and tool descriptions (`tools.json`); the rules the code keeps,
in the crate doc (`src/main.rs`).

## Settings

Every value the adapter runs with is read once, at its start — a change
takes a restart, and nothing re-reads one mid-run — save the store's key,
which the shell selects anew at each session it opens. A flag beats its
variable, and the start says so where the variable is set beside it to
another value; a variable set empty is unset, as the `skep` command reads
the same variables; a value that is not UTF-8 text is refused by name. Each
setting's refusal is exit 1, naming the setting as it was given, and the
start's `settings:` line names every setting in force and where it came
from. `src/main.rs`'s unit suite (`src/tests.rs`) holds each row's
spelling to the parse's and the figures it states to their constants, and
`tests/it/tidy.rs` holds every variable the source reads to a row here.

| setting | variable | default | checked | said at start | read | what it sets |
|---|---|---|---|---|---|---|
| `--board` | `SKEP_BOARD` (`skep` reads it too) | none: required | a canonical `http://` origin, an `https://` one refused, before any dial; one the board signs sessions for, at the session's open (`origin_state`) | the `settings:` line; the board line; the plaintext warning, off this machine's loopback | once, at start | the board, by one of its `--origin`s as written ([RUNBOOK.md](../../RUNBOOK.md) §3), the origin the agent's key is bound at: the adapter signs for the origin it dials, so a tunnel serves only where its local end is such an origin, and a hosted board, which signs its `https://` origin alone, is out of its reach |
| `--dir` | `SKEP_KEYSTORE` (`skep` reads it too, defaulting it to `~/.skep`; this adapter never does) | none: required | a directory that stands, that this process can write, and that no other adapter holds — waited for up to 30 s — before any dial; the store's key for the principal, before serving (`no_key`, `store_unreadable`) | the `settings:` line, as an absolute path; the signed-as line; a warning where it is the person's own `~/.skep` | at start, and the store's key again at each session the shell opens | the key store — `keys/` and `bindings`, the agent's key and its binding — and beside them the shell's search index (`index/`) and held bursts (`held/`), and `skep-mcp.lock`, whose lock keeps it one adapter process's; never a running `skep-dev serve`'s, which takes no such lock: a second shell over one directory finds its index `busy` and keeps its bursts in memory alone, each said in its log. The index persists across runs, built from scratch in a fresh directory, `search` and `places` answering `state.arm` `building` meanwhile |
| `--principal` | `SKEP_PRINCIPAL` (`skep` reads it too) | none: required | an integer from 0 to 2^53 − 1, before any dial; one the board seats, at the session's open (`not_registered`) | the `settings:` line; the signed-as line | once, at start | the principal the session acts as |
| `--tools-file` | — | the embedded catalog | read whole and held to this binary's dispatch, before any other setting | the `settings:` and serving lines, by its absolute path; a line where its text differs from the embedded catalog's | once, at start | the catalog every agent is told: the instructions, and each tool's name, description and schema |
| — | `SKEP_COMMONS` | unset | the commons' address, `1.1.0.1.0.1`, alone, before any dial | the `settings:` and serving lines | once, at start | the commons sentence the server instructions end with, pointing agents at the document whose subspace 3 names every link type |
| — | `SKEPD_URL` | — | never decoded | a line where it is set | never | nothing: no longer read |
| — | `HOME`, else `USERPROFILE` | — | — | the warning, where the store is the person's own | once, at start | where the person's own store, `~/.skep`, is, which the start compares the store with |
| — | `HOSTNAME`, else `COMPUTERNAME` | `dev-machine` | — | — | at the shell's open | an anchor box's default name, which the refusing arm never asks for |

`--version`'s commit is the build's `SKEP_GIT_SHA`, compiled in: `unknown`
where the build set none, as a developer's own `cargo build` does;
`scripts/release-pack.sh` sets it for a release. `--version` and `--help`
answer before any setting or stdin is read. The process exits 0 at stdin's
end or a closed stdout, the session closed at the board; 1 at a refusal
before serving or a stop while serving; 2 at a usage error; 101 at a panic,
a bug said in one line of the log.

Not settings: the pins, carded constants a rebuild alone moves, each stated
once at its home — the fetch's cap and deadline (`MAX_FETCH_BYTES`,
`FETCH_DEADLINE`, `src/media.rs`); the wait for a session the shell ended
(`SETTLE_WAIT`, `src/shell.rs`); the slow-call bound (`SLOW_CALL`,
`src/server.rs`, skep-client's `IO_TIMEOUT`) and the revision `initialize`
answers where a client names none (`FALLBACK_PROTOCOL_VERSION`); the start's
wait for a store another adapter holds (`STORE_WAIT`, `src/main.rs`); the
log's queue, line and stall bounds (`QUEUE_BYTES`, `LINE_BYTES`,
`DRAIN_STALL`, `src/log.rs`); skep-client's dial bounds (`CONNECT_TIMEOUT`,
`IO_TIMEOUT`); and skep-shell's own.

The log is stderr: every line opens `skep-mcp: ` and the moment it was said,
RFC 3339 UTC to the millisecond, as the daemon's own lines do, and the first
names the version the run began with and its process id. The lines of the
session's life name the session by its reference, as the shell's own lines
and the refusals an agent is answered name it. A call whose wait behind the
calls read before it and its own hold of the loop together pass a dial's
read bound is said with its tool, its request's id, its wait and its hold —
a harness's timeout counts both, from the moment it sent the request — and
a stop with its own wait; the clean stop's line says what the loop answered,
how much of the run it was busy and the longest a request waited, and the
next line how long the shell's stop took, its save of the index growing
with the index. No line quotes an answer's text — the client's refusal of
an answer it cannot parse is cut at its parse error — and none runs past
four kilobytes. A harness may read the log or leave it: a reader that stops
reading never holds the adapter up — the lines it leaves are dropped, and
the next line it takes says how many went, at the moment the first of them
was said.

## Starting it from an agent app

The MCP client configuration names the binary, its arguments and its
environment — for a board at the daemon's default port, a store under
`/var/lib/agent/skep` holding the agent's key, acting as principal 7:

```json
{
  "mcpServers": {
    "skep": {
      "command": "/usr/local/bin/skep-mcp",
      "args": ["--board", "http://127.0.0.1:8642", "--dir", "/var/lib/agent/skep", "--principal", "7"],
      "env": {}
    }
  }
}
```

The same three settings may ride as `SKEP_BOARD`, `SKEP_KEYSTORE` and
`SKEP_PRINCIPAL` in `env` instead. The store holds the key the agent
signs with — generated and enrolled by the person at their own client
(`skep keygen`, `skep enroll`, `skep bind`), who stops the agent by
retiring it (`skep retire`).

A binary crate; pair it with a running [skepd](../skepd).

## Running it

**Start.** One origin names the board in three places, character for
character: the board signs sessions for it (its `--origin`,
[RUNBOOK.md](../../RUNBOOK.md) §3); the agent's store binds its key at it
(the person's `skep keygen --dir <store> --payload` in that store, `skep
enroll` of the record from the person's own device, and `skep bind --dir
<store> --board <origin>` with the reply); and the harness runs `skep-mcp
--board <origin> --dir <store> --principal <n>`. The start is done when the
log says `signed as principal …` and `serving … tools`; a refusal before
then is one line naming the check that did not hold, and exit 1 — a board
that does not answer then among them, which a start does not wait out:
start the adapter again once the board answers.

**Stop.** The harness closes stdin and waits for the exit. The clean stop
closes the session at the board and saves the index: seconds where the
board answers or is gone, up to about a minute and a half where it accepts
the connection and then stops answering — the close and the feed's last
read each held to skep-client's exchange deadline — and longer as the index
grows, its save rewriting the index whole. The log says how long each stop
took: the figure to set the harness's grace before a signal by. A signal
ends the process at once: its held bursts are already on disk — save one
the shell answered `unwritable` or `other_window`, kept in memory alone and
lost with the process — the session lives on at the board until the board
restarts, and the index resumes from its last save. The person stops an
agent for good by retiring its key (`skep retire`); every start over that
store is then refused `retired`.

**Restart.** Stop it, then start it over the same `--dir`: the held bursts,
counted at the start, and the index carry over. A start over a store
another adapter still holds — a predecessor still stopping — waits up to
30 s for it to end, and is refused after that: a predecessor finishing a
fetch, or stopping at a board that accepts the connection and does not
answer, can take longer — end it by a signal, and start this one again.

**Upgrade.** Stop it, replace the binary, start it. Write any `--tools-file`
afresh from the new release's `tools.json`: the start refuses one whose
tools are not this release's, and says so of one whose text differs. An
older release over a store a newer one wrote leaves the newer index and held
file as found, each said at the start, until the newer release runs there
again.

**Back up.** Copy the store with the adapter stopped. `keys/` and `bindings`
are the agent's key and its binding: a copy of `keys/` is a copy of the
agent's signing key, and the person remakes both where they are lost.
`held/` is the one state only this adapter holds: put back, the shell reads
each document's changes before it resends a line, and a line whose document
moved waits on the agent's `resolve`. `index/` is rebuilt from the board and
needs no copy, and `skep-mcp.lock` is the running process's.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
