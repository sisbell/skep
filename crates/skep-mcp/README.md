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
  The startup lines on stderr name the board and its mode, the key and
  the account, and the person seam — and, for a board off this machine's
  loopback, the warning that its session's token rides in the clear
  unless a tunnel carries it, and the principal's held bursts an earlier
  run left at the board, or a held file the shell halted. Every line on
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
  its key, and the adapter's end is what the agent's client sees. A board
  that is not answering refuses each call `unreachable`, and the adapter
  stays up.
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
  the index is building holds the calls behind it. Stdin's end is the clean
  exit: the shell's stop closes the session at the board and saves the
  index. A signal ends the process with neither — the session then lives
  on at the board until it restarts.
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

| flag | variable | what |
|---|---|---|
| `--board <origin>` | `SKEP_BOARD` | the board, a canonical `http://` origin such as `http://127.0.0.1:8642`; required. An `https://` origin is refused: the adapter dials plain `http://` alone, so a hosted board is reached at the `http://` origin of a tunnel to it, and a board on another machine without one carries its session's token in the clear, as the start's warning says. `SKEPD_URL` is no longer read. |
| `--dir <path>` | `SKEP_KEYSTORE` | the key store the adapter signs from, a directory that stands; required, `~/.skep` never consulted. The shell's search index and its held bursts sit there too, so it is ONE DIRECTORY PER ADAPTER PROCESS, never a running `skep-dev serve`'s: the index's and the held store's locks are per process, and a second process on the same directory gets a `busy` index, said in its log, and holds its bursts in memory alone. The index persists there across runs and is built from scratch in a fresh directory — `search` and `places` answer `state.arm` `building` meanwhile. |
| `--principal <n>` | `SKEP_PRINCIPAL` | the principal the adapter acts as; required, an integer from 0 to 2^53 − 1 |
| — | `SKEP_COMMONS` | optional: the commons' address, which the server instructions then point agents at |
| `--tools-file <path>` | — | override the embedded catalog |

A flag beats its variable. `--version` and `--help` answer before any
setting or stdin is read. The process exits 0 at stdin's end or a closed
stdout, the session closed at the board; 1 at a refusal before serving or
a stop while serving; 2 at a usage error; 101 at a panic, a bug said in
one line of the log.

The log is stderr: every line opens `skep-mcp: ` and the moment it was said,
RFC 3339 UTC to the millisecond, as the daemon's own lines do, and the first
names the version the run began with and its process id. The lines of the
session's life name the session by its reference, as the shell's own lines
and the refusals an agent is answered name it; a call that holds the loop
past a dial's read bound is said with its tool, its request's id and how
long it held; and the clean stop's line says what the loop answered. No line
quotes an answer's text — the client's refusal of an answer it cannot parse
is cut at its parse error — and none runs past four kilobytes. A harness
may read the log or leave it: a reader that stops reading never holds the
adapter up — the lines it leaves are dropped, and the next line it takes
says how many went, at the moment the first of them was said.

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

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
