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
  the account, and the person seam.
- **Every tool is one call of the shell.** The forty-seven WIRE OPERATIONS
  of `docs/wire.md` §Operations are tools of their own names — the name
  is the frame's `op`, the arguments are the frame — sent as `op(session,
  frame)`: attested where the session's key attests the kind, held where
  the board cannot take a burst (the `held` answer comes back as data), a
  `write_busy` reissued once and a `durability` twice within the call, as
  the shell does. No general `op` tool ships: every op has a name. The
  shell's own calls are tools of their names — `boards`, `health`,
  `probe`, `search`, `places`, `held`, `resolve` — their arguments the
  bridge's row minus the session and the board, which the adapter
  supplies. Three are the adapter's own: `session_info` (the principal,
  the account, the key's fingerprint and label, the board, `writes`, the
  board's health with its mode), `changes_since(since, limit?)` (the
  shell's `changes`: a pull of what changed, the agent keeping `next`) and
  `fetch(i)` (a picture's bytes as an image block — the type sniffed off
  the bytes' magic for PNG, JPEG, GIF and WebP, never attested — else an
  embedded resource blob, under a cap of 8 MiB checked before a byte is
  read). The catalog is `tools.json` beside `Cargo.toml`, checked against
  the dispatch's two kinds at startup in both directions.
- **A refusal as a result.** The board's verdict on a frame — a `refused`
  refusal — is DATA: `isError: false`, the verdict's body verbatim with the
  shell's envelope (`name`, `status`, `code`, `detail`, `op`) beside it.
  Every other kind — `unreachable`, `halt`, `blocked`, the shell's own
  names — is `isError: true` with the refusal's value as the text: `isError`
  means one thing, that the shell could not get the board's verdict.
- **The session's life.** A board restart is met by the shell's silent
  re-open under a fresh reference, which the adapter takes from the call
  that met the death (reissuing it once) or from the `session-died` event
  it drains for the process's life; the agent sees nothing. A death the
  shell does not re-open — the key retired, the prefix blocked, the
  account seeded, a restart whose re-open the board refused — stops the
  process with one plain line naming the arm: the person stops an agent by
  retiring its key, and the adapter's end is what the agent's client sees.
  A board that is not answering refuses each call `unreachable` and the
  adapter stays up.
- **No person at the seam.** The shell is opened with the refusing arm:
  every SECRET and CONSENT moment would be refused `person_required`, and
  no ceremony tool is offered (no `keygen`, `fingerprint`, `claim`,
  `enroll`, `bind`, `recover`, `rotate`, `retire`, `handoff`, `accept`);
  nor `upload` or `restore`, whose media walk the shell does not reach
  yet (skep #502).
- **One call at a time.** Calls are served in arrival order, one at a time;
  a `fetch` of a large file or a `search` while the index is building holds
  the calls behind it. Stdin's end is the clean exit: the shell's stop
  closes the session at the board and saves the index. A signal ends the
  process with neither — the session then lives on at the board until it
  restarts.
- **Deliberately dependency-light** — the shell's core, `skep-client` for
  the types the shell's surface names and a key label's inert rendering,
  and `serde_json`; the stdio framing, the type sniff and the base64 are
  this crate's own.

## Settings

| flag | variable | what |
|---|---|---|
| `--board <origin>` | `SKEP_BOARD` | the board, a canonical origin such as `http://127.0.0.1:8642`; required. `SKEPD_URL` is no longer read. |
| `--dir <path>` | `SKEP_KEYSTORE` | the key store the adapter signs from; required, `~/.skep` never consulted. The shell's search index and its held bursts sit there too, so it is ONE DIRECTORY PER ADAPTER PROCESS, never a running `skep-dev serve`'s: the index's and the held store's locks are per process, and a second process on the same directory gets a `busy` index and holds its bursts in memory alone. The index persists there across runs and is built from scratch in a fresh directory — `search` and `places` answer `state.arm` `building` meanwhile. |
| `--principal <n>` | `SKEP_PRINCIPAL` | the principal the adapter acts as; required, an integer from 0 to 2^53 − 1 |
| — | `SKEP_COMMONS` | optional: the commons' address, which the server instructions then point agents at |
| `--tools-file <path>` | — | override the embedded catalog |

A flag beats its variable. `--version` and `--help` answer before any
setting or stdin is read.

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
