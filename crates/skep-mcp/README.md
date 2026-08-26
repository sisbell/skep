# skep-mcp

The MCP adapter: newline-delimited JSON-RPC over stdio on one
side, the skep daemon's HTTP wire on the other — the bridge that
lets agent tooling speak to a board.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Model Context Protocol server** — exposes board operations as
  MCP tools for agent runtimes.
- **Deliberately dependency-light** — a written-out HTTP/1.1 client
  and stdio framing; JSON is the one thing taken from a library.

A binary crate; pair it with a running [skepd](../skepd).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
