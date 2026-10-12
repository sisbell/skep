# skep-http

The plain HTTP/1.1 subset two programs speak over loopback: one request
per connection, the head read to its terminator and the body to its
`Content-Length`, each under a cap the caller gives, no chunked bodies,
and `Connection: close` on every answer.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **The read**, `read_request` — one request off the caller's stream,
  under the caller's `Limits { max_head, max_body }`: the head to its
  `\r\n\r\n` terminator, the request line — a method in uppercase
  letters, a target, `HTTP/1.1` or `HTTP/1.0` — and one header to a line,
  then the body to its `Content-Length`. It answers a `Request` — the
  method, the path, the query split off at the first `?`, the headers in
  the order sent, the body — whose `header` reads the first header of a
  name, case-insensitively, and `query_value` the first query member of a
  key; `None` for a connection that ends before its first byte, a port
  probe; or `Refused`: `Malformed`, its words saying what was wrong — a
  head past its cap, a bad request line, method token, header line or
  `Content-Length`, a `Content-Length` given twice, a
  `Transfer-Encoding`, or a close or a failed read inside the request —
  or `TooLarge`, a declared body past the cap, with the length and the
  cap, refused before any of the body is waited for.
- **The write**, `write_response` — one whole answer: the status line,
  the caller's headers in order, the content type where one is named, the
  body's length, `Cache-Control: no-store` and `Connection: close`, then
  the body, flushed; and `write_head`, the head alone, for a caller that
  streams the body after it.

The dev provider, `skep-dev serve` in `skep-cli`, calls it today, and the
provisioning service next; the daemon's own reader stays the daemon's.
An item lives here if and only if it is the plain subset, read and
written the same for any program that answers one request per
connection. No CORS header, no event stream and no cap value lives here:
each is its caller's own, and a cap is configuration, handed in at the
read. The crate names nothing of skep and depends on `std` alone. Its
rule in full is in its crate root (`src/lib.rs`); its place in the
workspace, in `ARCHITECTURE.md` §Code map.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
