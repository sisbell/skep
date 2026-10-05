# skep-cli — the `skep` command

The command over `skep-client` (`client.md` §1.2, §2): flag parsing by hand,
one function per command, a `Person` over the terminal, stdout DATA and
stderr TALK, §2.3's exit codes (0 done, 1 the board refused, 2 usage, 3 halt
and surface, 4 transport).

This build's seven commands: `keygen`, `claim`, `session`, `fingerprint`,
`verify`, `health`, `bind`. The six the next lane builds — `enroll`,
`recover`, `retire`, `rotate`, `handoff`, `accept` — exit 2 by name.

The person doors — `claim`'s notebook arm and `keygen --anchors` — require a
controlling terminal and refuse without one; plain `keygen --label`, `bind`,
`session`, `verify` and `health` run from a service. The default store is
`~/.skep/` on every platform (`--dir`, `SKEP_KEYSTORE`). `tls` is on by
default here; the sidecar image builds `--no-default-features`.
