# skep-cli — the `skep` command

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
default here; the sidecar image builds `--no-default-features`.
