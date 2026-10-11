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
plumbing with one verb today: `skep-dev seed` dials a RUNNING board the
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
and a killed run resume. The thirteen commands stand: the tool is no
command of `skep`, and the sidecar image, built `--bin skep`, holds none
of it.
