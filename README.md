# skep

> **skep** *(n.)* — the coiled-straw beehive: the structure a swarm
> builds and inhabits.

The implementation of the Xanadu-derived hypertext system: a permanent,
content-addressed document substrate (addresses, transactions, namespace,
content, arrangements, links, retrieval, query) with a stigmergic
**predicate-coordination** layer built on top, through which agents coordinate
by reading and emitting marks in the shared substrate.

Built in Rust as a Cargo workspace. The module decomposition, per-module
designs, and conformance suites are produced in the reasoning-lattice project
and exported here as they converge.

## Workspace

Twenty-eight crates; the boundaries are the architecture. Fourteen domain
crates realize the spec's converged designs (the M1–M10 modules, the
AUTH identity layer, signed ops, the registry and the blob store) and
encode the composition contract's
layering in the dependency graph itself — the
compiler enforces what the design ruled (no store depends on the engine,
type-only edges stay type-only, nothing depends on the engine but a
binary). Beneath them, one support crate; above them, the daemon's media
resource, one assembler, the transport adapters, the verifying registry
resolver, the search index, the client library and the `skep` command;
beside them, the differential-conformance harness.

| crate | role |
|---|---|
| `skep-address` | M1 — tumblers, T4 addresses, span algebra (pure values) |
| `skep-kernel` | M2 — transactions, journal/WAL, checkpoints, recovery |
| `skep-namespace` | M3 — accounts, delegation, baptism, ownership |
| `skep-content` | M4 — the permascroll: write-once address→value map |
| `skep-arrangement` | M5 — document arrangements (V→I), provenance |
| `skep-retrieval` | M6 — content/provenance queries |
| `skep-links` | M7 — permanent typed links, supersession, retraction |
| `skep-discovery` | M8 — link discovery, four-set queries, projection |
| `skep-coordination` | M9 — predicate definitions & coordinator (stateless) |
| `skep-febe` | M10 — the operation surface (`Operation<W>`), codec seam |
| `skep-identity` | AUTH — credential records, key sets, the identity fold (pure) |
| `skep-signature` | signed ops — the hybrid signature: key derivation, signing, verify |
| `skep-registry` | the registry's commons rows and binding/endpoint bodies (pure values) |
| `skep-blobs` | the blob store: deposited files, partial uploads, upload records, leases |
| `skep-util` | the support crate below the daemon and the media crate: the counting permit pool, the operator's notice line, the JSON determinism helpers |
| `skep-corpus` | the prose corpus a dev board is seeded from and the search budgets are measured over: a git repository read at one pinned commit through `git` alone, and the one deterministic cut into documents of 1–10 KiB — no skep crate, nothing but `std` and a `git` child process |
| `skep-http` | the plain HTTP/1.1 subset two programs speak over loopback: one request per connection read under the caller's caps, the response written with `Connection: close` — no CORS, no event stream, no cap of its own |
| `skep-media` | the daemon's media resource: the cell's one parser, the media door, the gate over the blob store, the cell index, the pruner, the fetch — generic over the world, no engine |
| `skep-engine` | the one assembler: `World`, genesis, recovery, `world_at` |
| `skep-core` | the daemon's core: the session layer, the commits (the door, the feed, the head), the wire codec; the daemon's two crates are what depends on the engine |
| `skepd` | the daemon: HTTP/JSON wire v4, sessions, history, SSE |
| `skep-mcp` | stdio MCP adapter for agent harnesses |
| `skep-resolve` | the verifying registry resolver: a library a client embeds (no engine, no store, never `skepd`) |
| `skep-search` | the search index: a library a client embeds — the document model, the tokenizer, the inverted index with positions (no engine, no store, never `skepd`) |
| `skep-client` | the library every acting client embeds: the dialer, sessions, the key store, signing, the reader's verifier, the claim ceremony |
| `skep-shell` | the shell's core, written once for the dev provider and the desktop shell: the bridge's twenty-three calls — §4b.1's twenty-two and the document index's listing — and seven events over `skep-client`, the board and session references the page is handed in a credential's place, the feed consumer's thread per board, the TypeScript declarations of every value that crosses the bridge — no feature, no transport, never `skepd` |
| `skep-cli` | the `skep` command over `skep-client`: keygen, claim, session, fingerprint, verify, health, bind, and the ceremonies enroll, recover, retire, rotate, handoff, accept |
| `skep-provision` | the service behind a hosted board's sign-up: the sign-up page and the claim form behind the proxy, the record checked in process, each board made through the host's `docker`, one proxy snippet per board, the live page and the follow-up mail — it holds no key |
| `skep-conformance` | differential harness vs. `udanax-green` goldens + ratchet |

Conventions: shared metadata and external-dependency versions live in
`[workspace.package]` / `[workspace.dependencies]` (crates add features,
never different versions); one lockstep version for the family; the
toolchain is pinned in `rust-toolchain.toml` and bumped only with a full
gate run. Release binaries are `skepd`, `skep`, `skep-mcp` and `skep-provision`; library crates
publish to crates.io as they stabilize (`skep-address` first). The wire contract clients build against is
`docs/wire.md` — the contract as it stands; versioning begins at the first
release, independent of crate versions. License: MIT OR Apache-2.0 (dual, the Rust convention).
The runbook for running a board — start, stop, restart, upgrade, back up, restore, the full volume — is [RUNBOOK.md](RUNBOOK.md).
See [CONTRIBUTING.md](CONTRIBUTING.md) for the commit convention.

**Keys and the claim.** The client you install IS the board: `skepd` on
your machine is the notebook, and stopping before `skep claim` leaves
nothing behind — no board, no account, no key. Once claimed, every edit to
your notebook, including what you later remove, is kept; its history is
permanent, and it is local: no mirror holds it and this board can never be
made public. The records it holds — your keys, your claim, the grants you
issue — stand as records of their own, so removing the text one names does
not remove it. This notebook is local forever; public work happens in an
org, and that venue is not reachable on any board today — this board can
never become one when they open. The page `skepd` serves is a READER: it
holds no keys, opens no sessions, writes nothing, and does not verify
signatures. A person acts from the `skep` command (`crates/skep-cli`:
`skep keygen` makes the device key, `skep claim` runs the ceremony) or
from the bundled app, whose page acts through the shell's bridge over
`skep-client`. The claim's backup moment writes two anchor FILES by default
— to directories you name, never under the key store — and prints a sheet
only under `--paper`; `skep recover` is the way back in from
a kept file or a print, and no one else holds a reset. The later gestures
are commands too: `skep enroll` adds a device from one already signed in,
`skep retire` and `skep rotate` retire and replace a device key after a
previewed, typed confirmation, `skep recover --anchor-lost` replaces a lost
paper under the surviving one, and `skep handoff` with `skep accept` give a
subdivision to another party.

## Running a daemon for frontend development

Build and run the daemon on loopback against a throwaway board:

```
cargo run -p skepd -- --data-dir ./board --origin http://127.0.0.1:8642
```

The daemon listens on 127.0.0.1:8642 only — `--bind`'s default, which only
the hosted image below widens. The board is UNCLAIMED until you
claim it, and while it is unclaimed anything that can reach the port can take
it: never forward the port before the claim. Claim it from the `skep` command
(`cargo run -p skep-cli --bin skep -- keygen`, then
`claim --board http://127.0.0.1:8642`); the claim writes two anchor files to
directories you name — keep them apart, and never under ~/.skep.

Local trust stays on, the daemon's default, because the dev provider below
opens a bare session as the claimant, which a claimed board admits only while
local trust is on. That lets any loopback party write as any principal, as the
daemon warns at each start once the board is claimed: a cost a throwaway nobody
else reaches can bear.

Your page never posts /session and never holds a session token. The dev
provider, `skep-dev serve`, is a process beside your dev server that opens the
session itself as a loopback peer and carries the page's calls to the daemon:

```
cargo run -p skep-cli --bin skep-dev -- serve --board http://127.0.0.1:8642 \
    --session bare --page-origin http://localhost:5173
```

`--page-origin` is your dev server's origin, the one origin the provider
admits; `crates/skep-cli/README.md` has the rest. Do NOT pass the dev server's
origin to the daemon as `--origin`: a configured origin is permanent on that
board and stays signable after the claim. Bare sessions write drafts and never
publish; to exercise publishing, start the provider with
`--session signed --dir ~/.skep`, which signs with the key that claimed the
board, and the page still holds no token.

To see the daemon's own read-only viewer, build with the `client` feature and
open http://127.0.0.1:8642/; it opens no session. `--allow-preview-keys` is for
the test fixtures only: a preview key enrolled is enrolled for life.

Throw the board away with `rm -rf ./board`. For a notebook you keep, see
[RUNBOOK.md](RUNBOOK.md): Start, step 2, and §9, Running it as a service.

## Running the hosted image

This section is for an operator hosting boards for other people: one
container per board, behind a reverse proxy, a fresh named volume each.
It is not how a notebook runs — that is the plain binary (RUNBOOK.md,
Start, and §9) — and not the frontend developer's day-to-day path, which
is the section above; no end user is ever asked to install Docker.

**Build.** From the repository root, the release image, its debug tag
and the claim sidecar, three targets of the one `Dockerfile`:

```
docker build -t skep-hosted --build-arg REVISION=$(git rev-parse HEAD) .
docker build -t skep-hosted:debug --build-arg REVISION=$(git rev-parse HEAD) \
    --build-arg RUNTIME="$(sed -n 's/^ARG RUNTIME_DEBUG=//p' Dockerfile)" .
docker build -t skep-cli --target skep-cli --build-arg REVISION=$(git rev-parse HEAD) .
```

`REVISION` is the commit the images' labels name, and their binaries'
`--version` lines its first twelve characters; a build that passes none
names `unknown`. The daemon is built `--no-default-features`: the image
serves no `/dump` and no page at `GET /`. The sidecar's `skep` is built
without `tls`, since it dials loopback and signs nothing. The one file
builds for `linux/arm64` (an Apple-silicon Mac) and `linux/amd64` (the
server) under buildx — `docker buildx build --platform linux/amd64 -t
skep-hosted .` cross-builds under emulation — and every base image is
pinned by digest. `scripts/docker-smoke.sh` builds all three and proves
the image on the machine it runs on; run it after every build.

**Run.** Every setting, named once. A `SKEPD_` name the daemon does not
read stops the start, exit 2, with one line naming it beside the names it
reads — `docker logs` shows it, `docker ps` the container restarting —
since a run line's `-e` checks no name. Baked into the image:
`SKEPD_DATA_DIR=/var/lib/skepd/board` (one level below the volume's
root), `SKEPD_LOCAL_TRUST=false`, `SKEPD_BIND=0.0.0.0` and
`SKEPD_PORT=8642`; the daemon runs as the numeric user `10001:10001`,
the binary owned by root. Per board, on the run line: `SKEPD_ORIGIN`, the
origin the board is DIALED at — `https://<name>` behind the proxy — which
is the origin a signed session signs and the only one accepted once the
board is claimed; `SKEPD_NODE_PREFIX=1.N` where a registry minted one,
omitted where none did (the start line then says the off-board test is
off and a hosted board must supply one: expected, until there is a
registry); `SKEPD_UPLOADS` (on by default); `SKEPD_WORKERS` (at or above
the floor `skepd --help` prints); and `SKEPD_BLOCKED_PREFIXES`, naming the
blocked-prefix list. The daemon reads that path at start alone, so a board
started without it blocks nothing until it is recreated with one: start
every board that may need a takedown with the variable naming a file that
holds `{"entries": []}`, in a mounted DIRECTORY and never a mounted file —
a mounted file keeps its first identity, so a new issue renamed over it on
the host is never seen (RUNBOOK.md, Start, step 8). The provisioning
service's boards carry `SKEPD_ORIGIN` alone of these, the rest at the
daemon's defaults. On the `docker run` line: `--init` (the daemon handles no signal, so as PID 1
without an init it would not take SIGTERM), `--read-only` (the volume is
the only writable path), `--cap-drop ALL`, `--security-opt
no-new-privileges`, `--ulimit nofile=1024:1024` (the daemon sizes its 64
event streams against a 256 soft limit), `--restart on-failure`, a log
driver with rotation (the operator stream never waits: a full pipe costs
lines, counted on the next, never service), and ONE named volume per
board, on a filesystem of its own where the floor must be the board's:

```
docker volume create alice
mkdir -p /srv/skep/alice/blocked
printf '{"entries": []}\n' > /srv/skep/alice/blocked/blocked.json
docker run -d --init --name alice --restart on-failure \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --ulimit nofile=1024:1024 --log-opt max-size=10m --log-opt max-file=5 \
    -v alice:/var/lib/skepd \
    -v /srv/skep/alice/blocked:/etc/skepd/blocked:ro \
    -e SKEPD_ORIGIN=https://alice.example \
    -e SKEPD_BLOCKED_PREFIXES=/etc/skepd/blocked/blocked.json \
    skep-hosted
```

No port is published: the proxy reaches the daemon at the container's
address on the bridge, port 8642, and nothing else does. No `HEALTHCHECK`
is baked and the daemon has no probe mode: the proxy's health-conditioned
route is the probe, as the next paragraph says.

**Claim the board.** Two runs of the same image on the same volume. The
claim run binds loopback and publishes nothing, so only a process inside
the container's own network namespace can reach the unclaimed board; the
sidecar joins that namespace and runs the claim with the person's record,
made on their own device (`skep keygen --anchors …`, or `--payload` for a
one-key account that can never recover); then the serving run above, on
the baked bind:

```
docker run -d --init --name alice --read-only --cap-drop ALL \
    --security-opt no-new-privileges --ulimit nofile=1024:1024 \
    -v alice:/var/lib/skepd \
    -e SKEPD_BIND=127.0.0.1 -e SKEPD_ORIGIN=https://alice.example \
    skep-hosted
docker run --rm --network container:alice -v ./alice.enroll:/payload:ro \
    skep-cli skep claim --board http://127.0.0.1:8642 --hosted /payload
docker stop alice && docker rm alice
# the serving run above, on the same volume
```

The sidecar prints `claimant 1.0.1`, then `account 1.0.1`, `principal 1`,
`origin http://127.0.0.1:8642` and the person's two first acts; relay them
to the person. On a claimed board it prints `claimed by 1.0.1` and exits
0. From then on `GET /health` answers `auth.claimant` `"1.0.1"` and
`auth.local_trust` `false`, and the proxy admits the route only while it
does, on this start and every restart. The proxy's configuration, its
health-conditioned route and the sign-up flow around the claim are the
deployment notes' §4 (`_designs/deployment-notes.md`, in the design
repository), not this file's. The sign-up behind the proxy, which runs
these steps for each person, is `skep-provision`'s
([crates/skep-provision/README.md](crates/skep-provision/README.md)); the
operator's steps are RUNBOOK.md §10.

**What the port gives.** Every connection through the proxy, or through a
published port, arrives from the bridge: the daemon reads the peer off
the socket and classes it Remote, and no bare session opens through a
Remote peer, whatever `SKEPD_LOCAL_TRUST` says — the `401
session_rejected` IS the handshake. What such a peer gets: reads of
everything public, and, once the board is claimed, signed writes with a
key enrolled for the person's account — the key that claimed it, or a
device added from a signed-in one with `skep enroll`, the hop. Local
trust on would admit nothing more through the proxy; it would admit every
process inside the container's namespace, which is why the image bakes
it off.

**The debug tag.** `skep-hosted:debug` is the same binary, user, volume
and baked environment on the `:debug` runtime, which adds busybox: a
shell to read the data directory as the daemon sees it (`docker run --rm
-v alice:/var/lib/skepd --entrypoint /busybox/sh skep-hosted:debug -c
'ls -la /var/lib/skepd/board'`) and `wget` to read `/health` from inside
a container's namespace (`docker run --rm --network container:alice
--entrypoint /busybox/wget skep-hosted:debug -qO-
http://127.0.0.1:8642/health`). It never runs behind a customer route.

**On a host.** Without the image, build the daemon as the image does,
`cargo build --release -p skepd --no-default-features`, and never serve a
board others reach with the release archive's `skepd` or RUNBOOK.md's
default build: both carry `observe` and answer `GET /dump`, a walk of the
whole world holding no permit, to every guest. The open's first line says
which build is running: the image's ends
`built with no optional feature`. Run the daemon as a user of its own and
let it create the data directory: it sets the directory `0700` and every
file `0600` itself, whatever the umask, and refuses at start a data
directory other users can read (RUNBOOK.md, Start, step 2, and §9's
dedicated-user option). The volume is the same shape: the daemon creates
`board/` one level below the mount and never the mount itself, whose
root is the runtime's. A bind mount in place of a named volume is made
`install -d -m 700 -o 10001 -g 10001 <dir>` beforehand; a directory at
`0755` is refused with the one line that names the `chmod`.

**Rehearsing the hosted shape on this machine.** The same image published
on the host's loopback — the claim run and the sidecar as above, then the
serving run with `-p 127.0.0.1:8642:8642 -e
SKEPD_ORIGIN=http://127.0.0.1:8642` — gives the dev provider started
`--session signed --dir <the store holding the record's device key>`
exactly what the server would: the published port is a Remote peer, so
`--session bare` is refused with the one 401, and signed sessions open
because the dialed origin is the configured one. It is not the notebook,
which is the plain binary of the section above; `scripts/docker-smoke.sh`
runs this rehearsal end to end and prints what each step found.

## Prebuilt binaries

Each tagged release at https://github.com/sisbell/skep/releases carries
one archive per platform, `skep-<version>-<triple>.tar.gz`, for
`aarch64-apple-darwin` (macOS on Apple silicon), `x86_64-apple-darwin`
(macOS on Intel), `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu`, and one `SHA256SUMS` file naming all four.
An archive holds four binaries, built from the tag's tree and stripped,
with a README and the two license texts:

- `skepd`, the daemon: one process over one board directory, the board
  served over HTTP on loopback;
- `skep`, the command: the device key, the claim that makes a board
  yours, sessions, verify, health, bind, and the key ceremonies;
- `skep-mcp`, the MCP adapter: an agent harness on stdio on one side,
  the daemon's HTTP wire on the other;
- `skep-provision`, the service behind a hosted board's sign-up: run on
  a host that serves boards for other people, as RUNBOOK.md §10 says —
  never on a notebook.

Each answers `--version` with the crate version and the commit it was
built from — `skepd 0.1.0 (a1b2c3d4e5f6)` — and a developer's own build
answers `(unknown)` there. Check a download before running anything
from it:

```
scripts/release-check.sh skep-0.1.0-aarch64-apple-darwin.tar.gz SHA256SUMS
```

verifies the archive's checksum against the file (a path, or the release
page's URL where `curl` is installed), unpacks it to a temporary
directory, and runs the four binaries' `--version`, holding them to one
version — the one the archive is named for — and one commit. The script
needs nothing of the repository but itself. Without it, the checksum
alone, from the directory holding the archive and the file:

```
shasum -a 256 --ignore-missing -c SHA256SUMS    # macOS
sha256sum --ignore-missing -c SHA256SUMS        # Linux
```

The macOS binaries are not signed or notarized: a copy a browser
downloaded carries the quarantine attribute and is refused at launch, so
download with `curl -LO`, or clear the attribute after checking
(`xattr -d com.apple.quarantine <file>`). There is no Windows archive:
`skepd` does not build for Windows at this release, because the blob
store reads the volume's free space through `statvfs`, which rustix
leaves out of its Windows build. To run a notebook you keep from these
binaries, see RUNBOOK.md: Start, step 2, and §9, Running it as a
service. The archives are what `scripts/release-pack.sh` builds, one
platform per run, which `.github/workflows/release.yml` runs on each
pushed `v*` tag.

---

*An independent reimplementation derived from the published Xanadu design
(Ted Nelson, *Literary Machines*) and Roger Gregory's `udanax-green`. Not
affiliated with or endorsed by Project Xanadu or Ted Nelson.*
