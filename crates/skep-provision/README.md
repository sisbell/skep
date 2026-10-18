# skep-provision

The service behind a hosted skep board's sign-up: the sign-up page and the
claim form, served over HTTP behind the proxy; the person's record checked
in process; the steps that make a board run through the host's `docker`
command, different names at once; one proxy snippet per board and a
reload; the live page at a status URL; and a follow-up mail once the
board is live. At its start it removes any board a stop left half-made.
It holds no key.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

## The verbs

```
skep-provision serve --state-dir <DIR> --reply-to <ADDRESS> [flags]
skep-provision invite --address <ADDRESS> --state-dir <DIR> [--code <CODE>] [--suffix <DOMAIN>]
skep-provision --version
```

- **`serve`** runs the service until the process ends: SIGTERM's default
  disposition stops it at once. Its start says the version it runs and the
  settings every board is made with, above the serving line. Every file it
  keeps is replaced whole by a rename, so no stop tears one; a board cut
  off before its snippet is written leaves what was made standing, and the
  next `serve` removes it before it serves (see
  [The sweep at start](#the-sweep-at-start)); a
  board cut off after its snippet is written and before its invite is
  spent stands, routed — or routed at the proxy's next reload — and the
  next `serve` counts it live and leaves it, its invite still issued: a
  post on that invite is admitted again unless the operator marks it
  spent. The log names such a board, its `snippet: written` with no
  `the invite is spent` after it, and the next `serve` names it again,
  `<name>: routed at start with no invite line spent under it …`.
- **`invite`** mints one invite into the state directory's invite file
  and prints one line on stdout, the invite link: the claim form's URL
  carrying the code, `https://<suffix>/claim?invite=<code>`. The owner
  mails that line by hand.
- **`--version`**, the first argument, prints `skep-provision <version>
  (<commit>)`, the form `skepd --version` prints.

A usage refusal (an unknown flag, a missing value, a value of the wrong
form — a log size of nothing, an empty path among them — a required flag
missing, `--mailer` without `--from` or the reverse) exits 2 with the
usage text, and the unit never restarts it; a start refused (a state
directory that is loose, another user's, cannot be made or is not a
directory; another `serve` holding it; a `--mailer` that cannot be run; a
snippet directory that cannot be read or written; an address that cannot
be bound; a thread the machine will not give — all but the last before
the sweep), or an `invite` that printed no invite link exits 1, as does a
`--version` or `--help` whose text cannot be written.

## `serve`'s flags

The command line is the one home of every setting: the service reads no
environment variable for one — `tests/it/tidy.rs` checks it — so under
the unit its `ExecStart=` holds them all. Each default is a named
constant in `src/args.rs`, and the usage text renders it from there; the
table below is read back against the usage by the crate's own suite.

Every flag is **checked** at the parse, a bad value a usage refusal,
exit 2, which the unit never restarts; and where the parse cannot see the
whole of it — a directory, a port, a program, a thread — again at start,
a refused start, exit 1, one line naming the value and the act, each
before the sweep but a thread the machine will not give, which the pools
meet after it. Every flag is **read** once, at start: a change is the
unit's line edited, `daemon-reload` and a restart, which ends what
RUNBOOK.md §10 step 12 says a stop ends. A setting fixed into each board
at its making reaches the boards made after the restart alone; a
standing board keeps its own until it is made again (RUNBOOK.md §10 step
13).

| flag | default | checked | read | what it sets |
|---|---|---|---|---|
| `--state-dir <DIR>` | required | parse, where an empty value is none; start: the door and the serve lock | at start; its files at each use | the sign-up file and the invite file; made `0700` where absent, refused at start where any group or other bit is set or where it is another user's, root's among them |
| `--reply-to <ADDRESS>` | required | parse: the address rule | at start | the owner's mailbox: the failure page names it, and an answer to the mail goes to it |
| `--listen <ADDR:PORT>` | `127.0.0.1:8842` (`DEFAULT_LISTEN`) | parse; start: the bind | at start | where the pages are served; how the proxy reaches it is the VM's configuration, the port one half of a pair (RUNBOOK.md §10 step 1) |
| `--boards-dir <DIR>` | `/etc/caddy/boards` (`DEFAULT_BOARDS_DIR`) | parse, where an empty value is refused; start: read and written | at start; its snippets at each post and each sweep | the proxy's snippet directory, and the list of boards the sweep at start spares: every labelled volume it lacks is removed |
| `--image <TAG>` | `skep-hosted` (`DEFAULT_IMAGE`) | parse: one word | at start; its tag resolved at each run, the image fixed into each board at its making | the hosted image |
| `--cli-image <TAG>` | `skep-cli` (`DEFAULT_CLI_IMAGE`) | parse: one word | at start; its tag resolved at each sidecar run | the claim sidecar's image |
| `--network <BRIDGE>` | `skep` (`DEFAULT_NETWORK`) | parse: one word | at start; fixed into each board at its making | the bridge the boards and the proxy share |
| `--caddy <CONTAINER>` | `caddy` (`DEFAULT_CADDY`) | parse: one word | at start | the proxy's container, which each route change reloads |
| `--suffix <DOMAIN>` | `skep.host` (`DEFAULT_SUFFIX`) | parse: the domain grammar | at start; fixed into each board at its making | the domain every board's name is under, `<name>.<domain>`; every `invite`'s `--suffix` is the same |
| `--log-max-size <SIZE>` | `10m` (`DEFAULT_LOG_MAX_SIZE`) | parse: a size of one or more | at start; fixed into each board at its making | a serving run's log file size, with a `k`, `m` or `g` after it |
| `--log-max-file <N>` | `5` (`DEFAULT_LOG_MAX_FILE`) | parse: one or more | at start; fixed into each board at its making | a serving run's log files kept |
| `--workers <N>` | `3` (`DEFAULT_WORKERS`) | parse: one or more; start: a thread each | at start | the boards made at once: one worker thread each |
| `--connections <N>` | `16` (`DEFAULT_CONNECTIONS`) | parse: one or more; start: a thread each | at start | the requests served at once: one thread each, made at start, and a descriptor while it serves, which the unit's `LimitNOFILE=` bounds; a further connection waits in the listener's queue |
| `--mailer <PROGRAM>` | none | parse: given with `--from`, never empty; start: a file it can run | at start; the client's own configuration at each send | the host's relay client, run as `<PROGRAM> -t` with the message on stdin; given with `--from` or not at all, and with neither no mail is sent and the serving line says so; its configuration the client's own, which no start checks |
| `--from <ADDRESS>` | none | parse: the address rule | at start | the mail's sending address |

A tag is resolved by `docker` at every run, not at the start: an image
rebuilt under `--image`'s tag is the next board's, one rebuilt under
`--cli-image`'s the next sidecar's, with no restart and no line, and the
settings line says the tags, never what they resolve to. What no check
reaches — that the images, the bridge and the proxy's container stand,
that the relay client is configured — the settings line names for the
operator to read before a board meets it.

The service finds `docker`, and a bare `--mailer`, on `PATH`, and runs
each with its own environment: `DOCKER_HOST`, `DOCKER_CONTEXT` and its
user's Docker configuration choose the Engine every call reaches — the
unit sets none, so the host's own — and the relay client reads its own
configuration at every send.

The figures the design fixes are constants, each carded where it is
defined, and no flag or variable sets them: the queue's depth, the
looks' cap and the dark claim's retry (`src/flow.rs`), the `/health`
wait (`src/health.rs`), the mail's retry (`src/sender.rs`), a request's
caps and deadlines and the status page's refresh (`src/pages.rs`), the
sign-up file's cap (`src/signups.rs`), the record's key cap
(`src/record.rs`), the rates a line is said at (`src/rates.rs`), and the
runs' hardening and the image's port and volume (`src/docker.rs`). A
change to one is a ruling's, made in the code; nothing at the VM moves
it. The unit's own settings — its user and group, its state directory,
its umask, its restarts, its stop and its open-file limit — are
`deploy/skep-provision.service`'s, each commented where it is set.

A build with the `test-hooks` feature also takes `--docker-fake
<SCRIPT>`, a scripted Docker runner in place of the host's `docker`, and
`--mailer-fake <LOG>`, which appends each message to a file. The
feature is off by default and no shipped build enables it, so a
shipped binary refuses both flags as unknown arguments. The crate's own
tests turn it on through a dev-dependency on the crate itself.

## The requests it answers

One request per connection, read and written through `skep-http`. A pool
of connection threads (`--connections`), made at start, serves them, a
connection past the pool waiting in the listener's queue; the request in
and the answer out have a minute each, so a client that trickles its
bytes is cut off rather than holding a thread. A panic
answering one request costs that connection alone, closed unanswered,
never its thread, and is said in one line by the binary's own hook —
`skep-provision: [<name>: ]the <thread> thread panicked at <file:line>`,
the board the thread was on where it was on one, and the panic's message
only where it is a literal the code wrote. An `accept` that fails — the
descriptor limit met — is said once, `connections: accept failed (…)`,
and its recovery once, with the count and the span; the pool standing
full is said the same way, `connections: all <n> threads serving …` once
as it fills and once a thread has stood free for fifteen seconds. Every
page is plain HTML with no script and nothing fetched from elsewhere.

The log is bounded against a stranger's requests, which come at a
request's rate and would otherwise drown the lines an operator reads —
past journald's limit on a unit's lines every line is dropped for the
rest of its interval, and below it the flood rotates the journal: a
refusal no invite bounds (a post with no code of the code's form, a code
the invite file does not hold or holds spent, a sign-up with no address)
is said at most once a minute, with the count of like ones since; a
failure met at every request (the invite file unread, the sign-up file
unkept, a look at a name not made) is said once as it starts, naming the
file and what it refuses, and once, with the count, as it ends.

- `GET /` is the sign-up page: one field, an email address.
- `POST /signup` keeps the address and answers a thanks page. An address
  the rule refuses (one `@` with a side each way, at most 254 bytes, ASCII
  alone, no control character, no whitespace, none of
  `( ) < > [ ] : ; \ , "`) is shown on the page again.
- `GET /claim` is the claim form: the board's name, the record, and the
  invite code, pre-filled from the `invite` query value where the query
  decodes and gives one.
- `POST /claim` judges the post before any `docker` call. The invite
  code must be one the file holds issued. The name must be one label
  after lowercasing: `[a-z0-9-]`, 2 to 63 bytes, no hyphen at either
  end — never hex digits alone, which a container command reads as the
  prefix of a container's ID, nor `localhost` or one of the `ip6-` names
  every container's hosts file answers. The record goes to
  `skep_identity::parse_enroll`, trimmed of its trailing line breaks;
  every key must be the production kind and decode, sixteen at most —
  what the hosted claim's genesis admits. Then the name must be free: not
  taken — no snippet, no volume and no container stands under it — and
  not held by a post in flight. A refused post is shown on the form
  again in the words for what refused it — a name taken, held or out of
  the label rule meets D-4, and one character, a hosts-file name or hex
  digits alone each a sentence of its own — and leaves no file and no
  queue entry; its log line names what refused it — the board whose post
  or live board holds a held invite, the posts that fill a full queue or
  the looks' cap, the board a spent invite was spent under. An admitted
  post is queued and answered with D-7 and its status URL, its log line
  naming its invite's issue date.
- `GET /status/<token>` shows D-7 while the post waits or runs, the live
  reply once the board is routed, and D-8 once it failed. A token the
  service does not hold is 404, and a token from before a restart is one
  of those: its page says a restart most often ends one, where a board
  that went live stands, and the person's next act — post again, or,
  where their name now meets D-4's "taken", write to the owner, for the
  board under it may be theirs. The reply ends on how long its status
  URL stands: until the service next restarts.
- Every other request is 404. A request the HTTP subset refuses — a head
  past 16 KiB or malformed, one cut off early, one that spent its minute —
  is 400, and so is a body the form decoder refuses (a `%` without two hex
  digits, or more than three fields); a body past 397,312 bytes (a record
  at its 128 KiB cap with every byte percent-encoded, and 4 KiB) is 413.

A page showing D-7 refreshes itself to the status URL every five
seconds with a `<meta>` refresh. Every status the service writes is one
`skep-http`'s reason table holds.

## The steps

A pool of worker threads (`--workers`) makes boards for different names
at once. The name is the unit of exclusion: a name is held from the
moment its post is admitted until the board is live or the post has
failed, a second post for a name in flight is refused on the
form (D-4), and so no two workers ever run the steps for one name. A post
waits on no board being made: its checks run under a short lock on the
queue and the status map, and its three reads of what stands under its
name take no lock at all and never wait behind a provisioning, so every
post is answered at once. Up to four posts make those reads at once, one
per invite, and up to four wait in the queue; a fifth past either is
answered D-8, "try again later", the first with no `docker` call.

A worker runs the deployment notes' §4 steps 3 to 5 for each post, in
order, saying `<name>: taken by a worker` as it takes it, with how long
the post waited and how many still wait — so a board taken with no `LIVE`
or `FAILED` after it is one being made, and never one still queued — and
saying its end, live or failed, with how long its steps took:

- **Step 3, the claim run.** Look again: no snippet, volume or container
  stands under the name. Then the volume,
  `docker volume create --label skep.provision=1 <name>`, labelled so the
  sweep at start finds it, and the claim run on it: the image bound to its
  own loopback, nothing published, the board's public origin
  `https://<name>.<suffix>` configured.
- **Step 4, the dark claim.** The sidecar's `skep claim --hosted -` in the
  claim run's network namespace, the record on its stdin, retried while
  the daemon is not yet listening. The six lines it prints are the claim;
  any other answer is a failure. Then `docker rm -f` the claim run.
- **Step 5, the serving run and the route.** The serving run on the
  bridge, then the sidecar's `skep health` until the board answers a
  claimant with local trust off — sixty tries a second apart, the wait
  saying its bound as it begins and what it sees at every fifteenth try,
  so no stretch of a board's steps goes a minute unsaid, and a silence
  that long is a `docker` call that has not returned. Then the snippet
  written to
  `<boards-dir>/<name>.caddy`, then the proxy reloaded. These two are a
  route change: one lock, the route lock, is held across a snippet's write
  and its reload, whichever name a worker is on, so route changes are
  serial and no reload lands between another board's snippet and its own
  reload. Where the write or the reload fails, the lock is held on across
  the snippet's removal and the reload that undoes it, so no other board's
  reload loads a snippet whose own route change failed. The lock is held
  nowhere else. The serving run sets `SKEPD_ORIGIN` alone of the daemon's
  per-board settings, so each board runs the image's baked settings and
  the daemon's defaults for the rest: uploads on, no node prefix, the
  default workers, no blocked-prefix list.

Then the status turns live, the invite is spent, and the mail goes to the
sender's own thread, its hand-over said with the mails ahead of it. That
thread sends one mail at a time, retries a refused send (seven tries, ten
minutes apart) and never holds up the next post; a send that panics gives
up its own mail, and no other. A refused try is said by the relay client's
exit code and its `sysexits.h` name, `exit 75 (EX_TEMPFAIL)`, never by the
relay's words, which name the recipient. A mail given up says the
operator's act: the person written to by hand, at the address the invite
file's line spent under the board holds (RUNBOOK.md §10 step 11).

When a step fails, what the steps made is undone in reverse order: the
snippet removed and the proxy reloaded where it may stand — a write's
error can come after its rename — the run removed where one may stand —
a `docker run` that fails can leave its container — its last lines read
and logged first, `<name>: cleanup: the run said: …`, the board's own
account of the failure, which the removal takes with it — the volume
removed. Where the `/health` wait gave up, the log names the last body's
pair as the board answered it (`claimant null`, a claim not on the
volume, reads apart from `local_trust true`).
Then the service looks again at what stands under the name, as a post
does, and the log says what it found: done, or INCOMPLETE naming what
still stands — a removal that itself failed. The status turns to D-8, and
the invite stays issued so the person can post again. Where something
still stands, the name stays taken until the operator clears it: the
snippet with `rm <boards-dir>/<name>.caddy` and a reload of the proxy
(`docker exec <caddy> caddy reload --config /etc/caddy/Caddyfile`), the
run with `docker rm -f <name>`, the volume with `docker volume rm <name>`
— a volume left with no snippet the next start's sweep clears too. Where
the look itself could not be made, its line names its source,
`docker could not run` or the snippet directory by its path, and the act
once one can be. A refused `docker rm -f` of a run that was never made,
and a reload that fails, leave nothing standing, and the log says done.
The look reads an Engine that cannot be reached as nothing standing, as a
post's look does; the removals' log lines above it then name the Engine,
and the next start's sweep finds the volume it left. A step that panics
is a failed step, and a cleanup that panics fails its post all the same,
the log saying INCOMPLETE: a panic costs its post, never the worker.

## The sweep at start

A stop in the middle of a board, before its snippet is written, leaves its
volume, and perhaps a run, standing under a name with no snippet — a name
the service would read as taken for good. So once `serve` has bound its
address and holds its state directory's `serve.lock`, and before it
serves, it lists the volumes that carry this service's label
(`docker volume ls -q --filter label=skep.provision=1`) — saying so on a
line of its own before it asks, so a start held by an Engine that does not
answer names the call it waits on — and, for each whose name is one label
of the grammar and has no `<name>.caddy` in the snippet directory, runs
the last two rows of the cleanup, `docker rm -f <name>` and
`docker volume rm <name>`, each answer logged, and then looks at what
stands: where something still stands, the log names it and the name stays
taken, for the operator — a volume left with no snippet the next start's
sweep's too. A volume whose snippet stands is left alone — it is a live
board, or one whose run stands stopped: `--restart on-failure` brings a
run back from a failure of its own, and by Docker's documentation not from
the Engine's restart or a reboot (RUNBOOK.md §10 step 12) — and so is a
listed volume whose name is not one of the grammar, which the log names; a
snippet that stands with no labelled volume — a route to no board, its
name taken for good, or a board made by hand outside the label — is named
and left; and a routed board with no line of the invite file spent under
it — a stop between its snippet's write and its spend, a spend that could
not be written, or its spent line removed by hand — is named and left, for
its invite may still say issued and a post on it is admitted again until
the operator marks it spent (RUNBOOK.md §10 step 11). If the listing
itself fails, the log says so, the sweep is skipped, and the service still
serves; a half-made board then stays taken until a start whose listing
answers. A sweep that listed ends on a line of its own: the volumes
listed, the half-made among them, those cleared, the names left
INCOMPLETE, and the time it took. The serving line carries the count of
boards cleared, `swept <n>`.

**The snippet directory is the list of boards the sweep spares.** A
labelled volume whose snippet is gone is half-made to it, however long it
has stood: a start over a directory emptier than the Engine's volumes — a
VM restored with its volumes and not the directory, `--boards-dir`
pointed elsewhere, a route taken down by removing its snippet — removes
every board it lacks, its run and its volume. Back up and restore the
directory, the state directory and the volumes as one moment
(RUNBOOK.md §10 step 14), and take a route down by stopping its run, its
snippet left (RUNBOOK.md §10 step 3).

The sweep asks one thing of the operator: **one `serve` per Docker host**.
The label is the host's, the same on every `serve`'s volumes, and a volume
is half-made by this service's snippet directory alone — so a second
service on the host would read the first's boards in flight, and under
another `--boards-dir` its live boards too, as half-made, and remove them.
A second `serve` over the same state directory — a binary started by hand
beside the unit — is refused at its start before its sweep, as is one on
the same port; a staging one under another of each, nothing in a volume
tells apart, and the operator keeps it.

## The strings

Every sentence a person reads lives in one table, `src/strings.rs`.
Each row names where its words come from:

- `D-1` … `D-9` are the deployment notes' draft rows for the form;
- `DRAFT` rows are words this crate wrote where no ruled text exists: the
  sign-up page, the thanks page, the refusals of a name Docker cannot take
  as a name alone, the invite refusal, the status URL, the reply's
  heading, the mail's subject and the error pages;
- `RULED` rows are carried verbatim: the public-venue statement, the
  three facts, and the two acts from the `skep` command's own format
  strings with the public origin filled in — the reply's suite reads the
  acts back from `skep-cli`'s source, so the two cannot drift apart;
- `RULED-SUBSTANCE / DRAFT-WORDING` rows are the operator sentence and the
  anchorless sentence, ruled in substance and worded here.

A row's `{slot}` is filled where the row is shown: every page fills the
site's two, the suffix and the owner's address, into any row it shows,
D-7's page the status URL beside them, and the reply its own four. A row
shown where a slot it names is not filled fails the test that renders
it, in every debug build; a release build shows the slot as written.

The live reply is rendered by one function for the page and the mail
alike. The `local_trust` clause has no row: the service never shows it,
because a board with local trust on fails the `/health` step.

## The files it keeps

- `<state-dir>/signups` holds one line per sign-up, `<address> <date>`. A
  repeated address is one more line, and the owner reads the file by hand.
  The file is capped at 256 KiB: a sign-up that would carry it past is
  refused, nothing written, until the owner trims the file.
  **The address is the one personal datum this program keeps.** How long
  it is kept is the operator's to decide and say; this crate decides
  none.
- `<state-dir>/invites` holds one line per invite: `<code> <address>
  issued <date>`, or `<code> <address> spent <name> <date>` once the
  invite's board is live. The code is an opaque string of URL-safe
  characters: 128 random bits as hex, or the `--code` value given. The
  invite's address is where the mail goes.
- `<state-dir>/invites.lock` is held over each rewrite of the invite file,
  so the service's spend and the owner's `invite` never lose each other's
  change. It is made `0600` and held there, as every file in the state
  directory is.
- `<state-dir>/serve.lock` is held by a running `serve` for its life, so a
  second `serve` over the same state directory is refused at its start.
- `<boards-dir>/<name>.caddy` is one board's proxy snippet, mode `0644`.
  The status map is rebuilt from these files at start: each snippet is a
  name routed at start, which the serving line counts as `live`. A snippet
  with no volume under the label behind it is said at the sweep.
- Every volume it creates carries the label `skep.provision=1` on the
  host's Docker, the one mark by which the sweep at start tells its
  volumes from every volume of another making; every `serve` marks its
  volumes alike, so one service per Docker host.

The two state files are written whole to a temp file and renamed into
place, born `0600`, and each snippet the same way: the temp file is made
fresh where nothing stands at its name, so a write follows no link
planted there. Every file is its maker's, so a run as anyone but the state
directory's owner — `invite` run as root over the service's — is refused
at the directory's door, naming both owners, before any state file is
written: a file root made there would be one the service could not read.
The door tells the owner by a probe file it makes and removes at once.

The start says the sign-up file's fill against its cap, and so does every
sign-up kept, `a sign-up kept; the file holds <n> of its 262144 bytes`;
the cap, once met, is said once — every sign-up refused until the owner
trims the file — and its end once, with the count refused. A file a
failure meets is named by its path in the line that says it.

## What it never logs

The log is one line per step on stderr, each naming the board, the step
and each call's exit code, with the sidecar's stderr kept whole — which
names each entry of the record by its fingerprint and its label, the
person's own words, already on the board with the record. It never
carries the record whole or a key of it, a person's address, an invite
code or a status token: where the operator must find an invite's line by
hand, it names the line's issue date — at the post's admission, and again
where its spend could not be written — and where a mail is given up, the
board whose spent line holds the address. A panic's line carries its
message only where it is a literal the code wrote, never one formatted
from a request. The one line on stdout is the serving line.

## What it holds, and how it ships

It holds no key. The record is the person's public line, and the sidecar
it runs signs nothing. What it does hold is the reach of the Docker
socket, through the host's `docker` command and the `docker` group.

The release archive carries it beside the daemon
([README.md](../../README.md), Prebuilt binaries), and the systemd unit
that runs it is
[deploy/skep-provision.service](../../deploy/skep-provision.service),
installed as [RUNBOOK.md](../../RUNBOOK.md) §10 says.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
