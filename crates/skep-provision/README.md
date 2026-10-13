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
  disposition stops it at once. Every file it keeps is replaced whole by a
  rename, so no stop tears one; a board cut off before its snippet is
  written leaves what was made standing, and the next `serve` removes it
  before it listens (see [The sweep at start](#the-sweep-at-start)); a
  board cut off after its snippet is written and before its invite is
  spent stands, routed — or routed at the proxy's next reload — and the
  next `serve` counts it live and leaves it, its invite still issued: a
  post on that invite is admitted again unless the owner marks it spent.
  The log names such a board, its `snippet: written` with no
  `the invite is spent` after it.
- **`invite`** mints one invite into the state directory's invite file
  and prints one line on stdout, the invite link: the claim form's URL
  carrying the code, `https://<suffix>/claim?invite=<code>`. The owner
  mails that line by hand.
- **`--version`**, the first argument, prints `skep-provision <version>
  (<commit>)`, the form `skepd --version` prints.

A usage refusal (an unknown flag, a missing value, a required flag
missing, `--mailer` without `--from` or the reverse) exits 2 with the usage
text; a start refused (a loose state directory, an unreadable snippet
directory, an address that cannot be bound, a thread the machine will not
give) or an `invite` that printed no invite link exits 1, as does a
`--version` or `--help` whose text cannot be written.

## `serve`'s flags

Each default is a named constant in `src/args.rs`, and the usage text
renders it from there.

| flag | default | what it sets |
|---|---|---|
| `--state-dir <DIR>` | required | the sign-up file and the invite file; made `0700` where absent, refused at start where any group or other bit is set |
| `--reply-to <ADDRESS>` | required | the owner's mailbox: the failure page names it, and the mail replies to it |
| `--listen <ADDR:PORT>` | `127.0.0.1:8842` (`DEFAULT_LISTEN`) | where the pages are served; how the proxy reaches it is the VM's configuration |
| `--boards-dir <DIR>` | `/etc/caddy/boards` (`DEFAULT_BOARDS_DIR`) | the proxy's snippet directory |
| `--image <TAG>` | `skep-hosted` (`DEFAULT_IMAGE`) | the hosted image |
| `--cli-image <TAG>` | `skep-cli` (`DEFAULT_CLI_IMAGE`) | the claim sidecar's image |
| `--network <BRIDGE>` | `skep` (`DEFAULT_NETWORK`) | the bridge the boards and the proxy share |
| `--caddy <CONTAINER>` | `caddy` (`DEFAULT_CADDY`) | the proxy's container |
| `--suffix <DOMAIN>` | `skep.host` (`DEFAULT_SUFFIX`) | the domain every board stands under, `<name>.<domain>` |
| `--log-max-size <SIZE>` | `10m` (`DEFAULT_LOG_MAX_SIZE`) | a serving run's log file size |
| `--log-max-file <N>` | `5` (`DEFAULT_LOG_MAX_FILE`) | a serving run's log files kept |
| `--workers <N>` | `3` (`DEFAULT_WORKERS`) | the boards made at once: one worker thread each; `0` is a usage refusal |
| `--connections <N>` | `16` (`DEFAULT_CONNECTIONS`) | the requests served at once: one thread each, made at start, a further connection waiting in the listener's queue; `0` is a usage refusal |
| `--mailer <PROGRAM>` | none | the host's relay client, run as `<PROGRAM> -t` with the message on stdin; given with `--from` or not at all, and with neither no mail is sent and the serving line says so |
| `--from <ADDRESS>` | none | the mail's sending address |

A build with the `test-hooks` feature also takes `--docker-fake
<SCRIPT>`, a scripted Docker runner in place of the host's `docker`, and
`--mailer-fake <LOG>`, which appends each message to a file. The
feature is off by default and no shipped build enables it, so a
shipped binary refuses both flags as unknown arguments. The crate's own
tests turn it on through a dev-dependency on the crate itself.

## The requests it answers

One request per connection, read and written through `skep-http`. A pool
of connection threads (`--connections`, sixteen by default), made at
start, serves them, a connection past the pool waiting in the listener's
queue; the request in and the answer out have a minute each, so a client
that trickles its bytes is cut off rather than holding a thread. A panic
answering one request costs that connection alone, closed unanswered,
never its thread. Every page is plain HTML with no script and nothing
fetched from elsewhere.

- `GET /` is the sign-up page: one field, an email address.
- `POST /signup` keeps the address and answers a thanks page. An address
  the rule refuses (one `@` with a side each way, at most 254 bytes, ASCII
  alone, no control character, no whitespace, none of
  `( ) < > [ ] : ; \ , "`) is shown on the page again.
- `GET /claim` is the claim form: the board's name, the record, and the
  invite code, pre-filled from the `invite` query value.
- `POST /claim` judges the post before any `docker` call. The invite
  code must be one the file holds issued. The name must be one label
  after lowercasing: `[a-z0-9-]`, 2 to 63 bytes, no hyphen at either
  end — never hex digits alone, which a container command reads as the
  prefix of a container's ID, nor `localhost` or one of the `ip6-` names
  every container's hosts file answers. The record goes to
  `skep_identity::parse_enroll`, trimmed of its trailing line breaks, and
  every key must be the production kind. Then the name must be free: not
  taken — no snippet, no volume and no container stands under it — and
  not held by a post in flight. A refused post is shown on the form
  again, and leaves no file and no queue entry. An admitted post is
  queued and answered with D-7 and its status URL.
- `GET /status/<token>` shows D-7 while the post waits or runs, the live
  reply once the board is routed, and D-8 once it failed. A token the
  service does not hold is 404, and a token from before a restart is one
  of those.
- Every other request is 404. A request the HTTP subset refuses — a head
  past 16 KiB or malformed, one cut off early, one that spent its minute —
  is 400, and so is a body the form decoder refuses (a `%` without two hex
  digits, or more than three fields); a body past 397,312 bytes (a record
  at its 128 KiB cap with every byte percent-encoded, and 4 KiB) is 413.

A page showing D-7 refreshes itself to the status URL every five
seconds with a `<meta>` refresh. Every status the service writes is one
`skep-http`'s reason table holds.

## The steps

A pool of worker threads (`--workers`, three by default) makes boards for
different names at once. The name is the unit of exclusion: a name is
held from the moment its post is admitted until the board is live or the
post has failed, a second post for a name in flight is refused on the
form (D-4), and so no two workers ever run the steps for one name. A post
waits on no board being made: its checks run under a short lock on the
queue and the status map, and its three reads of what stands under none,
never behind a provisioning, so every post is answered at once. Up to four
posts make those reads at once, and up to four wait in the queue; a fifth
past either is answered D-8, "try again later", the first with no `docker`
call.

A worker runs the deployment notes' §4 steps 3 to 5 for each post, in
order:

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
  claimant with local trust off. Then the snippet written to
  `<boards-dir>/<name>.caddy`, then the proxy reloaded. These two are a
  route change: one lock, the route lock, is held across a snippet's write
  and its reload, whichever name a worker is on, so route changes are
  serial and no reload lands between another board's snippet and its own
  reload. Where the write or the reload fails, the lock is held on across
  the snippet's removal and the reload that undoes it, so no other board's
  reload loads a snippet whose own route change failed. The lock is held
  nowhere else.

Then the status turns live, the invite is spent, and the mail goes to the
sender's own thread. That thread retries a refused send (seven tries, ten
minutes apart) and never holds up the next post; a send that panics gives
up its own mail, and no other.

When a step fails, what the steps made is undone in reverse order: the
snippet removed and the proxy reloaded where it may stand — a write's
error can come after its rename — the run removed where one may stand —
a `docker run` that fails can leave its container — the volume removed.
Then the service looks again at what stands under the name, as a post
does, and the log says what it found: done, or INCOMPLETE naming what
still stands — a removal that itself failed. The status turns to D-8, and
the invite stays issued so the person can post again. Where something
still stands, the name stays taken until the operator clears it: the
snippet with `rm <boards-dir>/<name>.caddy` and a reload of the proxy
(`docker exec <caddy> caddy reload --config /etc/caddy/Caddyfile`), the
run with `docker rm -f <name>`, the volume with `docker volume rm <name>`.
A refused `docker rm -f` of a run that was never made, and a reload that
fails, leave nothing standing, and the log says done. The look reads an
Engine that cannot be reached as nothing standing, as a post's look does;
the removals' log lines above it then name the Engine, and the next
start's sweep finds the volume it left. A step that panics is a failed
step, and a cleanup that panics fails its post all the same, the log
saying INCOMPLETE: a panic costs its post, never the worker.

## The sweep at start

A stop in the middle of a board, before its snippet is written, leaves its
volume, and perhaps a run, standing under a name with no snippet — a name
the service would read as taken for good. So before `serve` binds its
address it lists the volumes that carry this service's label
(`docker volume ls -q --filter label=skep.provision=1`) and, for each
whose name is one label of the grammar and has no `<name>.caddy` in the
snippet directory, runs the last two rows of the cleanup,
`docker rm -f <name>` and `docker volume rm <name>`, each answer logged,
and then looks at what stands: where something still stands, the log names
it and the name stays taken, for the operator. A volume whose snippet
stands is left alone — it is a live board, or a stopped one that Docker's
`--restart` brings back — and so is a listed volume whose name is not one
of the grammar, which the log names. If the listing itself fails, the log
says so, the sweep is skipped, and the service still serves. The serving
line carries the count of boards cleared, `swept <n>`.

The sweep asks one thing of the operator: **one `serve` per Docker host**.
The label is the host's, the same on every `serve`'s volumes, and a volume
is half-made by this service's snippet directory alone — so a second
service on the host, a staging one or a binary started by hand beside the
unit, would read the first's boards in flight, and under another
`--boards-dir` its live boards too, as half-made, and remove them. Nothing
in a volume tells two services apart, so the service cannot check it.

## The strings

Every sentence a person reads lives in one table, `src/strings.rs`.
Each row names where its words come from:

- `D-1` … `D-9` are the deployment notes' draft rows for the form;
- `DRAFT` rows are words this crate wrote where no ruled text exists: the
  sign-up page, the thanks page, the invite refusal, the status URL,
  the reply's heading, the mail's subject and the error pages;
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
- `<boards-dir>/<name>.caddy` is one board's proxy snippet, mode `0644`.
  The status map is rebuilt from these files at start: each snippet is a
  live name.
- Every volume it creates carries the label `skep.provision=1` on the
  host's Docker, the one mark by which the sweep at start tells its
  volumes from every volume of another making; every `serve` marks its
  volumes alike, so one service per Docker host.

The two state files are written whole to a temp file and renamed into
place, born `0600`, and each snippet the same way: the temp file is made
fresh where nothing stands at its name, so a write follows no link
planted there.

## What it never logs

The log is one line per step on stderr, each naming the board, the step
and each call's exit code, with the sidecar's stderr kept whole — which
names each entry of the record by its fingerprint and its label, the
person's own words, already on the board with the record. It never
carries the record whole or a key of it, a person's address, an invite
code or a status token. The one line on stdout is the serving line.

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
