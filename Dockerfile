# THE HOSTED IMAGE — `skep-hosted`: the daemon as an operator deploys it, one
# container per board behind a reverse proxy, a fresh named volume each
# (README.md, Running the hosted image; the deployment obligations are
# AUTH-4.57's one list). A notebook, a developer's machine and a self-run
# board run the plain binary and never this image: the daemon's `--bind`
# defaults to loopback, and this image alone sets it to the container's
# address, where the container's network is the boundary.
#
# ONE file, three targets:
#   skep-hosted        the default (the last stage)
#     docker build -t skep-hosted .
#   skep-hosted:debug  the same, on the :debug runtime (busybox: a shell, wget)
#     docker build -t skep-hosted:debug \
#         --build-arg RUNTIME="$(sed -n 's/^ARG RUNTIME_DEBUG=//p' Dockerfile)" .
#   skep-cli           the claim sidecar — the `skep` command alone
#     docker build -t skep-cli --target skep-cli .
#
# Both platforms the alpha runs on build from this one file under buildx —
# linux/arm64 (an Apple-silicon Mac) and linux/amd64 (the VM):
#     docker buildx build --platform linux/amd64 -o type=tar,dest=skep-hosted-amd64.tar .
# Every base image is pinned by its multi-arch INDEX digest, so one pin
# serves both; the tag stands beside each digest for the reader.

# THE RUNTIME BASE: distroless cc on Debian 13 — glibc, libgcc and libstdc++,
# no shell, no package manager; the stack is pure Rust and needs nothing
# else. The `:debug` variant adds busybox for the `skep-hosted:debug` tag:
# the same binary, user, volume and baked environment, NEVER behind a
# customer route. RUNTIME selects the base a build uses; RUNTIME_DEBUG is
# the debug reference, read by the debug build's --build-arg (the README's
# and scripts/docker-smoke.sh's build lines) and by nothing below.
ARG RUNTIME=gcr.io/distroless/cc-debian13:latest@sha256:159783207c2cd44c2aa5715961d13c8612368ac9bd450f887e3f08fc8ea461e3
ARG RUNTIME_DEBUG=gcr.io/distroless/cc-debian13:debug@sha256:5fc950b828e978e45c4b9cf957766ba7d4063b4cf5ed6a1a6833aad646145cc9

# ── the builder ───────────────────────────────────────────────────────────
# The pinned toolchain (rust-toolchain.toml: 1.99.0) on Debian 13 "trixie",
# the release the runtime is built from, so the glibc the binaries link is
# the glibc they run against.
FROM rust:1.99.0-trixie@sha256:6ff07edce8775d0f64be7aba9197229407301bddf2054d62c27b541a6238a181 AS chef
# cargo-chef lays the dependency build ahead of the source copy, so a source
# edit rebuilds the crates and not the dependency graph. Pinned.
RUN cargo install cargo-chef --locked --version 0.1.78
WORKDIR /src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
# The dependency layer, for exactly the two build lines below.
RUN cargo chef cook --release -p skepd --no-default-features --recipe-path recipe.json \
 && cargo chef cook --release -p skep-cli --bin skep --no-default-features --recipe-path recipe.json
COPY . .
# THE COMMIT the two binaries' `--version` names. .git is outside the
# context, so it arrives as REVISION, the build argument the images' labels
# read too, and reaches the compiler as SKEP_GIT_SHA (each binary's
# `option_env!`), cut to the twelve characters scripts/release-pack.sh
# names a release by; `unknown` where the build names none. Declared after
# the dependency layer, whose cache a new commit therefore leaves standing.
ARG REVISION=unknown
# THE TWO BUILD LINES. `-p skepd` alone — a `--workspace` build turns the
# signer on for everything it builds (RUNBOOK.md §3 step 1) — and
# `--no-default-features`: `observe` off (no `GET /dump`), `client` never on
# (no page at `GET /`; AUTH-4.57 (e)). The sidecar's `skep` without `tls`:
# the hosted arm dials loopback and signs nothing.
RUN SKEP_GIT_SHA="$(printf '%.12s' "$REVISION")" \
 && export SKEP_GIT_SHA \
 && cargo build --release --locked -p skepd --no-default-features \
 && cargo build --release --locked -p skep-cli --bin skep --no-default-features
# The volume's root, made here because the runtime has no shell: owned by
# the daemon's user and closed. THE DATA DIRECTORY IS ONE LEVEL BELOW IT,
# /var/lib/skepd/board: the daemon creates it itself at 0700 with every file
# 0600, whatever the umask, and REFUSES at start a directory with any group
# or other bit set — so the volume's root, which the runtime populates and
# owns, is never the data directory itself.
RUN install -d -m 700 -o 10001 -g 10001 /out/var/lib/skepd

# ── target: skep-cli — the claim sidecar ──────────────────────────────────
# `skep` alone, run in the daemon's network namespace for the dark claim:
#   docker run --rm --network container:<daemon> -v ./<record>:/payload:ro \
#       skep-cli skep claim --board http://127.0.0.1:8642 --hosted /payload
# No ENTRYPOINT: the run line names the command, as the recipe writes it; a
# bare run prints the command's usage.
FROM ${RUNTIME} AS skep-cli
ARG VERSION=0.1.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="skep-cli" \
      org.opencontainers.image.description="the skep command, built without tls for the hosted board's claim sidecar" \
      org.opencontainers.image.source="https://github.com/sisbell/skep" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=builder /src/target/release/skep /usr/local/bin/skep
USER 10001:10001
CMD ["skep", "--help"]

# ── target: skep-hosted — THE DEFAULT ─────────────────────────────────────
FROM ${RUNTIME} AS skep-hosted
# The OCI labels: the source, the version (the workspace's `version`,
# passed by the build script; the default restates it), the revision (the
# git commit, a build argument since .git is outside the context — the
# builder compiles its first twelve characters into `skepd --version`) and
# the licenses.
ARG VERSION=0.1.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="skep-hosted" \
      org.opencontainers.image.description="skepd, the skep daemon, as a hosted board: its own user, a closed data directory on a volume, local trust off, bound to the container's address" \
      org.opencontainers.image.source="https://github.com/sisbell/skep" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
# The binary, root-owned: the process cannot rewrite its own program.
COPY --from=builder /src/target/release/skepd /usr/local/bin/skepd
# The volume's root with its owner and its mode (the builder's `install -d`),
# copied as an entry of /var/lib so the mode survives the copy.
COPY --from=builder --chown=10001:10001 /out/var/lib/ /var/lib/
VOLUME /var/lib/skepd
# THE BAKED SET (AUTH-4.57 pin (i): "a hosted image must pass
# --no-local-trust affirmatively" — the daemon's own usage words): everything
# a run needs to be safe is here, and nothing per board is — SKEPD_ORIGIN
# (the origin the board is dialed at), SKEPD_NODE_PREFIX (where a registry
# minted one), SKEPD_UPLOADS, SKEPD_WORKERS and SKEPD_BLOCKED_PREFIXES are
# the run line's. The CLAIM RUN overrides the bind — `-e SKEPD_BIND=127.0.0.1`,
# no port published — so the board is claimed on loopback before the
# override is set (AUTH-4.57 (a)); the serving run takes the baked bind.
ENV SKEPD_DATA_DIR=/var/lib/skepd/board \
    SKEPD_LOCAL_TRUST=false \
    SKEPD_BIND=0.0.0.0 \
    SKEPD_PORT=8642
EXPOSE 8642
# Never root at runtime; numeric, since distroless has no useradd.
USER 10001:10001
# No HEALTHCHECK: the release image has no client and the daemon no probe
# mode; the proxy's health-conditioned route on GET /health is the probe
# (AUTH-4.57 (d)), the debug tag's `wget -qO- http://127.0.0.1:8642/health`
# the hand check. No CMD: every setting is an environment variable. The run
# line carries `--init`, since the daemon handles no signal and as PID 1
# without an init would not take SIGTERM.
ENTRYPOINT ["skepd"]
