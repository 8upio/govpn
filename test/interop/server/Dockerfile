# Builds and runs the interop harness's server: a real embedder of
# github.com/8upio/govpn (test/interop/server/main.go). This is Go build
# tooling for the library under test, not the pinned OpenVPN client image —
# that is test/interop/Dockerfile, one directory up, referenced by sha256
# digest per CLAUDE.md's self-built-image policy. This Dockerfile's own base
# image tag is not pinned by digest: it never runs unmodified third-party
# code the interop assertion depends on, it only compiles this repository's
# own Go source with the standard toolchain.
FROM golang:1.24-bookworm AS build
WORKDIR /src
# Zero external dependencies (go.mod has no require lines), so there is no
# go.sum to copy and no `go mod download` step needed — copy the source
# directly and build.
COPY . .
RUN CGO_ENABLED=0 go build -o /out/interop-server ./test/interop/server
# scratch (below) has no filesystem beyond what's explicitly COPYed in — no
# /tmp, and no shell to `mkdir` one at container start. main.go's
# writeDataChannelKeyExport/writeKeyMethod2Export (02-04-PLAN.md Task 2)
# need a writable /tmp to hand this session's derived key material to
# `docker cp` before the container is torn down, so this build stage
# prepares an empty directory to copy in below.
RUN mkdir -p /out/tmp

# A minimal, credential-free final stage: a static binary with no shell, no
# package manager, and no root filesystem beyond the binary itself and the
# one writable /tmp directory below. The non-root uid/gid (65534),
# no-added-capabilities, no-host-device posture is enforced by
# test/interop/docker-compose.yml's `user:` field rather than baked into
# this image, so it is verifiable at runtime via `docker inspect` on the
# live container (see the plan's T-01-07 mitigation). --chown on this COPY
# is load-bearing, not decorative: COPY --from=<stage> resets ownership to
# root by default regardless of what the source stage's own RUN chown set
# (confirmed live via `docker export` + `tar tv` on a first attempt that
# used a plain COPY — the copied /tmp showed up owned 0:0 despite an
# upstream `chown 65534:65534`), so without --chown here /tmp would be
# unwritable under the exact numeric uid:gid docker-compose.yml's
# `user: "65534:65534"` runs the final container as.
FROM scratch
COPY --from=build /out/interop-server /interop-server
COPY --from=build --chown=65534:65534 /out/tmp /tmp
ENTRYPOINT ["/interop-server"]
