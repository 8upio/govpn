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

# A minimal, credential-free final stage: a static binary with no shell, no
# package manager, and no root filesystem beyond the binary itself. The
# non-root uid/gid (65534), no-added-capabilities, no-host-device posture is
# enforced by test/interop/docker-compose.yml's `user:` field rather than
# baked into this image, so it is verifiable at runtime via `docker inspect`
# on the live container (see the plan's T-01-07 mitigation).
FROM scratch
COPY --from=build /out/interop-server /interop-server
ENTRYPOINT ["/interop-server"]
