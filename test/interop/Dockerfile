FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
# Pinned interop client image: a real, unmodified OpenVPN 2.6 client from
# Debian bookworm, self-built rather than pulled from a third-party image of
# unknown/unpinned version (CLAUDE.md "self-built image" policy).
#
# Digest resolved 2026-08-23 via `docker buildx imagetools inspect
# debian:bookworm-slim` (manifest-list digest, multi-arch — safe to build on
# both amd64 CI runners and arm64 developer machines).

# Resolved openvpn/tcpdump/iproute2 package versions as of 2026-08-23
# (`apt-cache policy` against this exact base digest) — recorded here so a
# future version drift shows up in a diff of this file, not silently:
#   openvpn   2.6.14-0+deb12u2
#   tcpdump   4.99.3-1
#   iproute2  6.1.0-3
RUN apt-get update && \
    apt-get install --no-install-recommends -y openvpn tcpdump iproute2 && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
