FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
# Pinned interop client image: a real, unmodified OpenVPN 2.6 client from
# Debian bookworm, self-built rather than pulled from a third-party image of
# unknown/unpinned version (CLAUDE.md "self-built image" policy).
#
# Digest resolved 2026-08-23 via `docker buildx imagetools inspect
# debian:bookworm-slim` (manifest-list digest, multi-arch — safe to build on
# both amd64 CI runners and arm64 developer machines).

# Resolved openvpn/tcpdump/iproute2/iputils-ping/curl package versions as of
# 2026-08-27 (`apt-cache policy` against this exact base digest) —
# recorded here so a future version drift shows up in a diff of this
# file, not silently:
#   openvpn       2.6.14-0+deb12u2
#   tcpdump       4.99.3-1
#   iproute2      6.1.0-3
#   iputils-ping  3:20221126-1+deb12u1
#   curl          7.88.1-10+deb12u15
#
# iputils-ping is added for 02-03-PLAN.md Task 1's live data-channel round
# trip: the entrypoint pings the server's pushed tunnel IP once the real
# client's tun0 interface is up, proving Session.Read/Write carry genuine
# encrypted IP traffic, not merely that the control-channel handshake
# completed.
#
# curl is added for 03-06-PLAN.md Task 1's HTTP page-load probes
# (RESEARCH.md flagged it absent from this image, with "add to the
# Dockerfile" as the stated fallback): entrypoint.sh uses it to load the
# tunnelweb site's pages through the tunnel and assert on their content
# markers.
RUN apt-get update && \
    apt-get install --no-install-recommends -y openvpn tcpdump iproute2 iputils-ping curl && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
