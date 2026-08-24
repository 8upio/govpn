# Phase 2: Tunnel Up — External API Coverage

**Assessed:** 2026-08-24 (planner, `/gsd-plan-phase 02`)

## Declaration

No external API integration: implements the OpenVPN wire protocol from the local C reference checkout; zero external services or SDKs.

## Reasoning

Every capability this phase delivers is a wire-format or crypto behavior specified
by the pinned OpenVPN 2.6 C reference at `/Users/svenloth/dev/openvpn-reference`
(branch `release/2.6`, commit `c9b790f`):

| Capability | Specified by | External API? |
|---|---|---|
| TLS 1.0 PRF (`openvpn_PRF` / `tls1_P_hash`) | `src/openvpn/ssl.c:1476-1517`, `src/openvpn/crypto_openssl.c:1467-1626` | No — hand-written against stdlib `crypto/md5`, `crypto/sha1`, `crypto/hmac` |
| Key Method 2 message codec | `src/openvpn/ssl.c:1890-1905, 1952-1959, 2387-2431` | No — byte layout read from source |
| Key expansion + per-direction slots | `src/openvpn/ssl.c:1519-1560, 1579-1630`, `src/openvpn/crypto.c:1506-1531` | No |
| PUSH_REQUEST / PUSH_REPLY | `src/openvpn/push.c:41, 567, 629-643, 775-837, 1089`, `src/openvpn/helper.c:496-558` | No — plain NUL-terminated ASCII |
| P_DATA_V2 AES-256-GCM | `src/openvpn/crypto.c:62-151, 340-470`, `src/openvpn/ssl.c:4142-4155` | No — stdlib `crypto/aes` + `crypto/cipher` |
| Replay window | `src/openvpn/packet_id.c`, `src/openvpn/packet_id.h:100` | No |
| Ping/keepalive magic | `src/openvpn/ping.c:42-45` | No |

`go.mod` remains at `module github.com/8upio/govpn` / `go 1.24` with **no `require`
directive** — the phase adds zero dependencies. RESEARCH.md's Package Legitimacy
Audit records zero packages proposed, so the Package Legitimacy Gate does not apply.

The only externally-produced software this phase interacts with is the pinned
**OpenVPN 2.6.14 Debian client binary** already built and digest-pinned by Phase 1's
`test/interop/Dockerfile`. It is a test fixture (the interop counterparty), not an
API this library integrates against, and it is not reachable from the core module.

## Assumption Delta (recorded, not re-asked)

This phase moves `Config.OnSession` from "TLS established" to "tunnel up" and adds a
second packet family (`P_DATA_V1`/`P_DATA_V2`) alongside the control opcodes. The
promote-vs-add-alongside question is **already decided** in `02-CONTEXT.md`:

- **D-08** — `OnSession` fires only after Key Method 2 + PUSH_REPLY complete and
  data-channel keys are live. The Phase-1 callsite in `runHandshake` moves deeper;
  it is not duplicated.
- **D-16** — Data packets get their own peer-id-keyed routing path
  (`Server.dataSessions map[uint32]*Session`); `handleDatagram` gains an
  opcode-class branch **before** the existing `packet[1:9]` session-ID parse, which
  is only valid for control opcodes (RESEARCH.md Pitfall 3).

Both are implemented as planned decisions in `02-02-PLAN.md` (D-08) and
`02-03-PLAN.md` (D-16). No further discussion is required.
