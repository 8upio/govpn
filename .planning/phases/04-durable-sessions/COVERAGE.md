# Phase 4: Durable Sessions — API Coverage

**Generated:** 2026-08-28

No external API integration: extends the in-repo OpenVPN protocol implementation from the local C reference; zero external services or SDKs.

## Assumption Delta

This phase **pluralizes the per-session data-channel key**: the single, fixed key slot
(`dataChannelKeyID = 0`, `ovpn.go:115-119`, and `Session.dataWrapper`, `session.go:174-181`)
becomes a two-slot key-state structure (primary + lame-duck), mirroring the reference's
`KS_PRIMARY`/`KS_LAME_DUCK` (`ssl_common.h:448-451`).

**Resolution (CONTEXT.md, locked):** promote a key-slot structure on `Session`; the fixed
`dataChannelKeyID = 0` constant retires. Recorded as **D-25** in the plan set. Every
Phase-1/2/3 call site that reads `sess.dataWrapper` (`Write`, `emitPing`, `handleDataPacket`,
`Close`'s snapshot, `performPushExchange`'s atomic publish) migrates to the primary slot in
plan `04-01`, Task 1 — no behavior change for a session that never renegotiates (its primary
slot stays key-id 0 for its whole life, which is exactly what "if key_id is 0, it is the first
key" means in `ssl.c:990-1002`).

## Protocol Constants Sourced This Phase

All from `/Users/svenloth/dev/openvpn-reference` (release/2.6) — the project's designated spec:

| Constant / rule | Value | Source |
|---|---|---|
| `P_KEY_ID_MASK` | `0x07` | `ssl_pkt.h:38` |
| Key-id increment | `(k+1) & 0x07`, `0 → 1` | `ssl.c:990-1002` |
| `occ_magic` | 16 bytes `28 7f 34 6b d4 ef 7a 81 2d 56 b8 d3 af c5 45 9c` | `occ.c:55-58` |
| `OCC_EXIT` | `0x06`, at plaintext offset 16 | `occ.h:29-30,67` |
| `renegotiate_seconds` default | 3600 | `options.c:878` |
| `transition_window` default | **not yet traced — executor must read `options.c` for `--tran-window`** | `ssl.c:1932` (use site) |
| Key-id mismatch disposition | hard error, never a soft drop | `ssl.c:3983-3990` |
