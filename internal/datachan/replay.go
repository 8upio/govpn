// This file (replay.go) implements the data channel's own 64-wide sliding
// anti-replay window (DATA-02).
//
// replayWindowSize: src/openvpn/packet_id.h:100 (DEFAULT_SEQ_BACKTRACK = 64,
// pinned reference checkout /Users/svenloth/dev/openvpn-reference, branch
// release/2.6, commit c9b790f5b9e8ebca5da38c22f479c31bb8d33686). Consulted
// only after crypto_check_replay's own AEAD tag verification, mirrored
// here by Open's ordering (crypto.c:438-455).
//
// replayWindow below is a DELIBERATE, independent copy of
// internal/tlscrypt's own replayWindow type and accept method — not a
// shared import. There are three genuinely separate packet-ID sequence
// spaces in this codebase: the control-channel reliability layer's own
// packet ID (internal/reliable.PacketID), internal/tlscrypt's own
// long-form (sequence + timestamp) packet ID, and this package's own
// short-form (4-byte, no timestamp) data-channel packet ID. Unifying any
// two of these windows "for simplicity" would make a legitimate packet on
// one sequence space get rejected because a number from a DIFFERENT
// sequence space happened to collide numerically — 02-RESEARCH.md Pitfall
// 5 documents exactly this failure mode. Keep this copy independent; do
// not refactor it into a shared type across packages.
package datachan

import "sync"

// replayWindowSize: packet_id.h:100 (DEFAULT_SEQ_BACKTRACK).
const replayWindowSize = 64

// replayWindow is a sliding anti-replay window over the data channel's own
// 32-bit packet ID — the same mu/init/highest/seen bit-shift design
// internal/tlscrypt.replayWindow already uses, copied here as its own
// independent instance (see this file's package doc).
type replayWindow struct {
	mu      sync.Mutex
	init    bool
	highest uint32
	seen    uint64 // bit i set means (highest - i) has been seen
}

// accept reports whether seq is acceptable (not a duplicate, not below the
// window floor) and marks it seen if so. Must only ever be called after
// the packet carrying seq has already passed AEAD authentication (T-02-15)
// — accept has no way to enforce that itself, so callers (Open) own the
// ordering.
func (r *replayWindow) accept(seq uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.init {
		r.init = true
		r.highest = seq
		r.seen = 1
		return true
	}

	if seq > r.highest {
		shift := seq - r.highest
		if shift >= replayWindowSize {
			r.seen = 1
		} else {
			r.seen = (r.seen << shift) | 1
		}
		r.highest = seq
		return true
	}

	diff := r.highest - seq
	if diff >= replayWindowSize {
		return false // below the window floor
	}
	bit := uint64(1) << diff
	if r.seen&bit != 0 {
		return false // duplicate
	}
	r.seen |= bit
	return true
}
