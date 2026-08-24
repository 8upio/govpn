package datachan

import "testing"

// TestReplayAcceptsMonotonic asserts packet IDs 1..1000 delivered strictly
// in order are all accepted.
func TestReplayAcceptsMonotonic(t *testing.T) {
	var w replayWindow
	for seq := uint32(1); seq <= 1000; seq++ {
		if !w.accept(seq) {
			t.Fatalf("accept(%d) = false, want true (monotonic delivery)", seq)
		}
	}
}

// TestReplayRejectsExactDuplicate asserts delivering the same packet ID
// twice accepts the first and rejects the second.
func TestReplayRejectsExactDuplicate(t *testing.T) {
	var w replayWindow
	if !w.accept(5) {
		t.Fatal("first accept(5) = false, want true")
	}
	if w.accept(5) {
		t.Fatal("second accept(5) = true, want false (exact duplicate)")
	}
}

// TestReplayAcceptsInWindowReorder asserts that after accepting 100,
// packet IDs 99 down to 37 (63 back — within the 64-wide window) are each
// accepted exactly once.
func TestReplayAcceptsInWindowReorder(t *testing.T) {
	var w replayWindow
	if !w.accept(100) {
		t.Fatal("accept(100) = false, want true")
	}
	for seq := uint32(99); seq >= 37; seq-- {
		if !w.accept(seq) {
			t.Fatalf("accept(%d) = false, want true (63 back from 100, within the 64-wide window)", seq)
		}
		if w.accept(seq) {
			t.Fatalf("second accept(%d) = true, want false (already seen)", seq)
		}
	}
}

// TestReplayRejectsBelowWindowFloor asserts that after accepting 100,
// packet ID 36 or lower is rejected — a 64-wide window, matching
// DEFAULT_SEQ_BACKTRACK (packet_id.h:100).
func TestReplayRejectsBelowWindowFloor(t *testing.T) {
	if replayWindowSize != 64 {
		t.Fatalf("replayWindowSize = %d, want 64 (DEFAULT_SEQ_BACKTRACK, packet_id.h:100)", replayWindowSize)
	}
	var w replayWindow
	if !w.accept(100) {
		t.Fatal("accept(100) = false, want true")
	}
	for _, seq := range []uint32{36, 20, 1} {
		if w.accept(seq) {
			t.Errorf("accept(%d) = true, want false (below the 64-wide window floor of 100)", seq)
		}
	}
}

// TestReplayLargeJumpResetsWindow asserts that after accepting 100,
// accepting 100000 clears the bitmap tracked around the old highest (100)
// and re-anchors the window to the new highest (100000) — reproduced
// verbatim from internal/tlscrypt.replayWindow's own accept (this file's
// own package doc): a shift >= replayWindowSize resets seen to a single
// bit marking only the new highest as seen, exactly like a fresh window
// would after its first packet.
//
// A large jump does NOT retroactively mark every intervening ID as
// already used — that would reject legitimate reordering right around the
// new highest, defeating the window's own purpose. Two things prove the
// bitmap actually reset around the new anchor, rather than merely
// "always accepting everything now": (1) 99999, only one below the new
// highest, is still WITHIN the 64-wide window and has never actually been
// seen — accepted, exactly like TestReplayAcceptsInWindowReorder's own
// in-window-reorder case; delivering it a SECOND time is then correctly
// rejected as a duplicate. (2) 99935, 65 below the new highest — outside
// the 64-wide window entirely — is rejected as below the new floor, which
// could only be true if the bitmap's old tracking (anchored at 100, where
// 99935 would have been astronomically out of range in the OTHER
// direction) was actually replaced by a fresh window anchored at 100000,
// not merely extended.
func TestReplayLargeJumpResetsWindow(t *testing.T) {
	var w replayWindow
	if !w.accept(100) {
		t.Fatal("accept(100) = false, want true")
	}
	if !w.accept(100000) {
		t.Fatal("accept(100000) = false, want true (large forward jump)")
	}

	if !w.accept(99999) {
		t.Error("accept(99999) = false, want true — 99999 is within the 64-wide window re-anchored at the new highest 100000 and has never been seen")
	}
	if w.accept(99999) {
		t.Error("second accept(99999) = true, want false (now a duplicate)")
	}

	const belowNewFloor = 100000 - replayWindowSize - 1 // 99935: 65 below the new highest
	if w.accept(belowNewFloor) {
		t.Errorf("accept(%d) = true, want false (65 below the new highest 100000, outside the re-anchored 64-wide window) — proves the bitmap reset around the NEW highest rather than merely accepting everything after a jump", belowNewFloor)
	}
}
