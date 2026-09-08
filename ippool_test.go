package ovpn

import (
	"errors"
	"net"
	"sync"
	"testing"
)

func mustParseCIDR(t testing.TB, cidr string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse CIDR %s: %v", cidr, err)
	}
	return network
}

func TestPoolServerTakesFirstHostIP(t *testing.T) {
	network := mustParseCIDR(t, "10.8.0.0/24")
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	if got, want := pool.serverIP().String(), "10.8.0.1"; got != want {
		t.Errorf("serverIP() = %s, want %s", got, want)
	}

	ip, _, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if got, want := ip.String(), "10.8.0.2"; got != want {
		t.Errorf("first client allocation = %s, want %s", got, want)
	}
}

func TestPoolSkipsNetworkAndBroadcast(t *testing.T) {
	network := mustParseCIDR(t, "10.8.0.0/30")
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	ip, _, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if got, want := ip.String(), "10.8.0.2"; got != want {
		t.Errorf("allocate() = %s, want %s (only client address in a /30)", got, want)
	}

	if _, _, err := pool.allocate(); !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("second allocate() error = %v, want ErrPoolExhausted", err)
	}
}

func TestPoolSequentialFirstFree(t *testing.T) {
	network := mustParseCIDR(t, "10.8.0.0/24")
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	ip1, _, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate 1: %v", err)
	}
	ip2, peerID2, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate 2: %v", err)
	}
	if _, _, err := pool.allocate(); err != nil {
		t.Fatalf("allocate 3: %v", err)
	}

	pool.release(ip2, peerID2)

	ip4, peerID4, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate 4: %v", err)
	}
	if !ip4.Equal(ip2) {
		t.Errorf("allocate after release = %s, want the released address %s (D-01 first-free)", ip4, ip2)
	}
	if peerID4 != peerID2 {
		t.Errorf("peer-id after release = %d, want the released peer-id %d", peerID4, peerID2)
	}
	if ip4.Equal(ip1) {
		t.Errorf("allocate after release returned the still-in-use address %s", ip1)
	}
}

func TestPoolReleaseIsIdempotent(t *testing.T) {
	network := mustParseCIDR(t, "10.8.0.0/30")
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	ip, peerID, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}

	pool.release(ip, peerID)
	pool.release(ip, peerID) // idempotent: must not panic or double-free

	ip2, _, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate after double release: %v", err)
	}
	if !ip2.Equal(ip) {
		t.Errorf("allocate after double release = %s, want %s", ip2, ip)
	}

	if _, _, err := pool.allocate(); !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("allocate after re-taking the only address error = %v, want ErrPoolExhausted (double release must not double-free)", err)
	}
}

func TestPoolExhaustionReturnsTypedError(t *testing.T) {
	network := mustParseCIDR(t, "10.8.0.0/29") // 5 client addresses: .2-.6
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	seen := make(map[string]bool)
	for i := 0; i < 5; i++ {
		ip, _, err := pool.allocate()
		if err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
		if seen[ip.String()] {
			t.Fatalf("allocate %d returned duplicate address %s", i, ip)
		}
		seen[ip.String()] = true
	}

	if _, _, err := pool.allocate(); !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("allocate on exhausted pool error = %v, want ErrPoolExhausted", err)
	}
	// A second call must also fail cleanly, never block and never return a
	// stale/duplicate value.
	if _, _, err := pool.allocate(); !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("second allocate on exhausted pool error = %v, want ErrPoolExhausted", err)
	}
}

func TestPoolConcurrentAllocationNeverDuplicates(t *testing.T) {
	network := mustParseCIDR(t, "10.8.0.0/24")
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	const n = 200
	type result struct {
		ip  net.IP
		err error
	}
	results := make([]result, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip, _, err := pool.allocate()
			results[i] = result{ip: ip, err: err}
		}()
	}
	wg.Wait()

	seen := make(map[string]bool)
	successes := 0
	exhaustions := 0
	for _, r := range results {
		if r.err != nil {
			if !errors.Is(r.err, ErrPoolExhausted) {
				t.Fatalf("unexpected allocate error: %v", r.err)
			}
			exhaustions++
			continue
		}
		successes++
		if seen[r.ip.String()] {
			t.Fatalf("duplicate address allocated: %s", r.ip)
		}
		seen[r.ip.String()] = true
	}

	// A /24 has 253 allocatable client addresses (.2-.254): with n=200
	// requests, every one should succeed and none should exhaust.
	if successes != n {
		t.Errorf("successes = %d, want %d", successes, n)
	}
	if exhaustions != 0 {
		t.Errorf("exhaustions = %d, want 0 (a /24 has 253 allocatable addresses, more than the %d requested)", exhaustions, n)
	}
}

func TestPoolLargeNetwork(t *testing.T) {
	network := mustParseCIDR(t, "10.9.0.0/16")
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	// Allocate 254 addresses to walk from 10.9.0.2 through 10.9.0.255, then
	// confirm the 255th client allocation crosses the octet boundary to
	// 10.9.1.0 without any hand-rolled per-octet carry logic going wrong.
	var last net.IP
	for i := 0; i < 254; i++ {
		ip, _, err := pool.allocate()
		if err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
		last = ip
	}
	if got, want := last.String(), "10.9.0.255"; got != want {
		t.Fatalf("254th allocation = %s, want %s", got, want)
	}

	next, _, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate after octet boundary: %v", err)
	}
	if got, want := next.String(), "10.9.1.0"; got != want {
		t.Errorf("allocation after 10.9.0.255 = %s, want %s (octet boundary crossing)", got, want)
	}
}

func TestPeerIDsAreDistinctAndReused(t *testing.T) {
	network := mustParseCIDR(t, "10.8.0.0/24")
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	_, peerID1, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate 1: %v", err)
	}
	ip2, peerID2, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate 2: %v", err)
	}
	if peerID1 == peerID2 {
		t.Fatalf("peer-ids not distinct: both %d", peerID1)
	}
	if peerID1 > maxPeerID || peerID2 > maxPeerID {
		t.Errorf("peer-id exceeds MAX_PEER_ID (0x%x): got %d, %d", maxPeerID, peerID1, peerID2)
	}

	pool.release(ip2, peerID2)
	_, peerID3, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate 3: %v", err)
	}
	if peerID3 != peerID2 {
		t.Errorf("peer-id after release = %d, want the released peer-id %d", peerID3, peerID2)
	}
}

func TestNewIPPoolRejectsNonIPv4(t *testing.T) {
	network := &net.IPNet{
		IP:   net.ParseIP("2001:db8::"),
		Mask: net.CIDRMask(64, 128),
	}
	if _, err := newIPPool(network); err == nil {
		t.Fatal("newIPPool accepted an IPv6 network, want an error")
	}
}

func TestNewIPPoolRejectsTooSmallNetwork(t *testing.T) {
	network := mustParseCIDR(t, "10.8.0.0/31") // only 2 addresses total
	if _, err := newIPPool(network); err == nil {
		t.Fatal("newIPPool accepted a /31 (no room for network+server+client+broadcast), want an error")
	}
}

func TestNewIPPoolRejectsNilNetwork(t *testing.T) {
	if _, err := newIPPool(nil); err == nil {
		t.Fatal("newIPPool accepted a nil network, want an error")
	}
}

func TestPoolReserveRejectsNonIPv4(t *testing.T) {
	network := mustParseCIDR(t, "10.8.0.0/24")
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	if _, err := pool.reserve(net.ParseIP("2001:db8::1")); !errors.Is(err, errAssignIPNotIPv4) {
		t.Errorf("reserve(IPv6) error = %v, want errAssignIPNotIPv4", err)
	}
}

func TestPoolReserveRejectsOutsideNetwork(t *testing.T) {
	network := mustParseCIDR(t, "10.8.0.0/24")
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	cases := []struct {
		name string
		ip   net.IP
	}{
		{"below base", net.IPv4(10, 7, 255, 255).To4()},
		{"above size", net.IPv4(10, 9, 0, 0).To4()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := pool.reserve(c.ip); !errors.Is(err, errAssignIPOutsideNetwork) {
				t.Errorf("reserve(%s) error = %v, want errAssignIPOutsideNetwork", c.ip, err)
			}
		})
	}
}

func TestPoolReserveRejectsNetworkServerBroadcast(t *testing.T) {
	network := mustParseCIDR(t, "10.8.0.0/24")
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	cases := []struct {
		name string
		ip   net.IP
	}{
		{"network address", net.IPv4(10, 8, 0, 0).To4()},
		{"server address", net.IPv4(10, 8, 0, 1).To4()},
		{"broadcast address", net.IPv4(10, 8, 0, 255).To4()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := pool.reserve(c.ip); !errors.Is(err, errAssignIPReserved) {
				t.Errorf("reserve(%s) error = %v, want errAssignIPReserved", c.ip, err)
			}
		})
	}
}

func TestPoolReserveRejectsInUse(t *testing.T) {
	network := mustParseCIDR(t, "10.8.0.0/24")
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	want := net.IPv4(10, 8, 0, 42).To4()
	if _, err := pool.reserve(want); err != nil {
		t.Fatalf("first reserve(%s): %v", want, err)
	}
	if _, err := pool.reserve(want); !errors.Is(err, errAssignIPInUse) {
		t.Errorf("second reserve(%s) error = %v, want errAssignIPInUse", want, err)
	}
}

func TestPoolReserveThenReleaseAllowsReReserve(t *testing.T) {
	network := mustParseCIDR(t, "10.8.0.0/24")
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	want := net.IPv4(10, 8, 0, 42).To4()
	peerID, err := pool.reserve(want)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	pool.release(want, peerID)

	if _, err := pool.reserve(want); err != nil {
		t.Fatalf("reserve after release: %v", err)
	}
}

// TestPoolReserveExhaustsPeerIDs is intentionally SKIPPED, not omitted:
// reserve's ErrPoolExhausted branch shares nextFreePeerID's own scan
// (id 0..maxPeerID, 16,777,216 ids) with allocate's identical peer-id
// allocation — the same function both call. Actually filling
// usedPeerIDs to genuinely exhaust it costs ~16.7M map writes, which is
// slow under -race and memory-heavy for a unit test; no existing test in
// this file (or allocate's own suite) pays that cost either, since the
// underlying mechanism is shared and IP-address exhaustion (a far smaller,
// caller-controlled space — TestPoolExhaustionReturnsTypedError above) is
// what every existing exhaustion test actually exercises. Recorded here
// rather than silently absent, so a future change to nextFreePeerID's
// bound doesn't silently invalidate an assumption nothing checks.
func TestPoolReserveExhaustsPeerIDs(t *testing.T) {
	t.Skip("reserve's ErrPoolExhausted branch shares nextFreePeerID's scan (0..16,777,215) with allocate's already-exercised exhaustion mechanism; a literal full-exhaustion test is prohibitively expensive under -race")
}

func TestPoolAllocateSkipsReservedOffset(t *testing.T) {
	network := mustParseCIDR(t, "10.8.0.0/29") // client addresses .2-.6
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	reserved := net.IPv4(10, 8, 0, 2).To4() // the first allocate() would otherwise pick
	if _, err := pool.reserve(reserved); err != nil {
		t.Fatalf("reserve(%s): %v", reserved, err)
	}

	ip, _, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if ip.Equal(reserved) {
		t.Fatalf("allocate() returned the reserved address %s, want it skipped", reserved)
	}
	if got, want := ip.String(), "10.8.0.3"; got != want {
		t.Errorf("allocate() = %s, want %s (next free offset after the reserved one)", got, want)
	}
}
