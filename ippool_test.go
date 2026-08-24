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
