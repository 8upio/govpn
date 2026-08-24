// This file (ippool.go) implements the Server-scoped tunnel-IP and
// peer-id allocator (D-01, D-02, D-04): sequential first-free allocation
// from a single configured IPv4 *net.IPNet, the server reserving the first
// host address for itself, and a released address/peer-id reused before a
// never-used higher one. It is pure in-memory state — no lease file, no
// persistence, no hold-down timer (D-02) — and never blocks: exhaustion
// returns a typed sentinel error immediately (T-02-08).
//
// IP arithmetic is stdlib net.IP/net.IPNet only, over a flattened uint32
// host-address space, so allocation crosses octet boundaries (e.g.
// 10.9.0.255 -> 10.9.1.0 for a /16) without any hand-rolled per-octet
// carry logic (RESEARCH.md Assumption A1: this pool's arithmetic is this
// project's own design, not upstream-verified, so it is built and tested
// deliberately rather than by analogy).
package ovpn

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

// maxPeerID is the 24-bit ceiling on the peer-id this server assigns and
// pushes as `peer-id <n>` (openvpn.h:552 MAX_PEER_ID).
const maxPeerID = 0xFFFFFF

// ErrPoolExhausted is returned by ipPool.allocate when no free host
// address or peer-id remains. Allocation never blocks and never hands out
// a duplicate — a session that races into exhaustion is closed rather than
// queued (T-02-08).
var ErrPoolExhausted = errors.New("ovpn: tunnel IP pool exhausted")

// ipPool is a Server-scoped, mutex-guarded allocator for tunnel IP
// addresses and peer-ids, drawn from a single configured IPv4 network.
// Every method is safe for concurrent use — the same shape as
// Server.mu/Server.sessions (ovpn.go).
type ipPool struct {
	mu sync.Mutex

	base uint32 // the network address, as a big-endian uint32
	size uint32 // number of addresses in the network (2^(32-prefixlen))

	usedIPs     map[uint32]bool // offset from base -> in use
	usedPeerIDs map[uint32]bool
}

// normalizeIPv4Mask reduces a net.IPMask to its 4-byte IPv4 form. A
// *net.IPNet's Mask can be either a 4-byte or a 16-byte slice depending on
// how it was constructed (e.g. a CIDR string using IPv4-mapped IPv6
// notation, or a manually-built *net.IPNet) — net.IP(mask).String() on the
// 16-byte form formats it as an IPv6 address rather than a dotted-decimal
// IPv4 netmask. Every caller that turns Config.Network's mask into either
// pool arithmetic (newIPPool) or an ifconfig netmask string
// (buildPushReply) must go through this one normalization path (WR-01).
func normalizeIPv4Mask(mask net.IPMask) net.IPMask {
	if len(mask) == net.IPv6len {
		return mask[12:]
	}
	return mask
}

// newIPPool builds an ipPool over network. It handles IPv4 only: a
// non-IPv4 network (or one smaller than a /30, which has no allocatable
// client address once the network, server, and broadcast addresses are
// reserved) is rejected here, at construction, rather than risking
// mis-sliced arithmetic later — net.IP parsed from a string can be 16
// bytes even for an IPv4 address, which is exactly where hand-rolled pool
// arithmetic goes wrong (RESEARCH.md Assumption A1).
func newIPPool(network *net.IPNet) (*ipPool, error) {
	if network == nil {
		return nil, errors.New("ovpn: Config.Network must be set")
	}
	ip4 := network.IP.To4()
	if ip4 == nil {
		return nil, errors.New("ovpn: Config.Network must be an IPv4 network")
	}
	mask := normalizeIPv4Mask(network.Mask)
	if len(mask) != net.IPv4len {
		return nil, errors.New("ovpn: Config.Network must be an IPv4 network")
	}
	ones, bits := net.IPMask(mask).Size()
	if bits != 32 {
		return nil, errors.New("ovpn: Config.Network must be an IPv4 network")
	}
	size := uint32(1) << uint(32-ones)
	if size < 4 {
		return nil, errors.New("ovpn: Config.Network is too small — at least a /30 is required (network + server + one client + broadcast)")
	}

	return &ipPool{
		base:        binary.BigEndian.Uint32(ip4),
		size:        size,
		usedIPs:     make(map[uint32]bool),
		usedPeerIDs: make(map[uint32]bool),
	}, nil
}

// serverIP returns the server's own tunnel address: base+1, the first host
// address in the configured network, reserved and never allocated to a
// client (D-01).
func (p *ipPool) serverIP() net.IP {
	return offsetToIP(p.base + 1)
}

// allocate returns the next free host address — first-free, so a released
// address is reused before a never-used higher one (D-01, D-02) — skipping
// the network address (offset 0), the reserved server address (offset 1),
// and the broadcast address (offset size-1), plus a free peer-id, marking
// both in use. It never blocks: if either is exhausted it returns
// ErrPoolExhausted immediately, never a duplicate and never a wait.
func (p *ipPool) allocate() (net.IP, uint32, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	offset, ok := p.nextFreeOffset()
	if !ok {
		return nil, 0, ErrPoolExhausted
	}
	peerID, ok := p.nextFreePeerID()
	if !ok {
		return nil, 0, ErrPoolExhausted
	}

	p.usedIPs[offset] = true
	p.usedPeerIDs[peerID] = true
	return offsetToIP(p.base + offset), peerID, nil
}

// release returns ip and peerID to the pool so a future allocate call may
// reuse them (D-02: no lease persistence, no hold-down timer). Safe to
// call more than once for the same values (idempotent): releasing an
// already-free entry is a no-op, not an error.
func (p *ipPool) release(ip net.IP, peerID uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if ip4 := ip.To4(); ip4 != nil {
		offset := binary.BigEndian.Uint32(ip4) - p.base
		delete(p.usedIPs, offset)
	}
	delete(p.usedPeerIDs, peerID)
}

func (p *ipPool) nextFreeOffset() (uint32, bool) {
	for o := uint32(2); o < p.size-1; o++ {
		if !p.usedIPs[o] {
			return o, true
		}
	}
	return 0, false
}

func (p *ipPool) nextFreePeerID() (uint32, bool) {
	for id := uint32(0); id <= maxPeerID; id++ {
		if !p.usedPeerIDs[id] {
			return id, true
		}
	}
	return 0, false
}

func offsetToIP(v uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}
