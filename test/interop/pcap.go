// Package interop's pcap.go is a minimal, stdlib-only reader for the
// classic libpcap file format: the 24-byte global header, followed by a
// 16-byte record header plus frame data per captured packet. It exists
// specifically to avoid a gopacket dependency for Phase 1's single
// wire-format verification step (RESEARCH Alternatives Considered defers
// gopacket to when Phase 2/3's more elaborate interop assertions actually
// need programmatic pcap parsing).
//
// It yields UDP payload bytes and direction for every record captured on a
// given port, honouring the pcap global header's link-type field rather
// than assuming one, and handling the link types the "any" pseudo-
// interface tcpdump -i any produces (Linux cooked capture, DLT_LINUX_SLL
// and its newer DLT_LINUX_SLL2 variant) as well as plain Ethernet.
package interop

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Direction identifies which side of the captured UDP flow a payload came
// from, relative to the given port (the OpenVPN tunnel port under test).
type Direction int

const (
	// DirClientToServer: the destination port equals the port under test —
	// this is inbound traffic to the OpenVPN server.
	DirClientToServer Direction = iota
	// DirServerToClient: the source port equals the port under test.
	DirServerToClient
)

func (d Direction) String() string {
	if d == DirClientToServer {
		return "client->server"
	}
	return "server->client"
}

// UDPPayload is one captured UDP datagram's payload bytes and direction.
type UDPPayload struct {
	Direction Direction
	Payload   []byte
}

// ErrUnknownLinkType is returned when the pcap global header names a link
// type this reader does not know how to strip a link-layer header from.
// The caller must not guess a fixed offset in this case (Task 2's own
// prohibition) — an unrecognized link type is a hard error, not a silent
// best-effort parse.
var ErrUnknownLinkType = errors.New("pcap: unrecognized link type")

const (
	globalHeaderSize = 24
	recordHeaderSize = 16

	linkTypeEthernet   = 1   // DLT_EN10MB
	linkTypeLinuxSLL   = 113 // DLT_LINUX_SLL ("cooked" capture, e.g. tcpdump -i any)
	linkTypeLinuxSLL2  = 276 // DLT_LINUX_SLL2 (newer cooked-capture variant)
	ethertypeIPv4      = 0x0800
	ethertypeVLANTag   = 0x8100
	ipProtoUDP         = 17
	ethernetHeaderSize = 14
	sllHeaderSize      = 16
	sll2HeaderSize     = 20
)

// magicMicrosecond/magicNanosecond are libpcap's global-header magic
// numbers (microsecond- and nanosecond-resolution timestamp variants,
// respectively); byte order is determined by which interpretation
// (big-endian or little-endian read of the same four bytes) produces one of
// these two values.
const (
	magicMicrosecond uint32 = 0xa1b2c3d4
	magicNanosecond  uint32 = 0xa1b23c4d
)

// detectByteOrder inspects the raw first four bytes of a pcap file's global
// header and returns the byte order the rest of the file's fixed-width
// fields were written in.
func detectByteOrder(magic []byte) (binary.ByteOrder, error) {
	be := binary.BigEndian.Uint32(magic)
	le := binary.LittleEndian.Uint32(magic)
	switch {
	case be == magicMicrosecond || be == magicNanosecond:
		return binary.BigEndian, nil
	case le == magicMicrosecond || le == magicNanosecond:
		return binary.LittleEndian, nil
	default:
		return nil, fmt.Errorf("pcap: unrecognized magic number %x", magic)
	}
}

// ReadUDPPayloads parses r as a libpcap capture file and returns the UDP
// payload bytes and direction of every record whose UDP source or
// destination port equals port. Records for other ports, non-IPv4 frames,
// and frames too short to contain a full link-layer+IP+UDP header are
// silently skipped — only an unrecognized pcap-level link type (declared
// once in the global header, applying to the whole file) is a hard error.
func ReadUDPPayloads(r io.Reader, port uint16) ([]UDPPayload, error) {
	br := bufio.NewReader(r)

	hdr := make([]byte, globalHeaderSize)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, fmt.Errorf("pcap: read global header: %w", err)
	}
	order, err := detectByteOrder(hdr[0:4])
	if err != nil {
		return nil, err
	}
	linkType := order.Uint32(hdr[20:24])
	switch linkType {
	case linkTypeEthernet, linkTypeLinuxSLL, linkTypeLinuxSLL2:
		// supported
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownLinkType, linkType)
	}

	var out []UDPPayload
	recHdr := make([]byte, recordHeaderSize)
	for {
		if _, err := io.ReadFull(br, recHdr); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("pcap: read record header: %w", err)
		}
		inclLen := order.Uint32(recHdr[8:12])

		frame := make([]byte, inclLen)
		if _, err := io.ReadFull(br, frame); err != nil {
			return nil, fmt.Errorf("pcap: read record data (truncated capture): %w", err)
		}

		ipPayload, ok := stripLinkLayer(linkType, frame)
		if !ok {
			continue
		}
		srcPort, dstPort, udpPayload, ok := parseIPv4UDP(ipPayload)
		if !ok {
			continue
		}
		if srcPort != port && dstPort != port {
			continue
		}

		dir := DirServerToClient
		if dstPort == port {
			dir = DirClientToServer
		}
		payload := make([]byte, len(udpPayload))
		copy(payload, udpPayload)
		out = append(out, UDPPayload{Direction: dir, Payload: payload})
	}

	return out, nil
}

// stripLinkLayer removes linkType's link-layer header from frame and
// returns the IPv4 payload beneath it. ok is false (not an error) for a
// too-short frame or a non-IPv4 payload — both are expected, benign
// occurrences in a real capture (ARP, IPv6 neighbor discovery, a truncated
// last record from a killed process) and are skipped by the caller, not
// treated as parse failures. linkType is assumed already validated by the
// caller against the supported set.
func stripLinkLayer(linkType uint32, frame []byte) (ipPayload []byte, ok bool) {
	switch linkType {
	case linkTypeEthernet:
		if len(frame) < ethernetHeaderSize {
			return nil, false
		}
		etherType := binary.BigEndian.Uint16(frame[12:14])
		payload := frame[ethernetHeaderSize:]
		for etherType == ethertypeVLANTag {
			if len(payload) < 4 {
				return nil, false
			}
			etherType = binary.BigEndian.Uint16(payload[2:4])
			payload = payload[4:]
		}
		if etherType != ethertypeIPv4 {
			return nil, false
		}
		return payload, true

	case linkTypeLinuxSLL:
		if len(frame) < sllHeaderSize {
			return nil, false
		}
		protocolType := binary.BigEndian.Uint16(frame[14:16])
		if protocolType != ethertypeIPv4 {
			return nil, false
		}
		return frame[sllHeaderSize:], true

	case linkTypeLinuxSLL2:
		if len(frame) < sll2HeaderSize {
			return nil, false
		}
		protocolType := binary.BigEndian.Uint16(frame[0:2])
		if protocolType != ethertypeIPv4 {
			return nil, false
		}
		return frame[sll2HeaderSize:], true

	default:
		// Unreachable: ReadUDPPayloads validates linkType against the
		// supported set before calling stripLinkLayer.
		return nil, false
	}
}

// parseIPv4UDP parses an IPv4 datagram carrying UDP and returns the source
// port, destination port, and UDP payload bytes. ok is false for anything
// that isn't a well-formed IPv4/UDP datagram — not an error, since a
// capture on a live interface can legitimately contain other traffic.
func parseIPv4UDP(b []byte) (srcPort, dstPort uint16, payload []byte, ok bool) {
	if len(b) < 20 {
		return 0, 0, nil, false
	}
	if b[0]>>4 != 4 {
		return 0, 0, nil, false // not IPv4
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return 0, 0, nil, false
	}
	if b[9] != ipProtoUDP {
		return 0, 0, nil, false
	}

	udp := b[ihl:]
	if len(udp) < 8 {
		return 0, 0, nil, false
	}
	srcPort = binary.BigEndian.Uint16(udp[0:2])
	dstPort = binary.BigEndian.Uint16(udp[2:4])
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))

	end := len(udp)
	if udpLen >= 8 && udpLen <= len(udp) {
		end = udpLen
	}
	return srcPort, dstPort, udp[8:end], true
}
