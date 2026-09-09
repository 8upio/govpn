// serverstats_test.go exercises Welle 2's introspection surface:
// Server.Sessions, Server.Stats, and the four handshake-outcome counters'
// partition invariant. Reuses closereason_test.go's live-tunnel-up harness
// (tunnelUpTestClient, testHandshakeTLSConfig) and ovpn_test.go's own
// poll-with-deadline convention (TestOnSessionDoesNotFireWhenPushNeverArrives)
// rather than adding a second one.
package ovpn

import (
	"bufio"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// waitForCondition polls cond every 5ms until it reports true or timeout
// elapses, failing the test on timeout — the same poll-with-deadline shape
// TestOnSessionDoesNotFireWhenPushNeverArrives already uses in this
// package's own test suite.
func waitForCondition(t *testing.T, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestServerStatsEmptyServer asserts a server with no sessions reports
// Sessions() empty and every Stats() counter zero.
func TestServerStatsEmptyServer(t *testing.T) {
	srv, serverPC, _ := newAssignIPTestServer(t, "10.65.0.0/24", Config{})
	defer serverPC.Close()
	defer srv.Close()

	// Give Serve a moment to actually start reading (irrelevant to this
	// assertion, but matches this file's other tests' setup shape).
	time.Sleep(10 * time.Millisecond)

	if got := srv.Sessions(); len(got) != 0 {
		t.Fatalf("Sessions() = %v, want empty", got)
	}
	stats := srv.Stats()
	if stats.ActiveSessions != 0 {
		t.Errorf("ActiveSessions = %d, want 0", stats.ActiveSessions)
	}
	if stats.HandshakesStarted != 0 || stats.HandshakesCompleted != 0 ||
		stats.HandshakesFailed != 0 || stats.HandshakesTimedOut != 0 ||
		stats.AuthFailed != 0 || stats.AssignIPRejected != 0 ||
		stats.PoolExhausted != 0 || stats.DatagramsRejected != 0 {
		t.Errorf("Stats() on an empty server = %+v, want every counter zero", stats)
	}
}

// TestServerSessionsSortedByIPRegardlessOfConnectOrder asserts three
// established sessions come back from Sessions() sorted ascending by
// assigned IP regardless of connection order, that a closed session drops
// out of the snapshot, and that ActiveSessions equals len(Sessions()).
func TestServerSessionsSortedByIPRegardlessOfConnectOrder(t *testing.T) {
	// Hand out addresses in DESCENDING order as clients connect (.4, .3,
	// .2), so a passing test proves Sessions() actually sorts rather than
	// happening to return connection order.
	addrs := []net.IP{
		net.IPv4(10, 65, 1, 4).To4(),
		net.IPv4(10, 65, 1, 3).To4(),
		net.IPv4(10, 65, 1, 2).To4(),
	}
	var calls int
	srv, serverPC, caPool := newAssignIPTestServer(t, "10.65.1.0/24", Config{
		AssignIP: func(peerCN string, cs tls.ConnectionState) (net.IP, error) {
			ip := addrs[calls]
			calls++
			return ip, nil
		},
	})
	defer serverPC.Close()
	defer srv.Close()

	var clients []*testPushClient
	for range addrs {
		client, reply := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
		clients = append(clients, client)
		doPushRequest(t, client, reply)
	}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()

	waitForCondition(t, 5*time.Second, "Sessions() never reached 3 entries", func() bool {
		return len(srv.Sessions()) == 3
	})

	sessions := srv.Sessions()
	want := []string{"10.65.1.2", "10.65.1.3", "10.65.1.4"}
	for i, sess := range sessions {
		if got := sess.AssignedIP().String(); got != want[i] {
			t.Errorf("Sessions()[%d] = %s, want %s (ascending order)", i, got, want[i])
		}
	}

	stats := srv.Stats()
	if stats.ActiveSessions != len(sessions) {
		t.Errorf("Stats().ActiveSessions = %d, want %d (== len(Sessions()))", stats.ActiveSessions, len(sessions))
	}

	// Close the middle session (10.65.1.3) and confirm it drops out.
	if err := sessions[1].Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	waitForCondition(t, 2*time.Second, "closed session never dropped out of Sessions()", func() bool {
		return len(srv.Sessions()) == 2
	})
	remaining := srv.Sessions()
	for _, sess := range remaining {
		if sess.AssignedIP().String() == "10.65.1.3" {
			t.Fatal("closed session 10.65.1.3 still present in Sessions()")
		}
	}
}

// TestServerSessionsNonEmptyWithoutOnSession asserts Sessions() keys on the
// established latch, not on published — a server with no Config.OnSession
// hook still reports an established session.
func TestServerSessionsNonEmptyWithoutOnSession(t *testing.T) {
	srv, serverPC, caPool := newAssignIPTestServer(t, "10.65.2.0/24", Config{})
	defer serverPC.Close()
	defer srv.Close()

	client, reply := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
	defer client.Close()
	doPushRequest(t, client, reply)

	waitForCondition(t, 2*time.Second, "Sessions() stayed empty with no Config.OnSession hook set", func() bool {
		return len(srv.Sessions()) == 1
	})
}

// TestHandshakeCountersPartitionOutcomes asserts HandshakesStarted
// increments once per new control channel, and each of the four outcome
// counters (Completed/Failed/TimedOut/AuthFailed) increments in exactly the
// scenario that produces it and nothing else — Started ==
// Completed+Failed+TimedOut+AuthFailed after each settled handshake.
func TestHandshakeCountersPartitionOutcomes(t *testing.T) {
	assertPartition := func(t *testing.T, srv *Server) {
		t.Helper()
		s := srv.Stats()
		sum := s.HandshakesCompleted + s.HandshakesFailed + s.HandshakesTimedOut + s.AuthFailed
		if s.HandshakesStarted != sum {
			t.Fatalf("HandshakesStarted = %d, want it to equal Completed+Failed+TimedOut+AuthFailed = %d (stats: %+v)", s.HandshakesStarted, sum, s)
		}
	}

	t.Run("completed", func(t *testing.T) {
		srv, serverPC, caPool := newAssignIPTestServer(t, "10.65.3.0/24", Config{})
		defer serverPC.Close()
		defer srv.Close()

		client, reply := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
		defer client.Close()
		doPushRequest(t, client, reply)

		waitForCondition(t, 2*time.Second, "HandshakesCompleted never reached 1", func() bool {
			return srv.Stats().HandshakesCompleted == 1
		})
		stats := srv.Stats()
		if stats.HandshakesStarted != 1 {
			t.Errorf("HandshakesStarted = %d, want 1", stats.HandshakesStarted)
		}
		if stats.HandshakesFailed != 0 || stats.HandshakesTimedOut != 0 || stats.AuthFailed != 0 {
			t.Errorf("Stats() = %+v, want only HandshakesCompleted set", stats)
		}
		assertPartition(t, srv)
	})

	t.Run("failed", func(t *testing.T) {
		srv, serverPC, caPool := newAssignIPTestServer(t, "10.65.4.0/24", Config{
			AssignIP: func(peerCN string, cs tls.ConnectionState) (net.IP, error) {
				return nil, errAssignIPTestHookError
			},
		})
		defer serverPC.Close()
		defer srv.Close()

		client, reply := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
		defer client.Close()
		doPushRequestExpectNoReply(t, client, reply)

		waitForCondition(t, 2*time.Second, "HandshakesFailed never reached 1", func() bool {
			return srv.Stats().HandshakesFailed == 1
		})
		stats := srv.Stats()
		if stats.HandshakesStarted != 1 {
			t.Errorf("HandshakesStarted = %d, want 1", stats.HandshakesStarted)
		}
		if stats.HandshakesCompleted != 0 || stats.HandshakesTimedOut != 0 || stats.AuthFailed != 0 {
			t.Errorf("Stats() = %+v, want only HandshakesFailed set", stats)
		}
		assertPartition(t, srv)
	})

	t.Run("timed out", func(t *testing.T) {
		_, network, err := net.ParseCIDR("10.65.5.0/24")
		if err != nil {
			t.Fatalf("parse network: %v", err)
		}
		key := testTLSCryptKey(t)
		serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("server listen: %v", err)
		}
		defer serverPC.Close()
		tlsCfg, caPool := testHandshakeTLSConfig(t)

		srv := NewServer(Config{
			TLSCryptKey:  key,
			TLSConfig:    tlsCfg,
			Network:      network,
			AuthUserPass: testPermissiveAuthUserPass,
		})
		srv.handshakeWindow = 100 * time.Millisecond
		go func() { _ = srv.Serve(serverPC) }()
		defer srv.Close()

		client := newTestPushClient(t, key, serverPC.LocalAddr(), caPool)
		defer client.Close()
		// Deliberately never complete the TLS handshake: the client's hard
		// reset alone is enough to create a session and start its
		// handshake-window timer.

		waitForCondition(t, 2*time.Second, "HandshakesTimedOut never reached 1", func() bool {
			return srv.Stats().HandshakesTimedOut == 1
		})
		stats := srv.Stats()
		if stats.HandshakesStarted != 1 {
			t.Errorf("HandshakesStarted = %d, want 1", stats.HandshakesStarted)
		}
		if stats.HandshakesCompleted != 0 || stats.HandshakesFailed != 0 || stats.AuthFailed != 0 {
			t.Errorf("Stats() = %+v, want only HandshakesTimedOut set", stats)
		}
		assertPartition(t, srv)
	})

	t.Run("auth failed", func(t *testing.T) {
		srv, serverPC, caPool := newAssignIPTestServer(t, "10.65.6.0/24", Config{
			AuthUserPass: func(username, password string, cs tls.ConnectionState) error {
				return errAssignIPTestHookError
			},
		})
		defer serverPC.Close()
		defer srv.Close()

		client := newTestPushClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
		defer client.Close()
		if err := client.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		if err := client.tlsConn.Handshake(); err != nil {
			t.Fatalf("client handshake: %v", err)
		}
		if err := writeTestClientKeyMethod2Creds(client.tlsConn, testPlaceholderUsername, testPlaceholderPassword); err != nil {
			t.Fatalf("write client Key Method 2: %v", err)
		}

		waitForCondition(t, 2*time.Second, "AuthFailed never reached 1", func() bool {
			return srv.Stats().AuthFailed == 1
		})
		stats := srv.Stats()
		if stats.HandshakesStarted != 1 {
			t.Errorf("HandshakesStarted = %d, want 1", stats.HandshakesStarted)
		}
		if stats.HandshakesCompleted != 0 || stats.HandshakesFailed != 0 || stats.HandshakesTimedOut != 0 {
			t.Errorf("Stats() = %+v, want only AuthFailed set", stats)
		}
		assertPartition(t, srv)
	})
}

// TestCipherNegotiationFailedCounterDoesNotTouchAuthFailed is Pitfall 3's
// own regression test: a cipher-negotiation refusal increments
// CipherNegotiationFailed and leaves AuthFailed at 0, and a credential
// rejection does the exact reverse — the two counters partition, they never
// double-count the same event.
func TestCipherNegotiationFailedCounterDoesNotTouchAuthFailed(t *testing.T) {
	key := testTLSCryptKey(t)

	t.Run("cipher negotiation failure", func(t *testing.T) {
		_, network, err := net.ParseCIDR("10.65.8.0/24")
		if err != nil {
			t.Fatalf("parse network: %v", err)
		}
		serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("server listen: %v", err)
		}
		defer serverPC.Close()
		tlsCfg, caPool := testHandshakeTLSConfig(t)
		srv := NewServer(Config{
			TLSCryptKey:  key,
			TLSConfig:    tlsCfg,
			Network:      network,
			AuthUserPass: testPermissiveAuthUserPass,
			DataCiphers:  []string{"AES-256-GCM", "AES-128-GCM"},
		})
		go func() { _ = srv.Serve(serverPC) }()
		defer srv.Close()

		// Pre-NCP client (nil peer_info) whose OCC cipher (BF-CBC) is not
		// in the server's allow-list: CIPH-03's refusal path.
		client := dialOCCFallbackTestClient(t, key, serverPC.LocalAddr(), caPool, []byte("cipher BF-CBC"), nil)
		defer client.Close()
		if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
			t.Fatalf("write push request: %v", err)
		}
		reader := bufio.NewReader(client.tlsConn)
		if _, err := readControlString(reader, maxControlStringLen); err != nil {
			t.Fatalf("read AUTH_FAILED: %v", err)
		}

		waitForCondition(t, 2*time.Second, "CipherNegotiationFailed never reached 1", func() bool {
			return srv.Stats().CipherNegotiationFailed == 1
		})
		stats := srv.Stats()
		if stats.AuthFailed != 0 {
			t.Errorf("AuthFailed = %d, want 0 after a cipher-negotiation refusal (stats: %+v)", stats.AuthFailed, stats)
		}
	})

	t.Run("credential rejection", func(t *testing.T) {
		srv, serverPC, caPool := newAssignIPTestServer(t, "10.65.9.0/24", Config{
			AuthUserPass: func(username, password string, cs tls.ConnectionState) error {
				return errAssignIPTestHookError
			},
		})
		defer serverPC.Close()
		defer srv.Close()

		client := newTestPushClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
		defer client.Close()
		if err := client.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		if err := client.tlsConn.Handshake(); err != nil {
			t.Fatalf("client handshake: %v", err)
		}
		if err := writeTestClientKeyMethod2Creds(client.tlsConn, testPlaceholderUsername, testPlaceholderPassword); err != nil {
			t.Fatalf("write client Key Method 2: %v", err)
		}

		waitForCondition(t, 2*time.Second, "AuthFailed never reached 1", func() bool {
			return srv.Stats().AuthFailed == 1
		})
		stats := srv.Stats()
		if stats.CipherNegotiationFailed != 0 {
			t.Errorf("CipherNegotiationFailed = %d, want 0 after a credential rejection (stats: %+v)", stats.CipherNegotiationFailed, stats)
		}
	})
}

// TestDatagramsRejectedCounted drives the cheap dispatch-drop paths
// directly with net.ListenPacket-written datagrams (too-short, bad-opcode)
// rather than through a full handshake, and asserts each increments
// DatagramsRejected by exactly one.
func TestDatagramsRejectedCounted(t *testing.T) {
	srv, serverPC, _ := newAssignIPTestServer(t, "10.65.7.0/24", Config{})
	defer serverPC.Close()
	defer srv.Close()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer client.Close()

	send := func(p []byte) {
		if _, err := client.WriteTo(p, serverPC.LocalAddr()); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}

	before := srv.stats.datagramsRejected.Load()

	// Too short: below minDatagramSize (49 bytes), and not a data-channel
	// opcode either, so it hits the "short-control" branch.
	send([]byte{0x38}) // OpControlHardResetClientV2<<3 | keyID 0, 1 byte total
	waitForCondition(t, 2*time.Second, "DatagramsRejected never reached before+1 (short-control)", func() bool {
		return srv.stats.datagramsRejected.Load() >= before+1
	})

	// Bad opcode: an opcode value with no meaning at all.
	send([]byte{0xF8}) // opcode nibble 0x1F (31), not a valid wire.Opcode
	waitForCondition(t, 2*time.Second, "DatagramsRejected never reached before+2 (bad-opcode)", func() bool {
		return srv.stats.datagramsRejected.Load() >= before+2
	})
}
