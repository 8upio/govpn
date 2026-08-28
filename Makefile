.PHONY: test interop golden gates

# Fast tier: vet, build, and the race-enabled unit + golden-vector tests
# (including internal/wire/golden_test.go and
# internal/tlscrypt/golden_test.go, which assert against real OpenVPN 2.6
# client bytes committed in testdata/golden). Never touches Docker. This is
# the default target (first rule in this file) — the cheap check stays
# reflexive. Depends on gates so this phase's own standing prohibitions
# (gates_test.go, 02-04-PLAN.md Task 3) are enforced on every default run,
# not opted into separately.
test: gates
	go vet ./...
	go build ./...
	go test -race ./...

# Runs the standing prohibition gates (gates_test.go) — every
# must_haves.prohibitions entry declared across Phase 2's, Phase 3's, and
# Phase 4's plans, turned into assertions that fail a normal `go test` run
# rather than sitting in a document nobody greps.
gates:
	go test -race -run 'TestPhase2|TestPhase3|TestPhase4' -v ./

# Full interop tier: generates a fresh test PKI in Go (large profile, so
# the certificate-fragmentation assertions have something to fragment —
# TestMain regenerates the correct profile per scenario internally too;
# this first run just guarantees test/interop/pki exists before Docker
# starts), builds the digest-pinned Debian OpenVPN 2.6 client image and the
# harness server image, and runs the full scenario table (clean-small,
# clean-large, lossy-large) via the Docker Compose-based end-to-end
# harness (01-04-PLAN.md Task 1).
interop:
	go run ./cmd/gentestpki -out test/interop/pki -profile large
	go test -tags interop -count=1 -timeout 900s ./test/interop/ -run TestInteropScenarios -v

# Regenerates testdata/golden from a fresh interop run's clean-large
# scenario capture (01-04-PLAN.md Task 2). A deliberate act, never a side
# effect of `test` or `interop` — see test/interop/golden_export.go.
golden:
	go test -tags interop -count=1 -timeout 900s ./test/interop/ -run TestInteropScenarios -update-golden -v

.DEFAULT_GOAL := test
