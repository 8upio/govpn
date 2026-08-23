.PHONY: test interop

# Fast tier: unit + golden-vector tests only. Never touches Docker.
test:
	go test ./...

# Full interop tier: generates a fresh test PKI in Go, builds the
# digest-pinned Debian OpenVPN 2.6 client image and the harness server
# image, and runs the Docker Compose-based end-to-end harness.
interop:
	go run ./cmd/gentestpki -out test/interop/pki
	go test -tags interop -count=1 -timeout 300s ./test/interop/...
