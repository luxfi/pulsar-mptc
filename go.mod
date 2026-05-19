module github.com/luxfi/pulsar-mptc

go 1.26.3

require (
	github.com/cloudflare/circl v1.6.3
	github.com/luxfi/pulsar v1.0.7
)

require (
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
)

// Local development overlay — uses the in-tree canonical pulsar
// instead of the published module. Stripped by scripts/cut-submission.sh
// at NIST tarball cut time; replaced with `go mod vendor` snapshot.
replace github.com/luxfi/pulsar => ../pulsar
