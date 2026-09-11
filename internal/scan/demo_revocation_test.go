//go:build demo

package scan

import (
	"net"
	"sync/atomic"
	"testing"
)

// The demonstration asks no certificate authority anything.
//
// Its privacy page says so in those words. The promise is kept by the guard in
// Scan, and until this test a sabotage removing that guard changed nothing any
// test could see — the page would have gone on making a claim the code had
// stopped honouring, which is the one failure this project treats as worse
// than a bug.
//
// Driven under the tag because that is the only build where the question
// exists. The ordinary build's opposite is asserted in revocation_off_test.go,
// so neither direction rests on the other being remembered.
func TestTheDemonstrationAsksNoAuthorityAnything(t *testing.T) {
	host, port := revocationServer(t, "http://lists.example/one.crl")

	var asked atomic.Bool
	scanTo(t, "denyfirst.dev:443", net.JoinHostPort(host, port), watchingFetcher(&asked))

	if asked.Load() {
		t.Error("the demonstration build tried to fetch a revocation list. Its privacy page " +
			"promises that no certificate authority is asked anything, and that promise is " +
			"this deployment's whole argument for existing in public")
	}
}
