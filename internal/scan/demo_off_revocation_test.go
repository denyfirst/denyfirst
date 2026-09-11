//go:build !demo

package scan

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

// The ordinary build reads the list the certificate names.
//
// The direction that is easy to lose. A guard written to keep the
// demonstration quiet is one `if` away from keeping everything quiet, and the
// failure would be silent: every report would say revocation was not checked,
// which is a sentence this project prints honestly in so many other situations
// that nobody would look twice.
func TestTheOrdinaryBuildReadsTheRevocationList(t *testing.T) {
	host, port := revocationServer(t, "http://lists.example/one.crl")

	var asked atomic.Bool
	out := scanTo(t, "denyfirst.dev:443", net.JoinHostPort(host, port), watchingFetcher(&asked))

	// And what came of it. The fetcher refuses every connection, so nothing was
	// established — and a report that said otherwise would be claiming a check
	// it did not perform, which is the one wrong answer here that matters (R4).
	if strings.Contains(out.RevocationLine, "does not name this certificate") {
		t.Errorf("the report says the list cleared this certificate after every fetch was "+
			"refused: %q", out.RevocationLine)
	}

	if !asked.Load() {
		t.Error("nothing tried to read the revocation list the certificate names. On every " +
			"deployment but the demonstration this is how revocation is established at all, " +
			"since the authorities issuing for most of the web publish no responder to staple " +
			"from")
	}
}
