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
	out := scanTo(t, "denyfirst.dev:443", net.JoinHostPort(host, port), watchingFetcher(&asked), nil)

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

// The ordinary build searches, when a caller configured a searcher.
//
// The direction that is easy to lose. A guard written to keep the demonstration
// quiet is one condition away from keeping everything quiet, and the failure
// would be silent: every report would simply omit the line, which is also what a
// deployment that configured no searcher correctly does.
func TestTheOrdinaryBuildSearchesTheLogsWhenAsked(t *testing.T) {
	host, port := revocationServer(t, "http://lists.example/one.crl")

	var fetched, searched atomic.Bool
	scanTo(t, "denyfirst.dev:443", net.JoinHostPort(host, port),
		watchingFetcher(&fetched), watchingSearcher{asked: &searched})

	if !searched.Load() {
		t.Error("a searcher was configured and nothing asked it. A certificate somebody else " +
			"obtained for this name is on somebody else's server and will never appear in a " +
			"handshake here; the logs are the only place it is visible")
	}
}

// And a deployment that configured none asks nobody.
func TestNoSearcherMeansNoSearch(t *testing.T) {
	host, port := revocationServer(t, "http://lists.example/one.crl")

	var fetched atomic.Bool
	out := scanTo(t, "denyfirst.dev:443", net.JoinHostPort(host, port),
		watchingFetcher(&fetched), nil)

	if out.LoggedLine != "" {
		t.Errorf("a report carries %q with no searcher configured; a sentence about the logs "+
			"from a scan that never asked them is a claim about somebody else's records",
			out.LoggedLine)
	}
}
