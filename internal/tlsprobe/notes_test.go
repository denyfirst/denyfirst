package tlsprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// localTLSServer starts a TLS listener on loopback and returns its host and
// port.
//
// Every other test in this package uses a dialer that never connects, which
// proves the wiring but never exercises a handshake. This one does, without
// depending on the internet being reachable or on a third party's
// configuration staying still.
func localTLSServer(t *testing.T) (host, port string, stop func()) {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatalf("parsing the test server URL: %v", err)
	}

	host, port, err = net.SplitHostPort(parsed.Host)
	if err != nil {
		srv.Close()
		t.Fatalf("splitting %q: %v", parsed.Host, err)
	}

	return host, port, srv.Close
}

// loopbackProber reaches a local listener, which safedial refuses by design.
// The exception belongs to this test and to nothing that ships.
func loopbackProber() *Prober {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &Prober{
		Dial:             d.DialContext,
		HandshakeTimeout: 5 * time.Second,
		TotalTimeout:     20 * time.Second,
	}
}

// Invariant R3: what could not be measured is stated.
//
// Go's TLS stack offers roughly twenty-seven of the three hundred suites in
// the IANA registry and gives no way to choose among TLS 1.3 suites. A report
// that omits this reads as exhaustive, and a reader would take a short cipher
// list as good news rather than as a partial view.
func TestSupportedVersionsCarryTheCoverageNote(t *testing.T) {
	host, port, stop := localTLSServer(t)
	defer stop()

	report, err := loopbackProber().Probe(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	var anySupported bool
	for _, v := range report.Versions {
		if v.Supported {
			anySupported = true
		}
	}
	if !anySupported {
		t.Fatal("the local TLS server accepted no version; the test proves nothing")
	}

	var declared bool
	for _, note := range report.Notes {
		if strings.Contains(note.Text, "Go's TLS stack") {
			declared = true
		}
	}
	if !declared {
		t.Errorf("a report with supported versions carries no note about what was not offered; notes: %v", report.Notes)
	}
}

// A real handshake, end to end. The rest of this package's tests use a dialer
// that never connects, so nothing else here would notice if the handshake
// path itself broke.
func TestProbeAgainstALocalServer(t *testing.T) {
	host, port, stop := localTLSServer(t)
	defer stop()

	report, err := loopbackProber().Probe(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if len(report.Certificates) == 0 {
		t.Fatal("no certificate chain was collected from a server that completed a handshake")
	}
	if report.Address == "" {
		t.Error("the address connected to was not recorded")
	}
	if report.Policy == "" {
		t.Error("the report does not name the policy that graded it")
	}
	if report.Verdict == "" {
		t.Error("a completed handshake produced no verdict")
	}
	if report.DurationMs < 0 {
		t.Errorf("DurationMs = %d", report.DurationMs)
	}

	// httptest serves TLS 1.2 and 1.3 and refuses the deprecated versions, so
	// a modern version must appear and the obsolete ones must not.
	supported := map[string]bool{}
	for _, v := range report.Versions {
		supported[v.Name] = v.Supported
	}
	if !supported["TLS 1.3"] && !supported["TLS 1.2"] {
		t.Error("neither TLS 1.2 nor TLS 1.3 was detected against a Go TLS server")
	}
	if supported["TLS 1.0"] || supported["TLS 1.1"] {
		t.Error("a deprecated version was reported as accepted by a Go TLS server, which does not offer them")
	}
}
