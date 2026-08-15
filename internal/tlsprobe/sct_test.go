package tlsprobe

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// Invariant R3 again, applied to a number rather than to a list.
//
// A count of zero is the most misleading value this report carries. Signed
// certificate timestamps reach a client one of two ways: in the handshake, or
// embedded in the certificate. This probe reads the first and not the second,
// and almost every authority uses the second — so a certificate that is
// properly logged, and that every browser accepts on exactly those grounds,
// reports none.
//
// The number is published in the JSON, so somebody is going to read it. Either
// it is explained or it is a claim that most of the web is absent from
// certificate transparency.
func TestZeroTimestampCountIsExplained(t *testing.T) {
	host, port, stop := localTLSServer(t)
	defer stop()

	report, err := loopbackProber().Probe(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(report.Certificates) == 0 {
		t.Fatal("the local server presented no certificate; the test proves nothing")
	}
	if report.SCTCount != 0 {
		t.Skipf("the test server delivered %d timestamps; this test covers the zero case", report.SCTCount)
	}

	var explained bool
	for _, note := range report.Notes {
		if strings.Contains(note, "transparency log") {
			explained = true
		}
	}
	if !explained {
		t.Errorf("a report counting no timestamps does not say what that excludes; notes: %v", report.Notes)
	}
}

// The note belongs to a report that has a certificate to talk about. A scan
// that reached nothing has no timestamps because it has no certificate, and
// saying so there would add a sentence about transparency logs to a report
// whose actual finding is that nothing answered.
func TestTimestampNoteIsAbsentWhenNothingWasReached(t *testing.T) {
	// A dialer that never connects, as the rest of this package's tests use.
	// Nothing here touches the network.
	prober := &Prober{
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, errors.New("no network in this test")
		},
		HandshakeTimeout: time.Second,
		TotalTimeout:     5 * time.Second,
	}

	report, err := prober.Probe(context.Background(), "example.invalid", "443")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(report.Certificates) != 0 {
		t.Fatal("a probe that reached nothing produced a certificate; the test proves nothing")
	}

	for _, note := range report.Notes {
		if strings.Contains(note, "transparency log") {
			t.Errorf("a report that reached nothing carries the timestamp note: %q", note)
		}
	}
}
