package tlsprobe

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A report names every address its handshakes reached.
//
// One scan is thirteen connections and each resolves the name again, so the
// address at the top of a report is the address of one handshake among many.
// Recording the set is what lets the report say whether the rows below it
// describe one machine.
func TestAReportNamesTheAddressesItReached(t *testing.T) {
	host, port, stop := localTLSServer(t)
	defer stop()

	report, err := loopbackProber().Probe(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if len(report.AddressesReached) == 0 {
		t.Fatal("the report names no address reached, so it cannot say whether one machine answered")
	}
	// One server, so one address, and Address has to be among them or the two
	// fields disagree about what was measured.
	if len(report.AddressesReached) != 1 {
		t.Errorf("one server answered and the report names %d addresses: %v",
			len(report.AddressesReached), report.AddressesReached)
	}
	if report.Address != report.AddressesReached[0] {
		t.Errorf("the address at the top of the report (%s) is not one it reached (%v)",
			report.Address, report.AddressesReached)
	}

	// And no note, because there is nothing to say.
	for _, note := range report.Notes {
		if strings.Contains(note.Text, "reached more than one address") {
			t.Error("a scan of one server says it reached more than one address")
		}
	}
}

// And it says so when they were not the same machine.
//
// This is the case the report could not see. A name on several addresses
// hands successive connections to different machines whenever the resolver
// rotates its answer, and the report merged them: it printed one address and
// presented every version, suite and certificate below as though one server
// had produced them all. No row was false. The report as a whole made a claim
// it had never checked.
//
// Two listeners and a dialler that alternates is exactly that situation, with
// the resolver's part played by something a test can control.
func TestAScanThatReachedTwoMachinesSaysSo(t *testing.T) {
	firstHost, firstPort, stopFirst := localTLSServer(t)
	defer stopFirst()
	secondHost, secondPort, stopSecond := localTLSServer(t)
	defer stopSecond()

	if firstPort == secondPort {
		t.Fatal("both test servers took the same port, so there is only one address to reach")
	}

	var turn atomic.Int64
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	prober := &Prober{
		HandshakeTimeout: 5 * time.Second,
		TotalTimeout:     20 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Alternate, the way a rotating answer set does.
			if turn.Add(1)%2 == 0 {
				return dialer.DialContext(ctx, network, net.JoinHostPort(secondHost, secondPort))
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(firstHost, firstPort))
		},
	}

	report, err := prober.Probe(context.Background(), firstHost, firstPort)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if len(report.AddressesReached) < 2 {
		t.Fatalf("the scan reached %v, so the alternating dialler did not do what this test needs",
			report.AddressesReached)
	}

	var said bool
	for _, note := range report.Notes {
		if strings.Contains(note.Text, "reached more than one address") {
			said = true
			for _, addr := range report.AddressesReached {
				if !strings.Contains(note.Text, addr) {
					t.Errorf("the note does not name %s, which this scan reached:\n  %s", addr, note.Text)
				}
			}
		}
	}
	if !said {
		t.Error("a scan whose handshakes reached two machines presented them as one server " +
			"and said nothing about it")
	}
}

// The set is a set, and it keeps the order things were reached in.
func TestTheAddressesReachedAreRecordedOnceEach(t *testing.T) {
	s := newAddressSet()
	for _, addr := range []string{"192.0.2.1:443", "", "198.51.100.7:443", "192.0.2.1:443", ""} {
		s.add(addr)
	}

	got := s.list()
	want := []string{"192.0.2.1:443", "198.51.100.7:443"}
	if len(got) != len(want) {
		t.Fatalf("recorded %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("recorded %v, want %v", got, want)
			break
		}
	}
}
