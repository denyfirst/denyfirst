//go:build demo

package webscan

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/webprobe"
)

// A demonstration build refuses a host this project does not own, whatever
// asks it.
//
// The check is in Scan rather than in a caller, so this is the property an
// entry point inherits rather than one each entry point has to remember. The
// HTTP service has no web address yet; when it gets one, this is what makes
// it safe on the day it is written rather than on the day somebody reviews
// it.
func TestTheWebScannerRefusesAHostThisProjectDoesNotOwn(t *testing.T) {
	// A dialler that would answer, so a refusal here is the list refusing and
	// not the network failing.
	s := &Scanner{Prober: &webprobe.Prober{Dial: refuseToDial}}

	_, err := s.Scan(context.Background(), "example.com")
	if !errors.Is(err, demo.ErrNotATarget) {
		t.Fatalf("Scan(example.com) = %v, want demo.ErrNotATarget", err)
	}
}

func TestARefusedHostIsNeverConnectedTo(t *testing.T) {
	// The whole reason the guard sits where it does. Moved below the probe it
	// still returns the same error, every other test here still passes, and
	// the connection has already been opened - which is the one thing the
	// refusal exists to prevent. A sabotage doing exactly that escaped on
	// 2026-09-10 and this is what closed it.
	//
	// The dialler records rather than refuses, because "did not connect" and
	// "tried and failed" are the two things being told apart.
	var dialled int32
	s := &Scanner{Prober: &webprobe.Prober{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			atomic.AddInt32(&dialled, 1)
			return nil, errors.New("nothing is listening")
		},
	}}

	if _, err := s.Scan(context.Background(), "example.com"); !errors.Is(err, demo.ErrNotATarget) {
		t.Fatalf("Scan = %v, want demo.ErrNotATarget", err)
	}
	if n := atomic.LoadInt32(&dialled); n != 0 {
		t.Errorf("%d connection(s) were opened to a host this deployment refuses", n)
	}
}

func TestTheWebRefusalNamesNoHost(t *testing.T) {
	// I6: an error says what the rule is, never what was asked. A refusal
	// that echoes the target back is a refusal that can be used to make this
	// service repeat a string to whoever reads its output.
	s := &Scanner{Prober: &webprobe.Prober{Dial: refuseToDial}}
	_, err := s.Scan(context.Background(), "secret-internal-name.example")
	if err == nil {
		t.Fatal("a host outside the list was accepted")
	}
	if strings.Contains(err.Error(), "secret-internal-name") {
		t.Errorf("the refusal names the host back: %v", err)
	}
}

func TestAMistypedTargetIsToldItIsMistyped(t *testing.T) {
	// Asked the other way round, a demonstration build answers "this
	// deployment does not demonstrate that" to somebody who simply typed a
	// port or a scheme, which tells them the wrong thing about their own
	// mistake.
	s := &Scanner{Prober: &webprobe.Prober{Dial: refuseToDial}}
	for _, bad := range []string{"example.com:443", "https://example.com", "localhost", ""} {
		_, err := s.Scan(context.Background(), bad)
		if errors.Is(err, demo.ErrNotATarget) {
			t.Errorf("Scan(%q) was refused as undemonstrated rather than as invalid", bad)
		}
		if !errors.Is(err, webprobe.ErrNotAHostname) {
			t.Errorf("Scan(%q) = %v, want ErrNotAHostname", bad, err)
		}
	}
}

// Nothing the page offers is a host this scanner then refuses.
//
// The menu and the boundary are separate questions, and they are checked
// against each other because an offer the scanner refuses is a page arguing
// with its own tool, and the visitor loses the argument.
func TestEveryHostOfferedIsOneThisScannerWillReach(t *testing.T) {
	hosts := demo.Hosts()
	if len(hosts) == 0 {
		t.Fatal("the demonstration build offers nothing")
	}
	s := &Scanner{Prober: &webprobe.Prober{Dial: refuseToDial}}
	for _, h := range hosts {
		if _, err := s.Scan(context.Background(), h.Host); errors.Is(err, demo.ErrNotATarget) {
			t.Errorf("%q is offered and the web scanner refuses it", h.Host)
		}
	}
}

func TestTheTagSwitchesTheWebScannerToo(t *testing.T) {
	if !demo.Enabled {
		t.Fatal("built with the demo tag and demo.Enabled is false")
	}
}
