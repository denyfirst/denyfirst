package webscan

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/exclusion"
	"github.com/denyfirst/denyfirst/internal/webprobe"
)

// dialRecorder answers nothing and records whether it was asked to.
//
// A refusal that still opened a connection is the failure worth catching, and
// no assertion about the returned error can see it. This can.
type dialRecorder struct{ dialed bool }

func (d *dialRecorder) dial(context.Context, string, string) (net.Conn, error) {
	d.dialed = true
	return nil, errors.New("nothing is listening")
}

// A name on the exclusion list is refused by this check too.
//
// It was not, until 2026-09-10. The TLS scanner asked the list inside
// Scanner.Scan and this one did not, so `-check tls army.mil` was refused and
// `-check web army.mil` was scanned — one guard, one caller, and a second
// caller written later that walked around it. That is the failure N6 is about,
// arriving through the door N6 predicted.
func TestTheWebScannerRefusesAnExcludedName(t *testing.T) {
	for _, host := range []string{"army.mil", "www.cia.gov", "nasa.gov", "ARMY.MIL", "army.mil."} {
		d := &dialRecorder{}
		s := &Scanner{Prober: &webprobe.Prober{
			Dial:           d.dial,
			RequestTimeout: time.Second,
			TotalTimeout:   2 * time.Second,
		}}

		_, err := s.Scan(context.Background(), host)
		if !errors.Is(err, exclusion.ErrRefused) {
			t.Errorf("Scan(%q) returned %v, want the exclusion refusal", host, err)
		}
		if d.dialed {
			t.Errorf("Scan(%q) was refused and opened a connection anyway", host)
		}
	}
}

// The refusal does not repeat the name back (I3).
func TestTheWebExclusionRefusalNamesNoHost(t *testing.T) {
	_, err := (&Scanner{}).Scan(context.Background(), "army.mil")
	if err == nil {
		t.Fatal("an excluded name was not refused")
	}
	if got := err.Error(); got != "this service does not scan that domain" {
		t.Errorf("the refusal reads %q, which is not the rule stated without the input", got)
	}
}
