//go:build !demo

package webscan

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/webprobe"
)

// A name that is not on the list is not refused by it.
//
// The other direction, and the one a too-eager matcher breaks: "mil" must not
// exclude domil.com, and a check that refused everything would satisfy every
// assertion about refusals.
//
// Only in the ordinary build. Under the demonstration tag a host outside that
// deployment's list is refused for a different and correct reason, which would
// make this test measure the deployment restriction rather than the matcher.
func TestTheWebScannerScansANameThatIsNotExcluded(t *testing.T) {
	served := make(chan struct{}, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case served <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer srv.Close()
	go func() { _ = srv.Serve(ln) }()

	s := &Scanner{Prober: &webprobe.Prober{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
		},
		RequestTimeout: 2 * time.Second,
		TotalTimeout:   5 * time.Second,
	}}

	if _, err := s.Scan(context.Background(), "domil.com"); err != nil {
		t.Fatalf("Scan(domil.com) was refused: %v; the list matches at label boundaries", err)
	}
	select {
	case <-served:
	default:
		t.Error("the scan was not refused and never reached the server either")
	}
}
