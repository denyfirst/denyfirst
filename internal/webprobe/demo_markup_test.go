//go:build demo

package webprobe

import (
	"net/http"
	"testing"
)

// A demonstration build reads no body, whatever it is asked.
//
// The published promise is on /web/method and in this package's own
// documentation, and it is the kind of promise that has shipped twice here with
// nothing guarding it: the revocation check and the transparency log search
// each announced what the demonstration does not do, and each was caught by a
// sabotage rather than by a test.
//
// ReadMarkup is set to true deliberately. Asserting that the demonstration does
// not read a body when nobody asked it to would assert nothing — the ordinary
// build does not either. What has to hold is that the field is ignored.
func TestTheDemonstrationReadsNoBodyEvenWhenAsked(t *testing.T) {
	body, repeat := bigPage(`<meta http-equiv="Content-Security-Policy" content="default-src 'self'">`)
	srv := &pageServer{contentType: "text/html", body: body, repeat: repeat}

	p := srv.prober(t)
	p.ReadMarkup = true

	hop := finalHop(t, p)
	if hop.Markup != nil {
		t.Fatalf("a demonstration build read a page: %+v. The promise on /web/method says it "+
			"reads headers and closes the body unread, and that promise is why somebody who "+
			"found this scanner in their access log is entitled not to investigate further.",
			hop.Markup)
	}
	if n := srv.taken.Load(); n > generous {
		t.Errorf("%d bytes of a %d-byte page were carried by a build that reads no bodies",
			n, enormous)
	}
}

// And the same for a response it would otherwise have been happy to read.
func TestTheDemonstrationIgnoresTheFieldOnAnOrdinaryPage(t *testing.T) {
	srv := &pageServer{
		contentType: "text/html",
		status:      http.StatusOK,
		body:        `<script src="http://cdn.example/a.js"></script>`,
	}
	p := srv.prober(t)
	p.ReadMarkup = true

	if hop := finalHop(t, p); hop.Markup != nil {
		t.Fatalf("a demonstration build read a page: %+v", hop.Markup)
	}
}
