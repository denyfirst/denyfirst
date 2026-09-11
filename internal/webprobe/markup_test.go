package webprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/markup"
)

// pageServer answers every request with one body, and records how much of it
// the client was willing to take.
//
// The accounting is the point of half the tests below, and it has to be done
// this way to mean anything. Counting what a handler hands to net/http measures
// nothing for a small body: it lands in a socket buffer whether or not anybody
// reads it, so "closed unread" and "read and discarded" come out the same. The
// body is written in chunks until a write fails instead, which happens once the
// client has closed — so the total says how far the client got rather than how
// far the server tried. A first version of this file counted the wrong thing
// and would have passed over a probe that read every page it fetched.
type pageServer struct {
	contentType string
	body        string
	status      int
	location    string

	// repeat sends body this many times, to make a page larger than any socket
	// buffer. Zero means once.
	repeat int

	taken atomic.Int64
}

func (p *pageServer) prober(t *testing.T) *Prober {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.location != "" {
			w.Header().Set("Location", p.location)
		}
		if p.contentType != "" {
			w.Header().Set("Content-Type", p.contentType)
		}
		status := p.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)

		times := p.repeat
		if times == 0 {
			times = 1
		}
		flusher, _ := w.(http.Flusher)
		for range times {
			// Stop when the client has gone, rather than blocking in Write
			// until the operating system notices.
			//
			// Without this the handler sits in a Write nobody is draining,
			// httptest.Server.Close waits for it in t.Cleanup, and the package
			// takes eleven minutes and is killed. That is what happened on
			// 2026-09-11, under the demo tag, where no client reads anything.
			select {
			case <-r.Context().Done():
				return
			default:
			}

			n, err := w.Write([]byte(p.body))
			p.taken.Add(int64(n))
			if err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	t.Cleanup(srv.Close)

	addr := srv.Listener.Addr().String()
	return &Prober{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
		RequestTimeout: 5 * time.Second,
		TotalTimeout:   15 * time.Second,
		MaxRedirects:   -1,
	}
}

// finalHop is the last hop of the plaintext chain, which is the one these tests
// drive: the local server speaks no TLS.
func finalHop(t *testing.T, p *Prober) *Hop {
	t.Helper()

	report, err := p.Probe(context.Background(), "example.test", nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hop := report.Plain.Final()
	if hop == nil {
		t.Fatal("the plaintext chain has no hops")
	}
	return hop
}

const (
	// chunk is one write, comfortably larger than a socket buffer's worth of
	// slack so that the loop above stops soon after the client does.
	chunk = 1 << 16

	// enormous is a page far larger than the bound, so that "the client read
	// it" and "the client closed" are different numbers rather than the same
	// number arriving at different times.
	enormous = 16 * markup.MaxBytes

	// generous is the most a bounded read may cost, with room for the buffering
	// between a handler's Write and a client's Read. It is four times the bound
	// rather than the bound because what is being asserted is that a bound
	// exists, not which byte it falls on.
	generous = 4 * markup.MaxBytes
)

func bigPage(head string) (body string, repeat int) {
	return head + strings.Repeat(" ", chunk), enormous / chunk
}

// The default reads nothing, which is what this package promised for its whole
// life and what every caller that has not been changed still gets.
func TestTheBodyIsNotReadUnlessItIsAskedFor(t *testing.T) {
	body, repeat := bigPage(`<script src="http://cdn.example/a.js"></script>`)
	srv := &pageServer{contentType: "text/html", body: body, repeat: repeat}
	p := srv.prober(t)

	hop := finalHop(t, p)
	if hop.Markup != nil {
		t.Errorf("a prober that was not asked to read the page read it: %+v", hop.Markup)
	}
	if n := srv.taken.Load(); n > generous {
		t.Errorf("%d bytes of a %d-byte page were carried by a probe that reads no bodies. "+
			"A body closed unread costs a socket buffer; this cost a page.", n, enormous)
	}
}

// Asked for, it reads the page and keeps facts.
func TestThePageIsReadWhenItIsAskedFor(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build reads no body, which its own test asserts")
	}

	srv := &pageServer{
		contentType: "text/html; charset=utf-8",
		body: `<meta http-equiv="Content-Security-Policy" content="default-src 'self'">` +
			`<script src="http://cdn.example/a.js"></script>`,
	}
	p := srv.prober(t)
	p.ReadMarkup = true

	hop := finalHop(t, p)
	if hop.Markup == nil {
		t.Fatal("the page was not read")
	}
	if !hop.Markup.Read {
		t.Error("the facts do not say a page was read")
	}
	if !hop.Markup.MetaCSP {
		t.Error("the policy in the markup was not seen")
	}
	if len(hop.Markup.Plaintext) != 1 || hop.Markup.Plaintext[0].Host != "cdn.example" {
		t.Errorf("the plaintext script was not seen: %+v", hop.Markup.Plaintext)
	}
}

// A response that is not HTML is not markup, and its bytes are not carried.
//
// Browsers sniff and this does not. Scanning a tarball for tag-shaped bytes
// would produce findings out of a file format, and the file would have been
// carried across the network to find them. text/plain holding markup is the
// case that says which of the two is happening: a scanner that sniffed would
// read it, and this one does not.
func TestSomethingThatIsNotAPageIsNotRead(t *testing.T) {
	for _, contentType := range []string{
		"application/json",
		"application/octet-stream",
		"text/plain",
		"image/png",
	} {
		body, repeat := bigPage(`<script src="http://cdn.example/a.js"></script>`)
		srv := &pageServer{contentType: contentType, body: body, repeat: repeat}
		p := srv.prober(t)
		p.ReadMarkup = true

		hop := finalHop(t, p)
		if hop.Markup != nil {
			t.Errorf("Content-Type %q was read as markup: %+v", contentType, hop.Markup)
		}
		if n := srv.taken.Load(); n > generous {
			t.Errorf("Content-Type %q: %d bytes were carried anyway", contentType, n)
		}
	}
}

// The media type is read out of the Content-Type, and parameters do not change
// what it is.
//
// A missing Content-Type is not HTML here, which is the same refusal to sniff:
// a site that serves markup without saying so gets no markup findings, and the
// report says the page was not read. That is true, and it is the safe direction
// for this to be wrong in (R4).
func TestTheMediaTypeIsReadWithoutItsParameters(t *testing.T) {
	for _, contentType := range []string{
		"text/html",
		"text/html; charset=utf-8",
		"TEXT/HTML;charset=UTF-8",
		"  text/html  ; boundary=x",
		"application/xhtml+xml",
	} {
		if !isHTML(contentType) {
			t.Errorf("isHTML(%q) = false, and a browser renders it", contentType)
		}
	}
	for _, contentType := range []string{
		"", "text/plain", "application/json", "texthtml", "text/html-ish", "text/htmlx",
	} {
		if isHTML(contentType) {
			t.Errorf("isHTML(%q) = true", contentType)
		}
	}
}

// A redirect's body is not the page.
//
// Nobody sees it, a browser does not render it, and reading it would cost the
// server bytes for a document that was never served to a visitor.
func TestARedirectsBodyIsNotRead(t *testing.T) {
	body, repeat := bigPage(`<script src="http://cdn.example/a.js"></script>`)
	srv := &pageServer{
		contentType: "text/html",
		status:      http.StatusFound,
		location:    "https://elsewhere.test/",
		body:        body,
		repeat:      repeat,
	}
	p := srv.prober(t)
	p.ReadMarkup = true

	hop := finalHop(t, p)
	if hop.Markup != nil {
		t.Errorf("a redirect's body was read: %+v", hop.Markup)
	}
	if n := srv.taken.Load(); n > generous {
		t.Errorf("%d bytes of a redirect's body were carried", n)
	}
}

// A 3xx with no Location is not a redirect, so its body is the page.
func TestAThreeHundredWithNowhereToGoIsAPage(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build reads no body")
	}

	srv := &pageServer{
		contentType: "text/html",
		status:      http.StatusMultipleChoices,
		body:        `<script src="http://cdn.example/a.js"></script>`,
	}
	p := srv.prober(t)
	p.ReadMarkup = true

	hop := finalHop(t, p)
	if hop.Markup == nil {
		t.Fatal("a response with no Location was treated as a redirect")
	}
	if len(hop.Markup.Plaintext) != 1 {
		t.Errorf("the page was read and produced %+v", hop.Markup.Plaintext)
	}
}

// A page longer than the bound costs the bound, and says nothing was seen past
// it (R4).
func TestALongPageIsBoundedAndSaysSo(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build reads no body")
	}

	body, repeat := bigPage("<p>x</p>")
	srv := &pageServer{contentType: "text/html", body: body, repeat: repeat}
	p := srv.prober(t)
	p.ReadMarkup = true

	hop := finalHop(t, p)
	if hop.Markup == nil {
		t.Fatal("the page was not read")
	}
	if !hop.Markup.Truncated {
		t.Error("a page over the bound did not say it was truncated, so an empty list of " +
			"findings would read as a page with nothing in it")
	}
	if n := srv.taken.Load(); n > generous {
		t.Errorf("%d bytes were carried for a read bounded at %d", n, markup.MaxBytes)
	}
}
