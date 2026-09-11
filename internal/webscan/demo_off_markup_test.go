//go:build !demo

package webscan

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/webprobe"
)

// pageHost is the name these tests scan.
//
// httptest's own certificate names example.com, and the header rules read the
// response a visitor lands on *over TLS* — so a plaintext fixture would make
// every assertion below pass over a scan that established nothing. The first
// version of this file used one, and every test in it failed for that reason
// rather than for the one it was written about.
const pageHost = "example.com"

// pageProber answers every request with one HTML page, over TLS.
func pageProber(t *testing.T, body string) *webprobe.Prober {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	addr := srv.Listener.Addr().String()
	return &webprobe.Prober{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
		Roots:          roots,
		RequestTimeout: 5 * time.Second,
		TotalTimeout:   15 * time.Second,
		MaxRedirects:   -1,
	}
}

func noteText(r *Result) string {
	var b strings.Builder
	for _, n := range r.Notes {
		b.WriteString(n.Text)
		b.WriteString("\n")
	}
	return b.String()
}

// The scanner decides whether the page is read, and the prober obeys.
//
// Asserted on the report rather than on the struct, because a test that read
// back the field it had just set would pass over a scanner that never handed it
// to anything — which is exactly how two sabotages escaped in this repository
// before, both of them on fields that were set, documented and never used.
func TestTheScannerDecidesWhetherThePageIsRead(t *testing.T) {
	page := `<meta http-equiv="Content-Security-Policy" content="default-src 'self'">`

	read, err := (&Scanner{Prober: pageProber(t, page), ReadMarkup: true}).Scan(context.Background(), pageHost)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	unread, err := (&Scanner{Prober: pageProber(t, page)}).Scan(context.Background(), pageHost)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if strings.Contains(noteText(read), "<meta http-equiv>") {
		t.Errorf("a scan that read the page says it did not:\n%s", noteText(read))
	}
	if !strings.Contains(noteText(unread), "<meta http-equiv>") {
		t.Errorf("a scan that read no page does not say so, so its silence about a policy reads "+
			"as a measurement:\n%s", noteText(unread))
	}
}

// A policy in the markup reaches the rules, and the two wrong sentences it used
// to produce are gone.
func TestAPolicyInThePageReachesTheReport(t *testing.T) {
	page := `<!doctype html><html><head>` +
		`<meta http-equiv="Content-Security-Policy" content="default-src 'self'; frame-ancestors 'none'">` +
		`</head><body>hello</body></html>`

	got, err := (&Scanner{Prober: pageProber(t, page), ReadMarkup: true}).Scan(context.Background(), pageHost)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	text := noteText(got)

	if strings.Contains(text, "Content-Security-Policy —") {
		t.Errorf("a site declaring a policy in its markup was told it sends none:\n%s", text)
	}
	if strings.Contains(text, "X-Frame-Options") {
		t.Errorf("a site with a policy was told it is missing framing protection, which the "+
			"policy's frame-ancestors supersedes. This was the second of the two wrong sentences "+
			"one omission produced:\n%s", text)
	}
}

// A page with no policy is still told it has none.
//
// The other direction, and the one that matters more: a reader of this check
// has to keep getting the true finding.
func TestAPageWithNoPolicyIsStillToldSo(t *testing.T) {
	got, err := (&Scanner{
		Prober:     pageProber(t, `<!doctype html><html><body>hello</body></html>`),
		ReadMarkup: true,
	}).Scan(context.Background(), pageHost)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	text := noteText(got)

	if !strings.Contains(text, "Content-Security-Policy —") {
		t.Errorf("a site with no policy anywhere was not told it sends none:\n%s", text)
	}
	if strings.Contains(text, "<meta http-equiv>") {
		t.Errorf("a scan that did read the page says it did not:\n%s", text)
	}
}

// The markup that reaches the rules is the markup of the response the headers
// came from.
//
// A policy declared in a page applies to that page. Reading one response's
// headers beside another's markup would assemble a site that does not exist out
// of two that do.
func TestTheMarkupAndTheHeadersComeFromOneResponse(t *testing.T) {
	got, err := (&Scanner{
		Prober:     pageProber(t, `<meta http-equiv="Content-Security-Policy" content="default-src 'self'">`),
		ReadMarkup: true,
	}).Scan(context.Background(), pageHost)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	final := got.Observed.Secure.Final()
	if final == nil || final.Markup == nil {
		t.Fatal("the response the rules read has no markup facts")
	}
	if !final.Markup.MetaCSP {
		t.Error("the facts on the response the rules read do not carry the policy")
	}
}

// Nothing of the page reaches the result.
//
// The condition reading a body was allowed on at all. A report is a thing
// people paste into issue trackers, and a page holds keys, tokens and names.
func TestNoMarkupReachesTheResult(t *testing.T) {
	secret := "tok_live_51H8sEcRETvalue"
	page := `<!doctype html><html><head>` +
		`<meta http-equiv="Content-Security-Policy" content="default-src 'self'">` +
		`<script>var apiKey = "` + secret + `";</script>` +
		`<!-- internal: ` + secret + ` -->` +
		`</head><body><form action="http://forms.example/x?session=` + secret + `"></form></body></html>`

	got, err := (&Scanner{Prober: pageProber(t, page), ReadMarkup: true}).Scan(context.Background(), pageHost)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	rendered := noteText(got)
	for _, f := range got.Findings {
		rendered += f.Title + " " + f.Rationale + "\n"
	}
	if final := got.Observed.Secure.Final(); final != nil && final.Markup != nil {
		for _, r := range final.Markup.Plaintext {
			rendered += string(r.Kind) + " " + r.Host + "\n"
		}
	}

	if strings.Contains(rendered, secret) {
		t.Fatalf("a value out of the page reached the result:\n%s", rendered)
	}
	if strings.Contains(rendered, "apiKey") || strings.Contains(rendered, "internal:") {
		t.Fatalf("markup reached the result:\n%s", rendered)
	}
}

// A verdict does not move because a page was read.
//
// This change adds no rule. It corrects where one rule looks, and the only
// verdict that could move is one that should never have been reached. Asserted
// so that a later change that does move a verdict has to notice it is doing so
// and bump the rule set (docs/policy-changes.md).
func TestReadingThePageMovesNoVerdictOnASiteWithNoPolicy(t *testing.T) {
	page := `<!doctype html><html><body>hello</body></html>`

	read, err := (&Scanner{Prober: pageProber(t, page), ReadMarkup: true}).Scan(context.Background(), pageHost)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	unread, err := (&Scanner{Prober: pageProber(t, page)}).Scan(context.Background(), pageHost)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if read.Verdict != unread.Verdict {
		t.Errorf("reading the page moved the verdict from %q to %q on a site whose policy did "+
			"not change", unread.Verdict, read.Verdict)
	}
	if read.Policy != policy.WebVersion || unread.Policy != policy.WebVersion {
		t.Errorf("the reports name %q and %q", unread.Policy, read.Policy)
	}
}

// Mixed content reaches the report, graded by what a browser does with it.
func TestWhatThePageLoadsOverPlaintextReachesTheReport(t *testing.T) {
	page := `<!doctype html><html><head>` +
		`<script src="http://cdn.example/a.js"></script>` +
		`<link rel="stylesheet" href="http://cdn.example/a.css">` +
		`</head><body>` +
		`<img src="http://images.example/logo.png">` +
		`<form action="http://forms.example/login"></form>` +
		`</body></html>`

	got, err := (&Scanner{Prober: pageProber(t, page), ReadMarkup: true}).Scan(context.Background(), pageHost)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	ids := map[string]policy.Verdict{}
	for _, f := range got.Findings {
		ids[f.RuleID] = f.Verdict
	}
	if ids["content.mixed-blocked"] != policy.Weak {
		t.Errorf("content.mixed-blocked = %q, want weak. Findings: %v", ids["content.mixed-blocked"], ids)
	}
	if ids["content.form-posts-in-the-clear"] != policy.Insecure {
		t.Errorf("content.form-posts-in-the-clear = %q, want insecure. Findings: %v",
			ids["content.form-posts-in-the-clear"], ids)
	}
	if got.Verdict != policy.Insecure {
		t.Errorf("verdict = %q, want insecure", got.Verdict)
	}

	// The image is reported and not graded: what a browser does with
	// optionally-blockable content is left open by the specification.
	if !strings.Contains(noteText(got), "images.example") {
		t.Errorf("the plaintext image was not reported:\n%s", noteText(got))
	}
	for _, f := range got.Findings {
		if strings.Contains(f.Rationale, "images.example") {
			t.Errorf("an optionally-blockable image was graded by %s", f.RuleID)
		}
	}
}

// A deployment that reads no page grades none of this.
//
// Both halves of the promise in one test: the demonstration cannot produce
// these findings, and neither can any caller that did not ask for the page.
func TestAScanThatReadNoPageGradesNothingAboutIt(t *testing.T) {
	page := `<form action="http://forms.example/login"></form>`

	got, err := (&Scanner{Prober: pageProber(t, page)}).Scan(context.Background(), pageHost)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range got.Findings {
		if strings.HasPrefix(f.RuleID, "content.") {
			t.Errorf("%s was raised by a scan that read no page", f.RuleID)
		}
	}
}

// Mixed content is a question about a page served over TLS.
//
// On a plaintext page everything is plaintext, and a finding there would be
// telling somebody their http page loads things over http. The reach rules
// already say the thing worth saying about such a site.
func TestThePlaintextChainIsNotJudgedForMixedContent(t *testing.T) {
	facts := contentFacts(nil)
	if facts.Read {
		t.Error("a nil chain reported that a page was read")
	}
	if len(facts.Blocking) != 0 || len(facts.Forms) != 0 || len(facts.Passive) != 0 {
		t.Errorf("a nil chain produced references: %+v", facts)
	}
}
