package ctsearch

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

// The answer comes from a service this project does not run, over a question
// that names the domain. Everything here is written from that direction.

// The shape of a real answer, taken from crt.sh for this project's own domain
// on 2026-09-11. Two entries, one serial: the precertificate and the
// certificate, both logged.
const realAnswer = `[
 {"issuer_ca_id":431054,"issuer_name":"C=US, O=Let's Encrypt, CN=YE2",
  "common_name":"denyfirst.dev","name_value":"denyfirst.dev","id":28772899880,
  "not_before":"2026-08-12T12:01:37","not_after":"2026-11-10T12:01:36",
  "serial_number":"06fe4d40c60a52d890d674da1278b4b0c5c7","result_count":2},
 {"issuer_ca_id":431054,"issuer_name":"C=US, O=Let's Encrypt, CN=YE2",
  "common_name":"denyfirst.dev","name_value":"denyfirst.dev","id":28775099577,
  "not_before":"2026-08-12T12:01:37","not_after":"2026-11-10T12:01:36",
  "serial_number":"06fe4d40c60a52d890d674da1278b4b0c5c7","result_count":2}
]`

// searching returns a searcher pointed at a server handing out one body.
func searching(t *testing.T, body string, status int) (*CRTSh, *[]string) {
	t.Helper()

	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.RequestURI())
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	return &CRTSh{
		Endpoint: srv.URL + "/?Identity=%s&output=json",
		Timeout:  5 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).
				DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}, &asked
}

// One certificate is one certificate, however many times it was logged.
//
// The trap this check would otherwise walk into on its first real answer. Every
// certificate is submitted twice — as a precertificate and as itself — so a
// name with one certificate comes back as two entries sharing one serial.
// Counting rows would tell an operator they have twice as many certificates as
// they do, and on a check whose whole purpose is "is there one you did not
// order", a phantom duplicate is the worst possible false alarm.
func TestOneCertificateLoggedTwiceIsOneCertificate(t *testing.T) {
	c, _ := searching(t, realAnswer, http.StatusOK)

	got := c.Search(context.Background(), "denyfirst.dev")
	if got.Reason != "" {
		t.Fatalf("search failed: %s", got.Reason)
	}
	if got.Distinct != 1 {
		t.Errorf("reported %d distinct certificates for one certificate logged twice", got.Distinct)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("listed %d entries, want 1", len(got.Entries))
	}

	e := got.Entries[0]
	if e.Serial != "06fe4d40c60a52d890d674da1278b4b0c5c7" {
		t.Errorf("serial is %q", e.Serial)
	}
	if !strings.Contains(e.Issuer, "Let's Encrypt") {
		t.Errorf("issuer is %q", e.Issuer)
	}
	if e.NotBefore.IsZero() || e.NotAfter.IsZero() {
		t.Error("the validity window was not read, so a report cannot say whether this " +
			"certificate is current")
	}
	if e.NotBefore.Year() != 2026 || e.NotBefore.Month() != time.August {
		t.Errorf("notBefore is %v, want 2026-08-12", e.NotBefore)
	}
}

// Two genuinely different certificates are two.
//
// The other direction, and the one that matters more: a check that collapsed
// everything to one would report a certificate somebody else obtained as
// nothing at all.
func TestTwoDifferentCertificatesAreTwo(t *testing.T) {
	body := `[
	 {"issuer_name":"C=US, O=Let's Encrypt, CN=YE2","name_value":"example.test",
	  "not_before":"2026-08-12T12:01:37","not_after":"2026-11-10T12:01:36",
	  "serial_number":"aaaa"},
	 {"issuer_name":"C=XX, O=Somebody Else","name_value":"example.test",
	  "not_before":"2026-09-01T00:00:00","not_after":"2026-12-01T00:00:00",
	  "serial_number":"bbbb"}
	]`

	c, _ := searching(t, body, http.StatusOK)

	got := c.Search(context.Background(), "example.test")
	if got.Distinct != 2 {
		t.Fatalf("reported %d distinct certificates, want 2: a certificate obtained by "+
			"somebody else is the finding this whole check exists for", got.Distinct)
	}
}

// The name is what gets asked about, and it is escaped on the way out.
func TestTheNameIsEscapedIntoTheQuery(t *testing.T) {
	c, asked := searching(t, `[]`, http.StatusOK)

	c.Search(context.Background(), "Example.TEST.")

	if len(*asked) != 1 {
		t.Fatalf("the monitor was asked %d times, want once", len(*asked))
	}

	// Folded before it is sent: a name with a trailing dot and mixed case is
	// the same name, and asking twice about one name is one disclosure too
	// many.
	if !strings.Contains((*asked)[0], "Identity=example.test") {
		t.Errorf("asked %q, want the folded name", (*asked)[0])
	}
}

func TestAwkwardNamesDoNotEscapeTheQuery(t *testing.T) {
	c, asked := searching(t, `[]`, http.StatusOK)

	c.Search(context.Background(), "a&b=c example.test")

	if len(*asked) != 1 {
		t.Fatalf("asked %d times", len(*asked))
	}
	got := (*asked)[0]

	// One parameter and one value. A name carrying & or = that arrived
	// unescaped would add parameters to somebody else's query string.
	u, err := url.ParseRequestURI(got)
	if err != nil {
		t.Fatalf("the request line does not parse: %v", err)
	}
	q := u.Query()

	// Exactly the two parameters this asks for, and Identity carrying the whole
	// name rather than the part before an ampersand. A name that added a
	// parameter of its own would be writing somebody else's query string, and an
	// earlier version of this test watched only that Identity appeared once —
	// which a weaker escaping passed, because the extra parameter it injected
	// was a different name.
	if len(q) != 2 {
		t.Errorf("the query carries %d parameters, want 2: %q", len(q), got)
	}
	if len(q["Identity"]) != 1 {
		t.Errorf("Identity appears %d times in %q", len(q["Identity"]), got)
	}
	if q.Get("Identity") != "a&b=c example.test" {
		t.Errorf("Identity is %q, want the whole name: %q", q.Get("Identity"), got)
	}
	if q.Get("output") != "json" {
		t.Errorf("the output parameter was displaced: %q", got)
	}
}

// Anything that is not an answer is reported as not established, never as none.
//
// "No certificates were found" is the reassuring half of this check, so every
// way of failing has to be distinguishable from it (R4). A monitor that is
// down, rate limiting, or answering with a page instead of a document must not
// read as a clean estate.
func TestNothingThatIsNotAnAnswerReadsAsNoneFound(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		status int
	}{
		{"the monitor refused", "", http.StatusTooManyRequests},
		{"the monitor broke", "", http.StatusBadGateway},
		{"an address that is not there", "not found", http.StatusNotFound},
		{"a page instead of a document", "<html>search results</html>", http.StatusOK},
		{"truncated json", `[{"serial_number":"aa"`, http.StatusOK},
	} {
		c, _ := searching(t, tc.body, tc.status)

		got := c.Search(context.Background(), "example.test")
		if got.Reason == "" {
			t.Errorf("%s: the search reported success with %d entries; a failure that reads "+
				"as an empty estate is the one wrong answer here", tc.name, len(got.Entries))
		}
		if len(got.Entries) != 0 || got.Distinct != 0 {
			t.Errorf("%s: entries came back from a failed search", tc.name)
		}
	}
}

// An empty answer is an answer.
func TestAnEmptyAnswerIsNotAFailure(t *testing.T) {
	c, _ := searching(t, `[]`, http.StatusOK)

	got := c.Search(context.Background(), "example.test")
	if got.Reason != "" {
		t.Errorf("an empty list was reported as a failure: %s", got.Reason)
	}
	if got.Distinct != 0 {
		t.Errorf("distinct is %d for an empty answer", got.Distinct)
	}
}

// What the monitor says is bounded and stripped before it is kept.
//
// These strings come from certificates anybody may obtain and log, so they are
// chosen by whoever obtained them rather than by the operator being scanned. A
// report is rendered in a browser and pasted into chat windows, and a control
// character in a subject is an old way of making one line look like another.
func TestWhatTheMonitorSaysIsBoundedAndStripped(t *testing.T) {
	long := strings.Repeat("A", maxField*3)
	// The name list carries a newline, which is how a multi-name certificate
	// arrives, and a NUL written the way a JSON document writes one.
	//
	// Built from a byte rather than typed, because Go forbids a literal NUL in
	// source and a test that cannot contain the character it is about would
	// have to test something else instead.
	nul := string([]byte{92}) + "u0000"
	body := `[{"issuer_name":"CN=` + long + `","name_value":"one.test\ntwo.test` + nul + `three.test",` +
		`"not_before":"2026-08-12T12:01:37","not_after":"2026-11-10T12:01:36",` +
		`"serial_number":"aaaa"}]`

	c, _ := searching(t, body, http.StatusOK)

	got := c.Search(context.Background(), "example.test")
	if len(got.Entries) != 1 {
		t.Fatalf("listed %d entries", len(got.Entries))
	}
	e := got.Entries[0]

	if len(e.Issuer) > maxField {
		t.Errorf("the issuer is %d characters, and the bound is %d", len(e.Issuer), maxField)
	}
	for _, n := range e.Names {
		if strings.ContainsAny(n, "\x00\n\r") {
			t.Errorf("a name carries a control character: %q", n)
		}
	}
	if len(e.Names) < 2 {
		t.Errorf("the names were not split: %v; a newline reaching a report unbroken is a "+
			"line a reader cannot attribute to the field it came from", e.Names)
	}
}

// The list a report shows is bounded, and says when it is not the whole list.
func TestALongHistoryIsBoundedAndSaysSo(t *testing.T) {
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < maxEntries+10; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt := `{"issuer_name":"CN=X","name_value":"example.test",` +
			`"not_before":"2026-08-12T12:01:37","not_after":"2026-11-10T12:01:36",` +
			`"serial_number":"%04x"}`
		b.WriteString(strings.Replace(fmt, "%04x", serialFor(i), 1))
	}
	b.WriteString("]")

	c, _ := searching(t, b.String(), http.StatusOK)

	got := c.Search(context.Background(), "example.test")
	if len(got.Entries) > maxEntries {
		t.Errorf("listed %d entries, and the bound is %d", len(got.Entries), maxEntries)
	}
	if !got.Truncated {
		t.Error("the list was cut and the result does not say so, so a reader takes a partial " +
			"list for the whole history")
	}

	// The count is still the real one. A bounded list with an honest total is
	// usable; a bounded list with a bounded total understates what exists.
	if got.Distinct != maxEntries+10 {
		t.Errorf("counted %d distinct certificates, want %d", got.Distinct, maxEntries+10)
	}
}

func serialFor(i int) string {
	const hex = "0123456789abcdef"
	return string([]byte{hex[(i/16)%16], hex[i%16], 'a', 'a'})
}

// An answer larger than the cap is refused rather than cut and parsed.
func TestAnOversizedAnswerIsRefusedRatherThanTruncated(t *testing.T) {
	c, _ := searching(t, strings.Repeat("x", maxBody+16), http.StatusOK)

	got := c.Search(context.Background(), "example.test")
	if !strings.Contains(got.Reason, "larger than this reads") {
		t.Errorf("reason is %q", got.Reason)
	}
}

// No reason names a resolver, an address, or a Go type.
func TestNoReasonDescribesTheMachine(t *testing.T) {
	// A monitor that cannot be reached at all: nothing is listening.
	c := &CRTSh{
		Endpoint: "http://127.0.0.1:1/?Identity=%s&output=json",
		Timeout:  2 * time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, net.UnknownNetworkError("no network in tests")
		},
	}

	got := c.Search(context.Background(), "example.test")
	if got.Reason == "" {
		t.Fatal("a failed search came back with no reason")
	}
	for _, leak := range []string{"127.0.0.1", "dial ", "tcp ", "*net.", "0x"} {
		if strings.Contains(got.Reason, leak) {
			t.Errorf("the reason contains %q: %s", leak, got.Reason)
		}
	}
}

// An empty name is not a search.
func TestAnEmptyNameIsNotSearchedFor(t *testing.T) {
	c, asked := searching(t, `[]`, http.StatusOK)

	got := c.Search(context.Background(), "   ")
	if got.Reason == "" {
		t.Error("an empty name was searched for")
	}
	if len(*asked) != 0 {
		t.Errorf("the monitor was asked about an empty name: %v", *asked)
	}
}
