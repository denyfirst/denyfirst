package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The budget belongs to the host, not to the spelling of it.
//
// A hash is exact where DNS is not. EXAMPLE.COM, example.com and example.com.
// reach one server, and keying the limiter on the bytes as sent gave each of
// them a budget of its own — so a caller with an eleven-letter hostname had
// two thousand budgets, which is not a limit.
//
// This is the one limit here that protects the party being scanned rather
// than this service, and one scan is up to fifty handshakes at the other end.
func TestTargetLimiterIgnoresSpelling(t *testing.T) {
	tl := newTargetLimiter(time.Now)

	// Spend the host's whole allowance under one spelling.
	spendTargetBudget(tl, "example.com", "443")

	for _, spelling := range []string{
		"EXAMPLE.COM",
		"Example.Com",
		"eXaMpLe.CoM",
		"example.com.",
		"ExAmPlE.cOm.",
	} {
		if tl.allow(spelling, "443") {
			t.Errorf("%q was admitted after example.com had spent its budget; one server must not have "+
				"a budget per spelling", spelling)
		}
	}

	// The port still separates budgets, because two ports are two servers as
	// far as the machine answering them is concerned.
	if !tl.allow("example.com", "8443") {
		t.Error("a different port was refused; the port is part of what a target is")
	}
}

// The same property through the handler, because the fold happens in
// scan.SplitTarget as well and a test of the limiter alone would not notice
// if the two disagreed.
func TestSpellingCannotBuyExtraScansOfOneHost(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	exhaustTarget(t, s, `{"target":"spelled.test"}`, "203.0.113.")

	for i, spelling := range []string{"SPELLED.TEST", "Spelled.Test", "spelled.test."} {
		w := postFrom(t, s, `{"target":"`+spelling+`"}`, "203.0.113."+strconv.Itoa(210+i)+":5000")
		if errorCode(t, w) != "target_busy" {
			t.Errorf("%q was scanned after spelled.test had spent its budget (code %q)",
				spelling, errorCode(t, w))
		}
	}
}

// A proxy may extend the header the client sent or add a line of its own.
// Both are conforming; Header.Get sees only the first, so against the second
// kind of proxy it returns whatever the client wrote — a key of the client's
// choosing on every request, which is the same as having no limiter at all.
func TestForwardedForReadsTheProxyLineNotTheClients(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	request := func(headers ...string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader("{}"))
		r.RemoteAddr = "10.0.0.5:4444"
		for _, h := range headers {
			r.Header.Add("X-Forwarded-For", h)
		}
		return r
	}

	// Two header lines: the client's, then the proxy's.
	if got := clientKey(request("1.1.1.1", "203.0.113.9"), trusted, 1); got != "v4:203.0.113.9" {
		t.Errorf("clientKey = %q, want v4:203.0.113.9: the entry the proxy appended is the one to trust", got)
	}

	// One header line carrying both, which is the other conforming shape.
	if got := clientKey(request("1.1.1.1, 203.0.113.9"), trusted, 1); got != "v4:203.0.113.9" {
		t.Errorf("clientKey = %q, want v4:203.0.113.9", got)
	}

	// Three lines and two trusted hops steps back two entries.
	if got := clientKey(request("1.1.1.1", "203.0.113.9", "203.0.113.10"), trusted, 2); got != "v4:203.0.113.9" {
		t.Errorf("clientKey = %q, want v4:203.0.113.9 with two hops", got)
	}

	// Whatever the client sends, an untrusted connection is keyed on itself.
	r := request("1.1.1.1", "203.0.113.9")
	r.RemoteAddr = "198.51.100.4:4444"
	if got := clientKey(r, trusted, 1); got != "v4:198.51.100.4" {
		t.Errorf("clientKey = %q, want v4:198.51.100.4: the header means nothing off a trusted network", got)
	}
}
