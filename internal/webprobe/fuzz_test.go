package webprobe

import (
	"net/http"
	neturl "net/url"
	"strings"
	"testing"
)

// FuzzNextURL feeds arbitrary Location headers to the redirect decision.
//
// Everything this function reads was written by the scanned server: the
// status, the header, and the address the header resolves against. It decides
// where this program connects next, which makes it the one place in the web
// probe where a hostile string chooses an action rather than a value.
func FuzzNextURL(f *testing.F) {
	f.Add("https://example.com/", "/somewhere")
	f.Add("https://example.com/", "https://elsewhere.example/")
	f.Add("https://example.com/", "//elsewhere.example/")
	f.Add("https://example.com/", "ftp://example.com/pub")
	f.Add("https://example.com/", "javascript:alert(1)")
	f.Add("https://example.com/", "file:///etc/passwd")
	f.Add("https://example.com/", "https://user:pass@example.com/")
	f.Add("https://example.com/", "http://127.0.0.1/")
	f.Add("https://example.com/", "")
	f.Add("https://example.com/", "\x00")
	f.Add("https://example.com/", strings.Repeat("a", maxLocationLength+1))
	f.Add("", "https://example.com/")

	f.Fuzz(func(t *testing.T, from, location string) {
		next, stopped := nextURL(
			Hop{Status: http.StatusFound, Headers: map[string][]string{"Location": {location}}},
			from,
		)

		if next != "" && stopped != "" {
			t.Fatalf("both an address (%q) and a reason not to follow (%q)", next, stopped)
		}
		if next == "" {
			return
		}

		u, err := neturl.Parse(next)
		if err != nil {
			t.Fatalf("returned an address that does not parse: %q", next)
		}
		switch u.Scheme {
		case "http", "https":
		default:
			// The whole point of the scheme check: a Location naming
			// javascript:, file: or anything else must never become an
			// address this program acts on.
			t.Fatalf("returned a %q address: %q", u.Scheme, next)
		}
		if u.User != nil {
			t.Fatalf("credentials survived into %q", next)
		}
		if u.Hostname() == "" {
			t.Fatalf("returned an address with no host: %q", next)
		}
		if u.Fragment != "" {
			t.Fatalf("a fragment is never sent on the wire, so it must not be carried: %q", next)
		}
	})
}

// FuzzCookies feeds arbitrary Set-Cookie headers to the cookie parser.
//
// The property that matters is structural: whatever comes in, what comes out
// is a name and a set of attributes, and nothing that could hold the value.
// A parser that produced a name containing the rest of the header would put
// the value into a report by a route no reader would look for.
func FuzzCookies(f *testing.F) {
	f.Add("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
	f.Add("__Host-sid=abc; Secure; Path=/")
	f.Add("__Secure-sid=abc; Secure")
	f.Add("=abc")
	f.Add("sid")
	f.Add("")
	f.Add("a=b=c=d; secure; secure; samesite=")
	f.Add("sid=abc; SameSite=Strict; SameSite=None")
	f.Add("\x00=\x00; Secure")
	f.Add(strings.Repeat("a", 4096) + "=b")

	f.Fuzz(func(t *testing.T, header string) {
		for _, c := range cookies([]string{header}) {
			if c.Name == "" {
				t.Fatal("a cookie with no name was recorded")
			}
			// The name is the text before the first "=", so neither the
			// separator nor anything after it can be in it.
			if strings.ContainsAny(c.Name, "=;") {
				t.Fatalf("the name %q carries part of the rest of the header", c.Name)
			}
			switch c.SameSite {
			case "", "strict", "lax", "none":
			default:
				// Anything else is a value the server chose, kept verbatim.
				// It is allowed to be unusual, but it must be lowercased, so
				// that a rule comparing against "none" cannot be evaded with
				// "None".
				if c.SameSite != strings.ToLower(c.SameSite) {
					t.Fatalf("SameSite %q was not lowercased", c.SameSite)
				}
			}
			if c.HostPrefix && !strings.HasPrefix(c.Name, "__Host-") {
				t.Fatalf("%q was reported with the host prefix", c.Name)
			}
			if c.SecurePrefix && !strings.HasPrefix(c.Name, "__Secure-") {
				t.Fatalf("%q was reported with the secure prefix", c.Name)
			}
		}
	})
}
