package main

import (
	"strings"
	"testing"
)

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort string
	}{
		{"example.com", "example.com", "443"},
		{"example.com:8443", "example.com", "8443"},
		{"  example.com  ", "example.com", "443"},

		// A pasted URL is a likely mistake, not an error worth refusing.
		{"https://example.com", "example.com", "443"},
		{"http://example.com", "example.com", "443"},
		{"https://example.com/", "example.com", "443"},
		{"https://example.com/path/to/page", "example.com", "443"},
		{"https://example.com:8443/x", "example.com", "8443"},

		{"[2606:4700:4700::1111]:443", "2606:4700:4700::1111", "443"},
	}

	for _, tc := range cases {
		host, port, err := splitTarget(tc.in)
		if err != nil {
			t.Errorf("splitTarget(%q) returned %v", tc.in, err)
			continue
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("splitTarget(%q) = %q, %q; want %q, %q", tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

// The same limits will apply to the HTTP service, where the input is
// untrusted. Keeping one implementation stops the two from drifting apart.
func TestSplitTargetRejectsMalformedInput(t *testing.T) {
	bad := []string{
		"",
		"   ",
		"https://",
		"exa mple.com",
		"example.com\n",
		"example.com\x00.evil.test",
		strings.Repeat("a", 300),
	}

	for _, in := range bad {
		if _, _, err := splitTarget(in); err == nil {
			t.Errorf("splitTarget(%q) accepted malformed input", in)
		}
	}
}

func TestWrapBreaksOnWords(t *testing.T) {
	const text = "The session key is derived from a long-term key, so anyone who later " +
		"obtains the server's private key can decrypt traffic captured months earlier."

	got := wrap(text, 40, "  ")

	for _, line := range strings.Split(got, "\n") {
		if len(strings.TrimSpace(line)) > 40 {
			t.Errorf("line exceeds the requested width: %q", line)
		}
	}

	// Wrapping must not lose or reorder words.
	if strings.Join(strings.Fields(got), " ") != strings.Join(strings.Fields(text), " ") {
		t.Error("wrap changed the text")
	}
}

func TestWrapHandlesEmptyInput(t *testing.T) {
	if got := wrap("", 40, "  "); got != "" {
		t.Errorf("wrap(\"\") = %q, want empty", got)
	}
}
