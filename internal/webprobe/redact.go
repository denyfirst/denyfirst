package webprobe

import (
	"net/url"
	"strings"
)

// redacted stands in for every query value a report would otherwise carry.
const redacted = "redacted"

// redactAddress is an address as a report may carry it.
//
// A redirect is where a site hands a visitor a token: a password reset, a
// single sign-on assertion, a session identifier in a query string. The probe
// follows the address as sent, because following anything else would change
// what is measured, and the report records it with every query value replaced,
// userinfo gone and no fragment. The keys stay, so a reader can still see that
// a redirect carries state; the path stays, because where a redirect leads is
// the thing the check reports. Until the 2026-09-16 audit (A27) the whole
// address went into a JSON report somebody might paste anywhere.
//
// An address that does not parse keeps nothing past its path.
func redactAddress(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		if i := strings.IndexAny(raw, "?#"); i >= 0 {
			raw = raw[:i]
		}
		// Whatever sits between the scheme and an @ in an address this
		// could not parse may be a credential, and nothing here can tell.
		scheme, rest, found := strings.Cut(raw, "://")
		if !found {
			scheme, rest = "", raw
		}
		if i := strings.LastIndex(rest, "@"); i >= 0 {
			rest = rest[i+1:]
		}
		if found {
			return scheme + "://" + rest
		}
		return rest
	}

	// An opaque address — mailto:, intent:, anything without a // — is
	// never followed, and its whole body is whatever the site put there.
	if u.Opaque != "" {
		return u.Scheme + ":" + redacted
	}

	u.User = nil
	u.Fragment = ""
	u.RawFragment = ""

	if u.RawQuery != "" {
		parts := strings.Split(u.RawQuery, "&")
		for i, part := range parts {
			key, _, hasValue := strings.Cut(part, "=")
			if hasValue {
				parts[i] = key + "=" + redacted
			}
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	u.ForceQuery = false
	return u.String()
}
