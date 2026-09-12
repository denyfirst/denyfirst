package dkim

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
)

// Documented are selectors that mail providers publish for their own service.
//
// Not a list this project invented. Each entry is the name a provider tells its
// own customers to create, in that provider's own setup instructions, and each
// carries the provider it belongs to so that a reader can go and check rather
// than take this file's word for it. That distinction is the whole reason the
// list is allowed to exist: a set of likely-looking names somebody here made up
// would be a threshold nobody can argue with (R21), and a set of names each
// provider publishes is a citation.
//
// It is a convenience and never a claim. A domain where none of these answer
// has not been shown to lack DKIM — it has been shown that these particular
// names hold nothing — and every report says which were tried and why (R4).
//
// The authoritative source is still the operator. They set the records up.
var Documented = []struct {
	Selector string
	Provider string
}{
	{"google", "Google Workspace"},
	{"selector1", "Microsoft 365"},
	{"selector2", "Microsoft 365"},
	{"k1", "Mailchimp and Mandrill"},
	{"k2", "Mailchimp and Mandrill"},
	{"s1", "SendGrid and several others"},
	{"s2", "SendGrid and several others"},
	{"mail", "a common default in self-hosted setups"},
	{"dkim", "a common default in self-hosted setups"},
	{"default", "a common default in self-hosted setups"},
}

// DocumentedSelectors is the list above, ready to look under.
func DocumentedSelectors() []Selector {
	out := make([]Selector, 0, len(Documented))
	for _, d := range Documented {
		out = append(out, Selector{Name: d.Selector, Source: FromProvider})
	}
	return out
}

// ProviderOf names who documents a selector, for a report that lists one.
func ProviderOf(selector string) string {
	for _, d := range Documented {
		if d.Selector == selector {
			return d.Provider
		}
	}
	return ""
}

// Named turns what an operator typed into selectors to look under.
//
// Comma separated, because that is what somebody types. Empty entries are
// dropped rather than refused: a trailing comma is a typing accident and not
// worth an error message.
func Named(list string) []Selector {
	var out []Selector
	for _, name := range strings.Split(list, ",") {
		name = fold(name)
		if name == "" {
			continue
		}
		out = append(out, Selector{Name: name, Source: FromOperator})
	}
	return out
}

// rsaBits reads the size of an RSA key out of a p= value.
//
// Zero for anything it cannot read, which is not a failure worth reporting on
// its own: the record was found either way, and a size nobody could parse is
// said as "published" rather than as a number that might be wrong.
//
// Only RSA has a size worth reporting. Ed25519 keys are all one length, so a
// number beside one would invite a comparison against the RSA floor that means
// nothing.
func rsaBits(p, algorithm string) int {
	if algorithm != "" && !strings.EqualFold(algorithm, "rsa") {
		return 0
	}

	// Whitespace is permitted inside a long TXT value and is common, because a
	// key is longer than one string and gets wrapped by hand.
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, p)

	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return 0
	}

	// A key from somebody else's zone, so it is parsed and never used. The
	// standard library's parser is the same one that reads a certificate's
	// key, and it is given bounded input: a TXT value cannot exceed what the
	// resolver already bounded.
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return 0
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return 0
	}
	return rsaKey.N.BitLen()
}
