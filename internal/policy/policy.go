// Package policy holds denyfirst's grading rules and the sources behind them.
//
// A scanner produces two different kinds of statement, and conflating them
// makes a report impossible to argue with.
//
// A fact comes from the handshake: this server accepted this cipher suite,
// whose key exchange is static RSA and whose mode is CBC. Facts do not change
// unless the server changes.
//
// A verdict is a judgement about that fact: static RSA is unacceptable. There
// is no single authority for such judgements. The IETF, NIST, the German BSI,
// Mozilla, and the CA/Browser Forum all publish recommendations, and they do
// not always agree. Go's crypto/tls carries its own opinion in
// InsecureCipherSuites, which is reasonable but is not a standard and has
// already moved suites between categories between releases.
//
// Inheriting a verdict from any of those means the tool's answer changes when
// the upstream opinion changes, with no record of why. A user who scans the
// same unchanged server twice and gets two different grades has been given a
// reason to distrust both.
//
// So the rules live here, versioned, each with the document it rests on. Go's
// list is kept as a cross-check in the tests rather than as the source of
// truth: if Go condemns something these rules do not, that is a signal to
// revisit the rules, not to change the answer silently.
package policy

import (
	"strings"
	"unicode"
)

// Version identifies this rule set. Every report states which version graded
// it, so a verdict can be reproduced later even after the rules move on.
//
// v2, 2026-08-22. Two suites change verdict and one changes its reason:
// finite-field DHE is now insecure rather than strong, because RFC 10015 made
// it MUST NOT; a suite this rule set does not recognise is now weak and says
// so, rather than insecure for a reason invented about it; and integrity-only
// suites are graded for the encryption they lack rather than for forward
// secrecy they have. A rule change is a version change, because a user who
// scans an unchanged server twice and gets two grades has been given a reason
// to distrust both.
const Version = "denyfirst-v6"

// ReviewBy is when these rules should next be read against their sources.
//
// Standards move on their own schedule. RFC 8996 appeared while TLS 1.0 was
// still common, and the CA/Browser Forum validity limit changes on dates
// already fixed. A rule set with no review date drifts until somebody
// notices it is wrong, and that somebody is usually a user.
//
// A test fails once this date passes. The failure is a reminder rather than a
// defect: read the rules against their references, then move the date.
//
// Reading the rules is half of it. The other half was missed in August 2026:
// check that each reference is still the current document. RFC 8446 had been
// obsoleted by RFC 9846 and BCP 195 updated twice, and nothing here noticed,
// because the rules were read against citations rather than the citations
// being read against the registry. Both halves, every time: open
// rfc-editor.org/info/rfcNNNN for each reference and look for an "obsoleted
// by" or "updated by" line before reading a word of the text.
const ReviewBy = "2026-12-01"

// Verdict is the severity assigned to a finding.
type Verdict string

const (
	// Ungraded means no verdict was reached, usually because nothing could be
	// measured. It is deliberately distinct from Strong: silence about
	// something untested must not read as approval.
	Ungraded Verdict = ""

	// Strong meets current best practice.
	Strong Verdict = "strong"

	// Weak is deprecated or carries a known structural weakness. It should be
	// removed, but no practical break is published.
	Weak Verdict = "weak"

	// Insecure is prohibited by a standards body, or has a published break.
	Insecure Verdict = "insecure"
)

// Rank orders verdicts by severity so callers can aggregate without
// hardcoding the order.
func (v Verdict) Rank() int {
	switch v {
	case Insecure:
		return 2
	case Weak:
		return 1
	default:
		return 0
	}
}

// Worst returns the most severe verdict in the list, ignoring Ungraded
// entries. An empty list, or one holding nothing but Ungraded, yields
// Ungraded.
//
// Aggregating by worst case rather than by average is the whole point. An
// attacker chooses which protocol version and cipher suite to negotiate, so
// one insecure option makes the configuration insecure however many strong
// options sit beside it.
func Worst(verdicts ...Verdict) Verdict {
	out := Ungraded
	for _, v := range verdicts {
		if v == Ungraded {
			continue
		}
		if out == Ungraded || v.Rank() > out.Rank() {
			out = v
		}
	}
	return out
}

// Reference is a document a verdict rests on. The URL is included so a reader
// can check the claim rather than take it on trust.
type Reference struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// Finding is one graded observation.
type Finding struct {
	// RuleID is stable across releases so findings can be tracked or
	// suppressed by identifier rather than by matching prose.
	RuleID string `json:"ruleId"`

	Verdict Verdict `json:"verdict"`
	Title   string  `json:"title"`

	// Rationale states what is wrong in one sentence, in terms of
	// consequence rather than category.
	Rationale string `json:"rationale"`

	References []Reference `json:"references"`

	// Policy records which rule set produced this verdict.
	Policy string `json:"policy"`
}

var (
	rfc7465 = Reference{"RFC 7465 — Prohibiting RC4 Cipher Suites", "https://www.rfc-editor.org/rfc/rfc7465"}
	rfc7568 = Reference{"RFC 7568 — Deprecating SSLv3", "https://www.rfc-editor.org/rfc/rfc7568"}
	// RFC 9846 replaced RFC 8446 as the TLS 1.3 specification, and obsoleted
	// RFC 5246 with it. The old number is not kept as an alias: a citation is
	// worth something only if a reader who follows it lands on the document
	// that is in force.
	rfc9846 = Reference{"RFC 9846 — TLS 1.3", "https://www.rfc-editor.org/rfc/rfc9846"}
	rfc8996 = Reference{"RFC 8996 — Deprecating TLS 1.0 and TLS 1.1", "https://www.rfc-editor.org/rfc/rfc8996"}
	rfc9155 = Reference{"RFC 9155 — Deprecating MD5 and SHA-1 signature hashes in TLS", "https://www.rfc-editor.org/rfc/rfc9155"}
	rfc9325 = Reference{"RFC 9325 (BCP 195) — Recommendations for Secure Use of TLS", "https://www.rfc-editor.org/rfc/rfc9325"}

	// BCP 195 is not one document. RFC 10015 raised three key-exchange
	// recommendations from SHOULD NOT to MUST NOT in July 2026, which is what
	// moves finite-field DHE from a suite this rule set tolerated to one it
	// grades insecure.
	rfc10015 = Reference{"RFC 10015 — Deprecating Obsolete Key Exchange Methods in TLS 1.2", "https://www.rfc-editor.org/rfc/rfc10015"}

	rfc9150 = Reference{"RFC 9150 — TLS 1.3 Authentication and Integrity-Only Cipher Suites", "https://www.rfc-editor.org/rfc/rfc9150"}

	nist80052   = Reference{"NIST SP 800-52 Rev. 2 — Guidelines for TLS Implementations", "https://csrc.nist.gov/pubs/sp/800/52/r2/final"}
	nist800131a = Reference{"NIST SP 800-131A Rev. 2 — Transitioning Cryptographic Algorithms", "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"}

	bsiTR02102 = Reference{"BSI TR-02102-2 — Cryptographic Mechanisms: TLS", "https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html"}

	mozillaTLS = Reference{"Mozilla Server Side TLS", "https://wiki.mozilla.org/Security/Server_Side_TLS"}

	sweet32 = Reference{"Sweet32 — CVE-2016-2183", "https://nvd.nist.gov/vuln/detail/CVE-2016-2183"}
	lucky13 = Reference{"Lucky Thirteen — CVE-2013-0169", "https://nvd.nist.gov/vuln/detail/CVE-2013-0169"}
	robot   = Reference{"ROBOT — Return Of Bleichenbacher's Oracle Threat", "https://robotattack.org/"}
	freak   = Reference{"FREAK — CVE-2015-0204", "https://nvd.nist.gov/vuln/detail/CVE-2015-0204"}
)

// CipherProperties are the facts read from a suite's IANA name. The registry
// assigns these names and does not reissue them, so parsing the name is
// stable in a way that depending on any library's constants is not.
type CipherProperties struct {
	Name string `json:"name"`

	// ForwardSecret is true for ephemeral key exchange, and for every TLS 1.3
	// suite, where the protocol requires it.
	ForwardSecret bool `json:"forwardSecret"`

	// AEAD is true for GCM, CCM, and ChaCha20-Poly1305.
	AEAD bool `json:"aead"`

	// KeyExchange and Cipher name the mechanisms, for display.
	KeyExchange string `json:"keyExchange"`
	Cipher      string `json:"cipher"`
}

// DescribeCipher extracts the facts. It makes no judgement.
func DescribeCipher(name string) CipherProperties {
	p := CipherProperties{Name: name}

	switch {
	case isIntegrityOnlySuite(name):
		// RFC 9150. A TLS 1.3 suite, so the key exchange is ephemeral, but
		// there is no encryption at all: the record carries an HMAC and the
		// payload in the clear. Handled before the branch below because that
		// one sets AEAD for every TLS 1.3 suite, and these are the exception
		// the naming scheme gives no way to spot.
		p.ForwardSecret = true
		p.KeyExchange = "ephemeral"
	case isTLS13Suite(name):
		// RFC 9846 removed static key exchange, so an ephemeral one holds for
		// every TLS 1.3 suite that encrypts.
		//
		// One qualification, because the name cannot carry it: TLS 1.3 also
		// has a PSK-only mode, psk_ke, which has no forward secrecy and is
		// negotiated through psk_key_exchange_modes rather than through the
		// suite. Nothing here performs a PSK handshake, so what this reports
		// is true of every connection this tool makes — and would need
		// qualifying if that ever stopped being so.
		p.ForwardSecret = true
		p.AEAD = true
		//
		// Named without the version it belongs to. Both faces print these
		// under a heading that already says "TLS 1.3", and a value that
		// repeats its own heading on every row is not an explanation of the
		// value — it is the heading again. Where the ephemerality comes from
		// is the paragraph above, and /method, and not a parenthesis on each
		// of the six rows of a table.
		p.KeyExchange = "ephemeral"
	case strings.Contains(name, "_ECDHE_"):
		p.ForwardSecret = true
		p.KeyExchange = "ECDHE"
	case strings.Contains(name, "_DHE_"):
		p.ForwardSecret = true
		p.KeyExchange = "DHE"
	case strings.Contains(name, "_ECDH_"):
		p.KeyExchange = "static ECDH"
	case strings.HasPrefix(name, "TLS_DH_"):
		p.KeyExchange = "static DH"
	case strings.HasPrefix(name, "TLS_RSA_"):
		p.KeyExchange = "static RSA"
	default:
		p.KeyExchange = "unknown"
	}

	switch {
	case isIntegrityOnlySuite(name):
		p.Cipher = "none"
	case strings.Contains(name, "_CHACHA20_POLY1305"):
		p.AEAD = true
		p.Cipher = "ChaCha20-Poly1305"
	// Before the generic AES branches: TLS_SM4_GCM_SM3 contains _GCM_, and
	// reporting a ShangMi suite as AES-GCM is a fact about the connection
	// stated wrongly. Facts are this function's only job.
	case strings.HasPrefix(name, "TLS_SM4_GCM"):
		p.AEAD = true
		p.Cipher = "SM4-GCM"
	case strings.HasPrefix(name, "TLS_SM4_CCM"):
		p.AEAD = true
		p.Cipher = "SM4-CCM"
	case strings.Contains(name, "_GCM_"), strings.HasSuffix(name, "_GCM_SHA256"), strings.HasSuffix(name, "_GCM_SHA384"):
		p.AEAD = true
		p.Cipher = "AES-GCM"
	case strings.Contains(name, "_CCM"):
		p.AEAD = true
		p.Cipher = "AES-CCM"
	case strings.Contains(name, "_CBC_"):
		p.Cipher = "CBC"
	case strings.Contains(name, "_RC4_"):
		p.Cipher = "RC4"
	case strings.Contains(name, "NULL"):
		p.Cipher = "none"
	default:
		p.Cipher = "unknown"
	}

	return p
}

type cipherRule struct {
	id        string
	match     func(name string) bool
	verdict   Verdict
	title     string
	rationale string
	refs      []Reference
}

// cipherRules are evaluated in order and the first match wins, so the most
// severe conditions come first. A suite matching nothing is graded on its
// properties at the end of GradeCipher.
var cipherRules = []cipherRule{
	{
		id:        "cipher.null",
		match:     func(n string) bool { return strings.Contains(n, "NULL") },
		verdict:   Insecure,
		title:     "No encryption",
		rationale: "Traffic is authenticated but sent in the clear, so anyone on the path reads it.",
		refs:      []Reference{rfc9325, nist80052},
	},
	{
		// RFC 9150 without the word NULL in the name, which is how it slipped
		// past the rule above. The consequence is identical and the sentence
		// is nearly the same; what differs is that this one is true of these
		// suites, and "no forward secrecy" — the verdict they used to get —
		// was not.
		id:        "cipher.no-encryption",
		match:     isIntegrityOnlySuite,
		verdict:   Insecure,
		title:     "No encryption",
		rationale: "The record carries an HMAC and the payload in the clear, so the connection is authenticated and readable by anyone on the path.",
		refs:      []Reference{rfc9150, rfc9325},
	},
	{
		id:        "cipher.anonymous",
		match:     func(n string) bool { return strings.Contains(n, "_anon_") },
		verdict:   Insecure,
		title:     "No server authentication",
		rationale: "Nothing binds the connection to an identity, so an active attacker can impersonate the server undetected.",
		refs:      []Reference{rfc9325},
	},
	{
		id:        "cipher.export",
		match:     func(n string) bool { return strings.Contains(n, "EXPORT") },
		verdict:   Insecure,
		title:     "Export-grade cryptography",
		rationale: "Key sizes were deliberately limited for 1990s export rules and are breakable today.",
		refs:      []Reference{freak, rfc9325},
	},
	{
		id:        "cipher.rc4",
		match:     func(n string) bool { return strings.Contains(n, "_RC4_") },
		verdict:   Insecure,
		title:     "RC4 stream cipher",
		rationale: "Biases in the RC4 keystream allow plaintext recovery; the IETF prohibits it outright.",
		refs:      []Reference{rfc7465, rfc9325},
	},
	{
		id:        "cipher.3des",
		match:     func(n string) bool { return strings.Contains(n, "_3DES_") },
		verdict:   Insecure,
		title:     "Triple DES",
		rationale: "A 64-bit block size makes collisions practical on long-lived connections, and NIST disallowed the algorithm after 2023.",
		refs:      []Reference{sweet32, nist800131a},
	},
	{
		id:        "cipher.des",
		match:     func(n string) bool { return strings.Contains(n, "_DES_") && !strings.Contains(n, "_3DES_") },
		verdict:   Insecure,
		title:     "Single DES",
		rationale: "A 56-bit key has been brute-forceable with commodity hardware for over two decades.",
		refs:      []Reference{nist800131a},
	},
	{
		id:        "cipher.md5",
		match:     func(n string) bool { return strings.HasSuffix(n, "_MD5") },
		verdict:   Insecure,
		title:     "MD5 message authentication",
		rationale: "MD5 is broken for collision resistance and is deprecated in TLS.",
		refs:      []Reference{rfc9155, nist800131a},
	},
	{
		// Finite-field ephemeral Diffie-Hellman. Forward-secret, and prohibited
		// anyway, which is why it needs a rule of its own: every property this
		// package reads off the name says the suite is fine.
		//
		// RFC 10015 (July 2026), updating BCP 195: "Clients MUST NOT offer and
		// servers MUST NOT select FFDHE cipher suites in (D)TLS 1.2
		// connections." That is the same language RFC 8996 uses about TLS 1.0,
		// and this rule set already grades that insecure rather than weak. The
		// reasons are Logjam and the long history of servers negotiating
		// groups they generated once and never looked at again; the elliptic
		// curve form is unaffected and remains the recommendation.
		//
		// _DHE_ does not match _ECDHE_: the character before DHE is C there,
		// not an underscore. Asserted in the tests rather than left to be
		// worked out from the substring.
		id:        "cipher.ffdhe",
		match:     func(n string) bool { return strings.Contains(n, "_DHE_") },
		verdict:   Insecure,
		title:     "Finite-field Diffie-Hellman key exchange",
		rationale: "RFC 10015 prohibits offering or selecting finite-field DHE suites in TLS 1.2. The exchange is forward-secret, but the groups are frequently weak or reused, and the elliptic curve form replaces it with no loss.",
		refs:      []Reference{rfc10015, rfc9325},
	},
	{
		// Narrowed on 2026-08-22, and the narrowing is the fix.
		//
		// This used to fire on !ForwardSecret, which is false for every suite
		// whose key exchange this package cannot read off the name. A suite it
		// did not recognise was therefore accused of deriving its session key
		// from a long-term key — a specific, checkable, and frequently untrue
		// statement. TLS_SM4_GCM_SM3 collected it, and so did every name the
		// standard library renders as a bare code point.
		//
		// It now fires only where the name says the key exchange is static,
		// which is the only case the rationale describes. Anything unreadable
		// falls to cipher.unrecognised, which claims nothing.
		id: "cipher.no-forward-secrecy",
		match: func(n string) bool {
			switch DescribeCipher(n).KeyExchange {
			case "static RSA", "static DH", "static ECDH":
				return true
			}
			return false
		},
		verdict:   Insecure,
		title:     "No forward secrecy",
		rationale: "The session key is derived from a long-term key, so anyone who later obtains the server's private key can decrypt traffic captured months or years earlier.",
		refs:      []Reference{rfc9325, rfc10015, rfc9846, robot, bsiTR02102},
	},
	{
		id: "cipher.cbc",
		match: func(n string) bool {
			return strings.Contains(n, "_CBC_")
		},
		verdict:   Weak,
		title:     "CBC mode",
		rationale: "The MAC-then-encrypt construction in TLS has produced a long line of padding-oracle attacks; AEAD replaces it.",
		refs:      []Reference{lucky13, rfc9325, mozillaTLS},
	},
	{
		// Last, so that anything actually known about the suite is reported
		// instead of this.
		//
		// GradeVersion has always answered an unrecognised version this way —
		// weak, and it says it was not graded. GradeCipher answered the same
		// question with an accusation. One package, one question, two answers,
		// and the wrong one was the one that spoke with confidence.
		//
		// Weak rather than ungraded: Worst() skips ungraded, so an unreadable
		// suite would drop out of the aggregate and a server accepting one
		// could still be graded strong overall. Weak carries into the
		// aggregate without asserting a defect.
		id:        "cipher.unrecognised",
		match:     func(n string) bool { return DescribeCipher(n).KeyExchange == "unknown" },
		verdict:   Weak,
		title:     "Unrecognised cipher suite",
		rationale: "This suite is not covered by the rule set and was not graded. Its key exchange could not be read from its name, so nothing here can say whether it is sound.",
		refs:      []Reference{rfc9325, mozillaTLS},
	},
}

// CipherFinding is a graded cipher suite.
type CipherFinding struct {
	CipherProperties
	Verdict Verdict `json:"verdict"`

	// Findings is empty when the suite meets current practice.
	Findings []Finding `json:"findings,omitempty"`
}

// GradeCipher applies the rules to one suite, identified by IANA name.
func GradeCipher(name string) CipherFinding {
	out := CipherFinding{
		CipherProperties: DescribeCipher(name),
		Verdict:          Strong,
	}

	for _, rule := range cipherRules {
		if !rule.match(name) {
			continue
		}
		out.Findings = append(out.Findings, Finding{
			RuleID:     rule.id,
			Verdict:    rule.verdict,
			Title:      rule.title,
			Rationale:  rule.rationale,
			References: rule.refs,
			Policy:     Version,
		})
		out.Verdict = rule.verdict
		break
	}

	// A suite that matched no rule still has to satisfy current practice:
	// AEAD with an ephemeral key exchange. Anything else is weak even if no
	// specific rule names it, so a future suite cannot slip through unrated.
	if len(out.Findings) == 0 && !(out.AEAD && out.ForwardSecret) {
		out.Verdict = Weak
		out.Findings = append(out.Findings, Finding{
			RuleID:     "cipher.not-current-practice",
			Verdict:    Weak,
			Title:      "Does not meet current practice",
			Rationale:  "Current guidance is AEAD encryption with an ephemeral key exchange; this suite provides one or neither.",
			References: []Reference{rfc9325, mozillaTLS},
			Policy:     Version,
		})
	}

	return out
}

// Protocol version constants. They match crypto/tls but are declared here so
// this package stays independent of it; a test asserts they agree.
const (
	VersionSSL30 uint16 = 0x0300
	VersionTLS10 uint16 = 0x0301
	VersionTLS11 uint16 = 0x0302
	VersionTLS12 uint16 = 0x0303
	VersionTLS13 uint16 = 0x0304
)

// VersionFinding is a graded protocol version.
type VersionFinding struct {
	Verdict  Verdict   `json:"verdict"`
	Findings []Finding `json:"findings,omitempty"`

	// Preferred marks the version current guidance points to.
	Preferred bool `json:"preferred"`
}

// GradeVersion grades one protocol version.
//
// TLS 1.0 and 1.1 are graded insecure rather than weak. RFC 8996 states that
// they MUST NOT be used and MUST NOT be negotiated, which is the strongest
// language the IETF issues. Several scanners are gentler here; this rule
// follows the document.
func GradeVersion(version uint16) VersionFinding {
	switch {
	case version <= VersionSSL30:
		return VersionFinding{
			Verdict: Insecure,
			Findings: []Finding{{
				RuleID:     "version.ssl3",
				Verdict:    Insecure,
				Title:      "SSL 3.0 or earlier",
				Rationale:  "SSL 3.0 is broken by POODLE and was deprecated by the IETF in 2015.",
				References: []Reference{rfc7568, rfc9325},
				Policy:     Version,
			}},
		}

	case version == VersionTLS10, version == VersionTLS11:
		name := "TLS 1.0"
		if version == VersionTLS11 {
			name = "TLS 1.1"
		}
		return VersionFinding{
			Verdict: Insecure,
			Findings: []Finding{{
				RuleID:     "version.deprecated",
				Verdict:    Insecure,
				Title:      name + " is deprecated",
				Rationale:  "RFC 8996 states that this version MUST NOT be used and MUST NOT be negotiated. It relies on SHA-1 and MD5 and offers no AEAD suites.",
				References: []Reference{rfc8996, nist80052, bsiTR02102},
				Policy:     Version,
			}},
		}

	case version == VersionTLS12:
		// Acceptable with a sound suite selection, which is graded
		// separately. No finding is raised for the version itself.
		return VersionFinding{Verdict: Strong}

	case version == VersionTLS13:
		return VersionFinding{Verdict: Strong, Preferred: true}

	default:
		return VersionFinding{
			Verdict: Weak,
			Findings: []Finding{{
				RuleID:     "version.unknown",
				Verdict:    Weak,
				Title:      "Unrecognised protocol version",
				Rationale:  "This version is not covered by the rule set and was not graded.",
				References: []Reference{rfc9325},
				Policy:     Version,
			}},
		}
	}
}

// isTLS13Suite reports whether the name belongs to the TLS 1.3 scheme.
//
// RFC 8446 changed how suites are named — TLS_AEAD_HASH, with the key exchange
// no longer part of the name — and the registry now holds four families under
// it. Matching the whole set matters more than it looks: a TLS 1.3 suite that
// is not recognised here falls through to a key exchange of "unknown", and
// until 2026-08-22 that produced a verdict of insecure with the reason "no
// forward secrecy", which is the one thing a TLS 1.3 suite cannot lack.
//
// Checked against the IANA registry on 2026-08-22. The list is a list rather
// than a rule about the absence of _WITH_, because two registered values —
// TLS_EMPTY_RENEGOTIATION_INFO_SCSV and TLS_FALLBACK_SCSV — are signalling
// values with no _WITH_ and no cipher, and a structural rule would grade them
// as strong TLS 1.3 suites.
func isTLS13Suite(name string) bool {
	return strings.HasPrefix(name, "TLS_AES_") ||
		strings.HasPrefix(name, "TLS_CHACHA20_POLY1305_") ||
		strings.HasPrefix(name, "TLS_SM4_") || // RFC 8998
		strings.HasPrefix(name, "TLS_AEGIS_")
}

// hasLetter distinguishes an algorithm name from a number.
//
// Both of the standard library's algorithm String methods render a value they
// have no name for as its decimal digits — "0" for the zero value, "99" for
// anything out of range. A rule matching on substrings of a name has to be
// able to tell that apart from a name, or it silently matches nothing and the
// certificate passes.
func hasLetter(s string) bool {
	return strings.IndexFunc(s, unicode.IsLetter) >= 0
}

// isIntegrityOnlySuite reports the two RFC 9150 suites, which authenticate
// without encrypting. Named exactly: the pair is closed, and a prefix rule
// over "TLS_SHA" would catch nothing else today and something else tomorrow.
func isIntegrityOnlySuite(name string) bool {
	return name == "TLS_SHA256_SHA256" || name == "TLS_SHA384_SHA384"
}
