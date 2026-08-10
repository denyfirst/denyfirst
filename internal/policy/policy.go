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

import "strings"

// Version identifies this rule set. Every report states which version graded
// it, so a verdict can be reproduced later even after the rules move on.
const Version = "denyfirst-v1"

// ReviewBy is when these rules should next be read against their sources.
//
// Standards move on their own schedule. RFC 8996 appeared while TLS 1.0 was
// still common, and the CA/Browser Forum validity limit changes on dates
// already fixed. A rule set with no review date drifts until somebody
// notices it is wrong, and that somebody is usually a user.
//
// A test fails once this date passes. The failure is a reminder rather than a
// defect: read the rules against their references, then move the date.
const ReviewBy = "2026-11-01"

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
	rfc8446 = Reference{"RFC 8446 — TLS 1.3", "https://www.rfc-editor.org/rfc/rfc8446"}
	rfc8996 = Reference{"RFC 8996 — Deprecating TLS 1.0 and TLS 1.1", "https://www.rfc-editor.org/rfc/rfc8996"}
	rfc9155 = Reference{"RFC 9155 — Deprecating MD5 and SHA-1 signature hashes in TLS", "https://www.rfc-editor.org/rfc/rfc9155"}
	rfc9325 = Reference{"RFC 9325 (BCP 195) — Recommendations for Secure Use of TLS", "https://www.rfc-editor.org/rfc/rfc9325"}

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
	case isTLS13Suite(name):
		// RFC 8446 removed static key exchange and non-AEAD ciphers, so both
		// properties hold for every TLS 1.3 suite by construction.
		p.ForwardSecret = true
		p.AEAD = true
		p.KeyExchange = "ephemeral (TLS 1.3)"
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
	case strings.Contains(name, "_CHACHA20_POLY1305"):
		p.AEAD = true
		p.Cipher = "ChaCha20-Poly1305"
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
		id: "cipher.no-forward-secrecy",
		match: func(n string) bool {
			p := DescribeCipher(n)
			return !p.ForwardSecret
		},
		verdict:   Insecure,
		title:     "No forward secrecy",
		rationale: "The session key is derived from a long-term key, so anyone who later obtains the server's private key can decrypt traffic captured months or years earlier.",
		refs:      []Reference{rfc9325, rfc8446, robot, bsiTR02102},
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

func isTLS13Suite(name string) bool {
	return strings.HasPrefix(name, "TLS_AES_") ||
		strings.HasPrefix(name, "TLS_CHACHA20_POLY1305_") ||
		strings.HasPrefix(name, "TLS_AEGIS_")
}
