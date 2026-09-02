package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	cabBR = Reference{
		"CA/Browser Forum — Baseline Requirements for TLS Server Certificates",
		"https://cabforum.org/working-groups/server/baseline-requirements/documents/",
	}
	cabSC081 = Reference{
		"CA/Browser Forum Ballot SC-081v3 — Schedule of Reducing Validity Periods",
		"https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/",
	}
	rfc5280 = Reference{
		"RFC 5280 — Internet X.509 Public Key Infrastructure Certificate Profile",
		"https://www.rfc-editor.org/rfc/rfc5280",
	}
	rfc6125 = Reference{
		"RFC 6125 — Representation and Verification of Application Service Identity",
		"https://www.rfc-editor.org/rfc/rfc6125",
	}
	nist80057 = Reference{
		"NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management",
		"https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final",
	}

	rfc9525 = Reference{
		"RFC 9525 — Service Identity in TLS",
		"https://www.rfc-editor.org/rfc/rfc9525",
	}

	roca2017 = Reference{
		"ROCA — Nemec, Sýs, Švenda, Klinec and Matyáš, ACM CCS 2017",
		"https://crocs.fi.muni.cz/public/papers/rsa_ccs17",
	}

	cve201715361 = Reference{
		"CVE-2017-15361 — Infineon RSA key generation",
		"https://nvd.nist.gov/vuln/detail/CVE-2017-15361",
	}
	shattered = Reference{
		"SHAttered — the first practical SHA-1 collision",
		"https://shattered.io/",
	}
)

// LeafFacts describes a server certificate in terms this package can grade
// without importing crypto/x509. The separation is the same one applied to
// cipher suites: certinfo measures, policy judges.
type LeafFacts struct {
	NotBefore time.Time
	NotAfter  time.Time

	// KeyAlgorithm is "RSA", "ECDSA", "Ed25519", or "" when unrecognised.
	KeyAlgorithm string

	// KeyFromBrokenGenerator is the RSA key carrying the RSALib fingerprint
	// of CVE-2017-15361. It is a statement about how the key was made, not a
	// claim that anybody factored it, and the rule below says so in those
	// words.
	KeyFromBrokenGenerator bool

	// KeyBits is the RSA modulus size or the elliptic curve field size.
	// Ed25519 has no size parameter and reports 0.
	KeyBits int

	// SignatureAlgorithm is the Go rendering of the OID, such as "SHA256-RSA".
	SignatureAlgorithm string

	// HasSAN is false for certificates that carry only a Common Name. Every
	// major browser has rejected those since 2017.
	HasSAN bool

	// SerialBits is the bit length of the serial number.
	SerialBits int

	// CommonName is the subject common name, and DNSNames the names in the
	// subject alternative name extension. Both are needed to say whether the
	// first is among the second.
	CommonName string
	DNSNames   []string

	// HasExtKeyUsage and ServerAuth describe the extended key usage
	// extension: whether the certificate carries one at all, and whether it
	// permits TLS server authentication. Absent is not the same as excluding.
	HasExtKeyUsage bool
	ServerAuth     bool

	SelfSigned bool

	// ChainTrusted is the result of verifying the presented chain against the
	// system trust store.
	ChainTrusted bool

	// ChainComplete is false when the server sent a leaf that needs an issuer
	// it did not provide. Some clients recover by fetching it; many do not.
	ChainComplete bool

	// HostnameMatches reports whether the requested name appears in the
	// certificate.
	HostnameMatches bool

	// What the certificate says it is allowed to be and to do.
	//
	// All three were displayed in the report and graded by nothing. A reader
	// saw "CA: true" beside a leaf and no finding next to it.

	// IsCA is the basic constraints extension saying this certificate may
	// sign others. On a leaf it is the largest thing a certificate can claim.
	IsCA bool

	// BasicConstraintsValid is false when the extension was absent or could
	// not be parsed, so IsCA means "not stated" rather than "false".
	BasicConstraintsValid bool

	// HasKeyUsage, KeyCertSign and DigitalSignature come from the key usage
	// extension. Absent is not the same as excluding, exactly as with the
	// extended key usage above.
	HasKeyUsage      bool
	KeyCertSign      bool
	DigitalSignature bool

	// UnhandledCriticalExtensions names the critical extensions this
	// implementation does not understand. RFC 5280 requires a client to
	// reject such a certificate, so the list is not a curiosity.
	UnhandledCriticalExtensions []string
}

// What a finding may repeat back from the certificate it describes.
//
// Every name quoted by a rule below is chosen by the server being examined,
// which on a hostile target means it is chosen by the target. internal/certinfo
// bounds what reaches the report for display and says why at the top of its
// file: passing it through unbounded turns one small request into a reply
// measured in megabytes, paid for by whoever asked for the scan rather than by
// the server that sent it.
//
// These are the same bound applied to a sentence, and they are separate
// because the two jobs differ: a rule has to decide on the whole list even
// when it may only quote part of it. A wildcard malformed at position three
// thousand is still a malformed wildcard.
//
// Measured on 2026-09-01, before this existed: a certificate carrying five
// thousand malformed names produced one finding of 1,085,200 bytes.
const (
	maxNamesInAFinding = 5
	maxNameInAFinding  = 64
)

// expiryWarningDays is when a certificate is close enough to expiry that
// something in the renewal path has probably failed. With the CA/Browser
// Forum moving towards 47-day certificates, renewal is expected to be
// automated, and thirty days of silence means the automation is not working.
const expiryWarningDays = 30

// MaxValidityDays returns the CA/Browser Forum maximum validity for a
// certificate issued at the given moment.
//
// The limit is a schedule, not a constant. Ballot SC-081v3 reduces it from
// 398 days to 200 on 15 March 2026, to 100 on 15 March 2027, and to 47 on
// 15 March 2029. Hardcoding any single value would make this rule quietly
// wrong on a known date.
//
// The comparison uses the issuance time rather than the time of the scan,
// because compliance is judged when the certificate is signed. A 398-day
// certificate issued in January 2026 is valid; the same certificate issued in
// April 2026 is a misissuance.
func MaxValidityDays(issued time.Time) int {
	switch {
	case !issued.Before(time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC)):
		return 47
	case !issued.Before(time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC)):
		return 100
	case !issued.Before(time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)):
		return 200
	default:
		return 398
	}
}

// LeafFinding is a graded server certificate.
type LeafFinding struct {
	Verdict  Verdict   `json:"verdict"`
	Findings []Finding `json:"findings,omitempty"`

	// DaysRemaining is negative once the certificate has expired.
	DaysRemaining int `json:"daysRemaining"`

	// ValidityDays is the certificate's own lifetime, and MaxValidityDays the
	// limit that applied when it was issued.
	ValidityDays    int `json:"validityDays"`
	MaxValidityDays int `json:"maxValidityDays"`
}

// GradeLeaf applies the certificate rules. The caller supplies now so results
// are reproducible in tests and so a report can state the moment it describes.
func GradeLeaf(f LeafFacts, now time.Time) LeafFinding {
	out := LeafFinding{
		Verdict:         Strong,
		DaysRemaining:   int(f.NotAfter.Sub(now).Hours() / 24),
		ValidityDays:    int(f.NotAfter.Sub(f.NotBefore).Hours() / 24),
		MaxValidityDays: MaxValidityDays(f.NotBefore),
	}

	add := func(id string, v Verdict, title, rationale string, refs ...Reference) {
		out.Findings = append(out.Findings, Finding{
			RuleID:     id,
			Verdict:    v,
			Title:      title,
			Rationale:  rationale,
			References: refs,
			Policy:     Version,
		})
	}

	// ── Validity window ──────────────────────────────────────────────
	switch {
	case now.After(f.NotAfter):
		add("cert.expired", Insecure,
			"Certificate has expired",
			fmt.Sprintf("Validity ended on %s, %d days ago. Clients will refuse the connection or warn the user.",
				f.NotAfter.UTC().Format(time.DateOnly), -out.DaysRemaining),
			rfc5280, cabBR)

	case now.Before(f.NotBefore):
		add("cert.not-yet-valid", Insecure,
			"Certificate is not yet valid",
			fmt.Sprintf("Validity begins on %s. Until then clients will reject it, and a clock skew on either side widens the window.",
				f.NotBefore.UTC().Format(time.DateOnly)),
			rfc5280)

	case out.DaysRemaining <= expiryWarningDays:
		add("cert.expiring-soon", Weak,
			"Certificate expires soon",
			fmt.Sprintf("%d days remain. Renewal is expected to be automated; this little margin suggests it is not running.",
				out.DaysRemaining),
			cabSC081)
	}

	// ── Trust ────────────────────────────────────────────────────────
	if f.SelfSigned {
		add("cert.self-signed", Insecure,
			"Self-signed certificate",
			"No certificate authority vouches for this key, so a client has no way to distinguish the real server from an impostor.",
			rfc5280, cabBR)
	} else if !f.ChainTrusted {
		add("cert.chain-untrusted", Insecure,
			"Chain does not reach a trusted root",
			"The presented chain could not be verified against the system trust store, so clients will refuse the connection.",
			rfc5280, cabBR)
	}

	if !f.ChainComplete && !f.SelfSigned {
		add("cert.chain-incomplete", Weak,
			"Incomplete certificate chain",
			"The server did not send the certificate that issued this one. Browsers often recover by fetching the missing issuer; command-line clients, mobile apps, and API consumers usually do not.",
			rfc5280, cabBR)
	}

	if !f.HostnameMatches {
		add("cert.hostname-mismatch", Insecure,
			"Certificate does not cover this hostname",
			"The requested name appears in neither the subject alternative names nor a matching wildcard, so clients cannot tell this certificate was issued for this server.",
			rfc6125, cabBR)
	}

	if !f.HasSAN {
		add("cert.no-san", Insecure,
			"No subject alternative name",
			"Identity is asserted only through the Common Name, which every major browser stopped honouring in 2017.",
			rfc6125, cabBR)
	}

	// ── Cryptography ─────────────────────────────────────────────────
	sig := strings.ToUpper(f.SignatureAlgorithm)
	switch {
	case !hasLetter(sig):
		// Go renders a signature algorithm it has no name for as its decimal
		// value — "0", "99" — so neither branch below matches and the
		// certificate used to pass the cryptography section in silence. The
		// key algorithm got this treatment on 2026-08-22 and the signature
		// algorithm did not, which is the same omission left half-closed.
		add("cert.signature-algorithm-unrecognised", Weak,
			"Signature algorithm not recognised",
			"The algorithm that signed this certificate is not one this rule set knows, so whether the hash behind it is sound was not established. Nothing here says it is weak; nothing here can say it is sound either.",
			rfc5280, rfc9155)

	case strings.Contains(sig, "MD2"), strings.Contains(sig, "MD5"):
		add("cert.signature-md5", Insecure,
			"Certificate signed with MD5 or MD2",
			"Collisions in these hashes are trivial to produce, so a forged certificate can carry a valid-looking signature.",
			rfc9155, cabBR)

	case strings.Contains(sig, "SHA1"):
		add("cert.signature-sha1", Insecure,
			"Certificate signed with SHA-1",
			"A practical SHA-1 collision was demonstrated in 2017, and certificate authorities were required to stop issuing SHA-1 certificates in 2016.",
			shattered, rfc9155, cabBR)
	}

	// Every case, not only the ones with a size to check.
	//
	// This used to be a switch with arms for RSA and ECDSA and no default, so
	// a key of any other type left the cryptography section in silence and the
	// certificate could still be graded strong. GradeVersion answers the same
	// question with a weak verdict and a sentence saying it was not graded;
	// this now does too.
	//
	// The default arm becomes reachable in a new way from Go 1.27, which adds
	// ML-DSA keys to crypto/x509. A post-quantum certificate is not weak, but
	// it is not something this rule set has read either, and saying so is the
	// only honest answer until somebody adds the case.
	switch f.KeyAlgorithm {
	case "RSA":
		if f.KeyFromBrokenGenerator {
			add("cert.roca", Insecure,
				"Key made by a generator known to produce factorable keys",
				"The modulus carries the fingerprint of Infineon's RSALib, which built primes from a "+
					"small family instead of at random. A key of that shape can be factored from the "+
					"public key alone by Coppersmith's method — weeks to months of computation, and "+
					"nothing an attacker needs the server for. Millions of smart cards, TPMs and "+
					"identity cards were affected in 2017 and the certificates among them were "+
					"revoked. This is a fingerprint of how the key was generated; nothing here "+
					"factored anything. Replace the key rather than reissuing the same one.",
				roca2017, cve201715361, cabBR)
		}
		if f.KeyBits < 2048 {
			add("cert.rsa-key-too-small", Insecure,
				fmt.Sprintf("RSA key of %d bits", f.KeyBits),
				"The CA/Browser Forum has required at least 2048 bits since 2014; below that the key is within reach of a well-resourced attacker.",
				cabBR, nist80057)
		}
	case "ECDSA":
		if f.KeyBits < 256 {
			add("cert.ec-key-too-small", Insecure,
				fmt.Sprintf("Elliptic curve key of %d bits", f.KeyBits),
				"Curves below P-256 fall short of the 128-bit security level expected of a public certificate.",
				cabBR, nist80057)
		}
	case "Ed25519":
		// No size parameter to check: the curve is the security level, and
		// there is only one. Listed rather than left to the default so that
		// the absence of a finding here is a decision and not an omission.

	default:
		// See the note in chain.go: an algorithm name of only whitespace is
		// no name, and testing for "" alone left "  key" in a sentence.
		named := strings.TrimSpace(f.KeyAlgorithm)
		if named == "" {
			named = "of an unnamed type"
		} else {
			named = named + " key"
		}
		add("cert.key-algorithm-unrecognised", Weak,
			"Key algorithm not recognised",
			fmt.Sprintf("The public key is %s, which this rule set does not know how to size, so its strength was not graded. Nothing here says it is weak; nothing here can say it is sound either.", named),
			nist80057, cabBR)
	}

	// A leaf that may sign other certificates.
	//
	// Displayed since this project began and graded by nothing: the report
	// printed "CA: true" beside a leaf and put no finding next to it.
	//
	// RFC 5280 does not forbid it, and Go's verifier accepts such a
	// certificate for a hostname, so nothing else on the page catches it. The
	// CA/Browser Forum does forbid it — a subscriber certificate must carry
	// cA:FALSE — and the reason is the size of what the key can do. A stolen
	// leaf key normally impersonates the names in that leaf. A stolen leaf
	// key that may sign issues certificates for any name at all, and every
	// client that trusts the chain accepts them.
	if f.BasicConstraintsValid && f.IsCA {
		add("cert.leaf-is-ca", Insecure,
			"This certificate may issue other certificates",
			"Basic constraints say cA:TRUE on the certificate served for this host, so whoever "+
				"holds its private key can sign certificates for any name, not only for the names "+
				"here. The Baseline Requirements require cA:FALSE on a subscriber certificate.",
			rfc5280, cabBR)
	}

	// A key usage that permits signing certificates, which is the same power
	// as above arriving by the other extension.
	//
	// Separate from the rule above because the two can disagree, and a
	// certificate where they disagree is malformed in a way worth naming:
	// RFC 5280 says keyCertSign is meaningful only where basic constraints
	// say cA:TRUE.
	if f.HasKeyUsage && f.KeyCertSign && !f.IsCA {
		add("cert.key-usage-cert-sign", Insecure,
			"The key usage permits signing certificates",
			"The key usage extension includes keyCertSign while basic constraints do not say "+
				"cA:TRUE. RFC 5280 permits keyCertSign only on a certificate authority, so this "+
				"certificate claims a power its own constraints deny it and clients disagree about "+
				"which of the two to believe.",
			rfc5280)
	}

	// A key usage that does not permit what TLS needs.
	//
	// Every TLS 1.3 handshake and every ECDHE handshake at TLS 1.2 has the
	// server sign with its key, so a certificate whose key usage omits
	// digitalSignature cannot be used for either. Absent is not excluding:
	// with no extension at all the key may be used for anything.
	if f.HasKeyUsage && !f.DigitalSignature {
		add("cert.no-digital-signature", Weak,
			"The key usage does not permit signing",
			"The key usage extension lists what this key may do and does not list "+
				"digitalSignature. Every TLS 1.3 handshake and every ECDHE handshake at TLS 1.2 "+
				"requires the server to sign with this key, so a client enforcing the extension "+
				"cannot use either with this certificate.",
			rfc5280)
	}

	// A critical extension nobody here understands.
	//
	// RFC 5280 is explicit: a client that meets a critical extension it does
	// not recognise must reject the certificate. Go's verifier does, so such
	// a certificate already produces cert.chain-untrusted — with no reason
	// attached. This names the reason, which is the difference between an
	// operator who can fix it and one who cannot.
	if len(f.UnhandledCriticalExtensions) > 0 {
		add("cert.critical-extension-unrecognised", Weak,
			"A critical extension this checker does not recognise",
			"The certificate marks "+listed(f.UnhandledCriticalExtensions)+" critical, and RFC 5280 "+
				"requires a client that does not recognise a critical extension to reject the "+
				"certificate. What this scan cannot tell you is whether the clients you care about "+
				"recognise it; what it can tell you is that this one does not.",
			rfc5280)
	}

	// ── What the certificate is for ──────────────────────────────────
	//
	// An extended key usage extension that lists purposes and omits server
	// authentication is a certificate for something else. RFC 5280 makes the
	// listed purposes exhaustive, so a client following it refuses the
	// connection; absent extension means any purpose and is not this case.
	if f.HasExtKeyUsage && !f.ServerAuth {
		add("cert.no-server-auth", Insecure,
			"Not a certificate for TLS servers",
			"The extended key usage extension lists what this certificate may be used for and does "+
				"not list server authentication. RFC 5280 makes that list exhaustive, so a client "+
				"following it refuses the connection whatever else is correct here.",
			rfc5280, cabBR)
	}

	// ── The names ────────────────────────────────────────────────────
	//
	// A wildcard has to be the whole of the leftmost label. `*.example.com`
	// is a wildcard; `w*.example.com`, `a.*.example.com` and `*` are not, and
	// clients following RFC 9525 match none of them — so a name in one of
	// those shapes covers nothing while looking as though it covers something.
	if bad := malformedWildcards(f.DNSNames); len(bad) > 0 {
		add("cert.wildcard-shape", Weak,
			"A wildcard name that no client will match",
			fmt.Sprintf("%s. A wildcard has to be the entire leftmost label — `*.example.com` and "+
				"nothing else — so a client following RFC 9525 matches no host against these. The "+
				"certificate covers less than it appears to.", listed(bad)),
			rfc9525, cabBR)
	}

	// The common name is not an identity and has not been one for years, but
	// it is still read by people. A hostname there that is absent from the
	// subject alternative name is matched by nothing and tells a reader the
	// certificate covers a host it does not.
	if f.CommonName != "" && looksLikeHostname(f.CommonName) && !covers(f.DNSNames, f.CommonName) {
		add("cert.cn-not-in-san", Weak,
			"The common name is not among the names",
			fmt.Sprintf("The subject common name is %s and it is not in the subject alternative name "+
				"extension. Clients have matched names only from that extension since RFC 2818 was "+
				"replaced, so this name is matched by nothing, and the CA/Browser Forum requires a "+
				"common name to repeat a value from the extension rather than add one.",
				listed([]string{f.CommonName})),
			rfc9525, cabBR)
	}

	// ── The serial ───────────────────────────────────────────────────
	//
	// Only for a chain that reaches the trust store: the requirement is the
	// CA/Browser Forum's, and a private authority answers to whoever runs it.
	//
	// The threshold is not 64, and the arithmetic is the reason. A serial
	// carrying 64 bits of output from a random source is uniform over
	// [0, 2^64), so its value has fewer than 64 bits half the time and fewer
	// than 63 a quarter of the time: a check demanding 64 would accuse half
	// of every compliant certificate ever issued. What can be said from one
	// certificate is that a serial this small cannot hold that output at all
	// — the chance a compliant one lands below 2^32 is one in four thousand
	// million.
	//
	// So this catches counters and sequences, which is the failure it can
	// honestly catch, and stays silent about the rest.
	// SerialBits is zero both when the serial is zero and when nobody read
	// it, and those are different states. The existing tests in this package
	// build facts by hand and leave it unset, and the first version of this
	// rule accused every one of them — a measurement that did not happen
	// drawn as one that did, which is R12 in the smallest possible form. So
	// the rule requires a measurement before it says anything, and a serial
	// that really is not positive is a malformed certificate reported as a
	// note beside the others.
	if f.ChainTrusted && f.SerialBits > 0 && f.SerialBits < 32 {
		add("cert.serial-entropy", Weak,
			"Serial number too small to be random",
			fmt.Sprintf("The serial number is %d bits. The CA/Browser Forum has required at least 64 "+
				"bits from a random source since 2016, because a predictable serial lets an attacker "+
				"who can influence the certificate's contents mount a hash collision against its "+
				"signature. A serial this small is a counter, not that output.", f.SerialBits),
			cabBR, rfc5280)
	}

	// ── Lifetime ─────────────────────────────────────────────────────
	if out.ValidityDays > out.MaxValidityDays {
		add("cert.validity-too-long", Weak,
			fmt.Sprintf("Lifetime of %d days exceeds the %d-day limit", out.ValidityDays, out.MaxValidityDays),
			fmt.Sprintf("A certificate issued on %s may run for at most %d days under Ballot SC-081v3. A longer lifetime keeps a compromised key usable for longer and, for a publicly trusted certificate, is grounds for revocation.",
				f.NotBefore.UTC().Format(time.DateOnly), out.MaxValidityDays),
			cabSC081, cabBR)
	}

	verdicts := make([]Verdict, 0, len(out.Findings))
	for _, f := range out.Findings {
		verdicts = append(verdicts, f.Verdict)
	}
	if v := Worst(verdicts...); v != Ungraded {
		out.Verdict = v
	}

	return out
}

// malformedWildcards returns the names whose wildcard is not a whole label.
//
// RFC 9525 permits one form: a leftmost label that is exactly "*", with at
// least one label after it. Everything else here was accepted by clients at
// some point in the past and is accepted by none now.
func malformedWildcards(names []string) []string {
	var bad []string
	for _, name := range names {
		if !strings.Contains(name, "*") {
			continue
		}
		labels := strings.Split(name, ".")
		switch {
		case len(labels) < 3:
			// "*" and "*.com" alike. The second is refused by every client
			// for a different reason as well, and neither is matchable here.
			bad = append(bad, name)
		case labels[0] != "*":
			bad = append(bad, name)
		case strings.Contains(name[1:], "*"):
			bad = append(bad, name)
		}
	}
	return bad
}

// looksLikeHostname reports whether a common name is trying to be a name.
//
// Most are not: an authority's own certificate carries something like "R11",
// and older leaf certificates carry an organisation. Reading either of those
// as a hostname absent from the extension would be an accusation about a
// field that was never claiming to be one.
func looksLikeHostname(cn string) bool {
	return strings.Contains(cn, ".") &&
		!strings.ContainsAny(cn, " \t,=+\"") &&
		!strings.HasPrefix(cn, ".") &&
		!strings.HasSuffix(cn, ".")
}

// covers reports whether the names include one, comparing as DNS does.
func covers(names []string, want string) bool {
	for _, name := range names {
		if strings.EqualFold(name, want) {
			return true
		}
	}
	return false
}

// named renders values for a sentence: quoted, shortened, and counted.
//
// Quoted with strconv.Quote rather than written in plain, which is not only
// for reading. A name arrives as the bytes the server chose, and a certificate
// may carry an escape sequence in one: a terminal reads 0x1b as an
// instruction, so a name can erase the verdict printed above it. Quoting
// renders it as \x1b and the terminal prints four characters. certinfo makes
// the same argument for the subject, one round earlier.
func listed(values []string) string {
	shown := values
	if len(shown) > maxNamesInAFinding {
		shown = shown[:maxNamesInAFinding]
	}

	quoted := make([]string, len(shown))
	for i, v := range shown {
		quoted[i] = strconv.Quote(shorten(v))
	}

	out := list(quoted)
	if extra := len(values) - len(shown); extra > 0 {
		out += fmt.Sprintf(", and %d more", extra)
	}
	return out
}

// shorten cuts on a rune boundary, so a truncated name is still text.
func shorten(s string) string {
	if len(s) <= maxNameInAFinding {
		return s
	}
	cut := maxNameInAFinding
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
