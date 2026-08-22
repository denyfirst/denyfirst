package policy

import (
	"fmt"
	"strings"
	"time"
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

	// KeyBits is the RSA modulus size or the elliptic curve field size.
	// Ed25519 has no size parameter and reports 0.
	KeyBits int

	// SignatureAlgorithm is the Go rendering of the OID, such as "SHA256-RSA".
	SignatureAlgorithm string

	// HasSAN is false for certificates that carry only a Common Name. Every
	// major browser has rejected those since 2017.
	HasSAN bool

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
}

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

	// An algorithm this rule set does not know is not an algorithm it approves
	// of. LeafFacts documents "" as the unrecognised case and the switch below
	// used to fall through it in silence, which left key strength ungraded and
	// the certificate graded strong — the same question that GradeVersion
	// answers with a weak verdict and a sentence saying so. certinfo already
	// adds a note; a note does not reach the verdict, and the verdict is what
	// is read.
	if f.KeyAlgorithm == "" {
		add("cert.key-algorithm-unrecognised", Weak,
			"Key algorithm not recognised",
			"The public key is of a type this rule set does not know, so its strength was not graded. Nothing here says it is weak; nothing here can say it is sound either.",
			nist80057, cabBR)
	}

	switch f.KeyAlgorithm {
	case "RSA":
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
