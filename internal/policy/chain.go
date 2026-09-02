package policy

import (
	"fmt"
	"strings"
	"time"
)

// The rest of the chain.
//
// Until 2026-09-02 all twenty-four certificate rules looked at the
// certificate served for the host and at nothing else. The chain was checked
// for trust — does it reach a root — and never for strength. A report said
//
//	Chain   4 certificates, trusted
//
// beside a strong verdict, and three of those four had been graded by
// nothing. An intermediate signed with SHA-1, or holding a 1024-bit key,
// passed in silence.
//
// It matters more on an issuer than on a leaf. A forged leaf impersonates the
// names inside it. A forged intermediate issues certificates for any name at
// all, and every client that trusts the chain accepts them — which is the
// same argument cert.leaf-is-ca rests on, arriving from the other direction.
//
// Nothing new is asked of the server: these are bytes the handshake already
// delivered.
//
// # What is deliberately not graded
//
// Names. A wildcard shape, a missing subject alternative name, a common name
// outside the SAN list are questions about a certificate presented for a
// name. An issuer is not presented for one.
//
// Self-signature. A root is self-signed; that is what a root is, and
// cert.self-signed would fire on every complete chain.
//
// Validity length. An authority is issued for ten or twenty years by design.
// The leaf's limit would fire on every chain ever served.
//
// Being an authority, and holding keyCertSign. On an issuer both are
// required rather than suspect — the exact inverse of the leaf rules.
//
// # And the root is not graded at all
//
// A root is trusted because the client already holds a copy, not because of
// the signature it carries. Nobody verifies that signature: a client that did
// would be asking the certificate to vouch for itself. So grading a root's
// own signature or key would raise an alarm about a risk no client is
// exposed to — and roots predating SHA-256 are still in every store, doing no
// harm. Any self-signed certificate in the chain is therefore skipped, which
// is how a client treats it too.

// IssuerFacts is one certificate between the leaf and the root.
type IssuerFacts struct {
	// Subject names the certificate a finding is about.
	//
	// It must already have been through certinfo's sanitiser. This is text
	// the scanned server chose and it is repeated back into a sentence here,
	// so an unfiltered value would let a scanned server write part of the
	// report about itself. R10.
	Subject string

	NotBefore time.Time
	NotAfter  time.Time

	// SignatureAlgorithm and the key fields carry the same values, in the
	// same spellings, as their counterparts on LeafFacts. The conditions
	// below are the leaf's conditions; a test holds the two to firing on the
	// same inputs, so a rule tightened on one face cannot be left loose on
	// the other.
	SignatureAlgorithm string

	KeyAlgorithm string
	KeyBits      int

	KeyFromBrokenGenerator bool

	UnhandledCriticalExtensions []string
}

// IssuerFinding is a graded certificate from the chain.
type IssuerFinding struct {
	Verdict  Verdict   `json:"verdict"`
	Findings []Finding `json:"findings,omitempty"`
}

// GradeIssuer applies the rules that hold for a certificate that issues
// others. The caller supplies now for the same reason GradeLeaf does.
func GradeIssuer(f IssuerFacts, now time.Time) IssuerFinding {
	out := IssuerFinding{Verdict: Strong}

	// Where the certificate's own text goes, and why it goes there.
	//
	// The subject is chosen by the server being examined and it is repeated
	// into a sentence this report writes. Two things follow.
	//
	// It cannot sit at the head of the sentence. It did, and the fuzzer found
	// the first consequence in forty seconds: a subject of one space produced
	// "  expires in 10 days", a sentence with a hole where a name belongs.
	// The second consequence is worse and no fuzzer would have named it — a
	// subject is free text, so a certificate could open a sentence of ours
	// with wording of its own and be read as this report's voice.
	//
	// So the report's own words are said first and completely, and the
	// certificate's text arrives last, in a sentence of its own, inside
	// quotation marks that show a reader exactly where it starts and ends.
	// The value itself is never altered: an odd name is the certificate's,
	// and correcting it here would be reporting something the server did not
	// send.
	named := ""
	if strings.TrimSpace(f.Subject) != "" {
		named = " The certificate is \u201c" + f.Subject + "\u201d."
	} else {
		named = " The certificate carries no subject."
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
	//
	// An expired issuer breaks the chain for every client at once, and the
	// report already says so through cert.chain-untrusted — with no reason
	// attached. This names the reason, which is the difference between an
	// operator who can fix it and one who cannot.
	days := int(f.NotAfter.Sub(now).Hours() / 24)
	switch {
	case now.After(f.NotAfter):
		add("chain.expired", Insecure,
			"An issuer in this chain has expired",
			fmt.Sprintf("An issuer in this chain expired on %s, %d days ago. A chain is only as valid as "+
				"every certificate in it, so this breaks verification for every client at once.%s",
				f.NotAfter.UTC().Format(time.DateOnly), -days, named),
			rfc5280, cabBR)

	case now.Before(f.NotBefore):
		add("chain.not-yet-valid", Insecure,
			"An issuer in this chain is not yet valid",
			fmt.Sprintf("An issuer in this chain becomes valid on %s. Until then the chain does not verify, "+
				"and a clock skew on either side widens the window.%s",
				f.NotBefore.UTC().Format(time.DateOnly), named),
			rfc5280)

	case days <= expiryWarningDays:
		add("chain.expiring-soon", Weak,
			"An issuer in this chain expires soon",
			fmt.Sprintf("An issuer in this chain expires in %d days. An authority certificate is normally "+
				"replaced years ahead; this margin means every certificate under it stops verifying on "+
				"that date.%s", days, named),
			cabBR)
	}

	// ── The signature it carries ─────────────────────────────────────
	//
	// The conditions are GradeLeaf's. The consequence is not: a collision
	// against an issuer's signature yields an issuer, and an issuer signs for
	// any name.
	sig := strings.ToUpper(f.SignatureAlgorithm)
	switch {
	case !hasLetter(sig):
		add("chain.signature-algorithm-unrecognised", Weak,
			"An issuer's signature algorithm is not recognised",
			fmt.Sprintf("The algorithm that signed an issuer in this chain is not one this rule set knows, "+
				"so whether the hash behind it is sound was not established. Nothing here says it is weak; "+
				"nothing here can say it is sound either.%s", named),
			rfc5280, rfc9155)

	case strings.Contains(sig, "MD2"), strings.Contains(sig, "MD5"):
		add("chain.signature-md5", Insecure,
			"An issuer in this chain is signed with MD5 or MD2",
			fmt.Sprintf("An issuer in this chain carries a signature over a hash whose collisions are "+
				"trivial to produce. A collision here forges an authority rather than a single "+
				"certificate, and an authority signs for any name.%s", named),
			rfc9155, cabBR)

	case strings.Contains(sig, "SHA1"):
		add("chain.signature-sha1", Insecure,
			"An issuer in this chain is signed with SHA-1",
			fmt.Sprintf("An issuer in this chain carries a SHA-1 signature. A practical collision was "+
				"demonstrated in 2017, and a collision against an authority's signature forges an "+
				"authority: certificates for any name, accepted by every client that trusts this "+
				"chain.%s", named),
			shattered, rfc9155, cabBR)
	}

	// ── The key it holds ─────────────────────────────────────────────
	switch f.KeyAlgorithm {
	case "RSA":
		if f.KeyFromBrokenGenerator {
			add("chain.roca", Insecure,
				"An issuer's key was made by a generator known to produce factorable keys",
				fmt.Sprintf("The modulus of an issuer in this chain carries the fingerprint of Infineon's "+
					"RSALib, which built primes from a small family instead of at random. Such a key can "+
					"be factored from the public key alone. On an authority that means an attacker who "+
					"does the work can issue certificates for any name. This is a fingerprint of how the "+
					"key was generated; nothing here factored anything.%s", named),
				roca2017, cve201715361, cabBR)
		}
		if f.KeyBits < 2048 {
			add("chain.rsa-key-too-small", Insecure,
				fmt.Sprintf("An issuer holds an RSA key of %d bits", f.KeyBits),
				fmt.Sprintf("An issuer in this chain holds a key below the 2048 bits the CA/Browser Forum "+
					"has required since 2014. Breaking it yields the power to issue, not merely to "+
					"impersonate one name.%s", named),
				cabBR, nist80057)
		}
	case "ECDSA":
		if f.KeyBits < 256 {
			add("chain.ec-key-too-small", Insecure,
				fmt.Sprintf("An issuer holds an elliptic curve key of %d bits", f.KeyBits),
				fmt.Sprintf("An issuer in this chain holds a curve below P-256, short of the 128-bit "+
					"security level expected of a public certificate — and of an authority above "+
					"all.%s", named),
				cabBR, nist80057)
		}
	case "Ed25519":
		// One curve, one security level, nothing to size. Listed rather than
		// left to the default so the absence of a finding is a decision.

	default:
		// Trimmed, unlike the subject above.
		//
		// This name is the standard library's rendering of a key algorithm,
		// not text the scanned server chose, so tidying it misrepresents
		// nothing. Testing for "" alone was not enough: " " is no name and
		// "0 " put two spaces into the sentence. The leaf grader had the
		// identical line and the identical hole, and the fuzzer found both —
		// three times over, each time on a slightly different shape of
		// nothing.
		kind := strings.TrimSpace(f.KeyAlgorithm)
		if kind == "" {
			kind = "of an unnamed type"
		} else {
			kind = kind + " key"
		}
		add("chain.key-algorithm-unrecognised", Weak,
			"An issuer's key algorithm is not recognised",
			fmt.Sprintf("The public key of an issuer in this chain is %s, which this rule set does not know "+
				"how to size, so its strength was not graded. Nothing here says it is weak; nothing here "+
				"can say it is sound either.%s", kind, named),
			nist80057, cabBR)
	}

	// ── An extension nobody here understands ─────────────────────────
	if len(f.UnhandledCriticalExtensions) > 0 {
		add("chain.critical-extension-unrecognised", Weak,
			"An issuer marks an extension critical that this checker does not recognise",
			fmt.Sprintf("An issuer in this chain marks %s critical, and RFC 5280 requires a client that "+
				"does not recognise a critical extension to reject the certificate. What this scan cannot "+
				"tell you is whether the clients you care about recognise it; what it can tell you is "+
				"that this one does not.%s", listed(f.UnhandledCriticalExtensions), named),
			rfc5280)
	}

	for _, finding := range out.Findings {
		out.Verdict = Worst(out.Verdict, finding.Verdict)
	}
	return out
}
