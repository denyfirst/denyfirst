// Package dane checks a mail exchanger's DANE records against the certificate
// it presented.
//
// # What RFC 7672 asks of a sender, and what is checked here
//
// A sending server that finds TLSA records for an exchanger, validated by
// DNSSEC, must negotiate TLS and must find a record matching what the exchanger
// presents; if none matches, it does not deliver. That is the question: given
// the records and the chain one exchanger sent, would such a sender deliver?
//
// Only the records RFC 7672 has SMTP use. DANE-EE(3) matches the leaf, and its
// name and dates are not checked (§3.1.1): the record is the binding. DANE-TA(2)
// matches a certificate the exchanger presented, and the leaf must then chain to
// it and name the exchanger (§3.1.2, §3.2.3). PKIX-TA(0) and PKIX-EE(1) are
// records a sender does not use for SMTP (§3.1.3), and a record whose selector or
// matching type is not defined, or whose digest is the wrong length, is one
// nothing can match. A domain publishing only those is authenticated by none of
// them, which is its own answer.
//
// # What is not established, and said as not established
//
// Two cases are left open rather than guessed. A DANE-TA record may publish a
// bare public key rather than a certificate, and where no presented certificate
// carries it, finding which one it signed needs a chain built from a key — which
// is not done here. And a trust anchor outside its own validity period fails
// Go's verifier, while whether a sender applies that date to an anchor named in
// DNS is not something this package settles. Both are Undetermined, never
// Mismatched: a report that told an operator their mail was being refused on
// the strength of a limit of this code would be the failure R4 describes.
//
// Whether the records validated is the caller's to carry. This package is given
// records and a chain, and answers about those.
package dane

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"time"

	"github.com/denyfirst/denyfirst/internal/dnsclient"
)

// Certificate usages, selectors and matching types, from RFC 6698 and RFC 7218.
const (
	UsagePKIXTA = 0
	UsagePKIXEE = 1
	UsageDANETA = 2
	UsageDANEEE = 3

	SelectorCertificate = 0
	SelectorPublicKey   = 1

	MatchingExact  = 0
	MatchingSHA256 = 1
	MatchingSHA512 = 2
)

// Outcome is what the records made of the chain.
type Outcome string

const (
	// Matched: a usable record matches, and for DANE-TA the leaf chains to the
	// anchor and names the exchanger. A sender applying DANE delivers.
	Matched Outcome = "matched"

	// Mismatched: there are usable records and none of them matches. A sender
	// applying DANE to validated records does not deliver.
	Mismatched Outcome = "mismatched"

	// NoUsableRecords: records exist, and none is one a sender uses for SMTP.
	NoUsableRecords Outcome = "no-usable-records"

	// Undetermined: a record could match in a way this package does not
	// establish, so neither answer above is given.
	Undetermined Outcome = "undetermined"
)

// Result is the answer for one exchanger.
type Result struct {
	Outcome Outcome

	// Usable is how many records a sender would use for SMTP.
	Usable int

	// Usage is the usage of the record that matched, for Matched.
	Usage uint8

	// Reason says why, for Mismatched and Undetermined, as a phrase that can
	// follow a host name and a colon.
	Reason string
}

// Check asks the records about the chain the exchanger presented for host, at
// the given time.
func Check(records []dnsclient.TLSA, chain []*x509.Certificate, host string, now time.Time) Result {
	var usable []dnsclient.TLSA
	for _, r := range records {
		if Usable(r) {
			usable = append(usable, r)
		}
	}
	out := Result{Usable: len(usable)}
	if len(usable) == 0 {
		out.Outcome = NoUsableRecords
		return out
	}
	if len(chain) == 0 {
		out.Outcome, out.Reason = Undetermined, "no certificate was presented to check the records against"
		return out
	}

	var (
		taFailure    string
		undetermined string
	)

	// Every record is tried and the first match decides. A sender accepts the
	// connection if any usable record matches, so one record that does not is
	// not a failure while another does.
	for _, r := range usable {
		switch r.Usage {
		case UsageDANEEE:
			if matches(r, chain[0]) {
				out.Outcome, out.Usage = Matched, UsageDANEEE
				return out
			}

		case UsageDANETA:
			anchored := false
			for _, c := range chain {
				if !matches(r, c) {
					continue
				}
				anchored = true
				verdict, reason := chainsTo(chain, c, host, now)
				switch verdict {
				case Matched:
					out.Outcome, out.Usage = Matched, UsageDANETA
					return out
				case Undetermined:
					undetermined = reason
				default:
					taFailure = reason
				}
			}
			if !anchored && r.Selector == SelectorPublicKey && r.Matching == MatchingExact {
				undetermined = "a DANE-TA record publishes a bare public key that no presented " +
					"certificate carries, and which certificate it signed is not established here"
			}
		}
	}

	switch {
	case undetermined != "":
		out.Outcome, out.Reason = Undetermined, undetermined
	case taFailure != "":
		out.Outcome, out.Reason = Mismatched, taFailure
	default:
		out.Outcome, out.Reason = Mismatched, "no usable DANE record matches the certificate it presented"
	}
	return out
}

// Usable reports whether a sender uses this record for SMTP.
func Usable(r dnsclient.TLSA) bool {
	if r.Usage != UsageDANETA && r.Usage != UsageDANEEE {
		return false
	}
	if r.Selector != SelectorCertificate && r.Selector != SelectorPublicKey {
		return false
	}
	switch r.Matching {
	case MatchingExact:
		return len(r.Data) > 0
	case MatchingSHA256:
		return len(r.Data) == sha256.Size
	case MatchingSHA512:
		return len(r.Data) == sha512.Size
	}
	return false
}

// matches compares one record with one certificate.
func matches(r dnsclient.TLSA, c *x509.Certificate) bool {
	content := c.Raw
	if r.Selector == SelectorPublicKey {
		content = c.RawSubjectPublicKeyInfo
	}
	switch r.Matching {
	case MatchingExact:
		return bytes.Equal(content, r.Data)
	case MatchingSHA256:
		sum := sha256.Sum256(content)
		return bytes.Equal(sum[:], r.Data)
	case MatchingSHA512:
		sum := sha512.Sum512(content)
		return bytes.Equal(sum[:], r.Data)
	}
	return false
}

// chainsTo asks whether the leaf chains to the anchor a DANE-TA record matched,
// and names the exchanger.
//
// Any key usage: RFC 7672 asks for the chain and the name, and a check that
// also demanded the server-authentication usage would be refusing on a rule the
// RFC does not state.
func chainsTo(chain []*x509.Certificate, anchor *x509.Certificate, host string, now time.Time) (Outcome, string) {
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}

	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       host,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err == nil {
		return Matched, ""
	}

	var (
		hostname x509.HostnameError
		invalid  x509.CertificateInvalidError
	)
	switch {
	case errors.As(err, &hostname):
		return Mismatched, "the certificate chains to the trust anchor its DANE-TA record names, and does not name the exchanger"
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired && invalid.Cert != nil && invalid.Cert.Equal(anchor):
		return Undetermined, "the trust anchor its DANE-TA record names is outside its own validity period, " +
			"and whether a sender applies that date to an anchor named in DNS is not established here"
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		return Mismatched, "a certificate between the trust anchor its DANE-TA record names and the leaf is outside its validity period"
	default:
		return Mismatched, "a presented certificate matches its DANE-TA record, and the leaf does not chain to it"
	}
}
