// Package certinfo describes the certificate chain a server presented and
// grades it against the rules in package policy.
//
// Nothing here touches the network. The chain arrives as a slice of parsed
// certificates, and everything else is computation, so the whole package is
// testable against certificates generated in memory.
//
// The split from tlsprobe is the same one that separates measurement from
// judgement elsewhere in this project: tlsprobe collects, certinfo describes,
// policy decides.
package certinfo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// ErrNoChain is returned when there is nothing to describe.
var ErrNoChain = errors.New("certinfo: no certificates were presented")

// Report describes one server's chain.
type Report struct {
	// Policy names the rule set that produced the verdict, so a result can be
	// reproduced after the rules change.
	Policy string `json:"policy"`

	// Verdict is the worst finding on the leaf certificate.
	Verdict policy.Verdict `json:"verdict"`

	// Grade carries the findings and the validity arithmetic.
	Grade policy.LeafFinding `json:"grade"`

	// Chain is every certificate the server sent, leaf first.
	Chain []Certificate `json:"chain"`

	// Hostname is the name the chain was checked against. Empty when the
	// caller did not supply one, in which case no name check was performed.
	Hostname string `json:"hostname,omitempty"`

	// Trusted reports whether the chain verifies against the system trust
	// store. An expired certificate does not clear this flag: expiry is
	// reported by its own finding, and saying the chain is untrusted as well
	// would describe one problem twice.
	Trusted bool `json:"trusted"`

	// VerifyError is the raw verification failure, kept because the reason
	// matters more than the boolean.
	VerifyError string `json:"verifyError,omitempty"`

	// CheckedAt is the moment the validity window was judged against.
	CheckedAt time.Time `json:"checkedAt"`

	// Notes records what could not be established.
	Notes []string `json:"notes,omitempty"`
}

// Certificate is one parsed certificate, rendered for display.
type Certificate struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	SerialNumber string `json:"serialNumber"`

	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`

	DNSNames       []string `json:"dnsNames,omitempty"`
	IPAddresses    []string `json:"ipAddresses,omitempty"`
	EmailAddresses []string `json:"emailAddresses,omitempty"`
	URIs           []string `json:"uris,omitempty"`

	KeyAlgorithm string `json:"keyAlgorithm"`

	// KeyBits is the RSA modulus size or the elliptic curve field size.
	// Ed25519 has no size parameter and reports 0.
	KeyBits int `json:"keyBits,omitempty"`

	SignatureAlgorithm string `json:"signatureAlgorithm"`

	IsCA        bool     `json:"isCA"`
	SelfSigned  bool     `json:"selfSigned"`
	KeyUsage    []string `json:"keyUsage,omitempty"`
	ExtKeyUsage []string `json:"extKeyUsage,omitempty"`

	// FingerprintSHA256 identifies this exact certificate. It is what a user
	// pins, and what lets two reports be compared without ambiguity.
	FingerprintSHA256 string `json:"fingerprintSha256"`
}

// Analyse describes and grades a chain. The chain must be leaf first, as TLS
// presents it. Passing an empty hostname skips the name check and says so in
// the notes rather than silently reporting a pass.
func Analyse(chain []*x509.Certificate, hostname string, now time.Time) (*Report, error) {
	if len(chain) == 0 {
		return nil, ErrNoChain
	}

	leaf := chain[0]

	report := &Report{
		Policy:   policy.Version,
		Hostname: hostname,
		// UTC is forced rather than inherited from the host. A local zone in
		// a response is a geographic fingerprint of wherever this runs, and a
		// privacy property should not depend on a machine being configured
		// correctly.
		CheckedAt: now.UTC(),
		Chain:     make([]Certificate, 0, len(chain)),
	}
	for _, c := range chain {
		report.Chain = append(report.Chain, describe(c))
	}

	selfSigned := isSelfSigned(leaf)

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}

	// The name is checked separately below so that a wrong name and an
	// untrusted chain remain distinguishable findings.
	_, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	report.Trusted = err == nil
	if err != nil {
		report.VerifyError = err.Error()

		// A chain that reaches a trusted root but has run out of time is not
		// an untrusted chain. Expiry has its own rule; reporting both would
		// charge one fault twice.
		var invalid x509.CertificateInvalidError
		if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
			report.Trusted = true
		}
	}

	hostnameMatches := true
	if hostname == "" {
		report.Notes = append(report.Notes,
			"No hostname was supplied, so the certificate was not checked against a name.")
	} else if err := leaf.VerifyHostname(hostname); err != nil {
		hostnameMatches = false
	}

	facts := policy.LeafFacts{
		NotBefore:          leaf.NotBefore,
		NotAfter:           leaf.NotAfter,
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
		HasSAN:             len(leaf.DNSNames) > 0 || len(leaf.IPAddresses) > 0,
		SelfSigned:         selfSigned,
		ChainTrusted:       report.Trusted,
		ChainComplete:      chainComplete(chain, selfSigned),
		HostnameMatches:    hostnameMatches,
	}
	facts.KeyAlgorithm, facts.KeyBits = keyDetails(leaf)

	if facts.KeyAlgorithm == "" {
		report.Notes = append(report.Notes,
			fmt.Sprintf("Public key algorithm %q is not recognised, so key strength was not graded.",
				leaf.PublicKeyAlgorithm.String()))
	}

	report.Grade = policy.GradeLeaf(facts, now)
	report.Verdict = report.Grade.Verdict

	if !facts.ChainComplete {
		if report.Trusted {
			report.Notes = append(report.Notes,
				"The issuer was not sent, yet verification succeeded: this platform's verifier fetched the missing certificate over the network. Clients that do not fetch — most command-line tools, mobile applications, and API consumers — will fail against this server.")
		} else {
			report.Notes = append(report.Notes,
				"The server did not send the certificate that issued the leaf.")
		}
	}

	return report, nil
}

// chainComplete reports whether the server sent the certificate that issued
// the leaf.
//
// This is answered structurally rather than from the verification result,
// because verification is not portable. On Windows and macOS, Go delegates to
// the platform verifier, which fetches a missing intermediate over the network
// through the authority information access extension. On Linux it does not.
// The same server would then read as complete on one machine and incomplete on
// another, which is the drift the policy package exists to prevent.
//
// Servers are not expected to send the root, so a missing root is not a gap. A
// leaf issued directly by a root would be reported as incomplete here; that
// arrangement is essentially absent from the public web, where every CA signs
// through an intermediate.
func chainComplete(chain []*x509.Certificate, selfSigned bool) bool {
	if selfSigned {
		return true
	}

	leaf := chain[0]
	for _, c := range chain[1:] {
		if bytes.Equal(c.RawSubject, leaf.RawIssuer) {
			return true
		}
	}
	return false
}

// isSelfSigned checks the signature, not only the names. A certificate can
// name itself as its own issuer without being able to prove it.
//
// CheckSignature is used rather than CheckSignatureFrom because the latter
// first applies RFC 5280's rule that a non-CA key must not verify certificate
// signatures. That rule is right for chain building and wrong here: most
// self-signed server certificates in the wild are not marked as CAs, and
// treating them as ordinary untrusted certificates would hide the one fact
// that actually explains the failure.
func isSelfSigned(c *x509.Certificate) bool {
	if !bytes.Equal(c.RawSubject, c.RawIssuer) {
		return false
	}
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func describe(c *x509.Certificate) Certificate {
	sum := sha256.Sum256(c.Raw)

	out := Certificate{
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		SerialNumber:       c.SerialNumber.String(),
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		DNSNames:           c.DNSNames,
		EmailAddresses:     c.EmailAddresses,
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		IsCA:               c.IsCA,
		SelfSigned:         isSelfSigned(c),
		KeyUsage:           keyUsages(c.KeyUsage),
		ExtKeyUsage:        extKeyUsages(c.ExtKeyUsage),
		FingerprintSHA256:  hex.EncodeToString(sum[:]),
	}

	for _, ip := range c.IPAddresses {
		out.IPAddresses = append(out.IPAddresses, ip.String())
	}
	for _, u := range c.URIs {
		out.URIs = append(out.URIs, u.String())
	}

	out.KeyAlgorithm, out.KeyBits = keyDetails(c)
	return out
}

// keyDetails returns the algorithm name and its size parameter. An empty
// algorithm means the key type was not recognised, which the caller reports
// rather than treating as a pass.
func keyDetails(c *x509.Certificate) (string, int) {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 0
	default:
		return "", 0
	}
}

func keyUsages(u x509.KeyUsage) []string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "keyCertSign"},
		{x509.KeyUsageCRLSign, "cRLSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	}

	var out []string
	for _, n := range names {
		if u&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

func extKeyUsages(us []x509.ExtKeyUsage) []string {
	var out []string
	for _, u := range us {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			out = append(out, "codeSigning")
		case x509.ExtKeyUsageEmailProtection:
			out = append(out, "emailProtection")
		case x509.ExtKeyUsageTimeStamping:
			out = append(out, "timeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			out = append(out, "OCSPSigning")
		case x509.ExtKeyUsageAny:
			out = append(out, "any")
		default:
			out = append(out, fmt.Sprintf("unknown(%d)", u))
		}
	}
	return out
}

// Summary renders the verdict as one line, for a terminal or a log.
func (r *Report) Summary() string {
	if len(r.Chain) == 0 {
		return "no certificate"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s", r.Chain[0].Subject, r.Verdict)

	if r.Grade.DaysRemaining >= 0 {
		fmt.Fprintf(&b, ", %d days remaining", r.Grade.DaysRemaining)
	} else {
		fmt.Fprintf(&b, ", expired %d days ago", -r.Grade.DaysRemaining)
	}

	if n := len(r.Grade.Findings); n > 0 {
		fmt.Fprintf(&b, ", %d finding(s)", n)
	}
	return b.String()
}
