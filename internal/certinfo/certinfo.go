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
//
// # The chain is untrusted input
//
// Every other limit in this project bounds what arrives in a request. These
// bound what arrives in a reply, which is a different direction and easy to
// forget: the scanner connects to a server chosen by whoever asked, and that
// server decides what to send back.
//
// A certificate may carry a subject thousands of characters long, hundreds of
// alternative names, and a chain of dozens. Go parses all of it. Passing it
// through unbounded would turn one small request into a response measured in
// megabytes, which the person who asked for the scan pays for, not the server
// that sent it.
//
// Anything cut is stated in the report. A truncated list presented as a
// complete one would be the same failure this project criticises elsewhere.
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

// Bounds on what a server can make this package repeat back.
//
// The values sit well above anything a real certificate carries and well
// below anything that would make a report unreadable. A public chain is two
// to four certificates; a name list beyond a few dozen entries belongs to a
// shared host, and the first fifty are enough to see that.
const (
	maxChainLength  = 10
	maxFieldLength  = 256
	maxListEntries  = 50
	maxUsageEntries = 20
)

// Report describes one server's chain.
type Report struct {
	// Policy names the rule set that produced the verdict, so a result can be
	// reproduced after the rules change.
	Policy string `json:"policy"`

	// Verdict is the worst finding on the leaf certificate.
	Verdict policy.Verdict `json:"verdict"`

	// Grade carries the findings and the validity arithmetic.
	Grade policy.LeafFinding `json:"grade"`

	// Chain is the certificates the server sent, leaf first, up to the limit
	// above. Notes says so when there were more.
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

	// Notes records what could not be established, and what was cut.
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
	// pins, and what lets two reports be compared without ambiguity. It is
	// taken over the whole certificate, before anything above was shortened,
	// so it still identifies what the server actually sent.
	FingerprintSHA256 string `json:"fingerprintSha256"`
}

// trimmer applies the bounds and remembers whether it had to.
//
// Recording that something was cut is the point. A shortened list rendered as
// a complete one is exactly the kind of quiet omission this project objects
// to in other tools.
type trimmer struct {
	cut bool
}

func (t *trimmer) text(s string) string {
	if len(s) <= maxFieldLength {
		return s
	}
	t.cut = true
	// The marker is inside the returned value so that a reader looking at one
	// field, rather than at the notes, still sees that it is incomplete.
	return s[:maxFieldLength] + "…"
}

func (t *trimmer) list(items []string, limit int) []string {
	out := items
	if len(out) > limit {
		out = out[:limit]
		t.cut = true
	}

	trimmed := make([]string, 0, len(out))
	for _, item := range out {
		trimmed = append(trimmed, t.text(item))
	}
	return trimmed
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
	}

	// Verification and completeness read the chain as sent. Only the
	// description is bounded, so a long chain is still judged on what it
	// really is.
	described := chain
	if len(described) > maxChainLength {
		described = described[:maxChainLength]
		report.Notes = append(report.Notes, fmt.Sprintf(
			"The server sent %d certificates. Only the first %d are described; the rest were judged but not listed.",
			len(chain), maxChainLength))
	}

	var trim trimmer
	report.Chain = make([]Certificate, 0, len(described))
	for _, c := range described {
		report.Chain = append(report.Chain, describe(c, &trim))
	}
	if trim.cut {
		report.Notes = append(report.Notes,
			"Some fields were longer than this report will carry and have been shortened. "+
				"The fingerprint is taken over the whole certificate, so it still identifies what the server sent.")
	}

	selfSigned := isSelfSigned(leaf)

	intermediates := x509.NewCertPool()
	// Bounded for the same reason: path building is work, and the number of
	// candidates is chosen by the server being examined.
	for _, c := range chain[1:min(len(chain), maxChainLength)] {
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
		report.VerifyError = trim.text(err.Error())

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
		report.Notes = append(report.Notes, fmt.Sprintf(
			"Public key algorithm %q is not recognised, so key strength was not graded.",
			leaf.PublicKeyAlgorithm.String()))
	}

	report.Grade = policy.GradeLeaf(facts, now)
	report.Verdict = report.Grade.Verdict

	// Invariant R3: what could not be measured is stated.
	//
	// "Trusted" here means the chain reaches a root and the dates are in
	// range. It does not mean the certificate has not been revoked, and a
	// reader will assume it does unless told otherwise.
	//
	// Revocation is not checked, and the reason is the same one that shapes
	// the rest of this project. Asking a certificate authority whether a
	// serial is still good tells that authority which certificate somebody is
	// looking at, and a stapled response would have to be validated against
	// the issuer to be worth anything. Either way a third party learns what
	// was scanned, which is the one thing this service undertakes not to let
	// happen.
	report.Notes = append(report.Notes,
		"Revocation was not checked. Asking a certificate authority whether this "+
			"certificate is still valid would tell it which certificate you are "+
			"looking at, which this service does not do. A chain reported as trusted "+
			"reaches a root and is in date; it may still have been revoked.")

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

func describe(c *x509.Certificate, trim *trimmer) Certificate {
	// Taken over the whole certificate, before anything below is shortened,
	// so the fingerprint still identifies what the server actually sent.
	sum := sha256.Sum256(c.Raw)

	out := Certificate{
		Subject:            trim.text(c.Subject.String()),
		Issuer:             trim.text(c.Issuer.String()),
		SerialNumber:       trim.text(c.SerialNumber.String()),
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		DNSNames:           trim.list(c.DNSNames, maxListEntries),
		EmailAddresses:     trim.list(c.EmailAddresses, maxListEntries),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		IsCA:               c.IsCA,
		SelfSigned:         isSelfSigned(c),
		KeyUsage:           keyUsages(c.KeyUsage),
		ExtKeyUsage:        trim.list(extKeyUsages(c.ExtKeyUsage), maxUsageEntries),
		FingerprintSHA256:  hex.EncodeToString(sum[:]),
	}

	addresses := make([]string, 0, len(c.IPAddresses))
	for _, ip := range c.IPAddresses {
		addresses = append(addresses, ip.String())
	}
	out.IPAddresses = trim.list(addresses, maxListEntries)

	uris := make([]string, 0, len(c.URIs))
	for _, u := range c.URIs {
		uris = append(uris, u.String())
	}
	out.URIs = trim.list(uris, maxListEntries)

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
