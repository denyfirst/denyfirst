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
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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

	// Revocation is what the leaf says about how its status may be checked.
	//
	// These are facts read from the certificate, not a judgement and not a
	// check: nothing here contacts a responder. Whether a response actually
	// arrived is a property of the handshake and is joined to these in
	// internal/scan, because neither half means anything alone.
	Revocation Revocation `json:"revocation"`

	// Transparency is what the leaf carries about certificate transparency.
	Transparency Transparency `json:"transparency"`

	// Notes records what could not be established, and what was cut.
	Notes []string `json:"notes,omitempty"`
}

// Transparency counts the signed certificate timestamps embedded in the leaf.
//
// A publicly trusted certificate has to be recorded in append-only logs, and
// the logs answer with a signed receipt saying when. Browsers refuse a
// certificate that arrives without enough of those receipts, which is what
// makes the count worth reporting rather than a curiosity.
//
// Counted and not verified. Checking a receipt's signature needs the log's
// public key, and the set of qualified logs is a list that browsers ship and
// revise; carrying a copy of it would be a dependency on somebody else's
// judgement that could go stale between releases. The count and the number of
// distinct logs are read from the certificate itself and need nothing external,
// which is the part that can be stated without qualification.
type Transparency struct {
	// EmbeddedCount is how many timestamps the leaf carries.
	EmbeddedCount int `json:"embeddedCount"`

	// LogIDs identifies the logs those timestamps came from, hex encoded.
	//
	// Identifiers rather than a count, because the same certificate can also
	// deliver receipts through the handshake and the two sets have to be
	// combined before "how many distinct logs" can be answered. Two counts
	// added together would double whichever log appears in both.
	//
	// Browsers require receipts from different logs rather than several from
	// one, so that a log which misbehaves cannot satisfy the requirement
	// alone. Three from one log is a different situation from three from
	// three, and a total cannot say which.
	LogIDs []string `json:"logIds,omitempty"`
}

// Revocation describes the revocation machinery a certificate asks for.
type Revocation struct {
	// MustStaple is true when the leaf carries the RFC 7633 TLS Feature
	// extension naming status_request. It is an instruction to the client to
	// refuse the connection unless a status response accompanies it.
	MustStaple bool `json:"mustStaple"`

	// ResponderCount is how many OCSP responders the leaf names in its
	// Authority Information Access extension.
	//
	// A count rather than the URLs. The URLs are chosen by whoever issued the
	// certificate being examined, which on a hostile target means they are
	// chosen by the target, and this report does not repeat attacker-supplied
	// strings back to a reader when a number answers the question. What a
	// reader needs to know is whether a responder exists at all.
	ResponderCount int `json:"responderCount"`

	// CRLCount is the same for CRL distribution points. Since the
	// CA/Browser Forum made OCSP optional and CRLs mandatory, a certificate
	// with no responder and no distribution point is the interesting case,
	// and it cannot be told from one with a list without counting both.
	CRLCount int `json:"crlCount"`
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
	s = sanitise(s)
	if len(s) <= maxFieldLength {
		return s
	}
	t.cut = true
	// Cut on a rune boundary. These are bytes the scanned server chose, so
	// there is no reason a byte offset should land between characters, and a
	// half rune reaches a reader as corruption this report introduced.
	cut := maxFieldLength
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	// The marker is inside the returned value so that a reader looking at one
	// field, rather than at the notes, still sees that it is incomplete.
	return s[:cut] + "…"
}

// sanitise replaces the bytes a display acts on rather than shows.
//
// Everything passed through here was chosen by the server being examined. Go
// parses a certificate's subject and its alternative names as bytes and
// escapes only the characters X.500 requires, so an ESC survives intact — and
// a terminal reads ESC as an instruction. A subject of
// "\x1b[2K\x1b[1A    Verdict      strong" rewrites the line printed above it,
// which means a scanned server can edit the report about itself. The command
// line tool is where that lands; the browser is safe because JSON escapes the
// byte and the page assigns it to textContent, and depending on two other
// layers to hold is not a reason to pass it on.
//
// C1 is included because several terminals accept 0x9b as CSI, so stripping
// only the C0 range leaves the same trick spelled differently.
//
// And Unicode's format characters are included, which is the half this missed
// until 2026-08-22. A control byte makes a terminal act; a format character
// makes a reader misread, and this report exists to be read. U+202E reverses
// the display of everything after it, so a subject of
// "safe.test\u202Emoc.knab-live" is shown as safe.testevil-bank.com by a
// terminal and by a browser alike — textContent does not switch off the
// bidirectional algorithm. The zero-width characters do the quieter version:
// "goo\u200Bgle.test" is a different name that reads as google.test. Both are
// the same attack as the ESC, aimed at the person instead of the pipe, and
// this is a tool whose entire output is a claim about which name a server
// presented. Trojan Source, CVE-2021-42574, is the published form.
//
// The whole Cf category rather than a list of the characters that are known
// to be dangerous. A deny list is worth exactly its completeness, which is the
// argument this project already makes about address families, and the ones
// added to Unicode after this was written would not be on any list written
// today. The cost is real and worth stating: a subject legitimately using
// U+200D to join glyphs in an Indic or Persian name will render with a
// replacement mark. A name shown imperfectly is recoverable; a name shown as
// somebody else's is not.
//
// Replaced rather than dropped: a reader should be able to see that something
// was there. This is the same rule dnsclient already applies to CAA values,
// which are attacker-chosen for exactly the same reason.
func sanitise(s string) string {
	if strings.IndexFunc(s, isDisplayControl) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isDisplayControl(r) {
			return '�'
		}
		return r
	}, s)
}

func isDisplayControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
		unicode.Is(unicode.Cf, r)
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
			"The server sent %d certificates. Only the first %d were used: the rest are neither "+
				"described here nor offered to the verifier when it builds a path to a root, so a "+
				"chain that needs one of them is reported as untrusted. The bound is this report's, "+
				"not a judgement about the server.",
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
		//
		// The inference this used to make was wrong, though, and wrong in the
		// direction that reassures. Go checks each certificate's dates before
		// it looks for an issuer, so Expired is the error it returns for an
		// expired certificate whether or not anything would ever have
		// vouched for it. Reading that as "trusted apart from the dates"
		// declared a self-signed or private-CA certificate trusted the moment
		// it went out of date — and cert.chain-untrusted then never fired,
		// and the transparency note swung round to telling a private
		// certificate that browsers would refuse it for not being logged.
		//
		// So the question is asked again at a moment the certificate was
		// actually valid, and that answer is the one reported. Measured
		// 2026-08-22: a leaf from an untrusted private CA, expired a week
		// earlier, was reported trusted.
		var invalid x509.CertificateInvalidError
		if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
			report.Trusted = trustedWithinValidity(leaf, intermediates)
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

	required, malformed := mustStaple(leaf)
	report.Revocation = Revocation{
		MustStaple:     required,
		ResponderCount: len(leaf.OCSPServer),
		CRLCount:       len(leaf.CRLDistributionPoints),
	}
	if malformed {
		// Stated rather than assumed either way. Reading it as absent would
		// hide a certificate that may be demanding stapling; reading it as
		// present would invent a requirement out of a parse failure.
		report.Notes = append(report.Notes,
			"The certificate carries a TLS Feature extension that could not be parsed, so whether it "+
				"requires a stapled status response could not be established.")
	}

	embedded, logIDs, sctMalformed := embeddedSCTs(leaf)
	report.Transparency = Transparency{EmbeddedCount: embedded, LogIDs: logIDs}
	if sctMalformed {
		// Same reasoning as above. A count of zero and an unreadable list are
		// different facts, and reporting the second as the first would say a
		// certificate is absent from every log when nobody managed to look.
		report.Notes = append(report.Notes,
			"The certificate carries a transparency timestamp list that could not be parsed, so the "+
				"timestamps embedded in it could not be counted.")
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
			// Two things can produce this, and the note used to assert the
			// second as though it were established. It is not: Go delegates
			// to the platform verifier on macOS and Windows, which do fetch a
			// missing issuer over the network, and does not on Linux, which
			// does not — and this service runs on Linux, where the sentence
			// was simply false. Which one applies is a fact about the machine
			// that ran the scan; what the operator needs is the same either
			// way.
			report.Notes = append(report.Notes,
				"The certificate that issued the leaf was not sent, and verification succeeded anyway. "+
					"Either that issuer is itself in this machine's trust store, or the platform verifier "+
					"fetched it over the network; which of the two happened is a property of the machine "+
					"that ran this scan rather than of the server. A client that neither holds the issuer "+
					"nor fetches one — most command-line tools, mobile applications, and API consumers — "+
					"will fail against this server.")
		} else {
			report.Notes = append(report.Notes,
				"The server did not send the certificate that issued the leaf.")
		}
	}

	return report, nil
}

// trustedWithinValidity asks whether the chain would have verified at a moment
// the leaf was in date, which is the question "is this trusted, apart from
// having expired" actually requires.
//
// The midpoint of the leaf's own window rather than either edge, so the same
// call answers for a certificate that has expired and one that is not yet
// valid; Go reports both as Expired. An intermediate that had already expired
// by then makes this false, which is the right answer: the chain was not
// verifiable at that moment either.
func trustedWithinValidity(leaf *x509.Certificate, intermediates *x509.CertPool) bool {
	window := leaf.NotAfter.Sub(leaf.NotBefore)
	if window <= 0 {
		// NotAfter at or before NotBefore. There is no moment to ask about.
		return false
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   leaf.NotBefore.Add(window / 2),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err == nil
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

	// DaysRemaining truncates toward zero, so a certificate that expired eight
	// hours ago and one that expires in eight hours both read 0. Choosing the
	// cheerful reading of that put "0 days remaining" on the same line as a
	// verdict of insecure and a finding that said the certificate had expired.
	// The expiry finding is the authority here; this line follows it.
	switch {
	case r.expired():
		b.WriteString(", expired")
	case r.Grade.DaysRemaining == 0:
		b.WriteString(", expires within a day")
	default:
		fmt.Fprintf(&b, ", %d days remaining", r.Grade.DaysRemaining)
	}

	if n := len(r.Grade.Findings); n > 0 {
		fmt.Fprintf(&b, ", %d finding(s)", n)
	}
	return b.String()
}

// expired reports what the grade already decided, so the summary line and the
// findings cannot disagree about whether the certificate is in date.
func (r *Report) expired() bool {
	for _, f := range r.Grade.Findings {
		if f.RuleID == "cert.expired" {
			return true
		}
	}
	return false
}

// tlsFeatureOID is the RFC 7633 TLS Feature extension, id-pe-tlsfeature.
var tlsFeatureOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

// statusRequestExtension is the TLS ExtensionType for status_request, from
// the IANA registry. A TLS Feature extension listing it is what the world
// calls "must-staple"; there is no extension by that name.
const statusRequestExtension = 5

// mustStaple reports whether the leaf demands a stapled status response.
//
// The second return value separates "the extension is not there" from "the
// extension is there and this parser could not read it". Collapsing the two
// into one boolean is how a certificate that requires stapling comes to be
// reported as one that does not, on the strength of a byte nobody looked at.
//
// The extension body is a SEQUENCE OF INTEGER. Nothing else is accepted:
// trailing bytes after a valid sequence are a sign that the certificate was
// assembled by something other than a conforming encoder, and this returns
// malformed rather than reading the part it happens to understand.
func mustStaple(leaf *x509.Certificate) (required, malformed bool) {
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(tlsFeatureOID) {
			continue
		}

		var features []int
		rest, err := asn1.Unmarshal(ext.Value, &features)
		if err != nil || len(rest) != 0 {
			return false, true
		}
		return slices.Contains(features, statusRequestExtension), false
	}
	return false, false
}

// sctListOID is the RFC 6962 extension holding embedded timestamps.
var sctListOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

const (
	// sctVersionV1 is the only version RFC 6962 defines. A list announcing
	// anything else is a format this parser has not seen, and guessing at the
	// layout of a structure whose version it does not know is how a parser
	// reads past the end of one field into another.
	sctVersionV1 = 0

	// minSerializedSCT is version (1) + log id (32) + timestamp (8) +
	// extensions length (2). A signature follows, so a real one is longer;
	// this is the floor below which the fields read here are not all present.
	minSerializedSCT = 43

	// logIDLen is the SHA-256 of a log's public key.
	logIDLen = 32
)

// embeddedSCTs counts the transparency timestamps carried by the leaf.
//
// The second return value separates a certificate with no timestamps from one
// whose list could not be read. Collapsing them would report a certificate as
// absent from every transparency log on the strength of a parse failure, which
// is a serious accusation to make by accident.
func embeddedSCTs(leaf *x509.Certificate) (count int, logIDs []string, malformed bool) {
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(sctListOID) {
			continue
		}

		// Two wrappings, and missing the inner one is the usual mistake.
		// RFC 6962 puts the TLS-encoded list inside an ASN.1 OCTET STRING,
		// and Go has already removed the outer one that X.509 requires of
		// every extension. What remains is DER and has to be unwrapped again
		// before a single byte of it means what it looks like.
		var list []byte
		rest, err := asn1.Unmarshal(ext.Value, &list)
		if err != nil || len(rest) != 0 {
			return 0, nil, true
		}
		return parseSCTList(list)
	}
	return 0, nil, false
}

// parseSCTList reads a TLS-encoded SignedCertificateTimestampList.
//
// Every length in this format is attacker-chosen: the bytes come from a
// certificate presented by whatever host was named in the request. Each one is
// therefore checked against what is actually left rather than trusted, and a
// declared length that does not match the buffer ends the parse rather than
// being clamped to fit. Clamping is how a parser is made to read one field as
// another.
//
// The loop terminates on its own: every iteration consumes at least two length
// bytes plus minSerializedSCT, so the number of passes is bounded by the input
// divided by 45. There is no counter to get wrong.
//
// Only the version and the log identifier are read. The timestamp and the
// signature are skipped over rather than interpreted, because nothing here
// verifies a signature and a timestamp nobody checked is a number with a date
// painted on it.
func parseSCTList(list []byte) (count int, logIDs []string, malformed bool) {
	if len(list) < 2 {
		return 0, nil, true
	}
	if int(binary.BigEndian.Uint16(list)) != len(list)-2 {
		return 0, nil, true
	}
	list = list[2:]

	seen := make(map[string]struct{}, 4)

	for len(list) > 0 {
		if len(list) < 2 {
			return 0, nil, true
		}
		size := int(binary.BigEndian.Uint16(list))
		list = list[2:]

		if size < minSerializedSCT || size > len(list) {
			return 0, nil, true
		}
		sct := list[:size]
		list = list[size:]

		if sct[0] != sctVersionV1 {
			return 0, nil, true
		}

		id := hex.EncodeToString(sct[1 : 1+logIDLen])
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			logIDs = append(logIDs, id)
		}
		count++
	}

	return count, logIDs, false
}
