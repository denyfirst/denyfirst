// Package ocsp reads a stapled certificate status response and says whether
// it means anything.
//
// # Why this exists
//
// A certificate stops being trustworthy before it expires when its key is
// stolen, when it was issued to the wrong person, or when a domain changes
// hands. Revocation is the mechanism for saying so, and a stapled OCSP
// response is the CA's signed statement that a particular certificate was not
// revoked as of a particular moment, handed to the client by the server so
// that the client never has to tell the CA which site it is visiting.
//
// Until this package existed, this project observed that some bytes arrived
// in the handshake and reported "a status response was stapled". A server can
// staple anything: an empty file, a response for a different certificate, a
// response signed by nobody, a year-old response, or a response that says
// revoked. All of them produced the same sentence, and a reader takes that
// sentence to mean a revocation check happened.
//
// The direction of that error is the worst available. Revocation is the
// emergency brake of the whole system, and the case it exists for — a
// certificate that really is revoked — is exactly the case a server has a
// motive to paper over.
//
// # What is checked
//
// In order, and every one of them has to pass:
//
//   - the outer response says the responder succeeded, and carries a basic
//     response rather than some other type;
//   - the response describes this certificate, by issuer name hash, issuer
//     key hash and serial number, all three;
//   - it was produced in the past and has not expired;
//   - it is signed either by the certificate's own issuer, or by a responder
//     the issuer delegated to and marked for that purpose, and the signature
//     verifies.
//
// Only then is the status it carries reported. Anything else is a response
// that was not understood, which is reported as such and never as good news.
//
// # What is not checked
//
// The delegated responder's own revocation status. RFC 6960 §4.2.2.2.1 lets
// an issuer omit that check by marking the responder certificate id-pkix-ocsp-
// nocheck, and the responder certificates in use carry short lifetimes for the
// same reason. Checking it properly would mean fetching another response for
// the responder, over the network, from an address the scanned party chooses.
//
// Nothing here fetches anything. Only bytes the server already sent are read.
package ocsp

import (
	"crypto/sha1" // #nosec G505 -- the CertID hash RFC 6960 specifies; see hashByOID.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"time"
)

// Status is what a validated response says about the certificate.
type Status string

const (
	// Good means the responder stated that this certificate is not revoked.
	Good Status = "good"

	// Revoked means the certificate has been withdrawn.
	Revoked Status = "revoked"

	// Unknown means the responder does not know about this certificate. It is
	// not reassurance: a responder that has never heard of a certificate it
	// should be authoritative for is a fact worth reporting.
	Unknown Status = "unknown"
)

// Response is a stapled response that was understood.
type Response struct {
	Status Status

	// ProducedAt, ThisUpdate and NextUpdate come from the response. NextUpdate
	// is the zero time when the responder did not state one, which RFC 6960
	// permits and which means fresher information is always available.
	ProducedAt time.Time
	ThisUpdate time.Time
	NextUpdate time.Time

	// RevokedAt and RevocationReason are set only when Status is Revoked.
	RevokedAt        time.Time
	RevocationReason int

	// SignedByDelegate is true when a responder certificate signed this
	// rather than the issuer itself.
	SignedByDelegate bool
}

// Errors a caller may want to distinguish. Everything else is described in
// prose, because a caller that cannot act differently on a distinction does
// not need one.
var (
	// ErrNoIssuer means the chain did not include the certificate that issued
	// the leaf, so nothing here can be verified. Not the response's fault and
	// not the server's answer about revocation; a separate finding already
	// covers an incomplete chain.
	ErrNoIssuer = errors.New("ocsp: the issuing certificate was not sent, so the response cannot be verified")

	// ErrWrongCertificate means the response is about some other certificate.
	// The one failure worth its own error: it is what a server replaying a
	// stale good response for a different serial produces.
	ErrWrongCertificate = errors.New("ocsp: the response describes a different certificate")
)

// Maximum sizes. Every one of these bounds something the scanned server
// chooses, and none of them is generous: a real response is a few hundred
// bytes and carries one entry.
const (
	maxResponse  = 64 << 10
	maxResponses = 16
	maxCerts     = 8

	// clockSkew is how far in the future a producedAt or thisUpdate may sit
	// before the response is refused. Responders and scanners disagree about
	// the time by seconds, not by minutes.
	clockSkew = 5 * time.Minute
)

var (
	oidBasicResponse = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidOCSPSigning   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// ── The structures RFC 6960 defines ─────────────────────────────────────

type responseASN1 struct {
	Status   asn1.Enumerated
	Response responseBytes `asn1:"optional,explicit,tag:0"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type basicResponse struct {
	TBSResponseData    responseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type responseData struct {
	// Raw is the encoding of this element, header included, which is exactly
	// what the signature covers. Taking it from the parser rather than
	// re-encoding it means a signature is checked over the bytes that
	// arrived, not over this program's idea of how they should have looked —
	// which is where signature-verification bugs live.
	Raw asn1.RawContent

	Version     int `asn1:"optional,default:0,explicit,tag:0"`
	ResponderID asn1.RawValue
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []singleResponse
	Extensions  []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

type singleResponse struct {
	CertID     certID
	Status     asn1.RawValue
	ThisUpdate time.Time        `asn1:"generalized"`
	NextUpdate time.Time        `asn1:"generalized,optional,explicit,tag:0"`
	Extensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

type certID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

type revokedInfo struct {
	RevocationTime time.Time `asn1:"generalized"`
	Reason         int       `asn1:"optional,explicit,tag:0"`
}

// ── Reading one ─────────────────────────────────────────────────────────

// Check reads a stapled response and reports what it establishes about leaf.
//
// issuer is the certificate that signed leaf, and must be the real one: every
// check below is against it. A nil issuer returns ErrNoIssuer rather than a
// verdict, because a response nobody can verify is not a response.
//
// now is supplied so a report can state the moment it describes and so tests
// are reproducible.
func Check(der []byte, leaf, issuer *x509.Certificate, now time.Time) (*Response, error) {
	switch {
	case leaf == nil:
		return nil, errors.New("ocsp: no certificate to check")
	case issuer == nil:
		return nil, ErrNoIssuer
	case len(der) == 0:
		return nil, errors.New("ocsp: the response is empty")
	case len(der) > maxResponse:
		return nil, fmt.Errorf("ocsp: the response is %d bytes, and this reads at most %d", len(der), maxResponse)
	}

	var outer responseASN1
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, fmt.Errorf("ocsp: the response is not a well-formed OCSPResponse: %w", err)
	}
	if len(rest) != 0 {
		// Trailing bytes after a complete DER value. Harmless to ignore and
		// wrong to ignore: it is the shape of a response with something
		// appended, and DER has exactly one encoding.
		return nil, fmt.Errorf("ocsp: %d bytes follow the response", len(rest))
	}

	if outer.Status != 0 {
		return nil, fmt.Errorf("ocsp: the responder did not answer successfully (status %d: %s)",
			outer.Status, responderStatus(int(outer.Status)))
	}
	if !outer.Response.ResponseType.Equal(oidBasicResponse) {
		return nil, fmt.Errorf("ocsp: the response is of type %v, and only the basic type is defined", outer.Response.ResponseType)
	}

	var basic basicResponse
	if rest, err := asn1.Unmarshal(outer.Response.Response, &basic); err != nil {
		return nil, fmt.Errorf("ocsp: the basic response is malformed: %w", err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("ocsp: %d bytes follow the basic response", len(rest))
	}

	if n := len(basic.TBSResponseData.Responses); n == 0 {
		return nil, errors.New("ocsp: the response describes no certificate")
	} else if n > maxResponses {
		return nil, fmt.Errorf("ocsp: the response describes %d certificates, and this reads at most %d", n, maxResponses)
	}

	single, err := forCertificate(basic.TBSResponseData.Responses, leaf, issuer)
	if err != nil {
		return nil, err
	}

	// Freshness before the signature, and the order is not arbitrary. A stale
	// response is the ordinary failure and its message should be the ordinary
	// one; reporting "the signature did not verify" for a response that
	// simply expired sends the reader looking for an attack.
	if err := fresh(basic.TBSResponseData.ProducedAt, single, now); err != nil {
		return nil, err
	}

	delegate, err := verifySignature(&basic, issuer, now)
	if err != nil {
		return nil, err
	}

	out := &Response{
		ProducedAt:       basic.TBSResponseData.ProducedAt,
		ThisUpdate:       single.ThisUpdate,
		NextUpdate:       single.NextUpdate,
		SignedByDelegate: delegate,
	}

	// CertStatus is a CHOICE, so the context tag is the answer.
	switch single.Status.Tag {
	case 0:
		out.Status = Good
	case 1:
		out.Status = Revoked
		var info revokedInfo
		// A revoked status whose detail will not parse is still revoked. The
		// time and the reason are decoration; the tag is the finding, and
		// refusing the whole response here would turn a malformed detail into
		// a certificate that reads as fine.
		if _, err := asn1.Unmarshal(single.Status.FullBytes, &info); err == nil {
			out.RevokedAt = info.RevocationTime
			out.RevocationReason = info.Reason
		} else if _, err := asn1.UnmarshalWithParams(single.Status.FullBytes, &info, "tag:1"); err == nil {
			out.RevokedAt = info.RevocationTime
			out.RevocationReason = info.Reason
		}
	case 2:
		out.Status = Unknown
	default:
		return nil, fmt.Errorf("ocsp: the certificate status is tag %d, which is not one of good, revoked or unknown", single.Status.Tag)
	}

	return out, nil
}

// forCertificate finds the entry that describes leaf, and refuses the
// response if none does.
//
// All three fields have to match. The serial alone is not enough — serials
// are unique per issuer, not globally — and the issuer hashes alone describe
// every certificate that issuer ever signed. Matching on a subset is how a
// response about one certificate comes to vouch for another.
func forCertificate(responses []singleResponse, leaf, issuer *x509.Certificate) (*singleResponse, error) {
	keyBytes, err := publicKeyBytes(issuer)
	if err != nil {
		return nil, err
	}

	for i := range responses {
		r := &responses[i]

		if r.CertID.SerialNumber == nil || leaf.SerialNumber == nil ||
			r.CertID.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
			continue
		}

		h, err := hashByOID(r.CertID.HashAlgorithm.Algorithm)
		if err != nil {
			// A hash this does not implement means this entry cannot be
			// matched. Keep looking rather than refusing: a response may
			// carry several, and one of them may be readable.
			continue
		}

		h.Reset()
		h.Write(issuer.RawSubject)
		if !equalHash(h.Sum(nil), r.CertID.IssuerNameHash) {
			continue
		}

		h.Reset()
		h.Write(keyBytes)
		if !equalHash(h.Sum(nil), r.CertID.IssuerKeyHash) {
			continue
		}

		return r, nil
	}

	return nil, ErrWrongCertificate
}

// publicKeyBytes returns the contents of the issuer's subjectPublicKey BIT
// STRING, which is what RFC 6960 hashes — not the whole SubjectPublicKeyInfo.
func publicKeyBytes(issuer *x509.Certificate) ([]byte, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, fmt.Errorf("ocsp: the issuer's public key could not be read: %w", err)
	}
	return spki.PublicKey.RightAlign(), nil
}

func hashByOID(oid asn1.ObjectIdentifier) (hash.Hash, error) {
	switch {
	case oid.Equal(oidSHA1):
		// SHA-1 is what responders use here and it is not a security choice
		// this package gets to make: the identifier in a request and the one
		// in the response have to agree, and a scanner that refused SHA-1
		// CertIDs would refuse most real responses. It identifies rather than
		// protects — the signature below is what protects — and every one of
		// the three fields has to match, so a collision would have to be
		// simultaneous in two hashes and exact in a serial number.
		return sha1.New(), nil // #nosec G401
	case oid.Equal(oidSHA256):
		return sha256.New(), nil
	case oid.Equal(oidSHA384):
		return sha512New384(), nil
	case oid.Equal(oidSHA512):
		return sha512New(), nil
	}
	return nil, fmt.Errorf("ocsp: the identifier uses hash %v, which this does not implement", oid)
}

// equalHash compares in constant time out of habit rather than necessity:
// nothing secret is on either side. It also refuses a length mismatch, which
// a plain prefix comparison would not.
func equalHash(a, b []byte) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// fresh refuses a response that describes a moment that has not arrived or
// one that has passed.
//
// The expiry check is the one that matters. A response saying good is true
// when it is made and says nothing about the following week, so a server that
// keeps serving an old one is serving a statement that has run out — and if
// the certificate was revoked in the meantime, that is precisely the statement
// it has a motive to keep serving.
func fresh(producedAt time.Time, r *singleResponse, now time.Time) error {
	if producedAt.After(now.Add(clockSkew)) {
		return fmt.Errorf("ocsp: the response says it was produced at %s, which is in the future",
			producedAt.UTC().Format(time.RFC3339))
	}
	if r.ThisUpdate.After(now.Add(clockSkew)) {
		return fmt.Errorf("ocsp: the response describes the status as of %s, which is in the future",
			r.ThisUpdate.UTC().Format(time.RFC3339))
	}
	if !r.NextUpdate.IsZero() && r.NextUpdate.Before(now) {
		return fmt.Errorf("ocsp: the response expired at %s and is still being stapled",
			r.NextUpdate.UTC().Format(time.RFC3339))
	}
	return nil
}

// verifySignature checks the response against the issuer, or against a
// responder the issuer delegated to.
//
// The delegation rules are RFC 6960 §4.2.2.2 and they are narrow on purpose:
// the responder certificate has to be signed by this same issuer and has to
// carry the OCSP signing extended key usage. Without the second, any
// certificate the issuer ever signed — including the leaf being checked —
// could vouch for its own revocation status.
func verifySignature(basic *basicResponse, issuer *x509.Certificate, now time.Time) (delegate bool, err error) {
	algo, err := signatureAlgorithm(basic.SignatureAlgorithm.Algorithm)
	if err != nil {
		return false, err
	}

	signed := basic.TBSResponseData.Raw
	signature := basic.Signature.RightAlign()

	if err := issuer.CheckSignature(algo, signed, signature); err == nil {
		return false, nil
	}

	if len(basic.Certificates) == 0 {
		return false, errors.New("ocsp: the response is not signed by the certificate's issuer, and names no responder that would explain why")
	}
	if len(basic.Certificates) > maxCerts {
		return false, fmt.Errorf("ocsp: the response carries %d certificates, and this reads at most %d",
			len(basic.Certificates), maxCerts)
	}

	var reasons []string
	for _, raw := range basic.Certificates {
		responder, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			reasons = append(reasons, "one of the responder certificates could not be parsed")
			continue
		}

		if err := responder.CheckSignatureFrom(issuer); err != nil {
			reasons = append(reasons, "a responder certificate was not issued by this certificate's issuer")
			continue
		}
		if !hasOCSPSigning(responder) {
			reasons = append(reasons, "a responder certificate is not marked for OCSP signing")
			continue
		}
		if now.Before(responder.NotBefore) || now.After(responder.NotAfter) {
			reasons = append(reasons, "a responder certificate is outside its validity period")
			continue
		}
		if err := responder.CheckSignature(algo, signed, signature); err != nil {
			reasons = append(reasons, "a responder certificate did not sign this response")
			continue
		}
		return true, nil
	}

	return false, fmt.Errorf("ocsp: the signature does not verify: %s", join(reasons))
}

func hasOCSPSigning(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageOCSPSigning {
			return true
		}
	}
	for _, oid := range c.UnknownExtKeyUsage {
		if oid.Equal(oidOCSPSigning) {
			return true
		}
	}
	return false
}

// signatureAlgorithm maps the identifier in the response onto something the
// standard library will check.
//
// Refused rather than guessed. An algorithm this does not recognise means the
// signature was not verified, and a response whose signature was not verified
// is not a response — which is the whole reason this package exists.
func signatureAlgorithm(oid asn1.ObjectIdentifier) (x509.SignatureAlgorithm, error) {
	switch {
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}):
		return x509.SHA256WithRSA, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}):
		return x509.SHA384WithRSA, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}):
		return x509.SHA512WithRSA, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}):
		return x509.SHA256WithRSAPSS, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}):
		return x509.ECDSAWithSHA256, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}):
		return x509.ECDSAWithSHA384, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}):
		return x509.ECDSAWithSHA512, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 101, 112}):
		return x509.PureEd25519, nil

	// Named rather than lumped into the default, because a SHA-1 signature is
	// a different report from an unrecognised one: it is a real algorithm
	// that is no longer strong enough, and the reader should be told which
	// they are looking at.
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}),
		oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}):
		return 0, errors.New("ocsp: the response is signed with SHA-1, which is not accepted here")
	}
	return 0, fmt.Errorf("ocsp: the response is signed with %v, which this does not verify", oid)
}

func responderStatus(n int) string {
	switch n {
	case 1:
		return "malformed request"
	case 2:
		return "internal error"
	case 3:
		return "try later"
	case 5:
		return "signature required"
	case 6:
		return "unauthorized"
	}
	return "unrecognised"
}

func join(reasons []string) string {
	if len(reasons) == 0 {
		return "no responder certificate matched"
	}
	out := reasons[0]
	for _, r := range reasons[1:] {
		out += "; " + r
	}
	return out
}

// sha512New384 and sha512New keep the crypto/sha512 import out of the switch
// above, where the three lines it would add are noise.
func sha512New384() hash.Hash { return sha512.New384() }
func sha512New() hash.Hash    { return sha512.New() }
