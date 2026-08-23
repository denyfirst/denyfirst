package ocsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- building the CertID RFC 6960 specifies.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

// ── Fixtures ────────────────────────────────────────────────────────────

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newAuthority(t testing.TB, name string) authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.AddDate(0, 0, -30),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the authority: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the authority: %v", err)
	}
	return authority{cert: cert, key: key}
}

func (a authority) issue(t testing.TB, serial int64, eku []x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "leaf.test"},
		NotBefore:    now.AddDate(0, 0, -1),
		NotAfter:     now.AddDate(0, 0, 60),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
		DNSNames:     []string{"leaf.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the leaf: %v", err)
	}
	return cert
}

// issueResponder returns a delegated responder certificate and its key.
func (a authority) issueResponder(t testing.TB, eku []x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "responder.test"},
		NotBefore:    now.AddDate(0, 0, -1),
		NotAfter:     now.AddDate(0, 0, 7),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatalf("issuing the responder: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the responder: %v", err)
	}
	return cert, key
}

// build assembles a response. Every field a test wants to spoil is a
// parameter, because the point of this package is what it does with a
// response that is wrong in one specific way.
type spec struct {
	leaf   *x509.Certificate
	issuer *x509.Certificate

	// signer signs the response. Nil means the issuer's own key.
	signerKey  *ecdsa.PrivateKey
	signerCert *x509.Certificate

	statusTag  int // 0 good, 1 revoked, 2 unknown
	producedAt time.Time
	thisUpdate time.Time
	nextUpdate time.Time

	serial       *big.Int // nil means the leaf's
	responderID  *x509.Certificate
	outerStatus  int
	responseType asn1.ObjectIdentifier
}

func build(t testing.TB, a authority, s spec) []byte {
	t.Helper()

	leafSerial := s.serial
	if leafSerial == nil {
		leafSerial = s.leaf.SerialNumber
	}
	if s.producedAt.IsZero() {
		s.producedAt = now.Add(-time.Hour)
	}
	if s.thisUpdate.IsZero() {
		s.thisUpdate = now.Add(-time.Hour)
	}
	if s.nextUpdate.IsZero() {
		s.nextUpdate = now.Add(72 * time.Hour)
	}

	keyBytes, err := publicKeyBytes(s.issuer)
	if err != nil {
		t.Fatalf("reading the issuer key: %v", err)
	}
	nameHash := sha1.Sum(s.issuer.RawSubject) // #nosec G401
	keyHash := sha1.Sum(keyBytes)             // #nosec G401

	var status asn1.RawValue
	switch s.statusTag {
	case 1:
		body, err := asn1.Marshal(revokedInfo{RevocationTime: now.Add(-2 * time.Hour), Reason: 1})
		if err != nil {
			t.Fatalf("marshalling revocation: %v", err)
		}
		// Re-tagged as [1] IMPLICIT, which is how CertStatus carries it.
		status = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: body[2:]}
	case 2:
		status = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: nil}
	default:
		status = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: nil}
	}

	responderName := s.responderID
	if responderName == nil {
		responderName = s.issuer
	}
	responder := asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true,
		Bytes: responderName.RawSubject,
	}

	data := responseData{
		ResponderID: responder,
		ProducedAt:  s.producedAt,
		Responses: []singleResponse{{
			CertID: certID{
				HashAlgorithm:  pkix.AlgorithmIdentifier{Algorithm: oidSHA1},
				IssuerNameHash: nameHash[:],
				IssuerKeyHash:  keyHash[:],
				SerialNumber:   leafSerial,
			},
			Status:     status,
			ThisUpdate: s.thisUpdate,
			NextUpdate: s.nextUpdate,
		}},
	}

	tbs, err := asn1.Marshal(data)
	if err != nil {
		t.Fatalf("marshalling the response data: %v", err)
	}

	key := s.signerKey
	if key == nil {
		key = a.key
	}
	sum := sha256sum(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	basic := basicResponse{
		TBSResponseData:    responseData{Raw: tbs},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Signature:          asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}
	if s.signerCert != nil {
		basic.Certificates = []asn1.RawValue{{FullBytes: s.signerCert.Raw}}
	}

	// asn1.Marshal writes RawContent verbatim when it is the first field, so
	// the bytes signed above are the bytes that end up in the response. That
	// is the property the parser relies on and the one a re-encoding would
	// quietly break.
	basicDER, err := asn1.Marshal(basic)
	if err != nil {
		t.Fatalf("marshalling the basic response: %v", err)
	}

	responseType := s.responseType
	if responseType == nil {
		responseType = oidBasicResponse
	}

	outer := responseASN1{
		Status: asn1.Enumerated(s.outerStatus),
		Response: responseBytes{
			ResponseType: responseType,
			Response:     basicDER,
		},
	}
	der, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatalf("marshalling the response: %v", err)
	}
	return der
}

func sha256sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// ── The tests ───────────────────────────────────────────────────────────

// The ordinary case, so every failure below is a difference from something
// that works rather than from nothing.
func TestAGoodResponseIsRead(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := ca.issue(t, 4242, nil)

	got, err := Check(build(t, ca, spec{leaf: leaf, issuer: ca.cert}), leaf, ca.cert, now)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Status != Good {
		t.Errorf("status = %q, want %q", got.Status, Good)
	}
	if got.SignedByDelegate {
		t.Error("a response signed by the issuer was reported as signed by a delegate")
	}
}

// The finding this package exists for. A revoked certificate reported as
// stapled-and-fine is the worst answer this project can give: revocation is
// the emergency brake, and the server has every motive to keep serving the
// last response that said good.
func TestARevokedCertificateIsReported(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := ca.issue(t, 4242, nil)

	got, err := Check(build(t, ca, spec{leaf: leaf, issuer: ca.cert, statusTag: 1}), leaf, ca.cert, now)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Status != Revoked {
		t.Fatalf("status = %q, want %q", got.Status, Revoked)
	}
	if got.RevokedAt.IsZero() {
		t.Error("the revocation time was not read")
	}
}

// A responder that does not know the certificate is not saying it is fine.
func TestAnUnknownStatusIsNotGood(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := ca.issue(t, 4242, nil)

	got, err := Check(build(t, ca, spec{leaf: leaf, issuer: ca.cert, statusTag: 2}), leaf, ca.cert, now)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Status != Unknown {
		t.Errorf("status = %q, want %q", got.Status, Unknown)
	}
}

// The replay. A server holding a good response for a certificate it also
// serves — or any response it happened to obtain — must not have it accepted
// for a different one.
func TestAResponseAboutAnotherCertificateIsRefused(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := ca.issue(t, 4242, nil)

	der := build(t, ca, spec{leaf: leaf, issuer: ca.cert, serial: big.NewInt(777)})

	if _, err := Check(der, leaf, ca.cert, now); !errors.Is(err, ErrWrongCertificate) {
		t.Errorf("a response for serial 777 was accepted for serial 4242: %v", err)
	}
}

// Same serial, different issuer. Serial numbers are unique per authority
// rather than globally, so matching on the serial alone would accept a
// response another CA issued about its own certificate.
func TestAResponseFromAnotherAuthorityIsRefused(t *testing.T) {
	ours := newAuthority(t, "Test CA")
	theirs := newAuthority(t, "Other CA")

	leaf := ours.issue(t, 4242, nil)
	other := theirs.issue(t, 4242, nil)

	der := build(t, theirs, spec{leaf: other, issuer: theirs.cert})

	if _, err := Check(der, leaf, ours.cert, now); !errors.Is(err, ErrWrongCertificate) {
		t.Errorf("a response from another authority about its own serial 4242 was accepted: %v", err)
	}
}

// The other replay, and the commoner one. A response saying good is true when
// it is made and says nothing about next week; a server that keeps stapling
// an expired one is serving a statement that has run out — and if the
// certificate was revoked in the meantime, that is the statement it has a
// motive to keep serving.
func TestAnExpiredResponseIsRefused(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := ca.issue(t, 4242, nil)

	der := build(t, ca, spec{
		leaf: leaf, issuer: ca.cert,
		producedAt: now.AddDate(0, 0, -30),
		thisUpdate: now.AddDate(0, 0, -30),
		nextUpdate: now.AddDate(0, 0, -23),
	})

	_, err := Check(der, leaf, ca.cert, now)
	if err == nil {
		t.Fatal("an expired response was accepted")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("the reason given is %q; a reader should be told it expired rather than sent looking for an attack", err)
	}
}

// A response dated in the future is not a fresh one.
func TestAResponseFromTheFutureIsRefused(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := ca.issue(t, 4242, nil)

	der := build(t, ca, spec{
		leaf: leaf, issuer: ca.cert,
		producedAt: now.Add(48 * time.Hour),
		thisUpdate: now.Add(48 * time.Hour),
	})

	if _, err := Check(der, leaf, ca.cert, now); err == nil {
		t.Fatal("a response produced in the future was accepted")
	}
}

// Without this, the whole package is decoration: a server could write its own
// response saying good and staple it.
func TestAResponseSignedByNobodyIsRefused(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	impostor := newAuthority(t, "Test CA") // same name, different key
	leaf := ca.issue(t, 4242, nil)

	der := build(t, ca, spec{leaf: leaf, issuer: ca.cert, signerKey: impostor.key})

	_, err := Check(der, leaf, ca.cert, now)
	if err == nil {
		t.Fatal("a response signed with the wrong key was accepted")
	}
	if !strings.Contains(err.Error(), "not signed by") && !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("the reason given is %q", err)
	}
}

// Delegation is how real authorities sign: a short-lived responder
// certificate rather than the root key.
func TestADelegatedResponderIsAccepted(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := ca.issue(t, 4242, nil)
	responder, key := ca.issueResponder(t, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning})

	der := build(t, ca, spec{leaf: leaf, issuer: ca.cert, signerKey: key, signerCert: responder})

	got, err := Check(der, leaf, ca.cert, now)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !got.SignedByDelegate {
		t.Error("a delegated signature was not reported as one")
	}
}

// The rule that makes delegation safe. Without the extended key usage, any
// certificate the authority ever signed could vouch for its own revocation
// status — including the certificate being checked.
func TestACertificateCannotVouchForItselfWithoutTheDelegation(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := ca.issue(t, 4242, nil)

	// A certificate from the same authority, marked for server
	// authentication rather than OCSP signing: exactly what a leaf is.
	impostor, key := ca.issueResponder(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	der := build(t, ca, spec{leaf: leaf, issuer: ca.cert, signerKey: key, signerCert: impostor})

	_, err := Check(der, leaf, ca.cert, now)
	if err == nil {
		t.Fatal("a certificate not marked for OCSP signing was accepted as a responder")
	}
	if !strings.Contains(err.Error(), "OCSP signing") {
		t.Errorf("the reason given is %q; it should name the missing delegation", err)
	}
}

// A responder certificate from somewhere else is not a delegation.
func TestAResponderFromAnotherAuthorityIsRefused(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	other := newAuthority(t, "Other CA")
	leaf := ca.issue(t, 4242, nil)
	responder, key := other.issueResponder(t, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning})

	der := build(t, ca, spec{leaf: leaf, issuer: ca.cert, signerKey: key, signerCert: responder})

	if _, err := Check(der, leaf, ca.cert, now); err == nil {
		t.Fatal("a responder certificate from another authority was accepted")
	}
}

// An unsuccessful responder reply carries no status, and reporting one would
// be inventing it.
func TestAnUnsuccessfulResponseIsNotAStatus(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := ca.issue(t, 4242, nil)

	der := build(t, ca, spec{leaf: leaf, issuer: ca.cert, outerStatus: 3})

	_, err := Check(der, leaf, ca.cert, now)
	if err == nil {
		t.Fatal("a try-later reply was read as a status")
	}
	if !strings.Contains(err.Error(), "try later") {
		t.Errorf("the reason given is %q", err)
	}
}

// Without the issuer nothing can be verified, and that is a different answer
// from a bad response.
func TestWithoutTheIssuerNothingIsClaimed(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := ca.issue(t, 4242, nil)

	der := build(t, ca, spec{leaf: leaf, issuer: ca.cert})

	if _, err := Check(der, leaf, nil, now); !errors.Is(err, ErrNoIssuer) {
		t.Errorf("err = %v, want ErrNoIssuer", err)
	}
}

// Bytes a server chose. None of these may panic, and none may return a
// status.
func TestRubbishIsRefusedWithoutPanicking(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := ca.issue(t, 4242, nil)
	good := build(t, ca, spec{leaf: leaf, issuer: ca.cert})

	cases := map[string][]byte{
		"empty":          {},
		"one byte":       {0x30},
		"truncated":      good[:len(good)/2],
		"trailing bytes": append(append([]byte{}, good...), 0x00, 0x00),
		"not asn.1":      []byte("this is not a certificate status response"),
		"oversized":      make([]byte, maxResponse+1),
	}

	for name, der := range cases {
		got, err := Check(der, leaf, ca.cert, now)
		if err == nil {
			t.Errorf("%s: accepted, and reported %q", name, got.Status)
		}
	}
}

// The response type matters: only the basic type is defined, and a response
// of some other type carries no status this can read.
func TestAnUnknownResponseTypeIsRefused(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := ca.issue(t, 4242, nil)

	der := build(t, ca, spec{
		leaf: leaf, issuer: ca.cert,
		responseType: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 99},
	})

	if _, err := Check(der, leaf, ca.cert, now); err == nil {
		t.Fatal("a response of an undefined type was read")
	}
}

// FuzzCheck runs the parser against bytes nobody chose.
//
// Everything this package reads is chosen by the scanned server, which is the
// definition of hostile input, and the parser is the part of this project
// most likely to be wrong in a way review does not catch. The contract is
// narrow and absolute: never panic, and never return a status together with a
// nil error unless every check passed.
func FuzzCheck(f *testing.F) {
	ca := newAuthority(f, "Test CA")
	leaf := ca.issue(f, 4242, nil)

	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Add(build(f, ca, spec{leaf: leaf, issuer: ca.cert}))
	f.Add(build(f, ca, spec{leaf: leaf, issuer: ca.cert, statusTag: 1}))

	f.Fuzz(func(t *testing.T, der []byte) {
		got, err := Check(der, leaf, ca.cert, now)
		if err != nil {
			return
		}
		switch got.Status {
		case Good, Revoked, Unknown:
		default:
			t.Fatalf("Check returned no error and status %q", got.Status)
		}
	})
}
