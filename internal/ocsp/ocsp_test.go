package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

	// Shapes real responders emit that the happy-path fixture does not.
	certIDHash      asn1.ObjectIdentifier // nil means SHA-1, which is what they use
	responderByKey  bool                  // [2] KeyHash instead of [1] Name
	explicitVersion bool                  // v1 written out instead of defaulted
	noNextUpdate    bool
	nonce           bool // a nonce in responseExtensions
	singleExtension bool
	extraEntries    int // further SingleResponses about other certificates
	rsaSigner       *rsa.PrivateKey
	rsaCert         *x509.Certificate
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

	hashOID := s.certIDHash
	if hashOID == nil {
		hashOID = oidSHA1
	}
	var nameHash, keyHash []byte
	switch {
	case hashOID.Equal(oidSHA256):
		n := sha256.Sum256(s.issuer.RawSubject)
		k := sha256.Sum256(keyBytes)
		nameHash, keyHash = n[:], k[:]
	default:
		n := sha1.Sum(s.issuer.RawSubject) // #nosec G401
		k := sha1.Sum(keyBytes)            // #nosec G401
		nameHash, keyHash = n[:], k[:]
	}

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
	if s.responderByKey {
		// [2] EXPLICIT KeyHash, where KeyHash is an OCTET STRING of the
		// SHA-1 of the responder's public key. Several real responders use
		// this form rather than the name.
		h := sha1.Sum(keyBytes) // #nosec G401
		inner, err := asn1.Marshal(h[:])
		if err != nil {
			t.Fatalf("marshalling the key hash: %v", err)
		}
		responder = asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: inner,
		}
	}

	var responseExtensions []pkix.Extension
	if s.nonce {
		responseExtensions = append(responseExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2},
			Value: []byte{0x04, 0x10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		})
	}
	var singleExtensions []pkix.Extension
	if s.singleExtension {
		// id-pkix-ocsp-archive-cutoff, which responders really do send.
		singleExtensions = append(singleExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 6},
			Value: []byte{0x18, 0x0f, '2', '0', '2', '0', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'},
		})
	}

	nextUpdate := s.nextUpdate
	if s.noNextUpdate {
		nextUpdate = time.Time{}
	}

	data := responseData{
		ResponderID: responder,
		ProducedAt:  s.producedAt,
		Extensions:  responseExtensions,
		Responses: []singleResponse{{
			CertID: certID{
				HashAlgorithm:  pkix.AlgorithmIdentifier{Algorithm: hashOID},
				IssuerNameHash: nameHash,
				IssuerKeyHash:  keyHash,
				SerialNumber:   leafSerial,
			},
			Status:     status,
			ThisUpdate: s.thisUpdate,
			NextUpdate: nextUpdate,
			Extensions: singleExtensions,
		}},
	}

	// Entries about other certificates, placed before the real one, so a
	// parser that reads only the first gets the wrong answer.
	for i := range s.extraEntries {
		other := singleResponse{
			CertID: certID{
				HashAlgorithm:  pkix.AlgorithmIdentifier{Algorithm: hashOID},
				IssuerNameHash: nameHash,
				IssuerKeyHash:  keyHash,
				SerialNumber:   big.NewInt(int64(900000 + i)),
			},
			Status:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: nil},
			ThisUpdate: s.thisUpdate,
			NextUpdate: nextUpdate,
		}
		data.Responses = append([]singleResponse{other}, data.Responses...)
	}
	if s.explicitVersion {
		data.Version = 0
	}

	tbs, err := asn1.Marshal(data)
	if err != nil {
		t.Fatalf("marshalling the response data: %v", err)
	}

	sum := sha256sum(tbs)

	var (
		sig    []byte
		sigOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2} // ecdsa-with-SHA256
	)
	if s.rsaSigner != nil {
		// sha256WithRSAEncryption, which is what most real responders use.
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.rsaSigner, crypto.SHA256, sum)
		if err != nil {
			t.Fatalf("signing with RSA: %v", err)
		}
		sigOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	} else {
		key := s.signerKey
		if key == nil {
			key = a.key
		}
		sig, err = ecdsa.SignASN1(rand.Reader, key, sum)
		if err != nil {
			t.Fatalf("signing: %v", err)
		}
	}

	basic := basicResponse{
		TBSResponseData:    responseData{Raw: tbs},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigOID},
		Signature:          asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}
	switch {
	case s.rsaCert != nil:
		basic.Certificates = []asn1.RawValue{{FullBytes: s.rsaCert.Raw}}
	case s.signerCert != nil:
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

	// The shapes a real authority emits, so the fuzzer starts from responses
	// that exercise the branches a hand-written happy path never reaches.
	f.Add(build(f, ca, spec{
		leaf: leaf, issuer: ca.cert,
		responderByKey: true, certIDHash: oidSHA256, explicitVersion: true,
		nonce: true, singleExtension: true, extraEntries: 2,
	}))
	f.Add(build(f, ca, spec{leaf: leaf, issuer: ca.cert, noNextUpdate: true}))

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

// The shapes real responders emit.
//
// Every response this parser had ever seen was one the tests built, and they
// all had the same shape: a name-form responder identifier, a SHA-1 CertID, an
// ECDSA signature, one entry, no extensions, an omitted version. A real
// authority varies every one of those, and a parser that only handles the
// shape it was written against fails on the first live response — reporting
// cert.staple-unverifiable, which is weak, against a server doing everything
// right.
//
// That direction is the one this project cannot accept: a false accusation is
// worse than a missed finding, because the reader has no way to tell it from a
// real one. So each variant is exercised on its own, and each has to come back
// good rather than merely not crash.
func TestTheShapesRealRespondersEmit(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := ca.issue(t, 4242, nil)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating an RSA key: %v", err)
	}
	rsaResponder := ca.issueRSAResponder(t, rsaKey)

	cases := map[string]spec{
		"responder identified by key hash": {responderByKey: true},
		"SHA-256 CertID":                   {certIDHash: oidSHA256},
		"version written out":              {explicitVersion: true},
		"no nextUpdate":                    {noNextUpdate: true},
		"a nonce in the response":          {nonce: true},
		"an archive cutoff on the entry":   {singleExtension: true},
		"three entries, ours last":         {extraEntries: 2},
		"RSA signature from a delegate":    {rsaSigner: rsaKey, rsaCert: rsaResponder},
		"everything at once": {
			responderByKey: true, certIDHash: oidSHA256, explicitVersion: true,
			nonce: true, singleExtension: true, extraEntries: 2,
			rsaSigner: rsaKey, rsaCert: rsaResponder,
		},
	}

	for name, tc := range cases {
		tc.leaf, tc.issuer = leaf, ca.cert

		got, err := Check(build(t, ca, tc), leaf, ca.cert, now)
		if err != nil {
			t.Errorf("%s: a well-formed response was refused: %v", name, err)
			continue
		}
		if got.Status != Good {
			t.Errorf("%s: status = %q, want %q", name, got.Status, Good)
		}
	}
}

// With several entries in one response, the right one has to be found. A
// parser that reads the first would report another certificate's revocation
// against this one, which is a false accusation rather than a missed finding.
func TestTheRightEntryIsFoundAmongSeveral(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := ca.issue(t, 4242, nil)

	// The two entries placed in front of ours say revoked.
	got, err := Check(build(t, ca, spec{leaf: leaf, issuer: ca.cert, extraEntries: 2}), leaf, ca.cert, now)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Status != Good {
		t.Errorf("status = %q; another certificate's entry was read as this one's", got.Status)
	}
}

// issueRSAResponder issues a delegated responder certificate over an RSA key,
// which is what most authorities actually sign responses with.
func (a authority) issueRSAResponder(t testing.TB, key *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(98),
		Subject:      pkix.Name{CommonName: "rsa-responder.test"},
		NotBefore:    now.AddDate(0, 0, -1),
		NotAfter:     now.AddDate(0, 0, 7),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatalf("issuing the RSA responder: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the RSA responder: %v", err)
	}
	return cert
}
