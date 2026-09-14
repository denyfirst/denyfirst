package ocsp

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"path/filepath"
	"testing"
)

// The question asks about exactly what a real responder answered.
//
// Built against the captured responses rather than against this package's own
// reading of RFC 6960: each real authority put a CertID in its answer, and a
// request asking about a different one — a hash over the whole key info rather
// than the key, a serial written as bytes rather than a number — would be a
// question no responder recognises, answered "unknown" or not at all, and
// reported as an authority that has never heard of its own certificate.
func TestTheRequestAsksAboutWhatARealResponderAnswered(t *testing.T) {
	compared := 0
	for host := range captured {
		leaf := readCertificate(t, filepath.Join("testdata", host+".leaf.der"))
		issuer := readCertificate(t, filepath.Join("testdata", host+".issuer.der"))
		der := readFixture(t, filepath.Join("testdata", host+".ocsp.der"))

		raw, err := Request(leaf, issuer)
		if err != nil {
			t.Fatalf("%s: Request: %v", host, err)
		}
		var asked ocspRequest
		rest, err := asn1.Unmarshal(raw, &asked)
		if err != nil || len(rest) != 0 {
			t.Fatalf("%s: the request does not parse as one OCSPRequest: %v, %d bytes over", host, err, len(rest))
		}
		if len(asked.TBSRequest.RequestList) != 1 {
			t.Fatalf("%s: the request asks about %d certificates, want one", host, len(asked.TBSRequest.RequestList))
		}
		q := asked.TBSRequest.RequestList[0].Cert

		var outer responseASN1
		if _, err := asn1.Unmarshal(der, &outer); err != nil {
			t.Fatalf("%s: the fixture does not parse: %v", host, err)
		}
		var basic basicResponse
		if _, err := asn1.Unmarshal(outer.Response.Response, &basic); err != nil {
			t.Fatalf("%s: the fixture's basic response does not parse: %v", host, err)
		}
		for _, r := range basic.TBSResponseData.Responses {
			if !r.CertID.HashAlgorithm.Algorithm.Equal(oidSHA1) {
				continue
			}
			compared++
			if !bytes.Equal(q.IssuerNameHash, r.CertID.IssuerNameHash) ||
				!bytes.Equal(q.IssuerKeyHash, r.CertID.IssuerKeyHash) ||
				q.SerialNumber.Cmp(r.CertID.SerialNumber) != 0 {
				t.Errorf("%s: the request asks about %x/%x/%s and the authority answered about %x/%x/%s",
					host, q.IssuerNameHash, q.IssuerKeyHash, q.SerialNumber,
					r.CertID.IssuerNameHash, r.CertID.IssuerKeyHash, r.CertID.SerialNumber)
			}
		}
	}
	if compared == 0 {
		t.Fatal("no captured response carries a SHA-1 CertID, so nothing was compared")
	}
}

// Without the issuer there is no question to ask, and no certificate is none.
func TestARequestNeedsTheCertificateAndItsIssuer(t *testing.T) {
	leaf := readCertificate(t, filepath.Join("testdata", "www.digicert.com.leaf.der"))
	if _, err := Request(leaf, nil); !errors.Is(err, ErrNoIssuer) {
		t.Errorf("a request without the issuer returned %v, want ErrNoIssuer", err)
	}
	if _, err := Request(nil, leaf); err == nil {
		t.Error("a request about no certificate was written")
	}
}
