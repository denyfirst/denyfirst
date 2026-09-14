package ocsp

import (
	"crypto/sha1" // #nosec G505 -- the CertID hash RFC 6960 specifies and responders expect; see hashByOID.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// The request structures RFC 6960 §4.1.1 defines, with the optional parts left
// out: no requestor name, no signature, no extensions and so no nonce.
//
// No nonce on purpose. A nonce stops a responder answering from a cache, which
// makes every question cost the authority a signature, and most responders
// ignore one anyway (RFC 8954). A replayed answer is refused by Check on its
// own dates, which is the defence that holds whether a nonce is honoured or not.
type ocspRequest struct {
	TBSRequest tbsRequest
}

type tbsRequest struct {
	RequestList []singleRequest
}

type singleRequest struct {
	Cert certID
}

// Request writes the question a client asks a responder about leaf: its issuer
// name hash, issuer key hash and serial number, in DER.
//
// Hashed with SHA-1, because that is the CertID every responder in use answers
// for and the one Check reads back. The identifier names a certificate; it
// protects nothing, so the weakness of the hash is not the weakness of anything.
//
// This builds a question and sends none. Whether a question is sent at all is
// the caller's decision, and in this project it is made by an operator on the
// command line (R3a).
func Request(leaf, issuer *x509.Certificate) ([]byte, error) {
	switch {
	case leaf == nil:
		return nil, errors.New("ocsp: no certificate to ask about")
	case issuer == nil:
		return nil, ErrNoIssuer
	case leaf.SerialNumber == nil:
		return nil, errors.New("ocsp: the certificate carries no serial number to ask about")
	}

	key, err := publicKeyBytes(issuer)
	if err != nil {
		return nil, err
	}

	nameHash := sha1.Sum(issuer.RawSubject) // #nosec G401 -- identifies, as RFC 6960 specifies
	keyHash := sha1.Sum(key)                // #nosec G401 -- identifies, as RFC 6960 specifies

	return asn1.Marshal(ocspRequest{TBSRequest: tbsRequest{RequestList: []singleRequest{{
		Cert: certID{
			HashAlgorithm:  pkix.AlgorithmIdentifier{Algorithm: oidSHA1, Parameters: asn1.NullRawValue},
			IssuerNameHash: nameHash[:],
			IssuerKeyHash:  keyHash[:],
			SerialNumber:   leaf.SerialNumber,
		},
	}}}})
}
