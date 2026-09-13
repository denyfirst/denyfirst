package ctlogs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// Status is what checking one receipt established.
type Status string

const (
	// Verified: the log named in the receipt signed this certificate, with
	// the key the list gives it.
	Verified Status = "verified"

	// BadSignature: the log is in the list and its key does not verify the
	// receipt. The receipt does not vouch for this certificate.
	BadSignature Status = "bad-signature"

	// UnknownLog: the list does not name the log, so there is no key to check
	// against. Not a false receipt — a log newer than the list, or one a
	// different browser trusts, looks exactly like this.
	UnknownLog Status = "unknown-log"

	// Unsupported: signed with an algorithm RFC 6962 does not allow.
	Unsupported Status = "unsupported-algorithm"

	// Unreadable: the receipt, or what it has to be checked against, could not
	// be read.
	Unreadable Status = "unreadable"
)

// Receipt is one timestamp, checked.
type Receipt struct {
	LogID  string // hex
	Log    string // the list's description of the log, when it names one
	State  string // the list's state for the log, when it names one
	Status Status
}

// sctListOID is the extension carrying embedded receipts (RFC 6962 §3.3).
var sctListOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// poisonOID marks a precertificate (RFC 6962 §3.1). Removed with the list, for
// the same reason: the log signed the certificate without either.
var poisonOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

const (
	entryX509    = 0
	entryPrecert = 1

	hashSHA256 = 4
	sigRSA     = 1
	sigECDSA   = 3

	logIDLen = 32

	// minSCT is version, log id, timestamp, extension length, hash and
	// signature algorithm, and signature length.
	minSCT = 1 + logIDLen + 8 + 2 + 2 + 2
)

var errMalformed = errors.New("ctlogs: a receipt is malformed")

// CheckEmbedded checks the receipts carried inside a certificate.
//
// The issuer is needed, because a log signs a precertificate and names the key
// of the authority that will issue it. Without the issuer every receipt is
// Unreadable rather than guessed at.
func CheckEmbedded(list *List, leaf, issuer *x509.Certificate) []Receipt {
	raw, found := embeddedList(leaf)
	if !found {
		return nil
	}
	scts, err := splitList(raw)
	if err != nil {
		return []Receipt{{Status: Unreadable}}
	}

	var tbs []byte
	var issuerHash [32]byte
	ready := issuer != nil
	if ready {
		issuerHash = sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
		if tbs, err = precertificateTBS(leaf.RawTBSCertificate); err != nil {
			ready = false
		}
	}

	out := make([]Receipt, 0, len(scts))
	for _, sct := range scts {
		out = append(out, check(list, sct, func(signed []byte) ([]byte, bool) {
			if !ready {
				return nil, false
			}
			d := binary.BigEndian.AppendUint16(signed, entryPrecert)
			d = append(d, issuerHash[:]...)
			return appendOpaque24(d, tbs), true
		}))
	}
	return out
}

// CheckHandshake checks receipts that arrived in the TLS extension. Those sign
// the certificate itself, as sent.
func CheckHandshake(list *List, scts [][]byte, leaf *x509.Certificate) []Receipt {
	out := make([]Receipt, 0, len(scts))
	for _, sct := range scts {
		out = append(out, check(list, sct, func(signed []byte) ([]byte, bool) {
			if leaf == nil {
				return nil, false
			}
			d := binary.BigEndian.AppendUint16(signed, entryX509)
			return appendOpaque24(d, leaf.Raw), true
		}))
	}
	return out
}

// check reads one serialized receipt and verifies it.
//
// entry appends the signed entry — which differs between an embedded and a
// handshake receipt — to the fields every receipt signs.
func check(list *List, sct []byte, entry func(signed []byte) ([]byte, bool)) Receipt {
	p, err := parseSCT(sct)
	if err != nil {
		return Receipt{Status: Unreadable}
	}

	r := Receipt{LogID: hex.EncodeToString(p.logID[:])}
	log, known := list.Log(p.logID)
	if !known {
		r.Status = UnknownLog
		return r
	}
	r.Log, r.State = log.Description, log.State

	if p.hashAlg != hashSHA256 {
		r.Status = Unsupported
		return r
	}

	// RFC 6962 §3.2: version, signature_type certificate_timestamp, timestamp,
	// the entry, and the receipt's extensions.
	signed := []byte{0, 0}
	signed = append(signed, p.timestamp[:]...)
	signed, ok := entry(signed)
	if !ok {
		r.Status = Unreadable
		return r
	}
	signed = binary.BigEndian.AppendUint16(signed, uint16(len(p.extensions))) // #nosec G115 -- bounded by parseSCT
	signed = append(signed, p.extensions...)
	digest := sha256.Sum256(signed)

	switch key := log.Key.(type) {
	case *ecdsa.PublicKey:
		if p.sigAlg != sigECDSA {
			r.Status = Unsupported
			return r
		}
		if ecdsa.VerifyASN1(key, digest[:], p.signature) {
			r.Status = Verified
		} else {
			r.Status = BadSignature
		}
	case *rsa.PublicKey:
		if p.sigAlg != sigRSA {
			r.Status = Unsupported
			return r
		}
		if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], p.signature) == nil {
			r.Status = Verified
		} else {
			r.Status = BadSignature
		}
	default:
		r.Status = Unsupported
	}
	return r
}

type sct struct {
	logID      [32]byte
	timestamp  [8]byte
	extensions []byte
	hashAlg    byte
	sigAlg     byte
	signature  []byte
}

// parseSCT reads a SerializedSCT. Every length is the scanned party's choice,
// so each is checked against what is left rather than believed.
func parseSCT(b []byte) (sct, error) {
	var s sct
	if len(b) < minSCT || b[0] != 0 {
		return s, errMalformed
	}
	copy(s.logID[:], b[1:1+logIDLen])
	copy(s.timestamp[:], b[1+logIDLen:1+logIDLen+8])
	b = b[1+logIDLen+8:]

	extLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if extLen > len(b) {
		return s, errMalformed
	}
	s.extensions, b = b[:extLen], b[extLen:]

	if len(b) < 4 {
		return s, errMalformed
	}
	s.hashAlg, s.sigAlg = b[0], b[1]
	sigLen := int(binary.BigEndian.Uint16(b[2:]))
	b = b[4:]
	if sigLen != len(b) {
		return s, errMalformed
	}
	s.signature = b
	return s, nil
}

// embeddedList returns the TLS-encoded list inside the certificate's extension.
func embeddedList(leaf *x509.Certificate) ([]byte, bool) {
	if leaf == nil {
		return nil, false
	}
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(sctListOID) {
			continue
		}
		var list []byte
		if rest, err := asn1.Unmarshal(ext.Value, &list); err != nil || len(rest) != 0 {
			return nil, true
		}
		return list, true
	}
	return nil, false
}

// splitList splits a SignedCertificateTimestampList into its receipts.
func splitList(list []byte) ([][]byte, error) {
	if len(list) < 2 || int(binary.BigEndian.Uint16(list)) != len(list)-2 {
		return nil, errMalformed
	}
	list = list[2:]

	var out [][]byte
	for len(list) > 0 {
		if len(list) < 2 {
			return nil, errMalformed
		}
		n := int(binary.BigEndian.Uint16(list))
		list = list[2:]
		if n < minSCT || n > len(list) {
			return nil, errMalformed
		}
		out = append(out, list[:n])
		list = list[n:]
	}
	return out, nil
}

// precertificateTBS rebuilds what a log signed for an embedded receipt: the
// certificate's TBSCertificate with the receipt list and the poison extension
// removed (RFC 6962 §3.2).
//
// Re-encoded with encoding/asn1 rather than edited in place: removing an
// extension changes the lengths of every enclosing structure, and asn1.Marshal
// of a RawValue recomputes a length from the bytes it wraps, which is the whole
// of what needs doing.
func precertificateTBS(raw []byte) ([]byte, error) {
	var tbs asn1.RawValue
	if rest, err := asn1.Unmarshal(raw, &tbs); err != nil || len(rest) != 0 {
		return nil, errMalformed
	}

	var fields []byte
	rest := tbs.Bytes
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			return nil, errMalformed
		}
		if field.Class != asn1.ClassContextSpecific || field.Tag != 3 {
			fields = append(fields, field.FullBytes...)
			continue
		}

		var extensions asn1.RawValue
		if tail, err := asn1.Unmarshal(field.Bytes, &extensions); err != nil || len(tail) != 0 {
			return nil, errMalformed
		}
		var kept []byte
		extRest := extensions.Bytes
		for len(extRest) > 0 {
			var ext asn1.RawValue
			if extRest, err = asn1.Unmarshal(extRest, &ext); err != nil {
				return nil, errMalformed
			}
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(ext.Bytes, &oid); err != nil {
				return nil, errMalformed
			}
			if oid.Equal(sctListOID) || oid.Equal(poisonOID) {
				continue
			}
			kept = append(kept, ext.FullBytes...)
		}

		sequence, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: kept})
		if err != nil {
			return nil, errMalformed
		}
		wrapped, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, IsCompound: true, Bytes: sequence})
		if err != nil {
			return nil, errMalformed
		}
		fields = append(fields, wrapped...)
	}

	out, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: fields})
	if err != nil {
		return nil, errMalformed
	}
	return out, nil
}

// appendOpaque24 appends a value behind a three-byte length.
func appendOpaque24(dst, value []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(value))) // #nosec G115 -- a certificate is far below 2^24 bytes; x509 has parsed it
	return append(append(dst, n[1:]...), value...)
}
