package crl

import (
	"crypto/x509"
	"encoding/asn1"
)

// What a list says about which certificates it covers.
//
// A list verified against the issuer and inside its own dates can still answer
// nothing about this certificate, because a list can say it covers only part of
// what the issuer signed. Absence from such a list is not "not revoked": it is
// silence about a certificate the list never claimed to describe. Until the
// 2026-09-16 audit (A09) this package read every verified list as complete, and
// a signed delta list — which lists only what changed since its base — answered
// "good" on its own.
//
// RFC 5280 §5.2 and §6.3.3 are the source. Only what can be decided exactly is
// accepted; anything else is unknown, which reaches a report as "not checked".

var (
	oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingPoint      = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidFreshestCRL       = asn1.ObjectIdentifier{2, 5, 29, 46}

	// understood are the list extensions crypto/x509 reads, or that say
	// nothing about coverage and may be marked critical by a careful issuer.
	understood = map[string]bool{
		"2.5.29.20":         true, // CRL number
		"2.5.29.35":         true, // authority key identifier
		"2.5.29.18":         true, // issuer alternative name
		"1.3.6.1.5.5.7.1.1": true, // authority information access
	}
)

// issuingDistributionPoint is RFC 5280 §5.2.5, IMPLICIT tags throughout.
type issuingDistributionPoint struct {
	DistributionPoint          asn1.RawValue  `asn1:"optional,tag:0"`
	OnlyContainsUserCerts      bool           `asn1:"optional,tag:1"`
	OnlyContainsCACerts        bool           `asn1:"optional,tag:2"`
	OnlySomeReasons            asn1.BitString `asn1:"optional,tag:3"`
	IndirectCRL                bool           `asn1:"optional,tag:4"`
	OnlyContainsAttributeCerts bool           `asn1:"optional,tag:5"`
}

// scopeReason says why a list does not answer for this certificate, or returns
// empty when it does.
//
// A list naming a distribution point must name one the certificate names, or
// it is a list about somebody else's certificates that carries the same
// issuer.
func scopeReason(list *x509.RevocationList, leaf *x509.Certificate) string {
	for _, ext := range list.Extensions {
		switch {
		case ext.Id.Equal(oidDeltaCRLIndicator):
			// Critical by definition, and checked whatever the flag says: a
			// delta lists only what changed since its base, so a serial
			// missing from it says nothing.
			return "the revocation list is a delta list, which answers only together with its base list"

		case ext.Id.Equal(oidIssuingPoint):
			if reason := issuingPointReason(ext.Value, leaf); reason != "" {
				return reason
			}

		case ext.Id.Equal(oidFreshestCRL):
			// Points at a delta. Not followed; the full list still answers.

		case ext.Critical && !understood[ext.Id.String()]:
			return "the revocation list carries a critical extension this does not read, so what it covers is not known"
		}
	}
	return ""
}

func issuingPointReason(value []byte, leaf *x509.Certificate) string {
	const unreadable = "the revocation list says it covers only part of what its issuer signs, in a form this does not read"

	var idp issuingDistributionPoint
	rest, err := asn1.Unmarshal(value, &idp)
	if err != nil || len(rest) != 0 {
		return unreadable
	}

	switch {
	case idp.OnlyContainsCACerts || idp.OnlyContainsAttributeCerts:
		return "the revocation list covers only certificates of another kind than this one"
	case idp.OnlySomeReasons.BitLength > 0:
		return "the revocation list covers only some reasons for revocation, so a certificate missing from it may be revoked for another"
	case idp.IndirectCRL:
		return "the revocation list is an indirect list, whose entries this does not attribute"
	}

	if len(idp.DistributionPoint.FullBytes) == 0 {
		return ""
	}

	// DistributionPointName is a CHOICE, so its [0] tag is explicit: inside it
	// is fullName [0] GeneralNames, or nameRelativeToCRLIssuer [1].
	var choice asn1.RawValue
	if rest, err := asn1.Unmarshal(idp.DistributionPoint.Bytes, &choice); err != nil || len(rest) != 0 {
		return unreadable
	}
	if choice.Class != asn1.ClassContextSpecific || choice.Tag != 0 {
		return unreadable
	}

	names := choice.Bytes
	matched, sawURI := false, false
	for len(names) > 0 {
		var name asn1.RawValue
		rest, err := asn1.Unmarshal(names, &name)
		if err != nil {
			return unreadable
		}
		names = rest
		if name.Class != asn1.ClassContextSpecific || name.Tag != 6 {
			continue // not a URI
		}
		sawURI = true
		for _, point := range leaf.CRLDistributionPoints {
			if point == string(name.Bytes) {
				matched = true
			}
		}
	}
	if sawURI && !matched {
		return "the revocation list is for a distribution point this certificate does not name"
	}
	if !sawURI {
		return unreadable
	}
	return ""
}
