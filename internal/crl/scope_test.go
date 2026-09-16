package crl

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// listWith builds a list signed by the authority carrying the extensions given.
func listWith(t *testing.T, by authority, exts ...pkix.Extension) []byte {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:          big.NewInt(2),
		ThisUpdate:      refNow.Add(-time.Hour),
		NextUpdate:      refNow.Add(time.Hour),
		ExtraExtensions: exts,
	}, by.cert, by.key)
	if err != nil {
		t.Fatalf("creating a list: %v", err)
	}
	return der
}

// idp builds an issuing distribution point extension.
func idp(t *testing.T, v issuingDistributionPoint) pkix.Extension {
	t.Helper()
	body, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling an issuing distribution point: %v", err)
	}
	return pkix.Extension{Id: oidIssuingPoint, Critical: true, Value: body}
}

// fullName is the explicit [0] DistributionPointName holding fullName URIs.
func fullName(t *testing.T, uris ...string) asn1.RawValue {
	t.Helper()
	var names []byte
	for _, u := range uris {
		b, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(u)})
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, b...)
	}
	inner, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: names})
	if err != nil {
		t.Fatal(err)
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}
}

// A list is read as an answer about this certificate only when it covers it.
//
// Every case is a list the issuer really signed, inside its dates, that does not
// name serial 42. Before the 2026-09-16 audit (A09) each answered "good".
func TestAListThatDoesNotCoverTheCertificateIsNotAnAnswer(t *testing.T) {
	const point = "http://lists.example/one.crl"
	for name, exts := range map[string]func(*testing.T) []pkix.Extension{
		"a delta list": func(t *testing.T) []pkix.Extension {
			v, _ := asn1.Marshal(1)
			return []pkix.Extension{{Id: oidDeltaCRLIndicator, Critical: true, Value: v}}
		},
		"a delta list marked non-critical": func(t *testing.T) []pkix.Extension {
			v, _ := asn1.Marshal(1)
			return []pkix.Extension{{Id: oidDeltaCRLIndicator, Value: v}}
		},
		"an unknown critical extension": func(t *testing.T) []pkix.Extension {
			return []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{5, 0}}}
		},
		"authority certificates only": func(t *testing.T) []pkix.Extension {
			return []pkix.Extension{idp(t, issuingDistributionPoint{OnlyContainsCACerts: true})}
		},
		"attribute certificates only": func(t *testing.T) []pkix.Extension {
			return []pkix.Extension{idp(t, issuingDistributionPoint{OnlyContainsAttributeCerts: true})}
		},
		"some reasons only": func(t *testing.T) []pkix.Extension {
			return []pkix.Extension{idp(t, issuingDistributionPoint{OnlySomeReasons: asn1.BitString{Bytes: []byte{0x40}, BitLength: 2}})}
		},
		"an indirect list": func(t *testing.T) []pkix.Extension {
			return []pkix.Extension{idp(t, issuingDistributionPoint{IndirectCRL: true})}
		},
		"another distribution point": func(t *testing.T) []pkix.Extension {
			return []pkix.Extension{idp(t, issuingDistributionPoint{DistributionPoint: fullName(t, "http://lists.example/other.crl")})}
		},
		"an unreadable issuing distribution point": func(t *testing.T) []pkix.Extension {
			return []pkix.Extension{{Id: oidIssuingPoint, Critical: true, Value: []byte{0x30, 0x03, 0xff}}}
		},
	} {
		ca := newAuthority(t, "Scope CA")
		f, _ := serving(t, listWith(t, ca, exts(t)...), http.StatusOK)
		leaf := newLeaf(t, ca, big.NewInt(42), point)
		got := f.Check(context.Background(), leaf, ca.cert, refNow)
		if got.Status != Unknown {
			t.Errorf("%s: status %s; a list that does not cover this certificate says nothing about it", name, got.Status)
		}
		if got.Reason == "" {
			t.Errorf("%s: no reason is given", name)
		}
	}
}

// The lists real authorities publish still answer.
//
// Let's Encrypt marks every list with a critical issuing distribution point
// naming the list's own address and user certificates only. Refusing that shape
// would leave most of the web unchecked, which is its own wrong answer.
func TestAListScopedToThisCertificateStillAnswers(t *testing.T) {
	const point = "http://lists.example/one.crl"
	for name, exts := range map[string]func(*testing.T) []pkix.Extension{
		"no scope at all": func(*testing.T) []pkix.Extension { return nil },
		"the Let's Encrypt shape": func(t *testing.T) []pkix.Extension {
			return []pkix.Extension{idp(t, issuingDistributionPoint{
				DistributionPoint: fullName(t, point), OnlyContainsUserCerts: true,
			})}
		},
		"one of several addresses": func(t *testing.T) []pkix.Extension {
			return []pkix.Extension{idp(t, issuingDistributionPoint{
				DistributionPoint: fullName(t, "http://mirror.example/one.crl", point),
			})}
		},
		"an unknown extension that is not critical": func(*testing.T) []pkix.Extension {
			return []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}, Value: []byte{5, 0}}}
		},
		"a pointer to a delta list": func(*testing.T) []pkix.Extension {
			return []pkix.Extension{{Id: oidFreshestCRL, Value: []byte{0x30, 0x00}}}
		},
	} {
		ca := newAuthority(t, "Scope CA")
		f, _ := serving(t, listWith(t, ca, exts(t)...), http.StatusOK)
		leaf := newLeaf(t, ca, big.NewInt(42), point)
		if got := f.Check(context.Background(), leaf, ca.cert, refNow); got.Status != Good {
			t.Errorf("%s: status %s (%s); a list covering this certificate and not naming it says good", name, got.Status, got.Reason)
		}
	}
}

// The issuing distribution point Let's Encrypt put on http://ye2.c.lencr.org/72.crl,
// byte for byte as fetched on 2026-09-16: critical, the list's own address, and
// user certificates only. Read by this parser, it answers for a certificate that
// names that address and for no other.
func TestARealIssuingDistributionPointIsRead(t *testing.T) {
	real := []byte{
		0x30, 0x26, 0xa0, 0x21, 0xa0, 0x1f, 0x86, 0x1d,
		'h', 't', 't', 'p', ':', '/', '/', 'y', 'e', '2', '.', 'c', '.', 'l', 'e', 'n', 'c', 'r', '.',
		'o', 'r', 'g', '/', '7', '2', '.', 'c', 'r', 'l',
		0x81, 0x01, 0xff,
	}
	named := &x509.Certificate{CRLDistributionPoints: []string{"http://ye2.c.lencr.org/72.crl"}}
	other := &x509.Certificate{CRLDistributionPoints: []string{"http://ye2.c.lencr.org/73.crl"}}

	if reason := issuingPointReason(real, named); reason != "" {
		t.Errorf("Let's Encrypt's own list does not answer for a certificate naming it: %s", reason)
	}
	if reason := issuingPointReason(real, other); reason == "" {
		t.Error("Let's Encrypt's list for 72.crl answers for a certificate naming 73.crl")
	}
}
