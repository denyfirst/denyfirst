package mailscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"testing"
	"time"

	danecheck "github.com/denyfirst/denyfirst/internal/dane"
	"github.com/denyfirst/denyfirst/internal/dnsclient"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/smtptls"
)

// selfSigned is a certificate an exchanger could present.
func selfSigned(t *testing.T, host string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(25), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

// endEntity is the "3 1 1" record for a certificate.
func endEntity(c *x509.Certificate) dnsclient.TLSA {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return dnsclient.TLSA{Usage: 3, Selector: 1, Matching: 1, Data: sum[:]}
}

// presenting is an exchanger that negotiated TLS and presented the certificate.
func presenting(host string, cert *x509.Certificate) smtptls.Result {
	return smtptls.Result{Host: host, Connected: true, Measured: true, Offered: true, Upgraded: true,
		Version: "TLS 1.3", Suite: "TLS_AES_128_GCM_SHA256", Chain: []*x509.Certificate{cert}}
}

func bindingsByHost(bindings []policy.DANEBinding) map[string]policy.DANEBinding {
	out := map[string]policy.DANEBinding{}
	for _, b := range bindings {
		out[b.Host] = b
	}
	return out
}

// Each exchanger's DANE records are checked against the certificate that
// exchanger presented — its own records against its own certificate.
func TestADANERecordIsCheckedAgainstWhatItsExchangerPresented(t *testing.T) {
	skipUnderDemo(t)
	one, two := selfSigned(t, "mx1.example.net"), selfSigned(t, "mx2.example.net")

	z := stsZone("mx1.example.net", "mx2.example.net")
	z.dane = map[string][]dnsclient.TLSA{
		"_25._tcp.mx1.example.net": {endEntity(one)},
		"_25._tcp.mx2.example.net": {endEntity(one)}, // mx2 publishes mx1's key
	}
	z.validated = map[string]bool{"_25._tcp.mx1.example.net": true, "_25._tcp.mx2.example.net": true}
	x := &fixedExchangers{answer: func(host string) smtptls.Result {
		if host == "mx1.example.net" {
			return presenting(host, one)
		}
		return presenting(host, two)
	}}

	got, err := (&Scanner{Resolver: z, ReadExchangers: true, Exchangers: x}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	b := bindingsByHost(got.Observed.DANEBindings)
	if b["mx1.example.net"].Outcome != policy.DANEMatched || !b["mx1.example.net"].Validated {
		t.Errorf("mx1: %+v; its record binds the key it presented", b["mx1.example.net"])
	}
	if b["mx2.example.net"].Outcome != policy.DANEMismatched || b["mx2.example.net"].Usable != 1 {
		t.Errorf("mx2: %+v; its record binds another exchanger's key", b["mx2.example.net"])
	}
	if !slices.Contains(findingIDs(got), "mail.dane-exchanger-fails-binding") {
		t.Errorf("findings are %v; a validated binding that does not hold is one RFC 7672 has senders act on", findingIDs(got))
	}
}

// Before a certificate, each state is said as itself.
func TestTheStatesBeforeACertificateAreSaidAsThemselves(t *testing.T) {
	skipUnderDemo(t)
	cert := selfSigned(t, "mx.example.net")

	for name, tc := range map[string]struct {
		answer  smtptls.Result
		records []dnsclient.TLSA
		want    string
	}{
		"not reached": {smtptls.Result{Host: "mx.example.net", Reason: "a reason"},
			[]dnsclient.TLSA{endEntity(cert)}, policy.DANENotChecked},
		"not negotiated": {smtptls.Result{Host: "mx.example.net", Connected: true, Measured: true, Offered: true, Reason: "a reason"},
			[]dnsclient.TLSA{endEntity(cert)}, policy.DANENotChecked},
		"no STARTTLS": {smtptls.Result{Host: "mx.example.net", Connected: true, Measured: true},
			[]dnsclient.TLSA{endEntity(cert)}, policy.DANENoSTARTTLS},
		"only records no sender uses": {presenting("mx.example.net", cert),
			[]dnsclient.TLSA{{Usage: 1, Selector: 1, Matching: 1, Data: endEntity(cert).Data}}, policy.DANENoUsableRecords},
	} {
		z := stsZone("mx.example.net")
		z.dane = map[string][]dnsclient.TLSA{"_25._tcp.mx.example.net": tc.records}
		x := &fixedExchangers{answer: func(string) smtptls.Result { return tc.answer }}

		got, err := (&Scanner{Resolver: z, ReadExchangers: true, Exchangers: x}).Scan(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("%s: Scan: %v", name, err)
		}
		if len(got.Observed.DANEBindings) != 1 || got.Observed.DANEBindings[0].Outcome != tc.want {
			t.Errorf("%s: bindings are %+v, want one saying %s", name, got.Observed.DANEBindings, tc.want)
			continue
		}
		// The count is the checker's, not a count of records with data in
		// them. A sabotage counting those escaped on 2026-09-14: the outcome
		// was still right, and the report said a record no sender uses was
		// one they do.
		wantUsable := 1
		if tc.want == policy.DANENoUsableRecords {
			wantUsable = 0
		}
		if b := got.Observed.DANEBindings[0]; b.Usable != wantUsable {
			t.Errorf("%s: %d usable records, want %d", name, b.Usable, wantUsable)
		}
	}
}

// Nothing is said about a binding where no certificate could have been seen, or
// where there is no binding.
func TestNoBindingIsClaimedWhereNothingWasChecked(t *testing.T) {
	skipUnderDemo(t)
	cert := selfSigned(t, "mx1.example.net")

	z := stsZone("mx1.example.net", "mx2.example.net")
	z.dane = map[string][]dnsclient.TLSA{"_25._tcp.mx1.example.net": {endEntity(cert)}}
	x := &fixedExchangers{answer: func(host string) smtptls.Result { return presenting(host, cert) }}

	notContacted, err := (&Scanner{Resolver: z, Exchangers: x}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(notContacted.Observed.DANEBindings) != 0 {
		t.Errorf("bindings %+v from a scan that contacted no exchanger", notContacted.Observed.DANEBindings)
	}

	contacted, err := (&Scanner{Resolver: z, ReadExchangers: true, Exchangers: x}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if b := contacted.Observed.DANEBindings; len(b) != 1 || b[0].Host != "mx1.example.net" {
		t.Errorf("bindings %+v; only mx1 publishes DANE", b)
	}
}

// The policy's outcome words are the dane package's, since one is written into
// the other as a string.
func TestTheReportsDANEWordsAreTheCheckersWords(t *testing.T) {
	for dane, report := range map[danecheck.Outcome]string{
		danecheck.Matched:         policy.DANEMatched,
		danecheck.Mismatched:      policy.DANEMismatched,
		danecheck.NoUsableRecords: policy.DANENoUsableRecords,
		danecheck.Undetermined:    policy.DANEUndetermined,
	} {
		if string(dane) != report {
			t.Errorf("the checker says %q where the report says %q", dane, report)
		}
	}
}
