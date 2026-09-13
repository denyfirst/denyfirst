package scan

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/denyfirst/denyfirst/internal/certinfo"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

func ctFixture(t *testing.T) (leaf, issuer *x509.Certificate) {
	t.Helper()
	read := func(name string) *x509.Certificate {
		der, err := os.ReadFile("../ctlogs/testdata/" + name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		return cert
	}
	return read("denyfirst.dev.der"), read("YE2.der")
}

// A real certificate's receipts are checked, through the path a scan takes.
//
// internal/ctlogs proves the check is right. This proves the scan makes it: the
// chain the server sent is handed over, the issuer is found in it, and the list's
// date reaches the facts a report is written from.
func TestAScanChecksTheReceiptsItCounts(t *testing.T) {
	leaf, issuer := ctFixture(t)

	f := policy.TransparencyFacts{Embedded: 2, FromLogs: 2, Trusted: true}
	checkReceipts(&f, &tlsprobe.Report{Certificates: []*x509.Certificate{leaf, issuer}})

	if !f.Checked || f.Verified != 2 {
		t.Fatalf("checked=%v verified=%d; denyfirst.dev's two receipts verify", f.Checked, f.Verified)
	}
	if f.ListDate == "" || f.ListVersion == "" {
		t.Errorf("date %q, version %q; the report cannot say which list it used", f.ListDate, f.ListVersion)
	}
	if !allReceiptsVerified(f) {
		t.Error("every receipt verified and the scan does not say so")
	}
}

// A chain without the issuer checks nothing, and does not claim to have.
func TestAChainWithoutItsIssuerVerifiesNothing(t *testing.T) {
	leaf, _ := ctFixture(t)

	f := policy.TransparencyFacts{Embedded: 2, FromLogs: 2, Trusted: true}
	checkReceipts(&f, &tlsprobe.Report{Certificates: []*x509.Certificate{leaf}})

	if f.Verified != 0 || f.Unreadable != 2 {
		t.Errorf("verified=%d unreadable=%d; without the issuer neither receipt can be checked", f.Verified, f.Unreadable)
	}
	if allReceiptsVerified(f) {
		t.Error("receipts nobody could check are reported as all verified")
	}
}

// Nothing to check, nothing claimed.
func TestNoCertificateMeansNothingChecked(t *testing.T) {
	var f policy.TransparencyFacts
	checkReceipts(&f, &tlsprobe.Report{})
	if f.Checked || allReceiptsVerified(f) {
		t.Errorf("a scan with no certificate claims to have checked receipts: %+v", f)
	}
}

// A receipt that arrived in the handshake is checked as well as the embedded ones,
// and two of three verified is not all of them.
//
// Every certificate in the fixture carries its receipts embedded, so without a
// handshake receipt here a scan that never checked that route, or one that called
// two of three "all verified", would pass the tests above.
func TestAHandshakeReceiptIsCheckedToo(t *testing.T) {
	leaf, issuer := ctFixture(t)

	f := policy.TransparencyFacts{Embedded: 2, InHandshake: 1, FromLogs: 2, Trusted: true}
	checkReceipts(&f, &tlsprobe.Report{
		Certificates: []*x509.Certificate{leaf, issuer},
		SCTs:         [][]byte{{0}},
	})

	if f.Verified != 2 || f.Unreadable != 1 {
		t.Errorf("verified=%d unreadable=%d; want the two embedded receipts verified and the unreadable handshake one counted",
			f.Verified, f.Unreadable)
	}
	if allReceiptsVerified(f) {
		t.Error("two of three receipts verified and the scan says all of them were")
	}
}

// The join a scan makes checks the receipts, and says when all of them verified.
//
// This is the function Scan calls. Testing checkReceipts alone left a scan that
// never called it indistinguishable from one that did.
func TestTheTransparencyJoinChecksTheReceipts(t *testing.T) {
	leaf, issuer := ctFixture(t)
	cert := &certinfo.Report{
		Trusted:      true,
		Transparency: certinfo.Transparency{EmbeddedCount: 2, LogIDs: []string{"a", "b"}},
	}

	f, verified := transparencyFor(cert, &tlsprobe.Report{Certificates: []*x509.Certificate{leaf, issuer}})
	if f.Embedded != 2 || f.FromLogs != 2 || !f.Trusted {
		t.Errorf("the join lost what the certificate carried: %+v", f)
	}
	if !f.Checked || f.Verified != 2 || !verified {
		t.Errorf("checked=%v verified=%d all=%v; the join did not check the receipts", f.Checked, f.Verified, verified)
	}
}
