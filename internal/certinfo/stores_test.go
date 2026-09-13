package certinfo

import (
	"crypto/x509"
	"os"
	"strings"
	"testing"
)

// Analyse names what each of the four stores makes of a chain.
//
// The deployment's own pool is empty here on purpose: the verdict rests on that
// pool and says untrusted, while the stores — a separate question — all include
// the root denyfirst.dev's chain reaches. A report conflating the two would show
// one of those answers twice.
func TestAnalyseNamesWhatEachStoreMakesOfTheChain(t *testing.T) {
	var chain []*x509.Certificate
	for _, name := range []string{"denyfirst.dev.der", "YE2.der", "RootYE.der", "ISRGRootX2-cross.der"} {
		der, err := os.ReadFile("../rootstores/testdata/" + name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		chain = append(chain, cert)
	}
	leaf := chain[0]
	at := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)

	report, err := Analyse(chain, "denyfirst.dev", at, x509.NewCertPool())
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if report.Trusted {
		t.Error("an empty deployment pool reported the chain trusted; the stores leaked into the verdict")
	}
	if report.Stores == nil || len(report.Stores.Stores) != 4 {
		t.Fatalf("stores = %+v; want what all four made of the chain", report.Stores)
	}
	for _, s := range report.Stores.Stores {
		if s.Verdict != "trusted" {
			t.Errorf("%s says %s for denyfirst.dev's chain", s.Store, s.Verdict)
		}
	}
	if !strings.HasPrefix(report.StoresLine, "trusted by Mozilla, Chrome, Microsoft and Apple") {
		t.Errorf("the stores line reads %q", report.StoresLine)
	}
}

// An expired certificate is judged at the middle of its validity, not today.
//
// Every store refuses an expired certificate on its dates, and whether the stores
// include its root is a separate question with a separate answer (R4b). Judged
// "now", a chain whose certificate lapsed would read as not trusted by all four —
// four findings about the stores for one fact about a date.
func TestAnExpiredChainIsJudgedWithinItsValidity(t *testing.T) {
	var chain []*x509.Certificate
	for _, name := range []string{"denyfirst.dev.der", "YE2.der", "RootYE.der", "ISRGRootX2-cross.der"} {
		der, err := os.ReadFile("../rootstores/testdata/" + name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		chain = append(chain, cert)
	}
	later := chain[0].NotAfter.AddDate(3, 0, 0)

	facts := judgeStores(chain, later)
	if len(facts.Stores) != 4 {
		t.Fatalf("stores = %+v", facts)
	}
	for _, s := range facts.Stores {
		if s.Verdict != "trusted" {
			t.Errorf("%s says %s for a chain judged three years after it expired; the stores still include its root",
				s.Store, s.Verdict)
		}
	}
}
