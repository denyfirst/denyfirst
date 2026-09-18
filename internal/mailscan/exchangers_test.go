package mailscan

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/smtptls"
)

// fixedExchangers stands in for the exchangers, and records which were asked.
type fixedExchangers struct {
	mu     sync.Mutex
	asked  []string
	answer func(host string) smtptls.Result
}

func (f *fixedExchangers) Probe(_ context.Context, host string) smtptls.Result {
	f.mu.Lock()
	f.asked = append(f.asked, host)
	f.mu.Unlock()
	if f.answer == nil {
		return smtptls.Result{Host: host, Connected: true, Measured: true}
	}
	return f.answer(host)
}

func (f *fixedExchangers) hosts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string(nil), f.asked...)
	slices.Sort(out)
	return out
}

// Nothing is contacted by a deployment that does not contact mail servers, and
// the report says so.
func TestExchangersAreAskedOnlyWhereTheDeploymentAllows(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net")
	x := &fixedExchangers{}

	got, err := (&Scanner{Resolver: z, Exchangers: x}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if asked := x.hosts(); len(asked) != 0 {
		t.Errorf("exchangers %v were contacted by a deployment that does not contact them", asked)
	}
	if got.Observed.ExchangersContacted || got.Observed.ExchangersReason == "" {
		t.Errorf("contacted=%v reason=%q; want not contacted, and why", got.Observed.ExchangersContacted,
			got.Observed.ExchangersReason)
	}
}

// Only the exchangers the domain's own MX records name are asked.
func TestOnlyTheExchangersTheDomainNamesAreAsked(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net", "mx2.example.net")
	x := &fixedExchangers{}

	if _, err := (&Scanner{Resolver: z, ReadExchangers: true, Exchangers: x}).Scan(context.Background(), "example.com"); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if asked := x.hosts(); !slices.Equal(asked, []string{"mx1.example.net", "mx2.example.net"}) {
		t.Errorf("asked %v; want exactly the two exchangers the domain publishes", asked)
	}
}

// A domain stating it takes no mail has no exchanger to ask.
func TestANullMXIsNeverContacted(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone()
	z.exchangers = map[string][]dnsclient.MX{"example.com": {{Preference: 0, Host: "."}}}
	x := &fixedExchangers{}

	if _, err := (&Scanner{Resolver: z, ReadExchangers: true, Exchangers: x}).Scan(context.Background(), "example.com"); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if asked := x.hosts(); len(asked) != 0 {
		t.Errorf("asked %v of a domain whose null MX says it takes no mail", asked)
	}
}

// The list is bounded, because it is written by whoever is being measured, and
// the report says it was.
func TestTheExchangersAskedAreBounded(t *testing.T) {
	skipUnderDemo(t)
	var hosts []string
	for i := range 12 {
		hosts = append(hosts, fmt.Sprintf("mx%02d.example.net", i))
	}
	z := stsZone(hosts...)
	x := &fixedExchangers{}

	got, err := (&Scanner{Resolver: z, ReadExchangers: true, Exchangers: x}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if asked := x.hosts(); len(asked) != maxExchangers {
		t.Errorf("%d exchangers were asked; the bound is %d", len(asked), maxExchangers)
	}
	if !got.Observed.ExchangersPartial {
		t.Error("the report does not say the list was cut short")
	}
}

// What an exchanger answered reaches the report whole.
func TestWhatAnExchangerAnsweredReachesTheReport(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net")
	want := smtptls.Result{
		Host: "mx1.example.net", Connected: true, Measured: true, Offered: true, Upgraded: true,
		Version: "TLS 1.2", Suite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		Trusted: false, NameMatches: true, CertificateReason: "it is outside its validity period",
		Reason: "a reason", ConnectTimedOut: true,
	}
	x := &fixedExchangers{answer: func(string) smtptls.Result { return want }}

	got, err := (&Scanner{Resolver: z, ReadExchangers: true, Exchangers: x}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !got.Observed.ExchangersContacted || len(got.Observed.Exchangers) != 1 {
		t.Fatalf("exchangers = %+v", got.Observed.Exchangers)
	}
	e := got.Observed.Exchangers[0]
	if e.Host != want.Host || e.Connected != want.Connected || e.Measured != want.Measured ||
		e.Offered != want.Offered || e.Upgraded != want.Upgraded || e.Version != want.Version ||
		e.Suite != want.Suite || e.Trusted != want.Trusted || e.NameMatches != want.NameMatches ||
		e.CertificateReason != want.CertificateReason || e.Reason != want.Reason ||
		e.ConnectTimedOut != want.ConnectTimedOut {
		t.Errorf("the report carries %+v; the exchanger answered %+v", e, want)
	}
}

// An enforcing policy and an exchanger that cannot keep it, through the whole
// scan.
func TestAnEnforcingPolicyAndAFailingExchangerAreGradedTogether(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net")
	sts := &fixedPolicy{policy: enforcing("mx1.example.net")}
	x := &fixedExchangers{answer: func(host string) smtptls.Result {
		return smtptls.Result{Host: host, Connected: true, Measured: true, Offered: false}
	}}

	got, err := (&Scanner{Resolver: z, ReadSTSPolicy: true, STS: sts, ReadExchangers: true, Exchangers: x}).
		Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if ids := findingIDs(got); !slices.Contains(ids, "mail.mta-sts-exchanger-fails-policy") {
		t.Errorf("findings are %v; an enforcing policy covering an exchanger without STARTTLS is not among them", ids)
	}
}

// The default prober carries the trust store and the EHLO name.
//
// Every test above supplies its own prober, so without this one a scanner that
// quietly stopped handing either to the real conversation would pass all of
// them — and the name is the one an operator set with -helo.
func TestTheDefaultExchangerProberCarriesTheStoreAndTheName(t *testing.T) {
	roots := x509.NewCertPool()
	p, ok := (&Scanner{Roots: roots, HeloName: "mail.example.test"}).exchangerProber().(*smtptls.Prober)
	if !ok {
		t.Fatal("the default prober is not internal/smtptls")
	}
	if p.Roots != roots {
		t.Error("the trust store did not reach the exchangers")
	}
	if p.HeloName != "mail.example.test" {
		t.Errorf("HeloName = %q; the operator's name did not reach the exchangers", p.HeloName)
	}
}
