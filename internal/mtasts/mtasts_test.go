package mtasts

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/safedial"
)

// The domain every test here asks about, and the host a policy for it lives on.
const (
	testDomain = "example.test"
	policyHost = Host + testDomain
)

// A policy with everything in it, used wherever the contents are not the point.
const wholePolicy = "version: STSv1\n" +
	"mode: enforce\n" +
	"mx: mx1.example.test\n" +
	"mx: mx2.example.test\n" +
	"max_age: 604800\n"

// policyServer answers with one body and records what was asked for.
//
// The certificate names the policy host rather than the domain, because that is
// what RFC 8461 requires a sending server to verify and therefore what this has
// to be verifying. A fixture presenting a certificate for the domain would make
// every test below pass against a fetcher that checked the wrong name.
func policyServer(t *testing.T, body string, status int) (*Fetcher, *[]string) {
	t.Helper()

	var asked []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.Host+r.URL.Path)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))

	leaf := certificateFor(t, policyHost)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return fetcherFor(t, srv, leaf), &asked
}

// fetcherFor reaches a test server, which the default dialler refuses.
//
// The certificate is still verified — that is as much the property under test as
// anything else here — so the authority that signed it is handed over the way an
// internal estate hands a deployment its own.
func fetcherFor(t *testing.T, srv *httptest.Server, trust *tls.Certificate) *Fetcher {
	t.Helper()

	addr := strings.TrimPrefix(srv.URL, "https://")
	roots := x509.NewCertPool()
	if trust != nil {
		parsed, err := x509.ParseCertificate(trust.Certificate[0])
		if err != nil {
			t.Fatalf("parsing the fixture certificate: %v", err)
		}
		roots.AddCert(parsed)
	}

	return &Fetcher{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		Roots:   roots,
		Timeout: 5 * time.Second,
	}
}

// certificateFor mints a self-signed certificate naming one host.
func certificateFor(t *testing.T, name string) *tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{name},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// One host, one path, and both fixed by the specification.
//
// The reason fetching this is not the path-guessing N7 refuses is that there is
// nothing to guess: RFC 8461 names the host and the path, the domain published a
// DNS record saying a policy is there, and every sending server on the internet
// reads the same address. A second address would make it a check.
func TestTheOnlyAddressAskedForIsTheOneRFC8461Names(t *testing.T) {
	f, asked := policyServer(t, wholePolicy, http.StatusOK)

	if got := f.Fetch(context.Background(), testDomain); !got.Fetched {
		t.Fatalf("the policy was not read: %s", got.Reason)
	}

	if len(*asked) != 1 {
		t.Fatalf("%d requests were made, want exactly one: %v", len(*asked), *asked)
	}

	got := (*asked)[0]
	if !strings.HasPrefix(got, policyHost) {
		t.Errorf("the request went to %q, want the host beneath %q; a policy is served from "+
			"mta-sts.<domain> and nowhere else", got, Host)
	}
	if !strings.HasSuffix(got, Path) {
		t.Errorf("the request asked for %q, want the path ending %q", got, Path)
	}
}

// What the policy says, which is the whole reason this package exists.
func TestThePolicyIsRead(t *testing.T) {
	f, _ := policyServer(t, wholePolicy, http.StatusOK)

	got := f.Fetch(context.Background(), testDomain)
	if !got.Fetched {
		t.Fatalf("the policy was not read: %s", got.Reason)
	}
	if got.Mode != Enforce {
		t.Errorf("mode = %q, want %q", got.Mode, Enforce)
	}
	if got.MaxAge != 604800 {
		t.Errorf("max_age = %d, want 604800", got.MaxAge)
	}
	if len(got.MX) != 2 || got.MX[0] != "mx1.example.test" || got.MX[1] != "mx2.example.test" {
		t.Errorf("mx = %v, want both exchangers in the order the policy gave them", got.MX)
	}
}

// A mode this package does not recognise is no mode at all.
//
// The three RFC 8461 defines and nothing else. "enforcing" is not "enforce", and
// reading it as one would report protection from a policy no sending server
// applies — which is the direction a wrong guess must never fall in.
func TestOnlyTheThreeModesAreRead(t *testing.T) {
	for body, want := range map[string]Mode{
		"mode: enforce":   Enforce,
		"mode: ENFORCE":   Enforce,
		"mode:   testing": Testing,
		"mode: None":      None,
		"mode: enforcing": "",
		"mode: strict":    "",
		"mode:":           "",
	} {
		f, _ := policyServer(t, "version: STSv1\n"+body+"\nmx: mx1.example.test\n", http.StatusOK)

		got := f.Fetch(context.Background(), testDomain)
		if got.Mode != want {
			t.Errorf("%q gave mode %q, want %q", body, got.Mode, want)
		}
	}
}

// A key nobody here knows is skipped, and the rest of the policy still reads.
//
// RFC 8461 says a parser must ignore unrecognised keys so that the format can be
// extended. A parser that refused the whole file would report no policy on the
// day somebody adds a field.
func TestAnUnknownKeyDoesNotDiscardThePolicy(t *testing.T) {
	f, _ := policyServer(t, "version: STSv1\nsomething: else\nmode: testing\n"+
		"mx: mx1.example.test\nmax_age: 86400\n", http.StatusOK)

	got := f.Fetch(context.Background(), testDomain)
	if got.Mode != Testing || got.MaxAge != 86400 || len(got.MX) != 1 {
		t.Errorf("an unknown key cost the rest of the policy: %+v", got)
	}
}

// Nothing is followed.
//
// RFC 8461 §3.3 says a sending server must not follow a redirect when fetching a
// policy, and the reason is the one behind every other refusal here: a redirect
// is the host choosing where this looks next, and a policy is a file at one
// address. A host that answers with one has not served a policy.
func TestARedirectIsNotFollowed(t *testing.T) {
	var asked []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		if r.URL.Path == Path {
			http.Redirect(w, r, "/elsewhere.txt", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(wholePolicy))
	}))
	leaf := certificateFor(t, policyHost)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	got := fetcherFor(t, srv, leaf).Fetch(context.Background(), testDomain)
	if got.Fetched {
		t.Error("a redirect was followed and whatever it pointed at was read as the policy")
	}
	if len(asked) != 1 {
		t.Errorf("%d requests were made, want one: %v", len(asked), asked)
	}
}

// A status that is not 200 is not a policy.
func TestOnlyASuccessfulResponseIsAPolicy(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden,
		http.StatusInternalServerError, http.StatusNoContent} {
		f, _ := policyServer(t, wholePolicy, status)

		got := f.Fetch(context.Background(), testDomain)
		if got.Fetched {
			t.Errorf("status %d was read as a policy", status)
		}
		if got.Mode != "" {
			t.Errorf("status %d produced mode %q out of a body nobody should have parsed",
				status, got.Mode)
		}
	}
}

// What the host can make this carry is bounded.
func TestAnEnormousBodyIsBounded(t *testing.T) {
	// A valid policy, then more of the same key than anybody would serve.
	body := wholePolicy + strings.Repeat("mx: flood.example.test\n", 200000)

	f, _ := policyServer(t, body, http.StatusOK)

	got := f.Fetch(context.Background(), testDomain)
	if !got.Fetched {
		t.Fatalf("the policy was not read: %s", got.Reason)
	}
	if len(got.MX) > maxNames {
		t.Errorf("%d exchangers were kept, and the bound is %d; the scanned party decides how "+
			"long the report is", len(got.MX), maxNames)
	}
}

// A failed fetch is not a domain without a policy.
//
// The two send an operator to opposite places: one to whoever runs the policy
// host, one nowhere at all. A zero Policy with Fetched false is the only way a
// caller can tell, which is why Fetch returns no error to ignore.
func TestAFailedFetchIsNotAnAbsentPolicy(t *testing.T) {
	f := &Fetcher{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("nothing is listening on 203.0.113.9:443")
		},
		Timeout: time.Second,
	}

	got := f.Fetch(context.Background(), testDomain)
	if got.Fetched {
		t.Fatal("a fetch that failed was reported as a policy that was read")
	}
	if got.Reason == "" {
		t.Error("nothing says why the policy was not read, so a caller cannot tell a failure " +
			"from a domain that published none")
	}
}

// A policy read over a connection this program would not trust is not a policy.
//
// The whole of MTA-STS is that nobody on the path can rewrite what the domain
// said. A fetcher that stopped verifying would still pass every test above,
// because they all supply the authority that signed the fixture — so this one
// deliberately does not.
func TestAPolicyIsNotReadOverAnUntrustedConnection(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(wholePolicy))
	}))
	leaf := certificateFor(t, policyHost)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// The fixture's own authority is deliberately withheld, which is what
	// somebody else answering for the name looks like.
	got := fetcherFor(t, srv, nil).Fetch(context.Background(), testDomain)
	if got.Fetched {
		t.Error("a policy was read over a connection this program does not trust; anybody able " +
			"to answer for the name could then write this domain's policy")
	}
}

// The certificate has to name the policy host, not the domain.
//
// RFC 8461 requires the policy be fetched over a connection valid for
// mta-sts.<domain>. A fetcher that checked the domain instead would accept a
// policy from whoever holds a certificate for the domain's website, which is not
// the same party and in a hosted arrangement is frequently somebody else.
func TestTheCertificateMustNameThePolicyHost(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(wholePolicy))
	}))
	// Valid for the domain, and for nothing beneath it.
	leaf := certificateFor(t, testDomain)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	got := fetcherFor(t, srv, leaf).Fetch(context.Background(), testDomain)
	if got.Fetched {
		t.Errorf("a certificate naming %q was accepted for %q", testDomain, policyHost)
	}
}

// No reason describes this machine or the other end's address (I6).
func TestNoReasonNamesTheInfrastructure(t *testing.T) {
	f := &Fetcher{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial tcp 203.0.113.9:443: connect: connection refused")
		},
		Timeout: time.Second,
	}

	got := f.Fetch(context.Background(), testDomain)
	for _, leak := range []string{"203.0.113.9", "dial tcp", "connection refused", "x509"} {
		if strings.Contains(got.Reason, leak) {
			t.Errorf("the reason %q carries %q, which describes the machinery rather than the rule",
				got.Reason, leak)
		}
	}
}

// The default dialler is the guarded one, and only over HTTPS.
//
// Asked of the dialler rather than through Fetch, because a caller sees the same
// phrase whether a destination was refused by policy or had nothing listening.
// That is right for a caller and blind for a test: nothing answers on loopback
// port 443 either, so a fetcher that had quietly stopped using safedial would
// pass a test written the other way round.
func TestTheDefaultDiallerRefusesPrivateAddresses(t *testing.T) {
	dial := (&Fetcher{}).dialFunc()

	for _, address := range []string{
		"127.0.0.1:443",
		"10.0.0.1:443",
		"169.254.169.254:443",
		"[::1]:443",
	} {
		conn, err := dial(context.Background(), "tcp", address)
		if conn != nil {
			_ = conn.Close()
		}
		if !errors.Is(err, safedial.ErrBlocked) {
			t.Errorf("dialling %s gave %v, want the policy refusal; the fetch is reachable by an "+
				"SSRF into whatever calls it", address, err)
		}
	}

	if _, err := dial(context.Background(), "tcp", "93.184.216.34:8443"); !errors.Is(err, safedial.ErrBlocked) {
		t.Errorf("dialling a port other than %s gave %v, want the policy refusal", securePort, err)
	}
}

// No proxy stands between this and the policy.
//
// Asserted on the transport rather than through Fetch, and the reason is how the
// sabotage that found this escaped: net/http reads the proxy variables once per
// process and ignores them for the fixtures' own dialler, so a fetcher honouring
// HTTPS_PROXY passed every test above. A proxy is a third party able to rewrite
// the one file MTA-STS exists to keep unrewritable.
func TestNoProxyIsConsulted(t *testing.T) {
	transport, ok := (&Fetcher{}).client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("the client no longer uses an *http.Transport, so nothing here can see its proxy")
	}
	if transport.Proxy != nil {
		t.Error("the fetch consults a proxy, which puts a third party between this and a policy " +
			"whose whole purpose is that nobody in the middle can rewrite it")
	}
}

// A wildcard covers one label, which is what RFC 8461 §4.1 defines.
//
// The rule a graded finding rests on: an enforcing policy that matches none of
// the domain's exchangers stops its mail, so a Covers that was too generous
// would hide the finding and one too strict would invent it. Both directions are
// here.
func TestTheWildcardCoversOneLabel(t *testing.T) {
	p := Policy{MX: []string{"mx1.example.test", "*.mail.example.test"}}

	for host, want := range map[string]bool{
		"mx1.example.test":          true,
		"MX1.Example.Test":          true,  // folded for comparison (I7)
		"mx1.example.test.":         true,  // a trailing root label is the same name
		"a.mail.example.test":       true,  // one label under the wildcard
		"mx2.example.test":          false, // a name the policy never mentions
		"a.b.mail.example.test":     false, // two labels: the wildcard is not a suffix match
		"mail.example.test":         false, // the wildcard requires a label to consume
		"evilmx1.example.test":      false, // a prefix of a pattern is not a pattern
		"mx1.example.test.evil.net": false, // and neither is a suffix
		"":                          false,
	} {
		if got := p.Covers(host); got != want {
			t.Errorf("Covers(%q) = %v, want %v", host, got, want)
		}
	}
}

// A policy with no patterns covers nothing.
//
// Not a detail: an enforcing policy naming no exchanger permits no delivery at
// all, and a Covers that returned true for everything when the list was empty
// would report that broken policy as covering every host.
func TestAPolicyWithNoPatternsCoversNothing(t *testing.T) {
	if (Policy{}).Covers("mx1.example.test") {
		t.Error("a policy naming no exchangers was read as permitting one")
	}
}

// A name in the policy is chosen by whoever is being measured (I5).
func TestAHostileNameInThePolicyIsStripped(t *testing.T) {
	f, _ := policyServer(t, "version: STSv1\nmode: enforce\n"+
		"mx: mx1.example.test<script>alert(1)</script>\n"+
		"mx: "+strings.Repeat("a", 400)+".example.test\n", http.StatusOK)

	got := f.Fetch(context.Background(), testDomain)
	if !got.Fetched {
		t.Fatalf("the policy was not read: %s", got.Reason)
	}

	for _, name := range got.MX {
		if strings.ContainsAny(name, "<>()!/\\ '\"") {
			t.Errorf("the policy names %q, which carries characters a hostname cannot hold and a "+
				"report should never be asked to render", name)
		}
		if len(name) > 253 {
			t.Errorf("a name of %d characters travels, and a hostname cannot exceed 253", len(name))
		}
	}
}
