package scan

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/certinfo"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort string
	}{
		{"example.com", "example.com", "443"},
		{"example.com:8443", "example.com", "8443"},

		// Surrounding whitespace is trimmed rather than refused: people paste
		// it constantly, and after trimming there is nothing left to exploit.
		{"  example.com  ", "example.com", "443"},
		{"example.com\n", "example.com", "443"},
		{"\texample.com:8443\r\n", "example.com", "8443"},

		// A pasted URL is a likely mistake, not an error worth refusing. A
		// scheme makes the host unambiguous, so the path goes with it.
		{"https://example.com", "example.com", "443"},
		{"http://example.com", "example.com", "443"},
		{"https://example.com/", "example.com", "443"},
		{"https://example.com/path/to/page", "example.com", "443"},
		{"https://example.com:8443/x", "example.com", "8443"},

		// A bare trailing slash discards nothing, so it needs no scheme.
		{"example.com/", "example.com", "443"},

		{"[2606:4700:4700::1111]:443", "2606:4700:4700::1111", "443"},

		// Bracketed and bare IPv6 without a port. Fuzzing found that the
		// earlier version left the brackets attached to the hostname, so the
		// resolver was handed a name it could never look up.
		{"[::1]", "::1", "443"},
		{"[2606:4700:4700::1111]", "2606:4700:4700::1111", "443"},
		{"::1", "::1", "443"},
		{"2606:4700:4700::1111", "2606:4700:4700::1111", "443"},
		{"[::1]:8443", "::1", "8443"},
	}

	for _, tc := range cases {
		host, port, err := SplitTarget(tc.in)
		if err != nil {
			t.Errorf("SplitTarget(%q) returned %v", tc.in, err)
			continue
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("SplitTarget(%q) = %q, %q; want %q, %q", tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

// Interior control characters survive trimming, and they are the ones that
// matter: a newline inside a hostname is how header injection starts, and a
// NUL byte is how a truncating parser is made to read a different name than
// the one that was checked.
func TestSplitTargetRejectsMalformedInput(t *testing.T) {
	bad := []string{
		"",
		"   ",
		"https://",
		"exa mple.com",
		"exam\nple.com",
		"example\r.com",
		"example.com\x00.evil.test",
		strings.Repeat("a", 300),

		// Every entry below was accepted by the earlier version. Fuzzing
		// found the first five; the rest follow from the same gap, which was
		// that the host was never examined for shape.
		"example.com:", // net.SplitHostPort permits an empty port
		"[",            // an unclosed bracket
		"]",            // a stray bracket as a hostname
		"[]",           // brackets around nothing
		"[]:443",       //
		"[::1]x",       // characters after the closing bracket
		"a:1:2:3",      // several colons, and not an IPv6 address
		":443",         // no host
		"user:pass@example.com",
		"example.com:0",
		"example.com:65536",
		"example.com:abc",
		"example.com:99999999999999999999",
		"example.com#fragment",
		"example.com?query=1",
		"münchen.de", // an internationalised name must be given in punycode
	}

	for _, in := range bad {
		if _, _, err := SplitTarget(in); err == nil {
			t.Errorf("SplitTarget(%q) accepted malformed input", in)
		}
	}
}

func TestCheckPort(t *testing.T) {
	for _, port := range AllowedPorts {
		if err := CheckPort(port); err != nil {
			t.Errorf("CheckPort(%s) rejected an allowed port: %v", port, err)
		}
	}

	// STARTTLS ports are absent on purpose: the probe speaks TLS from the
	// first byte, so a scan of port 25 would fail in a way that reads as a
	// server fault rather than as a missing feature.
	refused := []string{"22", "25", "80", "110", "143", "587", "3389", "9999"}
	for _, port := range refused {
		if err := CheckPort(port); err == nil {
			t.Errorf("CheckPort(%s) accepted a port outside the allow list", port)
		}
	}
}

// The allow list must not grow to include ports that would let this project
// be used to probe a third party's network.
func TestAllowedPortsAreImplicitTLS(t *testing.T) {
	startTLS := map[string]string{
		"25":  "SMTP",
		"110": "POP3",
		"143": "IMAP",
		"587": "SMTP submission",
		"21":  "FTP",
		"389": "LDAP",
	}

	for _, port := range AllowedPorts {
		if proto, found := startTLS[port]; found {
			t.Errorf("port %s (%s) negotiates TLS after a plaintext greeting; the probe cannot speak it", port, proto)
		}
	}
}

// A zero Scanner must reach safedial. If this ever succeeds against a private
// address, the guard has been disconnected from the pipeline.
//
// Addresses are also refused outright now, so most of these stop before the
// dialler. Both outcomes are correct; what must never happen is a completed
// handshake.
func TestZeroScannerRefusesPrivateTargets(t *testing.T) {
	s := &Scanner{AllowIPTargets: true}

	for _, target := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1"} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		result, err := s.Scan(ctx, target)
		cancel()

		if err != nil {
			continue // refused before producing a result: also correct
		}
		if result.Certificate != nil {
			t.Errorf("Scan(%s) returned a certificate from a private address", target)
		}
		for _, v := range result.TLS.Versions {
			if v.Supported {
				t.Errorf("Scan(%s) completed a handshake against a private address", target)
			}
		}
	}
}

// Nothing measured must not read as passing, and the policy version must be
// stated whatever the outcome.
func TestUnreachableTargetIsUngraded(t *testing.T) {
	// A demonstration build reaches only the hosts this project owns, and
	// this test scans one it does not. What is under test here is the tool,
	// and the demonstration build is the tool with a list — the list is
	// covered by its own tests under the same tag.
	if Demo {
		t.Skip("a demonstration build does not scan this host")
	}

	s := &Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
				return nil, errors.New("no network in this test")
			},
		},
	}

	result, err := s.Scan(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("Scan returned %v", err)
	}

	if result.Verdict != policy.Ungraded {
		t.Errorf("Verdict = %q, want it ungraded", result.Verdict)
	}
	if result.Policy != policy.Version {
		t.Errorf("Policy = %q, want %q", result.Policy, policy.Version)
	}
	if result.Certificate != nil {
		t.Error("a certificate report was produced although nothing connected")
	}
	if len(result.Findings()) != 0 {
		t.Errorf("findings were reported although nothing was measured: %v", result.Findings())
	}
}

func TestScanRejectsMalformedTarget(t *testing.T) {
	s := &Scanner{}
	if _, err := s.Scan(context.Background(), "exam\nple.com"); err == nil {
		t.Error("Scan accepted a host containing a newline")
	}
}

// The allow list must hold at the library level, not only in the HTTP
// handler. A guard that lives in one caller disappears the moment a second
// caller is written, and the second caller is where the mistake happens.
func TestScannerEnforcesPortsByDefault(t *testing.T) {
	s := &Scanner{}

	for _, target := range []string{"example.test:22", "example.test:3389", "example.test:25"} {
		_, err := s.Scan(context.Background(), target)
		if err == nil {
			t.Errorf("a zero Scanner accepted %s, a port outside the allow list", target)
			continue
		}
		if !strings.Contains(err.Error(), "not scannable") {
			t.Errorf("Scan(%s) failed for the wrong reason: %v", target, err)
		}
	}
}

// AllowAnyPort must actually lift the restriction, or the command line loses
// a capability it is entitled to.
func TestAllowAnyPortLiftsTheRestriction(t *testing.T) {
	s := &Scanner{
		AllowAnyPort: true,
		Prober: &tlsprobe.Prober{
			Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
				return nil, errors.New("no network in this test")
			},
		},
	}

	if _, err := s.Scan(context.Background(), "example.test:22"); err != nil {
		if strings.Contains(err.Error(), "not scannable") {
			t.Error("AllowAnyPort did not disable the port check")
		}
	}
}

// A bare address is refused by default. A scan of a name carries that name in
// the client hello, which is what a browser does; a scan of an address
// carries nothing, which is what a scanner does.
func TestScannerRefusesAddressesByDefault(t *testing.T) {
	s := &Scanner{}

	for _, target := range []string{
		"93.184.216.34",
		"93.184.216.34:8443",
		"2606:4700:4700::1111",
		"[2606:4700:4700::1111]:443",
	} {
		_, err := s.Scan(context.Background(), target)
		if err == nil {
			t.Errorf("a zero Scanner accepted %s", target)
			continue
		}
		if !strings.Contains(err.Error(), "takes a hostname") {
			t.Errorf("Scan(%s) failed for the wrong reason: %v", target, err)
		}
	}
}

// The command line has the case the service refuses: an operator checking a
// server whose name does not resolve yet.
func TestAllowIPTargetsLiftsTheRestriction(t *testing.T) {
	s := &Scanner{
		AllowIPTargets: true,
		Prober: &tlsprobe.Prober{
			Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
				return nil, errors.New("no network in this test")
			},
		},
	}

	if _, err := s.Scan(context.Background(), "93.184.216.34"); err != nil {
		if strings.Contains(err.Error(), "takes a hostname") {
			t.Error("AllowIPTargets did not lift the restriction")
		}
	}
}

// A name that resembles an address must still be accepted, or the check is
// matching strings rather than parsing. Services such as nip.io exist and
// resolve ordinary-looking names to addresses; refusing them would be wrong
// and would not stop anybody determined.
func TestIsIPTarget(t *testing.T) {
	addresses := []string{
		"93.184.216.34",
		"127.0.0.1",
		"::1",
		"2606:4700:4700::1111",
		"::ffff:127.0.0.1",
	}
	for _, host := range addresses {
		if !IsIPTarget(host) {
			t.Errorf("IsIPTarget(%q) = false, want true", host)
		}
	}

	names := []string{
		"example.com",
		"1.example.com",
		"93.184.216.34.example.com",
		"1.2.3.4.nip.io",
		"xn--e1afmkfd.xn--p1ai",
		"localhost",
	}
	for _, host := range names {
		if IsIPTarget(host) {
			t.Errorf("IsIPTarget(%q) = true, want false", host)
		}
	}
}

// The property fuzzing broke: splitting a target, rejoining it, and splitting
// again has to give the same answer. Where it does not, a check performed on
// one form does not describe the form that is eventually dialled, which is
// where parser-mismatch attacks live.
func TestSplitTargetIsStable(t *testing.T) {
	inputs := []string{
		"example.com",
		"example.com:8443",
		"https://example.com/path",
		"[::1]",
		"[::1]:8443",
		"::1",
		"[2606:4700:4700::1111]:443",
		"2606:4700:4700::1111",
		"::ffff:127.0.0.1",
	}

	for _, in := range inputs {
		host, port, err := SplitTarget(in)
		if err != nil {
			t.Errorf("SplitTarget(%q) returned %v", in, err)
			continue
		}

		rejoined := net.JoinHostPort(host, port)
		host2, port2, err := SplitTarget(rejoined)
		if err != nil {
			t.Errorf("SplitTarget(%q) produced %q, which SplitTarget then rejected: %v", in, rejoined, err)
			continue
		}
		if host2 != host || port2 != port {
			t.Errorf("SplitTarget is not stable: %q gave (%q, %q); rejoined as %q it gives (%q, %q)",
				in, host, port, rejoined, host2, port2)
		}
	}
}

// A port has to be a number before the allow list is consulted. Otherwise an
// arbitrary string reaches CheckPort and, from there, any message built from
// it.
func TestPortSyntaxIsCheckedBeforeTheAllowList(t *testing.T) {
	for _, in := range []string{"example.com:44 3", "example.com:443x", "example.com:-1", "example.com:+443"} {
		if _, _, err := SplitTarget(in); err == nil {
			t.Errorf("SplitTarget(%q) accepted a port that is not a number", in)
		}
	}
}

// A name with no dot is completed by the resolver from its search list. On a
// machine configured with "search corp.example.com", asking for "intranet"
// dials intranet.corp.example.com: the report names one host and the
// connection goes to another.
//
// It is also what a person means. example.az and example.com are different
// companies, and a bare "example" is neither of them.
func TestBareNamesAreRefused(t *testing.T) {
	bare := []string{
		"salam",
		"intranet",
		"localhost",
		"router",
		"example",
		".",
		".com",
		"example..com",
		"com.",
	}

	for _, host := range bare {
		if _, _, err := SplitTarget(host); err == nil {
			t.Errorf("SplitTarget(%q) accepted a name the resolver would complete from its search list", host)
		}
	}
}

// An address answers for itself and needs no dot; "::1" has none.
func TestDottedNamesAndAddressesAreAccepted(t *testing.T) {
	good := []string{
		"example.com",
		"example.az",
		"a.b.c.example.com",
		"example.com.", // fully qualified, which is the most explicit form
		"93.184.216.34",
		"2606:4700:4700::1111",
		"::1",
	}

	for _, host := range good {
		if _, _, err := SplitTarget(host); err != nil {
			t.Errorf("SplitTarget(%q) returned %v", host, err)
		}
	}
}

// Truncating at the first slash is right for a URL and wrong for anything
// else. "emanat.az/mpay.az/example.com" is not a URL, and scanning emanat.az
// while discarding two thirds of what somebody typed would surprise them —
// the report would name the right host and the person would still be wrong
// about what happened.
func TestPathIsOnlyDroppedFromAURL(t *testing.T) {
	withScheme := map[string]string{
		"https://example.com/login":             "example.com",
		"http://example.com/a/b/c":              "example.com",
		"https://example.com/":                  "example.com",
		"https://example.com:8443/admin":        "example.com",
		"https://emanat.az/mpay.az/example.com": "emanat.az",
	}
	for in, want := range withScheme {
		host, _, err := SplitTarget(in)
		if err != nil {
			t.Errorf("SplitTarget(%q) returned %v", in, err)
			continue
		}
		if host != want {
			t.Errorf("SplitTarget(%q) = %q, want %q", in, host, want)
		}
	}

	// A bare trailing slash discards nothing.
	if host, _, err := SplitTarget("example.com/"); err != nil || host != "example.com" {
		t.Errorf(`SplitTarget("example.com/") = %q, %v; want example.com`, host, err)
	}

	// Without a scheme, anything after a slash would be dropped in silence.
	for _, in := range []string{
		"example.com/login",
		"emanat.az/mpay.az/example.com",
		"example.com/a/b",
		"example.com/?x=1",
	} {
		if _, _, err := SplitTarget(in); err == nil {
			t.Errorf("SplitTarget(%q) silently discarded everything after the slash", in)
		}
	}
}

// A finding about an issuer reaches the list a caller reads.
//
// Findings() is what the page, the terminal report and the API all walk, and
// it collected the leaf's findings and the alternate chains' and stopped
// there. An issuer graded insecure would have sat in the certificate section
// and never appeared among the problems — which is the same silence, one
// level down, that grading the chain exists to end.
func TestAFindingAboutAnIssuerReachesTheFindings(t *testing.T) {
	r := &Result{
		Certificate: &certinfo.Report{
			IssuerGrades: []policy.IssuerFinding{{
				Verdict:  policy.Insecure,
				Findings: []policy.Finding{{RuleID: "chain.signature-sha1", Verdict: policy.Insecure}},
			}},
		},
		AlternateCertificates: []*certinfo.Report{{
			IssuerGrades: []policy.IssuerFinding{{
				Verdict:  policy.Weak,
				Findings: []policy.Finding{{RuleID: "chain.expiring-soon", Verdict: policy.Weak}},
			}},
		}},
	}

	seen := map[string]bool{}
	for _, f := range r.Findings() {
		seen[f.RuleID] = true
	}
	for _, want := range []string{"chain.signature-sha1", "chain.expiring-soon"} {
		if !seen[want] {
			t.Errorf("%s was graded and does not appear among the findings a caller reads", want)
		}
	}
}

// The port allow list reaches the dialer as well as the handler.
//
// The check in Scan is the one that holds, and it holds for every caller —
// that is why it is there rather than in the HTTP handler. This is the second
// lock on the same door: the prober's dialer refuses the port too, so a future
// entry point that reaches a prober without passing Scan still cannot open a
// connection to an arbitrary port on somebody else's machine.
//
// The whole argument for running this service in public rests on that: it is
// a TLS checker, not a scanner for hire, and the logs of a scanned network
// name us rather than whoever asked.
func TestThePortAllowListReachesTheDialer(t *testing.T) {
	s := &Scanner{}
	if _, err := s.Scan(context.Background(), "example.test:22"); err == nil {
		t.Fatal("the scanner dialled a port that is not on the list")
	}

	// And the prober this scanner actually builds carries the list, so the
	// refusal does not depend on Scan having been the way in. Read from the
	// scanner rather than constructed here: a test that builds its own prober
	// proves only that a prober can hold a list.
	built := (&Scanner{}).prober()
	if !slices.Equal(built.AllowedPorts, AllowedPorts) {
		t.Fatalf("the prober the scanner builds carries %v, not the allow list %v",
			built.AllowedPorts, AllowedPorts)
	}
	for _, port := range AllowedPorts {
		if err := CheckPort(port); err != nil {
			t.Errorf("port %s is on the list and CheckPort refuses it: %v", port, err)
		}
	}
	for _, port := range []string{"22", "80", "3389", "25", "587", "0", "65536"} {
		if err := CheckPort(port); err == nil {
			t.Errorf("port %s is not on the list and CheckPort allows it", port)
		}
	}
}
