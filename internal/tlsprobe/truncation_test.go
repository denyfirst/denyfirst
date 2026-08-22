package tlsprobe

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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// serverAccepting starts a TLS 1.2 server that really does accept the suites
// given, so that a truncated enumeration can be compared against the truth.
func serverAccepting(t *testing.T, suites []uint16) (host, port string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: suites,
	})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}()
		}
	}()

	host, port, _ = net.SplitHostPort(l.Addr().String())
	return host, port
}

// A suite list cut short must not be reported as the suites a server accepts.
//
// Enumeration makes one handshake per suite accepted, up to twenty-two at
// TLS 1.2, and a host that rate-limits or resets will end that early. Go's
// server answers with its strongest suite first, so a truncated list loses the
// weak end — the suites that decide the verdict. Before 2026-08-22 every
// handshake error was read as "nothing left that both sides accept", and the
// report presented what was reached as what was accepted.
//
// The measurement below: four suites accepted, two of them CBC. Cut the
// connection after the second handshake and the old code reported strong.
func TestATruncatedSuiteListIsNotReportedAsComplete(t *testing.T) {
	host, port := serverAccepting(t, []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	})

	undisturbed := &Prober{Dial: (&net.Dialer{}).DialContext}
	full, complete := undisturbed.enumerateCiphers(context.Background(), host, port, tls.VersionTLS12)
	if !complete {
		t.Fatalf("an undisturbed enumeration reported itself unfinished after %d suites", len(full))
	}
	if len(full) != 4 {
		t.Fatalf("found %d suites, want the 4 the server accepts", len(full))
	}

	// A host that stops answering after two handshakes, the way a rate-limited
	// or defended one does.
	var opened int32
	cut := &Prober{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if atomic.AddInt32(&opened, 1) > 2 {
			return nil, errors.New("dial tcp: connect: connection reset by peer")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}

	short, complete := cut.enumerateCiphers(context.Background(), host, port, tls.VersionTLS12)
	if complete {
		t.Errorf(`enumeration stopped after %d of %d suites and reported itself finished.

The connection was reset; the server never said it had run out of suites. Only
the server saying so finishes a list. Everything else leaves the rest unknown,
and the rest is where the weak suites are.`, len(short), len(full))
	}
	if len(short) >= len(full) {
		t.Fatalf("the interrupted run found %d suites and the undisturbed one %d; this test needs them to differ",
			len(short), len(full))
	}
}

// And the verdict must not be the one the truncation manufactured.
func TestAnUnfinishedListCannotProduceStrong(t *testing.T) {
	strongOnly := []CipherResult{gradeCipher(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)}

	finished := []VersionResult{{
		Version: tls.VersionTLS12, Name: "TLS 1.2", Supported: true,
		Grade: policy.GradeVersion(tls.VersionTLS12), Ciphers: strongOnly,
		CipherListComplete: true,
	}}
	if got, _ := summarise(finished); got != policy.Strong {
		t.Errorf("a finished list of strong suites graded %q, want %q", got, policy.Strong)
	}

	unfinished := []VersionResult{{
		Version: tls.VersionTLS12, Name: "TLS 1.2", Supported: true,
		Grade: policy.GradeVersion(tls.VersionTLS12), Ciphers: strongOnly,
		CipherListComplete: false,
	}}
	if got, _ := summarise(unfinished); got == policy.Strong {
		t.Error(`an unfinished list of strong suites graded strong.

Strong is the verdict that claims an absence — that nothing worse is there —
and an enumeration that stopped early cannot support one. A scanned host that
answers twice and then goes quiet would be choosing its own grade.`)
	}

	// The asymmetry: worst-case aggregation still holds. A weak suite that was
	// seen was seen, however the list ended.
	weakSeen := []VersionResult{{
		Version: tls.VersionTLS12, Name: "TLS 1.2", Supported: true,
		Grade: policy.GradeVersion(tls.VersionTLS12),
		Ciphers: []CipherResult{
			gradeCipher(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			gradeCipher(tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
		},
		CipherListComplete: false,
	}}
	if got, _ := summarise(weakSeen); got != policy.Weak {
		t.Errorf("an unfinished list containing a weak suite graded %q, want %q; "+
			"a suite that was seen does not become unseen", got, policy.Weak)
	}
}

// Only the server saying "nothing in common" finishes a list. Everything else
// is the conversation failing, and the difference is the whole fix.
func TestOnlyARefusalFinishesAnEnumeration(t *testing.T) {
	finishes := []string{
		"remote error: tls: handshake failure",
		"remote error: tls: insufficient security",
		"tls: no cipher suite supported by both client and server",
		"remote error: tls: protocol version not supported",
	}
	for _, msg := range finishes {
		if !isNoSharedSuite(errors.New(msg)) {
			t.Errorf("%q is the server saying no and was read as the connection failing", msg)
		}
	}

	interrupts := []string{
		"dial tcp 203.0.113.1:443: i/o timeout",
		"read tcp 203.0.113.1:443: connection reset by peer",
		"dial tcp 203.0.113.1:443: connect: connection refused",
		"EOF",
		"context deadline exceeded",
		"write tcp 203.0.113.1:443: broken pipe",
		"dial tcp: lookup example.test: no such host",
	}
	for _, msg := range interrupts {
		if isNoSharedSuite(errors.New(msg)) {
			t.Errorf("%q is the conversation failing and was read as the server having nothing left", msg)
		}
	}

	// The two sets must not overlap with what classifyHandshakeError calls a
	// server refusal, or the version probe and the enumeration would disagree
	// about the same error.
	for _, msg := range finishes {
		got, refused := classifyHandshakeError(errors.New(msg), tls.VersionTLS12)
		if !refused && !strings.Contains(got, "declined to offer") {
			t.Errorf("%q finishes an enumeration but classifyHandshakeError calls it %q", msg, got)
		}
	}
}

// An entry that could not be read is counted, so the report can say so.
//
// It used to be skipped in silence, on the reasoning that the total beside it
// would make the gap visible. That asks a reader to notice two numbers
// disagreeing and work out why, which is the same reasoning certinfo rejected
// for the embedded list — where an unparseable one raises a note.
func TestUnreadableHandshakeTimestampsAreCounted(t *testing.T) {
	good := make([]byte, 43)
	short := make([]byte, 20)
	wrongVersion := make([]byte, 43)
	wrongVersion[0] = 9

	ids, unreadable := handshakeLogIDs([][]byte{good, short, wrongVersion})

	if len(ids) != 1 {
		t.Errorf("read %d identifiers, want 1", len(ids))
	}
	if unreadable != 2 {
		t.Errorf("counted %d unreadable entries, want 2; a skipped entry that is not counted "+
			"cannot be mentioned in the report", unreadable)
	}
}

// The sentence bounding what this client offered was attached to success, and
// dropped in the one report that most needs it.
//
// A server speaking only suites Go does not implement answers every probe with
// a handshake failure, which is the same alert as a version refusal. Every row
// then reads "refused", the verdict is ungraded, and without this note nothing
// on the page suggests the other reading — that the server speaks these
// versions perfectly well and shares no cipher with the scanner.
func TestTheLimitsOfThisClientAreStatedWhenNothingWasAccepted(t *testing.T) {
	cases := map[string]struct {
		results []VersionResult
		want    bool
	}{
		"something was accepted": {
			[]VersionResult{{Supported: true}}, true,
		},
		"everything was refused": {
			[]VersionResult{{Refused: true}, {Refused: true}},
			true,
		},
		"nothing answered at all": {
			[]VersionResult{
				{Error: "the name did not resolve"},
				{Error: "the name did not resolve"},
			},
			false,
		},
		"one refusal among failures": {
			[]VersionResult{{Error: "the connection timed out"}, {Refused: true}},
			true,
		},
	}

	for name, tc := range cases {
		if got := suiteCoverageApplies(tc.results); got != tc.want {
			t.Errorf("%s: the note applies = %v, want %v", name, got, tc.want)
		}
	}
}
