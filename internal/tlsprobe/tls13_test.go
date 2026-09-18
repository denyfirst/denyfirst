package tlsprobe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/rawhello"
)

// accept13 is a TLS 1.3 ServerHello record choosing one suite.
func accept13(suite uint16) []byte {
	body := binary.BigEndian.AppendUint16(nil, 0x0303)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, suite)
	body = append(body, 0)
	ext := []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	msg := append([]byte{2, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	out := []byte{22, 3, 1, 0, byte(len(msg))}
	return append(out, msg...)
}

func ask13(t *testing.T, p *Prober, negotiated uint16) ([]CipherResult, bool, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return p.tls13Suites(ctx, "example.test", "443", negotiated, newAddressSet())
}

func suiteIDs(ciphers []CipherResult) []uint16 {
	var out []uint16
	for _, c := range ciphers {
		out = append(out, c.ID)
	}
	return out
}

// Every suite in the registry is asked, each alone: a hello offering two lets
// the server's preference answer for both.
func TestEveryRegistryTLS13SuiteIsAskedAlone(t *testing.T) {
	var (
		mu    sync.Mutex
		heard []uint16
	)
	p, _ := scriptedProber(func(h heardHello) []byte {
		mu.Lock()
		defer mu.Unlock()
		if len(h.suites) != 1 {
			t.Errorf("a hello offered %v; each asks about one suite", h.suites)
		}
		heard = append(heard, h.suites...)
		return accept13(h.suites[0])
	})
	ask13(t, p, 0x1301)

	slices.Sort(heard)
	want := rawhello.IDs(rawhello.TLS13)
	slices.Sort(want)
	if !slices.Equal(heard, want) {
		t.Errorf("asked %x, want every registry suite %x", heard, want)
	}
}

// What the server accepts is listed and graded; what it refuses is not.
//
// The case the change is for: a TLS 1.3 server accepting an integrity-only
// suite, which Go's client never offers and every record of which is sent in
// the clear.
func TestTheTLS13SuitesAServerAcceptsAreListedAndGraded(t *testing.T) {
	accepts := []uint16{0x1301, 0x1302, 0xC0B4}
	p, _ := scriptedProber(func(h heardHello) []byte {
		if slices.Contains(accepts, h.suites[0]) {
			return accept13(h.suites[0])
		}
		return alert(40)
	})

	ciphers, complete, reason := ask13(t, p, 0x1301)
	if reason != "" || !complete {
		t.Fatalf("complete=%v reason=%q; every hello was answered", complete, reason)
	}
	if got := suiteIDs(ciphers); !slices.Equal(got, accepts) {
		t.Errorf("listed %x, want %x", got, accepts)
	}
	for _, c := range ciphers {
		if c.ID == 0xC0B4 && c.Verdict != policy.Insecure {
			t.Errorf("TLS_SHA256_SHA256 graded %s; it encrypts nothing", c.Verdict)
		}
	}
}

// A suite the server did not answer about leaves the list incomplete, rather
// than counting as refused (R4).
func TestASilentTLS13SuiteLeavesTheListIncomplete(t *testing.T) {
	p, _ := scriptedProber(func(h heardHello) []byte {
		switch h.suites[0] {
		case 0x1301:
			return accept13(0x1301)
		case 0x1305:
			return nil
		default:
			return alert(40)
		}
	})
	ciphers, complete, _ := ask13(t, p, 0x1301)
	if complete {
		t.Error("a suite nobody answered about was counted as refused")
	}
	if got := suiteIDs(ciphers); !slices.Equal(got, []uint16{0x1301}) {
		t.Errorf("listed %x", got)
	}
}

// Unless the suite Go negotiated comes back accepted at TLS 1.3, the hellos are
// not answering the question, and only the negotiated suite is listed.
//
// Two ways the calibration fails: every hello refused, including the suite a
// real handshake just negotiated; and a server answering at TLS 1.2, which is
// not an acceptance of a TLS 1.3 suite whatever it names.
func TestWithoutCalibrationOnlyTheNegotiatedSuiteIsListed(t *testing.T) {
	for name, respond := range map[string]func(heardHello) []byte{
		"everything refused": func(heardHello) []byte { return alert(40) },
		"answered at TLS 1.2": func(h heardHello) []byte {
			return accept(tls.VersionTLS12, h.suites[0])
		},
		"another suite": func(heardHello) []byte { return accept13(0x1302) },
	} {
		p, _ := scriptedProber(respond)
		ciphers, complete, reason := ask13(t, p, 0x1301)
		if reason == "" {
			t.Errorf("%s: no reason is given for listing only one suite", name)
		}
		if got := suiteIDs(ciphers); !slices.Equal(got, []uint16{0x1301}) || !complete {
			t.Errorf("%s: listed %x complete=%v; want the negotiated suite alone, as before", name, got, complete)
		}
	}
}

// crypto/tls's own server, which chooses among the three suites it implements,
// is found to accept exactly those — an agreement between this hand-written hello
// and a server somebody else wrote to RFC 8446.
func TestAGoServerIsEnumeratedAtTLS13(t *testing.T) {
	cert, _ := twoCertificates(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()

	addr := listener.Addr().String()
	p := &Prober{
		HandshakeTimeout: 3 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}

	ciphers, complete, reason := ask13(t, p, tls.TLS_AES_128_GCM_SHA256)
	if reason != "" || !complete {
		t.Fatalf("complete=%v reason=%q against crypto/tls", complete, reason)
	}
	want := []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256}
	if got := suiteIDs(ciphers); !slices.Equal(got, want) {
		t.Errorf("crypto/tls was found to accept %x, want %x", got, want)
	}
}

// A whole probe lists every TLS 1.3 suite the server accepts, not only the one
// its handshake negotiated — the list is the report's, not a helper's.
func TestAProbeListsEveryTLS13SuiteTheServerAccepts(t *testing.T) {
	host, port, stop := localTLSServer(t)
	defer stop()

	report, err := loopbackProber().Probe(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, v := range report.Versions {
		if v.Version != tls.VersionTLS13 {
			continue
		}
		if !v.Supported || !v.CipherListComplete {
			t.Fatalf("TLS 1.3: %+v", v)
		}
		want := []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256}
		if got := suiteIDs(v.Ciphers); !slices.Equal(got, want) {
			t.Errorf("the report lists %x at TLS 1.3; crypto/tls accepts %x", got, want)
		}
		return
	}
	t.Fatal("the report has no TLS 1.3 row")
}

// oneSuiteDropped closes any connection whose first write is a hello offering
// exactly one suite — what a middlebox dropping unfamiliar hellos looks like to
// the hand-written ones, while Go's own handshakes, which offer many, go through.
type oneSuiteDropped struct {
	net.Conn
	checked bool
}

func (c *oneSuiteDropped) Write(b []byte) (int, error) {
	if !c.checked {
		c.checked = true
		if len(b) > 5+4+35 {
			body := b[9:]
			if sid := int(body[34]); len(body) >= 35+sid+2 && binary.BigEndian.Uint16(body[35+sid:]) == 2 {
				_ = c.Conn.Close()
				return 0, net.ErrClosed
			}
		}
	}
	return c.Conn.Write(b)
}

// Where the hand-written hellos are not answered as Go's handshake was, the
// report lists the negotiated suite and says why, rather than listing it
// silently as though the others had been asked.
//
// A sabotage dropping the sentence escaped every other test on 2026-09-14:
// they call the helper, which returns the reason, and none ran a whole probe
// against a server that would not answer the hand-written hello.
func TestAProbeSaysWhyTheTLS13SuitesWereNotEnumerated(t *testing.T) {
	host, port, stop := localTLSServer(t)
	defer stop()

	p := loopbackProber()
	dial := p.Dial
	p.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &oneSuiteDropped{Conn: conn}, nil
	}

	report, err := p.Probe(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	said := false
	for _, n := range report.Notes {
		said = said || n.Text == tls13NotEnumerated
	}
	if !said {
		t.Errorf("only the negotiated suite could be listed and the report does not say why:\n%v", report.Notes)
	}
	for _, v := range report.Versions {
		if v.Version == tls.VersionTLS13 && len(v.Ciphers) != 1 {
			t.Errorf("TLS 1.3 lists %d suites; only the negotiated one could be established", len(v.Ciphers))
		}
	}
}
