package tlsprobe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/rawhello"
)

// heardHello is what a scripted server read out of a hello.
type heardHello struct {
	recordVersion uint16
	clientVersion uint16
	suites        []uint16
}

func (h heardHello) offers(id uint16) bool { return slices.Contains(h.suites, id) }

var errShortHello = errors.New("test: the hello is shorter than its lengths say")

// readHeardHello reads a hello the way a server does.
func readHeardHello(r io.Reader) (heardHello, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return heardHello{}, err
	}
	body := make([]byte, binary.BigEndian.Uint16(header[3:5]))
	if _, err := io.ReadFull(r, body); err != nil {
		return heardHello{}, err
	}

	h := heardHello{recordVersion: binary.BigEndian.Uint16(header[1:3])}
	if len(body) < 4+35 {
		return h, errShortHello
	}
	b := body[4:]
	h.clientVersion = binary.BigEndian.Uint16(b[0:2])
	sid := int(b[34])
	if len(b) < 35+sid+2 {
		return h, errShortHello
	}
	b = b[35+sid:]
	n := int(binary.BigEndian.Uint16(b[0:2]))
	if len(b) < 2+n {
		return h, errShortHello
	}
	for i := 0; i < n; i += 2 {
		h.suites = append(h.suites, binary.BigEndian.Uint16(b[2+i:4+i]))
	}
	return h, nil
}

// accept is a ServerHello record choosing one version and one suite.
func accept(version, suite uint16) []byte {
	body := binary.BigEndian.AppendUint16(nil, version)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, suite)
	body = append(body, 0)
	msg := append([]byte{2, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	out := []byte{22, 3, 1, 0, byte(len(msg))}
	return append(out, msg...)
}

// alert is a fatal alert record.
func alert(description byte) []byte { return []byte{21, 3, 1, 0, 2, 2, description} }

// scriptedProber answers every connection by reading the hello and replying as
// told. A nil reply closes the connection without a word.
func scriptedProber(respond func(heardHello) []byte) (*Prober, *atomic.Int32) {
	var dials atomic.Int32
	p := &Prober{
		HandshakeTimeout: 2 * time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(2 * time.Second))
				h, err := readHeardHello(server)
				if err != nil {
					return
				}
				if reply := respond(h); reply != nil {
					_, _ = server.Write(reply)
				}
			}()
			return client, nil
		},
	}
	return p, &dials
}

// answered is a set of ordinary handshakes that succeeded at these versions.
func answered(versions ...uint16) []VersionResult {
	var out []VersionResult
	for _, v := range versions {
		out = append(out, VersionResult{Version: v, Name: versionName(v), Supported: true,
			Grade: policy.GradeVersion(v), CipherListComplete: true})
	}
	return out
}

// refusedEverything is a server that answered every ordinary handshake with no.
var refusedEverything = []VersionResult{
	{Version: tls.VersionTLS13, Name: "TLS 1.3", Refused: true},
	{Version: tls.VersionTLS12, Name: "TLS 1.2", Refused: true},
}

func ruleIDs(fs []policy.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func askAll(t *testing.T, p *Prober, results []VersionResult) Legacy {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return p.legacy(ctx, "example.test", "443", results, newAddressSet())
}

// A server speaking only SSL 3.0 is insecure, not a server that refuses
// everything.
//
// The case this whole change exists for. Go's client cannot speak SSL 3.0, so
// until the hello was written by hand this server's report said every version
// was refused and graded nothing — the flattering direction, on the server that
// most needs the finding.
func TestAServerSpeakingOnlySSL3IsGradedInsecure(t *testing.T) {
	p, _ := scriptedProber(func(h heardHello) []byte {
		if h.clientVersion == policy.VersionSSL30 && h.offers(0x000A) {
			return accept(policy.VersionSSL30, 0x000A)
		}
		return alert(40)
	})

	l := askAll(t, p, refusedEverything)
	if !l.SSL3.Accepted || l.SSL3.VersionGrade == nil {
		t.Fatalf("SSL 3.0 = %+v; the server accepted it", l.SSL3)
	}
	if l.SSL3.Version != "SSL 3.0" {
		t.Errorf("version = %q", l.SSL3.Version)
	}
	if !l.Export.Refused || !l.Null.Refused {
		t.Errorf("export %+v, NULL %+v; both were refused with an alert", l.Export, l.Null)
	}

	verdict, findings := summarise(refusedEverything)
	verdict, findings = mergeLegacy(verdict, findings, l)
	if verdict != policy.Insecure {
		t.Errorf("verdict = %q, want insecure", verdict)
	}
	if !slices.Contains(ruleIDs(findings), "version.ssl3") {
		t.Errorf("findings are %v; version.ssl3 is not among them", ruleIDs(findings))
	}
}

// An export suite accepted is graded, and named.
func TestAnExportSuiteAcceptedIsGraded(t *testing.T) {
	p, _ := scriptedProber(func(h heardHello) []byte {
		if h.clientVersion == policy.VersionTLS12 && h.offers(0x0014) {
			return accept(policy.VersionTLS10, 0x0014)
		}
		return alert(40)
	})

	results := answered(tls.VersionTLS12)
	l := askAll(t, p, results)
	if !l.Export.Accepted || l.Export.Suite == nil {
		t.Fatalf("export = %+v; the server accepted one", l.Export)
	}
	if l.Export.Suite.Name != "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" || l.Export.Version != "TLS 1.0" {
		t.Errorf("accepted %q at %q", l.Export.Suite.Name, l.Export.Version)
	}
	if l.Export.VersionGrade != nil {
		t.Error("a TLS 1.0 answer carries a version grade; only SSL 3.0 is graded here, TLS 1.0 is graded by the ordinary handshakes")
	}

	verdict, findings := summarise(results)
	verdict, findings = mergeLegacy(verdict, findings, l)
	if verdict != policy.Insecure || !slices.Contains(ruleIDs(findings), "cipher.export") {
		t.Errorf("verdict %q, findings %v; want insecure with cipher.export", verdict, ruleIDs(findings))
	}
}

// A NULL suite accepted is graded.
func TestANullSuiteAcceptedIsGraded(t *testing.T) {
	p, _ := scriptedProber(func(h heardHello) []byte {
		if h.clientVersion == policy.VersionTLS12 && h.offers(0xC010) {
			return accept(policy.VersionTLS12, 0xC010)
		}
		return alert(40)
	})

	results := answered(tls.VersionTLS12)
	l := askAll(t, p, results)
	if !l.Null.Accepted || l.Null.Suite == nil || l.Null.Suite.Name != "TLS_ECDHE_RSA_WITH_NULL_SHA" {
		t.Fatalf("NULL = %+v", l.Null)
	}
	verdict, findings := summarise(results)
	verdict, findings = mergeLegacy(verdict, findings, l)
	if verdict != policy.Insecure || !slices.Contains(ruleIDs(findings), "cipher.null") {
		t.Errorf("verdict %q, findings %v; want insecure with cipher.null", verdict, ruleIDs(findings))
	}
}

// A server refusing all of it is measured as refusing, and graded for nothing.
//
// The other direction. A server that turned SSL 3.0, export and NULL away has
// done exactly the right thing, and a report that found something to mark down
// in that would be penalising a correct configuration (R6).
func TestARefusalIsMeasuredAndCostsNothing(t *testing.T) {
	p, _ := scriptedProber(func(heardHello) []byte { return alert(40) })

	results := answered(tls.VersionTLS13, tls.VersionTLS12)
	l := askAll(t, p, results)
	for name, a := range map[string]LegacyAnswer{"SSL 3.0": l.SSL3, "export": l.Export, "NULL": l.Null} {
		if !a.Measured || !a.Refused || a.Accepted {
			t.Errorf("%s = %+v, want measured and refused", name, a)
		}
	}

	before, beforeFindings := summarise(results)
	verdict, findings := mergeLegacy(before, beforeFindings, l)
	if verdict != before || len(findings) != len(beforeFindings) {
		t.Errorf("a server refusing all of it went from %q to %q with %v", before, verdict, ruleIDs(findings))
	}
}

// A closed connection is not a refusal, and the report says so (R4).
func TestAClosedConnectionIsNotARefusal(t *testing.T) {
	p, _ := scriptedProber(func(heardHello) []byte { return nil })

	results := answered(tls.VersionTLS12)
	l := askAll(t, p, results)
	for name, a := range map[string]LegacyAnswer{"SSL 3.0": l.SSL3, "export": l.Export, "NULL": l.Null} {
		if a.Measured || a.Refused {
			t.Errorf("%s = %+v; a server hanging up was recorded as a decision", name, a)
		}
		if a.Reason == "" {
			t.Errorf("%s says nothing about why it was not measured", name)
		}
	}

	r := &Report{Legacy: l}
	r.describeLegacy()
	var said bool
	for _, n := range r.Notes {
		if n.Kind == policy.KindUnsettled && strings.Contains(n.Text, "SSL 3.0") {
			said = true
		}
	}
	if !said {
		t.Errorf("nothing tells a reader SSL 3.0 was not established; notes: %v", r.Notes)
	}
}

// An answer choosing something that was never offered is not believed.
//
// A server may only choose from the hello. One that picks a TLS 1.3 suite in
// reply to a hello offering export suites is not speaking the protocol, and
// grading what it named would be believing it about the one thing it has just
// shown it gets wrong.
func TestAnAnswerOutsideTheOfferIsNotBelieved(t *testing.T) {
	for name, reply := range map[string]func(heardHello) []byte{
		"a suite not offered": func(heardHello) []byte { return accept(policy.VersionTLS12, 0xC02F) },
		"a version above the hello": func(h heardHello) []byte {
			return accept(h.clientVersion+1, h.suites[0])
		},
	} {
		p, _ := scriptedProber(reply)
		l := askAll(t, p, answered(tls.VersionTLS12))
		for label, a := range map[string]LegacyAnswer{"SSL 3.0": l.SSL3, "export": l.Export, "NULL": l.Null} {
			if a.Accepted {
				t.Errorf("%s: %s was read as accepted: %+v", name, label, a)
			}
		}
	}
}

// Nothing is asked of a host that answered nothing.
//
// A name that did not resolve or a destination safedial refused: four more
// connections would learn nothing and would add four attempts to the counter an
// operator reads to spot abuse.
func TestNothingIsAskedWhenNothingAnswered(t *testing.T) {
	p, dials := scriptedProber(func(heardHello) []byte { return alert(40) })

	l := askAll(t, p, []VersionResult{
		{Version: tls.VersionTLS12, Name: "TLS 1.2", Error: "the name did not resolve"},
		{Version: tls.VersionTLS13, Name: "TLS 1.3", Error: "the connection timed out"},
	})
	if got := dials.Load(); got != 0 {
		t.Errorf("%d connections were made to a host that answered nothing", got)
	}
	if l.Asked {
		t.Error("the report says these were asked")
	}
}

// The downgrade signal: honoured, not honoured, and refused for another reason.
func TestTheFallbackSignalIsReadInAllThreeWays(t *testing.T) {
	results := answered(tls.VersionTLS13, tls.VersionTLS12)

	for name, tc := range map[string]struct {
		reply    func(heardHello) []byte
		measured bool
		honoured bool
	}{
		"honoured": {
			reply: func(h heardHello) []byte {
				if h.offers(rawhello.FallbackSCSV) {
					return alert(rawhello.AlertInappropriateFallback)
				}
				return alert(40)
			},
			measured: true, honoured: true,
		},
		"not honoured": {
			reply: func(h heardHello) []byte {
				if h.offers(rawhello.FallbackSCSV) {
					return accept(h.clientVersion, h.suites[0])
				}
				return alert(40)
			},
			measured: true,
		},
		"refused for another reason": {
			reply:    func(heardHello) []byte { return alert(40) },
			measured: false,
		},
	} {
		var claimed atomic.Uint32
		p, _ := scriptedProber(func(h heardHello) []byte {
			if h.offers(rawhello.FallbackSCSV) {
				claimed.Store(uint32(h.clientVersion))
			}
			return tc.reply(h)
		})

		f := askAll(t, p, results).Fallback
		if f.Measured != tc.measured || f.Honoured != tc.honoured {
			t.Errorf("%s: %+v", name, f)
		}
		if got := uint16(claimed.Load()); got != tls.VersionTLS12 {
			t.Errorf("%s: the downgraded hello claimed %#04x, want TLS 1.2 — the newest version below the newest accepted", name, got)
		}
		if !tc.measured && f.Reason == "" {
			t.Errorf("%s: nothing says why the signal was not established", name)
		}
	}
}

// A server accepting one version has nowhere to be pushed down to, and is not
// asked.
func TestTheFallbackIsNotAskedOfASingleVersion(t *testing.T) {
	var asked atomic.Bool
	p, _ := scriptedProber(func(h heardHello) []byte {
		if h.offers(rawhello.FallbackSCSV) {
			asked.Store(true)
		}
		return alert(40)
	})

	f := askAll(t, p, answered(tls.VersionTLS13)).Fallback
	if asked.Load() {
		t.Error("a downgraded hello was sent to a server that accepts one version")
	}
	if f.Measured || f.Reason == "" {
		t.Errorf("fallback = %+v, want not measured with a reason", f)
	}
}

// Against a real TLS implementation rather than a script.
//
// Every test above asserts that this package reads replies correctly — replies
// this file wrote. This one asks crypto/tls's own server, which was written by
// somebody else to RFC 7507 and refuses SSL 3.0 and every export and NULL suite,
// so an agreement here is two independent readings of the same documents.
func TestAGoServerRefusesTheLegacyAndHonoursTheSignal(t *testing.T) {
	cert, _ := twoCertificates(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
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

	l := askAll(t, p, answered(tls.VersionTLS13, tls.VersionTLS12))
	for name, a := range map[string]LegacyAnswer{"SSL 3.0": l.SSL3, "export": l.Export, "NULL": l.Null} {
		if a.Accepted {
			t.Errorf("%s: crypto/tls was read as accepting it: %+v", name, a)
		}
		if !a.Refused {
			t.Errorf("%s: crypto/tls sends a fatal alert here, and it was read as %+v", name, a)
		}
	}
	if !l.Fallback.Measured || !l.Fallback.Honoured {
		t.Errorf("fallback = %+v; crypto/tls implements RFC 7507 and refuses a downgraded hello", l.Fallback)
	}
}

// What the hellos find can make a verdict worse and never better.
//
// The ordinary handshakes return Ungraded when a suite list was cut short, and
// policy.Worst ignores Ungraded — so a strong answer folded in without care
// would turn "no verdict was reached" into "strong".
func TestLegacyNeverTurnsNoVerdictIntoStrong(t *testing.T) {
	strong := policy.GradeCipher("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	if strong.Verdict != policy.Strong {
		t.Fatalf("the fixture suite grades %q; the test needs a strong one", strong.Verdict)
	}

	l := Legacy{Asked: true, Export: LegacyAnswer{Measured: true, Accepted: true,
		Suite: &CipherResult{CipherFinding: strong}}}

	if verdict, _ := mergeLegacy(policy.Ungraded, nil, l); verdict != policy.Ungraded {
		t.Errorf("an incomplete measurement became %q because a hand-written hello was answered", verdict)
	}
}

// A finding the ordinary handshakes already raised is not raised twice.
func TestALegacyFindingIsCountedOnce(t *testing.T) {
	export := policy.GradeCipher("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA")
	existing := export.Findings

	l := Legacy{Asked: true, Export: LegacyAnswer{Measured: true, Accepted: true,
		Suite: &CipherResult{CipherFinding: export}}}

	_, findings := mergeLegacy(policy.Insecure, existing, l)
	var n int
	for _, f := range findings {
		if f.RuleID == "cipher.export" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("cipher.export appears %d times", n)
	}
}

// No reason carries an address, a resolver or Go's wording (I6).
func TestNoLegacyReasonNamesTheMachine(t *testing.T) {
	for _, err := range []error{
		errors.New("dial tcp 203.0.113.7:443: connect: connection refused"),
		errors.New("read tcp 10.0.0.2:51514->203.0.113.7:443: read: connection reset by peer"),
		errors.New("lookup example.test on 185.12.64.2:53: no such host"),
		rawhello.ErrNotTLS,
		io.EOF,
		context.DeadlineExceeded,
	} {
		reason := legacyReason(err)
		for _, leak := range []string{"203.0.113.7", "10.0.0.2", "185.12.64.2", "dial tcp", "lookup", "rawhello:"} {
			if strings.Contains(reason, leak) {
				t.Errorf("legacyReason(%q) = %q, which carries %q", err, reason, leak)
			}
		}
	}
}

// The whole path, through Probe, for the server this change exists for.
//
// Every test above calls a piece: legacy, mergeLegacy, describeLegacy. None of
// them notices if Probe stops calling one — a sabotage deleting the merge left
// every one of them passing, because each still works when it is called. This
// one drives a real Probe against a scripted server that refuses every hello Go
// sends and accepts only SSL 3.0, and asserts what a reader of the report sees.
func TestProbeReportsAServerSpeakingOnlySSL3(t *testing.T) {
	p, _ := scriptedProber(func(h heardHello) []byte {
		switch {
		case h.clientVersion == policy.VersionSSL30 && h.offers(0x000A):
			return accept(policy.VersionSSL30, 0x000A)
		case h.offers(0xC010):
			// The NULL hello is met with silence, so the report has one
			// question it could not settle and has to say so.
			return nil
		default:
			return alert(40)
		}
	})

	report, err := p.Probe(context.Background(), "example.test", "443")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if report.Verdict != policy.Insecure {
		t.Errorf("verdict = %q; a server speaking SSL 3.0 is insecure, and before this change it was graded nothing", report.Verdict)
	}
	if !slices.Contains(ruleIDs(report.Findings), "version.ssl3") {
		t.Errorf("findings are %v; version.ssl3 is not among them", ruleIDs(report.Findings))
	}
	if !report.Legacy.Asked || !report.Legacy.SSL3.Accepted {
		t.Errorf("legacy = %+v", report.Legacy)
	}

	var unsettledNull, limit bool
	for _, n := range report.Notes {
		if n.Kind == policy.KindUnsettled && strings.Contains(n.Text, "NULL") {
			unsettledNull = true
		}
		if n.Text == policy.LimitCipherSuitesOffered.Text {
			limit = true
		}
	}
	if !unsettledNull {
		t.Error("the NULL question went unanswered and no note says so, so a reader takes silence for a refusal")
	}
	if !limit {
		t.Error("the standing limit bounding what was offered is missing from a report where hellos were answered")
	}

	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var sent map[string]any
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}
	if _, ok := sent["legacy"]; !ok {
		t.Error("the report sends no legacy field, so the page has nothing to draw the SSL 3.0 row from")
	}
}

// The standing limit says what the hand-written hellos ask.
//
// It said SSL 3.0 was not covered for the life of this project, and a limit
// still saying so beside a finding titled SSL 3.0 would be one report
// contradicting itself two inches apart.
func TestTheSuitesLimitSaysWhatTheHandWrittenHelloAsks(t *testing.T) {
	text := policy.LimitCipherSuitesOffered.Text
	for _, want := range []string{"SSL 3.0", "export-grade", "NULL", "finite-field DHE", "anonymous", "hand-written hello", "not every one"} {
		if !strings.Contains(text, want) {
			t.Errorf("the limit does not say %q: %q", want, text)
		}
	}
	if strings.Contains(text, "SSLv3") {
		t.Errorf("the limit still names SSLv3 as uncovered: %q", text)
	}
}

// A server accepting a finite-field DHE or an anonymous suite is graded for it.
//
// Go's client implements no suite of either family, so the ordinary
// enumeration could never list one: a server accepting TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
// beside modern suites was reported strong, and RFC 10015 now says it must not
// select that suite at all. And each is asked with a hello offering only its
// own family, so a server's preference for something sound cannot answer for it.
func TestAFiniteFieldOrAnonymousSuiteAcceptedIsGraded(t *testing.T) {
	for name, tc := range map[string]struct {
		family []rawhello.Suite
		pick   uint16
		rule   string
		answer func(Legacy) LegacyAnswer
	}{
		"DHE":       {rawhello.FFDHE, 0x009E, "cipher.ffdhe", func(l Legacy) LegacyAnswer { return l.FFDHE }},
		"anonymous": {rawhello.Anonymous, 0x0034, "cipher.anonymous", func(l Legacy) LegacyAnswer { return l.Anonymous }},
	} {
		family := rawhello.IDs(tc.family)
		p, _ := scriptedProber(func(h heardHello) []byte {
			if slices.Equal(h.suites, family) {
				return accept(tls.VersionTLS12, tc.pick)
			}
			return alert(40)
		})

		l := askAll(t, p, answered(tls.VersionTLS12))
		got := tc.answer(l)
		if !got.Accepted || got.Suite == nil || got.Suite.ID != tc.pick || got.Suite.Verdict != policy.Insecure {
			t.Errorf("%s: the answer is %+v", name, got)
			continue
		}
		verdict, findings := mergeLegacy(policy.Strong, nil, l)
		if verdict != policy.Insecure || !slices.Contains(ruleIDs(findings), tc.rule) {
			t.Errorf("%s: the report comes back %s with %v, want insecure with %s", name, verdict, ruleIDs(findings), tc.rule)
		}
		for other, a := range map[string]LegacyAnswer{"SSL 3.0": l.SSL3, "export": l.Export, "NULL": l.Null} {
			if a.Accepted {
				t.Errorf("%s: %s was read as accepted from a hello it was not in", name, other)
			}
		}
	}
}

// A DHE or anonymous hello nobody answered is named as not established, like
// the others — nothing reported accepted is not the same as nothing accepted.
//
// A sabotage leaving the DHE question out of that sentence escaped on
// 2026-09-14: the only test of the sentence predates the two families.
func TestAnUnansweredDHEOrAnonymousHelloIsSaidToBeUnsettled(t *testing.T) {
	refused := LegacyAnswer{Measured: true, Refused: true}
	r := &Report{Legacy: Legacy{
		Asked: true, SSL3: refused, Export: refused, Null: refused,
		FFDHE:     LegacyAnswer{Reason: "the server did not answer in time"},
		Anonymous: LegacyAnswer{Reason: "the server did not answer in time"},
		Fallback:  Fallback{Reason: "not asked"},
	}}
	r.describeLegacy()

	var unsettled []string
	for _, n := range r.Notes {
		if n.Kind == policy.KindUnsettled {
			unsettled = append(unsettled, n.Text)
		}
	}
	text := strings.Join(unsettled, "\n")
	for _, want := range []string{"a finite-field DHE suite", "an anonymous suite"} {
		if !strings.Contains(text, want) {
			t.Errorf("the unsettled notes do not name %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "SSL 3.0") {
		t.Errorf("a question that was answered is named as unsettled:\n%s", text)
	}
}

// Where nothing answered, neither family is asked, and each says why.
//
// A sabotage dropping the DHE reason escaped on 2026-09-14: an empty reason
// renders as "not measured" and nothing more, which is a row that explains
// nothing.
func TestNeitherFamilyIsAskedWhenNothingAnswered(t *testing.T) {
	p, dials := scriptedProber(func(heardHello) []byte { return alert(40) })
	l := askAll(t, p, []VersionResult{{Version: tls.VersionTLS12, Name: "TLS 1.2"}})

	if l.Asked || dials.Load() != 0 {
		t.Fatalf("asked=%v after %d connections; nothing answered, so nothing is asked", l.Asked, dials.Load())
	}
	for name, a := range map[string]LegacyAnswer{"DHE": l.FFDHE, "anonymous": l.Anonymous} {
		if a.Reason != notAskedNothingAnswered {
			t.Errorf("%s carries reason %q, want the sentence saying why it was not asked", name, a.Reason)
		}
	}
}
