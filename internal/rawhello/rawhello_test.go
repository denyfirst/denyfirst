package rawhello

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// record wraps a payload in a record header.
func record(content byte, payload []byte) []byte {
	out := []byte{content, 3, 1}
	out = binary.BigEndian.AppendUint16(out, uint16(len(payload)))
	return append(out, payload...)
}

// serverHello builds a ServerHello record choosing one version and one suite.
func serverHello(version, suite uint16, sessionID int) []byte {
	body := binary.BigEndian.AppendUint16(nil, version)
	body = append(body, make([]byte, 32)...)
	body = append(body, byte(sessionID))
	body = append(body, make([]byte, sessionID)...)
	body = binary.BigEndian.AppendUint16(body, suite)
	body = append(body, 0)
	msg := append([]byte{typeServerHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return record(contentHandshake, msg)
}

// parsedHello is what a server would read out of a hello.
type parsedHello struct {
	recordType    byte
	recordVersion uint16
	clientVersion uint16
	random        []byte
	suites        []uint16
	compression   []byte
	extensions    map[uint16][]byte
}

// parseHello reads a hello the way a server does, and fails the test on any
// length that does not add up. Written independently of Marshal, so that the
// two agreeing means the wire format is right rather than that one function was
// read back by its own inverse.
func parseHello(t *testing.T, raw []byte) parsedHello {
	t.Helper()
	var p parsedHello

	if len(raw) < 5 {
		t.Fatalf("a hello of %d bytes has no record header", len(raw))
	}
	p.recordType = raw[0]
	p.recordVersion = binary.BigEndian.Uint16(raw[1:3])
	if got := int(binary.BigEndian.Uint16(raw[3:5])); got != len(raw)-5 {
		t.Fatalf("record length says %d and %d bytes follow", got, len(raw)-5)
	}

	msg := raw[5:]
	if msg[0] != typeClientHello {
		t.Fatalf("handshake type %d, want client_hello", msg[0])
	}
	if got := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3]); got != len(msg)-4 {
		t.Fatalf("handshake length says %d and %d bytes follow", got, len(msg)-4)
	}

	b := msg[4:]
	p.clientVersion = binary.BigEndian.Uint16(b[0:2])
	p.random = b[2:34]
	sid := int(b[34])
	b = b[35+sid:]

	n := int(binary.BigEndian.Uint16(b[0:2]))
	for i := 0; i < n; i += 2 {
		p.suites = append(p.suites, binary.BigEndian.Uint16(b[2+i:4+i]))
	}
	b = b[2+n:]

	c := int(b[0])
	p.compression = b[1 : 1+c]
	b = b[1+c:]

	p.extensions = map[uint16][]byte{}
	if len(b) == 0 {
		return p
	}
	total := int(binary.BigEndian.Uint16(b[0:2]))
	if total != len(b)-2 {
		t.Fatalf("extensions length says %d and %d bytes follow", total, len(b)-2)
	}
	b = b[2:]
	for len(b) > 0 {
		kind := binary.BigEndian.Uint16(b[0:2])
		size := int(binary.BigEndian.Uint16(b[2:4]))
		p.extensions[kind] = b[4 : 4+size]
		b = b[4+size:]
	}
	return p
}

// The hello is what RFC 5246 says a hello is, byte for byte.
func TestTheHelloIsWhatTheWireFormatSays(t *testing.T) {
	suites := []uint16{0x0003, 0x0008, 0x0014}
	raw, err := Hello{RecordVersion: 0x0301, ClientVersion: 0x0303, Suites: suites,
		Extensions: true, ServerName: "example.test"}.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	p := parseHello(t, raw)
	if p.recordType != contentHandshake || p.recordVersion != 0x0301 || p.clientVersion != 0x0303 {
		t.Errorf("record %d version %#04x, hello claims %#04x", p.recordType, p.recordVersion, p.clientVersion)
	}
	if len(p.suites) != len(suites) {
		t.Fatalf("offered %v, want %v", p.suites, suites)
	}
	for i := range suites {
		if p.suites[i] != suites[i] {
			t.Errorf("suite %d is %#04x, want %#04x", i, p.suites[i], suites[i])
		}
	}
	if !bytes.Equal(p.compression, []byte{0}) {
		t.Errorf("compression methods %v, want null alone: offering DEFLATE asks about CRIME", p.compression)
	}
	for _, kind := range []uint16{0x0000, 0x000a, 0x000b, 0x000d} {
		if _, ok := p.extensions[kind]; !ok {
			t.Errorf("extension %#04x is missing; without supported_groups and ec_point_formats a "+
				"server cannot choose an elliptic-curve suite at all", kind)
		}
	}
	if sni := p.extensions[0x0000]; !bytes.Contains(sni, []byte("example.test")) {
		t.Errorf("server_name carries %q", sni)
	}
}

// An SSL 3.0 hello carries no extensions.
//
// The question is whether a server speaks SSL 3.0, not whether it survives bytes
// from a later protocol. A hello that failed for the second reason would be
// reported as a server that does not speak the first.
func TestAnSSL3HelloCarriesNoExtensions(t *testing.T) {
	raw, err := Hello{RecordVersion: 0x0300, ClientVersion: 0x0300, Suites: IDs(SSL3)}.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	p := parseHello(t, raw)
	if len(p.extensions) != 0 {
		t.Errorf("an SSL 3.0 hello carries extensions %v", p.extensions)
	}
	if p.recordVersion != 0x0300 || p.clientVersion != 0x0300 {
		t.Errorf("record %#04x, hello %#04x; want SSL 3.0 on both", p.recordVersion, p.clientVersion)
	}
}

// Two hellos do not share a random.
//
// A fixed random is a fingerprint: every server this scanned would see the same
// thirty-two bytes, and anybody comparing logs could tell which connections came
// from this tool. A zeroed one is worse, and several scanners have shipped it.
func TestEveryHelloHasItsOwnRandom(t *testing.T) {
	h := Hello{RecordVersion: 0x0301, ClientVersion: 0x0303, Suites: []uint16{0x0001}}
	a, _ := h.Marshal()
	b, _ := h.Marshal()

	ra, rb := parseHello(t, a).random, parseHello(t, b).random
	if bytes.Equal(ra, rb) {
		t.Error("two hellos carry the same random")
	}
	if bytes.Equal(ra, make([]byte, 32)) {
		t.Error("the random is all zeroes")
	}
}

// An address is never sent as a server name, and nor is anything a hostname
// cannot hold.
func TestOnlyAHostnameIsSentAsAServerName(t *testing.T) {
	for name, sent := range map[string]bool{
		"example.test":             true,
		"example.test.":            true,
		"203.0.113.9":              false,
		"2001:db8::1":              false,
		"":                         false,
		"example.test\r\nX: y":     false,
		"exa mple.test":            false,
		strings.Repeat("a", 254):   false,
		"xn--nxasmq6b.example.com": true,
	} {
		raw, err := Hello{RecordVersion: 0x0301, ClientVersion: 0x0303, Suites: []uint16{1},
			Extensions: true, ServerName: name}.Marshal()
		if err != nil {
			t.Fatalf("Marshal(%q): %v", name, err)
		}
		_, got := parseHello(t, raw).extensions[0x0000]
		if got != sent {
			t.Errorf("server name %q sent = %v, want %v", name, got, sent)
		}
	}
}

// A hello that is not one is not sent.
func TestAMalformedHelloIsRefusedBeforeItIsSent(t *testing.T) {
	for name, h := range map[string]Hello{
		"no suites":       {RecordVersion: 0x0301, ClientVersion: 0x0303},
		"too many suites": {RecordVersion: 0x0301, ClientVersion: 0x0303, Suites: make([]uint16, maxSuites+1)},
		"not a version":   {RecordVersion: 0x0301, ClientVersion: 0x0200, Suites: []uint16{1}},
	} {
		if _, err := h.Marshal(); err == nil {
			t.Errorf("%s: a hello was built", name)
		}
	}
}

// A ServerHello is an acceptance, and its choices are read.
func TestAServerHelloIsReadAsAnAcceptance(t *testing.T) {
	for _, sid := range []int{0, 32} {
		got := ReadReply(bytes.NewReader(serverHello(0x0300, 0x000A, sid)))
		if got.Answer != Accepted || got.Version != 0x0300 || got.Suite != 0x000A {
			t.Errorf("session id %d: %+v, want accepted at SSL 3.0 with 0x000A", sid, got)
		}
	}
}

// A fatal alert is a refusal, and a warning is not.
//
// close_notify arrives as a warning. Reading it as a refusal would record a
// server hanging up as a server saying no, which is the flattering direction.
func TestOnlyAFatalAlertIsARefusal(t *testing.T) {
	fatal := ReadReply(bytes.NewReader(record(contentAlert, []byte{alertFatal, 40})))
	if fatal.Answer != Refused || fatal.Alert != 40 {
		t.Errorf("a fatal handshake_failure read as %+v", fatal)
	}

	warning := ReadReply(bytes.NewReader(record(contentAlert, []byte{1, 0})))
	if warning.Answer == Refused {
		t.Error("a warning-level close_notify was read as a refusal")
	}
}

// Silence is not a refusal (R4).
func TestSilenceIsNotARefusal(t *testing.T) {
	for name, reply := range map[string][]byte{
		"closed":         nil,
		"closed mid-way": serverHello(0x0301, 0x0003, 0)[:9],
	} {
		got := ReadReply(bytes.NewReader(reply))
		if got.Answer != Unanswered {
			t.Errorf("%s: read as %s", name, got.Answer)
		}
	}
}

// What is not TLS is not an answer, whatever it happens to begin with.
func TestAReplyThatIsNotTLSIsNotBelieved(t *testing.T) {
	huge := []byte{contentHandshake, 3, 1, 0xFF, 0xFF}

	for name, reply := range map[string][]byte{
		"an HTTP error page":         []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
		"an oversized record":        huge,
		"an empty record":            {contentHandshake, 3, 1, 0, 0},
		"application data":           record(23, []byte("hello")),
		"a certificate, not a hello": record(contentHandshake, []byte{11, 0, 0, 40, 0, 0, 0, 0}),
	} {
		got := ReadReply(bytes.NewReader(reply))
		if got.Answer != Unanswered {
			t.Errorf("%s: read as %s", name, got.Answer)
		}
	}
}

// A session id longer than the protocol allows is not believed.
//
// The length byte is the server's to choose. Believing 200 would be skipping
// bytes on the server's say-so and reading a suite from wherever that lands.
func TestAnOversizedSessionIDIsNotBelieved(t *testing.T) {
	got := ReadReply(bytes.NewReader(serverHello(0x0303, 0x0003, 200)))
	if got.Answer == Accepted {
		t.Errorf("a ServerHello with a 200-byte session id was read as choosing %#04x", got.Suite)
	}
}

// A ServerHello that runs on into a second record is not guessed at.
func TestAServerHelloSplitAcrossRecordsIsNotGuessed(t *testing.T) {
	whole := serverHello(0x0303, 0x0003, 32)
	payload := whole[5:]
	first := record(contentHandshake, payload[:20])
	second := record(contentHandshake, payload[20:])

	got := ReadReply(bytes.NewReader(append(first, second...)))
	if got.Answer == Accepted {
		t.Errorf("half a ServerHello was read as choosing %#04x", got.Suite)
	}
	if !errors.Is(got.Err, ErrSplit) {
		t.Errorf("err = %v, want the split to be named", got.Err)
	}
}

// countingReader counts what is taken from it.
type countingReader struct {
	r    io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

// No more is read than the answer needs.
//
// A server may send a certificate chain of many kilobytes straight after its
// hello. None of it is wanted, and reading it would be parsing input from the
// scanned party for no reason (N11 is about exactly that).
func TestNoMoreIsReadThanTheAnswerNeeds(t *testing.T) {
	reply := serverHello(0x0303, 0x0003, 32)
	reply = append(reply, record(contentHandshake, bytes.Repeat([]byte{0x41}, 16000))...)

	c := &countingReader{r: bytes.NewReader(reply)}
	if got := ReadReply(c); got.Answer != Accepted {
		t.Fatalf("read as %+v", got)
	}
	if limit := 5 + 4 + serverHelloFixed + maxSessionID + 2; c.read > limit {
		t.Errorf("%d bytes were read, and the answer needs at most %d", c.read, limit)
	}
}

// Ask talks over the connection it is given.
func TestAskSendsTheHelloAndReadsTheAnswer(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		header := make([]byte, 5)
		if _, err := io.ReadFull(server, header); err != nil {
			return
		}
		rest := make([]byte, binary.BigEndian.Uint16(header[3:5]))
		if _, err := io.ReadFull(server, rest); err != nil {
			return
		}
		_, _ = server.Write(serverHello(0x0301, 0x0014, 0))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got := Ask(ctx, client, Hello{RecordVersion: 0x0301, ClientVersion: 0x0303, Suites: IDs(Export)})
	if got.Answer != Accepted || got.Suite != 0x0014 || got.Version != 0x0301 {
		t.Errorf("got %+v", got)
	}
}

// A server that accepts the connection and says nothing is given until the
// deadline and not a moment longer.
func TestAskStopsWhenTheContextDoes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() { _, _ = io.Copy(io.Discard, server) }()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	// In a goroutine, with a bound of its own. This called Ask directly until
	// 2026-09-13, and a sabotage removing both the deadline and the
	// cancellation did not fail it — it hung it, for the ten minutes go test
	// allows, which the sabotage harness could not read as a failure and a
	// person waiting on CI reads as a broken runner. A test of whether
	// something stops has to be able to stop itself.
	done := make(chan Result, 1)
	go func() {
		done <- Ask(ctx, client, Hello{RecordVersion: 0x0301, ClientVersion: 0x0303, Suites: IDs(Null)})
	}()

	select {
	case got := <-done:
		if got.Answer != Unanswered {
			t.Errorf("a server that said nothing was read as %s", got.Answer)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Ask kept waiting on a silent server past its deadline")
	}
}

// Every name is the registry's, and grades the way its family should.
//
// internal/policy grades by name. A typo in one of these would not fail to
// compile; it would grade an export suite as merely not current practice.
func TestEveryNameGradesAsItsFamily(t *testing.T) {
	seen := map[uint16]string{}
	check := func(list []Suite, family, ruleID string) {
		for _, s := range list {
			if other, ok := seen[s.ID]; ok && other != s.Name {
				t.Errorf("%#04x is named both %s and %s", s.ID, other, s.Name)
			}
			seen[s.ID] = s.Name

			if !strings.Contains(s.Name, family) {
				t.Errorf("%s is in the %s list and its name does not say so", s.Name, family)
			}
			got := policy.GradeCipher(s.Name)
			if got.Verdict != policy.Insecure {
				t.Errorf("%s grades %s, want insecure", s.Name, got.Verdict)
			}
			var ids []string
			for _, f := range got.Findings {
				ids = append(ids, f.RuleID)
			}
			if ruleID != "" && !strings.Contains(strings.Join(ids, " "), ruleID) &&
				!strings.Contains(strings.Join(ids, " "), "cipher.anonymous") {
				t.Errorf("%s raises %v, want %s", s.Name, ids, ruleID)
			}
		}
	}
	check(Export, "EXPORT", "cipher.export")
	check(Null, "NULL", "cipher.null")
	check(FFDHE, "_DHE_", "cipher.ffdhe")
	check(Anonymous, "_anon_", "cipher.anonymous")

	all := append(slices.Clone(SSL3), FFDHE...)
	all = append(all, Anonymous...)
	for _, s := range append(all, TLS13...) {
		if Name(s.ID) != s.Name {
			t.Errorf("Name(%#04x) = %q, want %q", s.ID, Name(s.ID), s.Name)
		}
	}
	// 0xCCA8 is a real suite, and not one this package offers.
	if Name(0xCCA8) != "" {
		t.Error("a suite this package never offers was given a name")
	}

	// Every TLS 1.3 name is one internal/policy reads as a TLS 1.3 suite:
	// ephemeral key exchange. A misspelling would fall through to the rules for
	// names it cannot read.
	for _, s := range TLS13 {
		if s.ID == seenAsOther(seen, s) {
			t.Errorf("%#04x is also in another list", s.ID)
		}
		if p := policy.DescribeCipher(s.Name); !p.ForwardSecret || p.KeyExchange != "ephemeral" {
			t.Errorf("%s is not read as a TLS 1.3 suite: %+v", s.Name, p)
		}
	}
}

// seenAsOther returns the suite's ID when another list already holds it.
func seenAsOther(seen map[uint16]string, s Suite) uint16 {
	if _, ok := seen[s.ID]; ok {
		return s.ID
	}
	return 0
}

// serverHelloWith builds a ServerHello record with a random and an extension
// block of the caller's choosing.
func serverHelloWith(version, suite uint16, random, ext []byte) []byte {
	body := binary.BigEndian.AppendUint16(nil, version)
	body = append(body, random...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, suite)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	msg := append([]byte{typeServerHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return record(contentHandshake, msg)
}

// supportedTLS13 is a supported_versions extension naming TLS 1.3.
var supportedTLS13 = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}

// A TLS 1.3 hello names TLS 1.3 and carries a key share a server can use.
//
// Without supported_versions a server answers at TLS 1.2 and a TLS 1.3 suite
// is never chosen; without a key share on a group it supports, RFC 8446 has it
// send an alert or a retry. Either would be read as something about the suite.
func TestATLS13HelloNamesTLS13AndCarriesAKeyShare(t *testing.T) {
	h := Hello{RecordVersion: 0x0301, ClientVersion: 0x0303, Suites: []uint16{0x1301}, TLS13: true, ServerName: "example.test"}
	a, err := h.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	b, _ := h.Marshal()

	pa, pb := parseHello(t, a), parseHello(t, b)
	if pa.clientVersion != 0x0303 {
		t.Errorf("legacy_version %#04x, want TLS 1.2 as RFC 8446 says", pa.clientVersion)
	}
	if !bytes.Equal(pa.extensions[0x002b], []byte{2, 0x03, 0x04}) {
		t.Errorf("supported_versions is %x, want TLS 1.3 alone", pa.extensions[0x002b])
	}
	share := pa.extensions[0x0033]
	if len(share) != 2+2+2+32 || binary.BigEndian.Uint16(share[2:4]) != 0x001d || binary.BigEndian.Uint16(share[4:6]) != 32 {
		t.Fatalf("key_share is %x, want one X25519 share of 32 bytes", share)
	}
	if bytes.Equal(share[6:], make([]byte, 32)) {
		t.Error("the key share is all zeroes, which no server accepts and every log would recognise")
	}
	if bytes.Equal(share, pb.extensions[0x0033]) {
		t.Error("two hellos carry the same key share, which is a fingerprint")
	}
	if _, ok := pa.extensions[0x0000]; !ok {
		t.Error("a TLS 1.3 hello carries no server name")
	}
}

// An ordinary hello does not claim TLS 1.3. A TLS 1.2 question with
// supported_versions in it would be answered at TLS 1.3 by a modern server, and
// read as its answer to the question asked.
func TestAnOrdinaryHelloDoesNotClaimTLS13(t *testing.T) {
	raw, err := Hello{RecordVersion: 0x0301, ClientVersion: 0x0303, Suites: []uint16{0x0003}, Extensions: true}.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	p := parseHello(t, raw)
	for _, kind := range []uint16{0x002b, 0x0033} {
		if _, ok := p.extensions[kind]; ok {
			t.Errorf("a TLS 1.2 hello carries extension %#04x", kind)
		}
	}
}

// The version supported_versions names is the version, and a HelloRetryRequest
// still chooses the suite.
func TestTheVersionSupportedVersionsNamesIsRead(t *testing.T) {
	got := ReadReply(bytes.NewReader(serverHelloWith(0x0303, 0x1302, make([]byte, 32), supportedTLS13)))
	if got.Answer != Accepted || got.Version != 0x0304 || got.Suite != 0x1302 || got.RetryRequest {
		t.Errorf("a TLS 1.3 ServerHello read as %+v", got)
	}

	retry := ReadReply(bytes.NewReader(serverHelloWith(0x0303, 0x1303, helloRetryRandom[:], supportedTLS13)))
	if retry.Answer != Accepted || retry.Version != 0x0304 || retry.Suite != 0x1303 || !retry.RetryRequest {
		t.Errorf("a HelloRetryRequest read as %+v; the server chose the suite and asked for another key share", retry)
	}

	// And a ServerHello with no extensions is what it always was.
	plain := ReadReply(bytes.NewReader(serverHello(0x0303, 0xC02F, 0)))
	if plain.Answer != Accepted || plain.Version != 0x0303 {
		t.Errorf("a TLS 1.2 ServerHello read as %+v", plain)
	}
}

// An extension block that does not add up is not believed, and the answer
// stands at its legacy version rather than being refused: a server that
// answered a TLS 1.2 question is recorded as it was before this was read.
func TestAnExtensionBlockThatDoesNotAddUpLeavesTheLegacyVersion(t *testing.T) {
	body := binary.BigEndian.AppendUint16(nil, 0x0303)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, 0x1301)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, 100) // claims 100, carries 6
	body = append(body, supportedTLS13...)
	msg := append([]byte{typeServerHello, 0, 0, byte(len(body))}, body...)

	got := ReadReply(bytes.NewReader(record(contentHandshake, msg)))
	if got.Answer != Accepted || got.Version != 0x0303 {
		t.Errorf("an extension block claiming more than it carries read as %+v", got)
	}

	inner := append([]byte{0x00, 0x2b, 0x00, 0x09}, 0x03, 0x04) // an extension claiming 9 bytes of 2
	if got := ReadReply(bytes.NewReader(serverHelloWith(0x0303, 0x1301, make([]byte, 32), inner))); got.Version != 0x0303 {
		t.Errorf("an extension claiming more than the block holds read as %+v", got)
	}
}

// Extensions past the bound are not read, whatever they would have said.
func TestExtensionsPastTheBoundAreNotRead(t *testing.T) {
	filler := append([]byte{0xff, 0xff}, binary.BigEndian.AppendUint16(nil, uint16(maxExtensions))...)
	filler = append(filler, make([]byte, maxExtensions)...)
	reply := serverHelloWith(0x0303, 0x1301, make([]byte, 32), append(filler, supportedTLS13...))

	c := &countingReader{r: bytes.NewReader(reply)}
	got := ReadReply(c)
	if got.Version != 0x0303 {
		t.Errorf("a version past the bound was read: %+v", got)
	}
	if limit := 5 + 4 + serverHelloFixed + maxSessionID + 2 + 3 + maxExtensions; c.read > limit {
		t.Errorf("%d bytes were read, past the bound of %d", c.read, limit)
	}
}

// A record claiming a version outside 3.x is not believed, however well formed.
//
// The inputs above that are not TLS all fail for a second reason too — an HTTP
// page is not a handshake record at all — so a sabotage removing the version
// check escaped every one of them on 2026-09-13. This reply is a perfect
// ServerHello in every byte but that one.
func TestARecordFromAnotherProtocolVersionIsNotBelieved(t *testing.T) {
	reply := serverHello(0x0303, 0x0003, 0)
	reply[1] = 2

	if got := ReadReply(bytes.NewReader(reply)); got.Answer == Accepted {
		t.Errorf("a record claiming version 2.x was read as choosing %#04x", got.Suite)
	}
}

// A record header claiming more than a record may hold is not believed, even
// when a real hello follows it.
//
// The oversized input above is followed by nothing, so it fails whether or not
// the length is checked. This one is followed by everything a reader would need
// to be fooled.
func TestAnOversizedRecordIsNotBelievedWhateverFollows(t *testing.T) {
	reply := serverHello(0x0303, 0x0003, 0)
	binary.BigEndian.PutUint16(reply[3:5], maxRecord+1)

	if got := ReadReply(bytes.NewReader(reply)); got.Answer == Accepted {
		t.Errorf("a record claiming %d bytes was believed and read as choosing %#04x", maxRecord+1, got.Suite)
	}
}

// Only a ServerHello is an acceptance.
//
// A certificate message laid out like a hello would otherwise be read as one:
// the bytes after its header land where the version and suite would be. The
// short certificate above is refused for being short, which hid that.
func TestOnlyAServerHelloIsAnAcceptance(t *testing.T) {
	reply := serverHello(0x0303, 0x0003, 0)
	reply[5] = 11 // certificate, not server_hello

	if got := ReadReply(bytes.NewReader(reply)); got.Answer == Accepted {
		t.Errorf("a certificate message was read as a ServerHello choosing %#04x", got.Suite)
	}
}

// A cancelled scan stops asking, even where nothing set a deadline.
//
// TestAskStopsWhenTheContextDoes gives its context a deadline, and the deadline
// alone stops Ask — so it passes whether or not cancellation is wired in. A
// scan cancelled by the service shutting down, or by the person who started it,
// has no deadline to fall back on.
func TestAskStopsWhenTheContextIsCancelledWithoutADeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() { _, _ = io.Copy(io.Discard, server) }()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel)

	done := make(chan Result, 1)
	go func() {
		done <- Ask(ctx, client, Hello{RecordVersion: 0x0301, ClientVersion: 0x0303, Suites: IDs(Null)})
	}()

	select {
	case got := <-done:
		if got.Answer != Unanswered {
			t.Errorf("a cancelled question was read as %s", got.Answer)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Ask kept waiting on a silent server after the scan was cancelled")
	}
}
