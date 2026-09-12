package dnsclient

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// connFor answers with the type asked for, rather than always CAA.
//
// fakeResolver.conn was written when CAA was the only type with a parser, and
// it builds every reply as one. A reply whose answer section is labelled with
// the wrong type is a reply parseAnswers skips entirely, so a test using it for
// MX would assert that nothing was found and pass.
func (f *fakeResolver) connFor(t *testing.T, qtype uint16) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()

	return func(_ context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()

		go func() {
			defer server.Close() //nolint:errcheck // the test half of a pipe

			buf := make([]byte, udpPayload)
			n, err := server.Read(buf)
			if err != nil || n < headerLen {
				return
			}
			raw := buf[:n]

			end, err := skipName(raw, headerLen)
			if err != nil {
				return
			}
			question := raw[headerLen:end]
			asked := lowerName(readableName(question))
			f.asked = append(f.asked, asked)

			flags := uint16(flagsAnswerValidated)
			if f.missing[asked] {
				flags = 0x8183 // NXDOMAIN
			}

			_, _ = server.Write(message(
				binary.BigEndian.Uint16(raw[0:2]),
				flags,
				question,
				qtype,
				f.answers[asked]...,
			))
		}()

		return client, nil
	}
}

// mxRecord builds one MX in wire form: a preference and an uncompressed name.
func mxRecord(t *testing.T, pref uint16, host string) []byte {
	t.Helper()

	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, pref)

	encoded, err := encodeName(host, false)
	if err != nil {
		t.Fatalf("test data is wrong: encoding %q: %v", host, err)
	}
	return append(out, encoded...)
}

func tlsaRecord(usage, selector, matching byte, data ...byte) []byte {
	return append([]byte{usage, selector, matching}, data...)
}

func answering(t *testing.T, qtype uint16, at string, records ...record) *Client {
	t.Helper()

	fake := &fakeResolver{answers: map[string][]record{lowerName(at): records}}
	return &Client{Server: "resolver.invalid:53", Dial: fake.connFor(t, qtype)}
}

// The exchangers come back with their preferences.
func TestTheMailExchangersAreRead(t *testing.T) {
	q := name(t, "example.com")
	c := answering(t, TypeMX, "example.com",
		record{q, TypeMX, mxRecord(t, 10, "mx1.example.net")},
		record{q, TypeMX, mxRecord(t, 20, "mx2.example.net")},
	)

	got, err := c.LookupMX(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupMX: %v", err)
	}
	if len(got.Records) != 2 {
		t.Fatalf("got %+v", got.Records)
	}
	if got.Records[0].Preference != 10 || got.Records[0].Host != "mx1.example.net" {
		t.Errorf("first exchanger is %+v", got.Records[0])
	}
	if got.Records[1].Preference != 20 || got.Records[1].Host != "mx2.example.net" {
		t.Errorf("second exchanger is %+v", got.Records[1])
	}
}

// A null MX is a statement, not an empty field.
//
// RFC 7505: a single "." says the domain accepts no mail at all. An empty host
// would read as a record nobody could parse, which is the opposite of what the
// domain is saying.
func TestANullMXIsReadAsOne(t *testing.T) {
	q := name(t, "example.com")
	c := answering(t, TypeMX, "example.com",
		record{q, TypeMX, mxRecord(t, 0, "")},
	)

	got, err := c.LookupMX(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupMX: %v", err)
	}
	if len(got.Records) != 1 {
		t.Fatalf("got %+v", got.Records)
	}
	if got.Records[0].Host != "." {
		t.Errorf("the null MX came back as %q, want %q", got.Records[0].Host, ".")
	}
}

// A name from a resolver is bounded and stripped (N5, I5).
func TestAHostileExchangerNameIsStripped(t *testing.T) {
	q := name(t, "example.com")
	c := answering(t, TypeMX, "example.com",
		record{q, TypeMX, mxRecord(t, 10, "MX\r\n<b>.example")},
	)

	got, err := c.LookupMX(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupMX: %v", err)
	}
	if len(got.Records) != 1 {
		t.Fatalf("got %+v", got.Records)
	}
	host := got.Records[0].Host
	for _, bad := range []string{"\r", "\n", "<", ">"} {
		if strings.Contains(host, bad) {
			t.Errorf("%q survived into %q, which forges a line in a terminal report", bad, host)
		}
	}
	if strings.ContainsAny(host, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Errorf("%q was not folded, so two spellings of one host compare as two (I7)", host)
	}
}

// An enormous name is bounded before it travels.
//
// Built byte by byte rather than through encodeName, which refuses a name this
// long — correctly, because that is the encoder for questions this client asks.
// A resolver answering is under no such restraint, and what it sends is exactly
// what N5 says to treat as hostile.
func TestAnEnormousExchangerNameIsBounded(t *testing.T) {
	rdata := []byte{0, 10}
	for range 20 {
		rdata = append(rdata, 31)
		rdata = append(rdata, []byte(strings.Repeat("a", 31))...)
	}
	rdata = append(rdata, 0)

	q := name(t, "example.com")
	c := answering(t, TypeMX, "example.com",
		record{q, TypeMX, rdata},
	)

	// Refused outright rather than truncated, because readName already bounds
	// a name while decoding it. That is the stronger answer: a reply carrying a
	// name no name may be is a reply this client does not believe, and reading
	// part of it would be reporting a host the domain never named.
	if _, err := c.LookupMX(context.Background(), "example.com"); err == nil {
		t.Error("a reply carrying a name longer than a name may be was accepted")
	}
}

// nameText bounds what it is given, even though readName gets there first.
//
// Two guards for one property, and the second is not ceremony: readName's bound
// is about decoding a message, nameText's is about what may reach a report, and
// they are changed by different people for different reasons. A test that only
// went through the reader would leave the reporting bound unexercised and free
// to be deleted.
func TestTheNameRendererBoundsWhatItIsGiven(t *testing.T) {
	var encoded []byte
	for range 20 {
		encoded = append(encoded, 31)
		encoded = append(encoded, []byte(strings.Repeat("a", 31))...)
	}

	if got := nameText(encoded); len(got) > maxNameLength {
		t.Errorf("nameText returned %d bytes, and the bound is %d", len(got), maxNameLength)
	}
}

// The root name is the null MX's statement rather than an empty string.
func TestTheRootNameIsReadableAsItself(t *testing.T) {
	if got := nameText([]byte{0}); got != "." {
		t.Errorf("the root came back as %q, want %q", got, ".")
	}
	if got := nameText(nil); got != "." {
		t.Errorf("an empty name came back as %q, want %q", got, ".")
	}
}

// The DANE selectors are read and the association data is not kept.
//
// Keeping the data would invite a report claiming the binding was checked, and
// checking it needs a certificate from the mail host — which needs a connection
// the mail check does not make (N13).
func TestTheDANESelectorsAreReadAndTheDataIsNot(t *testing.T) {
	q := name(t, "_25._tcp.mx1.example.net")
	c := answering(t, TypeTLSA, "_25._tcp.mx1.example.net",
		record{q, TypeTLSA, tlsaRecord(3, 1, 1, 0xde, 0xad, 0xbe, 0xef)},
	)

	got, err := c.LookupTLSA(context.Background(), "_25._tcp.mx1.example.net")
	if err != nil {
		t.Fatalf("LookupTLSA: %v", err)
	}
	if len(got.Records) != 1 {
		t.Fatalf("got %+v", got.Records)
	}
	if r := got.Records[0]; r.Usage != 3 || r.Selector != 1 || r.Matching != 1 {
		t.Errorf("selectors are %+v", r)
	}
}

// A name that does not exist is not a name with no records (R4).
func TestANameWithNoMXIsNotANameThatDoesNotExist(t *testing.T) {
	fake := &fakeResolver{
		answers: map[string][]record{},
		missing: map[string]bool{"gone.example": true},
	}
	c := &Client{Server: "resolver.invalid:53", Dial: fake.connFor(t, TypeMX)}

	missing, err := c.LookupMX(context.Background(), "gone.example")
	if err != nil {
		t.Fatalf("LookupMX: %v", err)
	}
	if missing.Existed {
		t.Error("a name the resolver says does not exist came back as existing")
	}

	quiet, err := answering(t, TypeMX, "quiet.example").
		LookupMX(context.Background(), "quiet.example")
	if err != nil {
		t.Fatalf("LookupMX: %v", err)
	}
	if !quiet.Existed {
		t.Error("a name that exists and publishes no MX came back as not existing, which is a " +
			"different fact and sends a reader somewhere else")
	}
	if len(quiet.Records) != 0 {
		t.Errorf("got %+v", quiet.Records)
	}
}

// A truncated record is refused rather than read as zeros.
func TestAShortMailRecordIsRefused(t *testing.T) {
	q := name(t, "example.com")
	c := answering(t, TypeMX, "example.com",
		record{q, TypeMX, []byte{0x00}},
	)
	if _, err := c.LookupMX(context.Background(), "example.com"); err == nil {
		t.Error("an MX record shorter than its own header was accepted")
	}

	d := answering(t, TypeTLSA, "_25._tcp.example.com",
		record{name(t, "_25._tcp.example.com"), TypeTLSA, []byte{3, 1}},
	)
	if _, err := d.LookupTLSA(context.Background(), "_25._tcp.example.com"); err == nil {
		t.Error("a TLSA record shorter than its own header was accepted")
	}
}

// cnameRecord builds one CNAME in wire form: an uncompressed target name.
func cnameRecord(t *testing.T, target string) []byte {
	t.Helper()

	encoded, err := encodeName(target, false)
	if err != nil {
		t.Fatalf("test data is wrong: encoding %q: %v", target, err)
	}
	return encoded
}

// answeringMany serves a reply built from records at several names.
func answeringMany(t *testing.T, qtype uint16, at string, records ...record) *Client {
	t.Helper()

	fake := &fakeResolver{answers: map[string][]record{lowerName(at): records}}
	return &Client{Server: "resolver.invalid:53", Dial: fake.connFor(t, qtype)}
}

// A record reached through a CNAME answers the question.
//
// The case that made DKIM useless. Most mail providers publish a signing key as
// a CNAME into their own zone, so a resolver returns the alias and the TXT at
// its target — and the target's owner name is not the one that was asked about.
// Accepting only the question's name saw the alias and nothing else, and the
// report said the key could not be read.
func TestARecordReachedThroughACNAMEIsRead(t *testing.T) {
	asked := name(t, "key1._domainkey.example.com")
	target := name(t, "key1.example.com._domainkey.provider.example")

	c := answeringMany(t, TypeTXT, "key1._domainkey.example.com",
		record{asked, TypeCNAME, cnameRecord(t, "key1.example.com._domainkey.provider.example")},
		record{target, TypeTXT, txtRecord("v=DKIM1; k=rsa; p=AAAA")},
	)

	got, err := c.LookupTXT(context.Background(), "key1._domainkey.example.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if len(got.Values) != 1 || !strings.Contains(got.Values[0], "DKIM1") {
		t.Errorf("the record behind the alias was not read: %+v", got.Values)
	}
}

// A record for a name nothing points at is still skipped.
//
// The property the owner check exists for, and the one the CNAME chain must not
// cost. A resolver is hostile (N5) and a reply may carry records for any name it
// likes; what is accepted is the chain the reply itself draws from the question,
// never whatever else happens to be in the section.
func TestARecordForAnUnrelatedNameIsStillSkipped(t *testing.T) {
	elsewhere := name(t, "somewhere.else.example")

	c := answeringMany(t, TypeTXT, "key1._domainkey.example.com",
		record{elsewhere, TypeTXT, txtRecord("v=DKIM1; k=rsa; p=INJECTED")},
	)

	got, err := c.LookupTXT(context.Background(), "key1._domainkey.example.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if len(got.Values) != 0 {
		t.Errorf("a record for a name nothing pointed at was accepted: %+v", got.Values)
	}
}

// A CNAME chain that loops ends rather than running forever.
func TestACNAMELoopEnds(t *testing.T) {
	a := name(t, "a.example.com")
	b := name(t, "b.example.com")

	c := answeringMany(t, TypeTXT, "a.example.com",
		record{a, TypeCNAME, cnameRecord(t, "b.example.com")},
		record{b, TypeCNAME, cnameRecord(t, "a.example.com")},
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.LookupTXT(context.Background(), "a.example.com")
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a CNAME pointing back at itself did not end")
	}
}

// txtRecord builds one TXT in wire form: length-prefixed character strings.
func txtRecord(values ...string) []byte {
	var out []byte
	for _, v := range values {
		for len(v) > 255 {
			out = append(out, 255)
			out = append(out, v[:255]...)
			v = v[255:]
		}
		out = append(out, byte(len(v)))
		out = append(out, v...)
	}
	return out
}
