package dnsclient

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// ── Builders, matching what a resolver puts on the wire ──────────────────

func name(t *testing.T, s string) []byte {
	t.Helper()

	encoded, err := encodeName(s, false)
	if err != nil {
		t.Fatalf("test data is wrong: encoding %q: %v", s, err)
	}
	return encoded
}

func caaRecord(flags byte, tag, value string) []byte {
	out := []byte{flags, byte(len(tag))}
	out = append(out, tag...)
	return append(out, value...)
}

type record struct {
	name   []byte
	rrType uint16
	rdata  []byte
}

func message(id uint16, flags uint16, question []byte, qtype uint16, records ...record) []byte {
	header := make([]byte, headerLen)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], flags)
	binary.BigEndian.PutUint16(header[4:6], 1)
	binary.BigEndian.PutUint16(header[6:8], uint16(len(records)))

	msg := append([]byte{}, header...)
	msg = append(msg, question...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, classIN)

	for _, r := range records {
		msg = append(msg, r.name...)
		msg = binary.BigEndian.AppendUint16(msg, r.rrType)
		msg = binary.BigEndian.AppendUint16(msg, classIN)
		msg = binary.BigEndian.AppendUint32(msg, 300)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(r.rdata)))
		msg = append(msg, r.rdata...)
	}
	return msg
}

const (
	flagsAnswer          = 0x8180 // response, recursion available, no error
	flagsAnswerValidated = 0x81A0 // the same, with AD set
)

// ── What a reply has to satisfy before it is read at all ─────────────────

// The checks that come before any record is parsed are the ones that matter.
// A reply failing them was written by something that did not see the query,
// and on a plaintext UDP path that is the definition of the attacker this
// service can actually expect to meet.
func TestReplyMustAnswerTheQuestionAsked(t *testing.T) {
	q := name(t, "denyfirst.dev")
	good := message(0x1234, flagsAnswer, q, TypeCAA,
		record{q, TypeCAA, caaRecord(0, "issue", "letsencrypt.org")})

	if _, err := parseReply(good, 0x1234, q, TypeCAA); err != nil {
		t.Fatalf("a well-formed reply was refused: %v", err)
	}

	other := name(t, "example.com")

	cases := []struct {
		name string
		raw  []byte
		id   uint16
		q    []byte
		what string
	}{
		{
			name: "a different query identifier",
			raw:  good, id: 0x9999, q: q,
			what: "an off-path forger has to guess this",
		},
		{
			name: "a different question",
			raw:  good, id: 0x1234, q: other,
			what: "a reply about another name is not an answer to this one",
		},
		{
			// The reason the question is compared as bytes rather than as a
			// name. Randomised case makes a forger reproduce what they never
			// saw; comparing case-insensitively would throw that away.
			name: "the same name in different case",
			raw:  good, id: 0x1234, q: name(t, "DENYFIRST.dev"),
			what: "0x20 encoding is only a defence if the comparison is exact",
		},
		{
			name: "not marked as a reply",
			raw:  message(0x1234, 0x0100, q, TypeCAA), id: 0x1234, q: q,
			what: "a query arriving as an answer is not an answer",
		},
		{
			name: "an answer to a different kind of query",
			raw:  message(0x1234, 0x8800, q, TypeCAA), id: 0x1234, q: q,
			what: "the opcode is part of what was asked",
		},
		{
			name: "shorter than a header",
			raw:  []byte{0x12, 0x34}, id: 0x1234, q: q,
			what: "nothing can be read out of this",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseReply(tc.raw, tc.id, tc.q, TypeCAA); err == nil {
				t.Errorf("accepted a reply that should have been refused: %s", tc.what)
			}
		})
	}
}

// A resolver that will not answer has not answered none.
func TestResponseCodesAreNotAllTheSame(t *testing.T) {
	q := name(t, "denyfirst.dev")

	t.Run("no such name is an answer", func(t *testing.T) {
		got, err := parseReply(message(0x1234, 0x8183, q, TypeCAA), 0x1234, q, TypeCAA)
		if err != nil {
			t.Fatalf("NXDOMAIN was reported as an error: %v", err)
		}
		if got.existed {
			t.Error("a name the resolver says does not exist is reported as existing")
		}
	})

	t.Run("server failure is not", func(t *testing.T) {
		// This is what a validating resolver returns when a signature does not
		// check out. Reporting it as an empty answer would turn a broken
		// DNSSEC chain into a clean result, which is the wrong direction for
		// every failure this service reports.
		_, err := parseReply(message(0x1234, 0x8182, q, TypeCAA), 0x1234, q, TypeCAA)
		if !errors.Is(err, ErrServerFail) {
			t.Errorf("SERVFAIL produced %v, want ErrServerFail", err)
		}
	})

	t.Run("refused is not", func(t *testing.T) {
		_, err := parseReply(message(0x1234, 0x8185, q, TypeCAA), 0x1234, q, TypeCAA)
		if !errors.Is(err, ErrRefused) {
			t.Errorf("REFUSED produced %v, want ErrRefused", err)
		}
	})
}

// The AD bit is read and reported. It is somebody else's claim, and the report
// says so; what it must not do is go missing.
func TestAuthenticDataBitIsCarriedThrough(t *testing.T) {
	q := name(t, "denyfirst.dev")
	rec := record{q, TypeCAA, caaRecord(0, "issue", "letsencrypt.org")}

	plain, err := parseReply(message(0x1234, flagsAnswer, q, TypeCAA, rec), 0x1234, q, TypeCAA)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if plain.validated {
		t.Error("a reply without the AD bit is reported as validated")
	}

	signed, err := parseReply(message(0x1234, flagsAnswerValidated, q, TypeCAA, rec), 0x1234, q, TypeCAA)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if !signed.validated {
		t.Error("a reply with the AD bit is not reported as validated")
	}
}

// ── The records themselves ───────────────────────────────────────────────

func TestCAARecordsAreRead(t *testing.T) {
	q := name(t, "denyfirst.dev")

	got, err := parseReply(message(0x1234, flagsAnswer, q, TypeCAA,
		record{q, TypeCAA, caaRecord(0, "issue", "letsencrypt.org")},
		record{q, TypeCAA, caaRecord(0x80, "issuewild", ";")},
		record{q, TypeCAA, caaRecord(0, "iodef", "mailto:abuse@denyfirst.dev")},
	), 0x1234, q, TypeCAA)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}

	if len(got.records) != 3 {
		t.Fatalf("read %d records, want 3: %+v", len(got.records), got.records)
	}
	if got.records[0].Tag != "issue" || got.records[0].Value != "letsencrypt.org" {
		t.Errorf("first record is %+v", got.records[0])
	}
	if !got.records[1].Critical {
		t.Error("the critical flag was dropped; an authority that cannot read a critical property must refuse to issue")
	}
	if got.records[0].Critical {
		t.Error("the critical flag was invented")
	}
}

// A signed zone answers with RRSIG beside the records asked for, because the
// query asked for DNSSEC. Treating that as a fault would refuse every zone
// this service most wants to read.
func TestOtherRecordTypesAreSkipped(t *testing.T) {
	q := name(t, "denyfirst.dev")
	const typeRRSIG = 46

	got, err := parseReply(message(0x1234, flagsAnswerValidated, q, TypeCAA,
		record{q, TypeCAA, caaRecord(0, "issue", "letsencrypt.org")},
		record{q, typeRRSIG, []byte("not a CAA record and not meant to be read as one")},
	), 0x1234, q, TypeCAA)
	if err != nil {
		t.Fatalf("a reply carrying RRSIG was refused: %v", err)
	}
	if len(got.records) != 1 {
		t.Errorf("read %d records, want 1", len(got.records))
	}
}

// Every length here is chosen by whoever controls the zone, which on a hostile
// target is the target.
func TestMalformedRecordsAreRefused(t *testing.T) {
	q := name(t, "denyfirst.dev")

	cases := []struct {
		name  string
		rdata []byte
	}{
		{"empty", nil},
		{"flags with no tag length", []byte{0x00}},
		{"a tag of no length", []byte{0x00, 0x00}},
		{"a tag longer than the record", []byte{0x00, 0xFF, 'i', 's'}},
		{"a tag that is not printable", []byte{0x00, 0x02, 0x01, 0x02}},
		{"a value that is not printable", append([]byte{0x00, 0x05}, append([]byte("issue"), 0x00, 0x07)...)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseReply(message(0x1234, flagsAnswer, q, TypeCAA,
				record{q, TypeCAA, tc.rdata}), 0x1234, q, TypeCAA)
			if err == nil {
				t.Error("a malformed record was accepted")
			}
		})
	}
}

// ── Compression pointers ─────────────────────────────────────────────────

// The oldest way to hang a hand-written DNS parser is a name that points at
// itself. Two rules close it and both are tested, because either one alone
// would pass a test written for the other.
func TestCompressionPointersCannotLoop(t *testing.T) {
	t.Run("a pointer to itself", func(t *testing.T) {
		raw := append(make([]byte, headerLen), 0xC0, byte(headerLen))
		if _, err := skipName(raw, headerLen); err == nil {
			t.Error("a name pointing at itself was followed")
		}
	})

	t.Run("a pointer forwards", func(t *testing.T) {
		raw := append(make([]byte, headerLen), 0xC0, 0x20)
		raw = append(raw, make([]byte, 32)...)
		if _, err := skipName(raw, headerLen); err == nil {
			t.Error("a pointer into later bytes was followed; only backwards terminates")
		}
	})

	t.Run("a chain of backward pointers", func(t *testing.T) {
		// Each points at the one before it, descending two bytes at a time.
		// Every hop is legal on its own; the cap is what ends it.
		raw := []byte{0x00}
		for i := 0; i < 64; i++ {
			offset := len(raw) - 2
			if offset < 0 {
				offset = 0
			}
			raw = append(raw, 0xC0, byte(offset))
		}
		if _, err := skipName(raw, len(raw)-2); err == nil {
			t.Error("a long chain of backward pointers was followed to the end")
		}
	})

	t.Run("an ordinary backward pointer is followed", func(t *testing.T) {
		q := name(t, "denyfirst.dev")
		raw := append(append([]byte{}, q...), 0xC0, 0x00)
		end, err := skipName(raw, len(q))
		if err != nil {
			t.Fatalf("a legitimate pointer was refused: %v", err)
		}
		if end != len(q)+2 {
			t.Errorf("the name ends at %d, want %d", end, len(q)+2)
		}
	})
}

// ── Query construction ───────────────────────────────────────────────────

// Case randomisation is the cheapest defence available against an off-path
// forger, and it is only a defence if it actually varies.
func TestQuestionCaseIsRandomised(t *testing.T) {
	const host = "abcdefghijklmnop.example"

	seen := map[string]struct{}{}
	for i := 0; i < 32; i++ {
		encoded, err := encodeName(host, true)
		if err != nil {
			t.Fatalf("encoding: %v", err)
		}
		if !strings.EqualFold(readableName(encoded), host) {
			t.Fatalf("randomisation changed the name to %q", readableName(encoded))
		}
		seen[string(encoded)] = struct{}{}
	}

	if len(seen) < 8 {
		t.Errorf("32 encodings produced %d distinct questions; the case is not being randomised", len(seen))
	}
}

func TestNamesThatCannotBeAsked(t *testing.T) {
	for _, bad := range []string{
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 200) + "example",
		"double..dot.example",
	} {
		if _, err := encodeName(bad, false); err == nil {
			t.Errorf("encoded a name that is not one: %q", bad)
		}
	}
}

// The query carries the two bits that make the answer worth reading: AD, so a
// validating resolver reports its result, and the EDNS0 record that raises the
// size limit and carries DO.
func TestQueryAsksForWhatTheAnswerNeeds(t *testing.T) {
	q := name(t, "denyfirst.dev")
	query := buildQuery(0x1234, q, TypeCAA)

	if binary.BigEndian.Uint16(query[0:2]) != 0x1234 {
		t.Error("the identifier is not in the header")
	}

	const authenticData = 0x0020
	if binary.BigEndian.Uint16(query[2:4])&authenticData == 0 {
		t.Error("the AD bit is not set; a validating resolver reports its result only when asked")
	}
	if binary.BigEndian.Uint16(query[10:12]) != 1 {
		t.Error("no additional record; EDNS0 carries the payload size and the DO bit")
	}

	// The OPT record sits after the question. Its class field is the payload
	// size, which is what stops a reply being cut to 512 bytes.
	opt := headerLen + len(q) + 4
	if opt+11 > len(query) {
		t.Fatal("the query is too short to hold an OPT record")
	}
	if binary.BigEndian.Uint16(query[opt+1:opt+3]) != typeOPT {
		t.Error("the additional record is not OPT")
	}
	if got := binary.BigEndian.Uint16(query[opt+3 : opt+5]); got != udpPayload {
		t.Errorf("the advertised payload is %d, want %d", got, udpPayload)
	}
	const dnssecOK = 0x8000
	if binary.BigEndian.Uint16(query[opt+5:opt+7])&dnssecOK == 0 {
		t.Error("the DO bit is not set")
	}
}

// readableName turns wire form back into text, for tests only.
func readableName(encoded []byte) string {
	var parts []string
	for i := 0; i < len(encoded); {
		size := int(encoded[i])
		if size == 0 || i+1+size > len(encoded) {
			break
		}
		parts = append(parts, string(encoded[i+1:i+1+size]))
		i += 1 + size
	}
	return strings.Join(parts, ".")
}

// ── Fuzzing ──────────────────────────────────────────────────────────────

// The reply is bytes from the network, and on a plaintext UDP path anyone able
// to answer first wrote them.
//
// Every defect this project has found was in a parser, and none was found by
// reading. The invariant checked here is not that parsing succeeds — almost
// none of the input will be a DNS message — but that a refusal returns nothing
// and a success returns only what the input could have held.
func FuzzParseReply(f *testing.F) {
	q, err := encodeName("denyfirst.dev", false)
	if err != nil {
		f.Fatalf("seed: %v", err)
	}

	f.Add(message(0x1234, flagsAnswer, q, TypeCAA,
		record{q, TypeCAA, caaRecord(0, "issue", "letsencrypt.org")}))
	f.Add(message(0x1234, flagsAnswerValidated, q, TypeCAA))
	f.Add(message(0x1234, 0x8183, q, TypeCAA))
	f.Add(append(message(0x1234, flagsAnswer, q, TypeCAA), 0xC0, 0x0C))
	f.Add([]byte{})
	f.Add([]byte{0x12, 0x34, 0x81, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := parseReply(raw, 0x1234, q, TypeCAA)

		if err != nil {
			if len(got.records) != 0 {
				t.Errorf("a refusal returned %d records", len(got.records))
			}
			return
		}

		// A record occupies at least a name, ten bytes of header, and two of
		// data, so a count above that ceiling means something was counted
		// that is not in the message.
		if ceiling := len(raw) / 13; len(got.records) > ceiling {
			t.Errorf("read %d records from %d bytes, which holds at most %d",
				len(got.records), len(raw), ceiling)
		}

		for _, r := range got.records {
			if r.Tag == "" {
				t.Error("a record was accepted with no tag")
			}
			if !printableASCII(r.Tag) || !printableASCII(r.Value) {
				t.Errorf("a record reached a caller unprintable: %+v", r)
			}
		}
	})
}

// skipName is reached through parseReply, and separately here because a name
// is the part of a message an attacker has the most room to shape.
func FuzzSkipName(f *testing.F) {
	f.Add([]byte{3, 'w', 'w', 'w', 0}, 0)
	f.Add([]byte{0xC0, 0x00}, 0)
	f.Add([]byte{0}, 0)
	f.Add([]byte{0xFF, 0xFF}, 0)

	f.Fuzz(func(t *testing.T, raw []byte, offset int) {
		if offset < 0 || offset > len(raw) {
			t.Skip()
		}

		end, err := skipName(raw, offset)
		if err != nil {
			return
		}
		if end < 0 || end > len(raw) {
			t.Errorf("a name in %d bytes ended at %d", len(raw), end)
		}
	})
}
