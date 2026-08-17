package certinfo

import (
	"encoding/binary"
	"testing"
)

// serializedSCT builds one entry the way RFC 6962 lays it out: a version byte,
// a 32-byte log identifier, an 8-byte timestamp, a two-byte extensions length,
// and a signature this parser never reads.
func serializedSCT(logID byte, version byte, signatureLen int) []byte {
	body := make([]byte, 0, minSerializedSCT+signatureLen)
	body = append(body, version)
	for i := 0; i < logIDLen; i++ {
		body = append(body, logID)
	}
	body = append(body, make([]byte, 8)...) // timestamp
	body = append(body, 0, 0)               // no extensions
	body = append(body, make([]byte, signatureLen)...)

	out := make([]byte, 2, 2+len(body))
	binary.BigEndian.PutUint16(out, uint16(len(body)))
	return append(out, body...)
}

func sctList(entries ...[]byte) []byte {
	var inner []byte
	for _, e := range entries {
		inner = append(inner, e...)
	}
	out := make([]byte, 2, 2+len(inner))
	binary.BigEndian.PutUint16(out, uint16(len(inner)))
	return append(out, inner...)
}

// The shapes a real certificate carries.
func TestParseSCTListCountsTimestampsAndLogs(t *testing.T) {
	cases := []struct {
		name      string
		list      []byte
		wantCount int
		wantLogs  int
	}{
		{
			name:      "two timestamps from two logs",
			list:      sctList(serializedSCT(1, 0, 70), serializedSCT(2, 0, 70)),
			wantCount: 2,
			wantLogs:  2,
		},
		{
			name:      "three timestamps from three logs",
			list:      sctList(serializedSCT(1, 0, 70), serializedSCT(2, 0, 70), serializedSCT(3, 0, 70)),
			wantCount: 3,
			wantLogs:  3,
		},
		{
			// The reason the two numbers are reported separately. Browsers ask
			// for receipts from different logs precisely so that one log
			// cannot satisfy the requirement on its own, and a single count
			// cannot tell these two situations apart.
			name:      "three timestamps from one log",
			list:      sctList(serializedSCT(7, 0, 70), serializedSCT(7, 0, 70), serializedSCT(7, 0, 70)),
			wantCount: 3,
			wantLogs:  1,
		},
		{
			name:      "a list with nothing in it",
			list:      sctList(),
			wantCount: 0,
			wantLogs:  0,
		},
		{
			// Signature length varies with the algorithm, and nothing here
			// reads it. A parser that assumed a fixed size would work against
			// ECDSA and fail against RSA, or the reverse.
			name:      "a longer signature is skipped over",
			list:      sctList(serializedSCT(1, 0, 260), serializedSCT(2, 0, 70)),
			wantCount: 2,
			wantLogs:  2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			count, logIDs, malformed := parseSCTList(tc.list)
			if malformed {
				t.Fatal("a well-formed list was reported as malformed")
			}
			if count != tc.wantCount {
				t.Errorf("counted %d timestamps, want %d", count, tc.wantCount)
			}
			if len(logIDs) != tc.wantLogs {
				t.Errorf("named %d logs, want %d: %v", len(logIDs), tc.wantLogs, logIDs)
			}
		})
	}
}

// Every length in this format is chosen by whoever presented the certificate.
//
// The failure this guards against is not a crash — Go bounds-checks slices, so
// the worst case is a panic rather than a read past the buffer. It is the
// quieter one: a length that does not match the data, accepted anyway, makes
// the parser read one field as another and report a count that describes
// nothing. Each case below is a declared size that disagrees with what is
// there, and each must end the parse rather than be clamped to fit.
func TestParseSCTListRefusesMalformedInput(t *testing.T) {
	valid := serializedSCT(1, 0, 70)

	cases := []struct {
		name string
		list []byte
	}{
		{"empty", nil},
		{"one byte", []byte{0}},
		{"outer length longer than the buffer", []byte{0x00, 0xff, 0x00, 0x00}},
		{"outer length shorter than the buffer", append(sctList(valid), 0x00)},
		{"entry length longer than what is left", []byte{0x00, 0x04, 0xff, 0xff, 0x00, 0x00}},
		{"entry shorter than the fields it declares", sctList([]byte{0x00, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})},
		{"a version this parser has not seen", sctList(serializedSCT(1, 9, 70))},
		{"a trailing length with no entry after it", append(sctList(valid), 0x00, 0x2b)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			count, logIDs, malformed := parseSCTList(tc.list)
			if !malformed {
				t.Errorf("accepted malformed input and reported %d timestamps from %d logs", count, len(logIDs))
			}
			if count != 0 || len(logIDs) != 0 {
				t.Errorf("returned %d/%d alongside the malformed flag; a refusal must count nothing", count, len(logIDs))
			}
		})
	}
}

// The parser reads attacker-chosen lengths, which is the shape of code this
// project has found six defects in. Every one of them was in a parser, and
// none was found by reading.
func FuzzParseSCTList(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(sctList())
	f.Add(sctList(serializedSCT(1, 0, 70)))
	f.Add(sctList(serializedSCT(1, 0, 70), serializedSCT(2, 0, 260)))
	f.Add([]byte{0x00, 0xff, 0xff, 0xff})
	f.Add([]byte{0xff, 0xff})

	f.Fuzz(func(t *testing.T, list []byte) {
		count, logIDs, malformed := parseSCTList(list)
		logs := len(logIDs)

		if malformed {
			if count != 0 || logs != 0 {
				t.Errorf("a refusal returned %d timestamps from %d logs", count, logs)
			}
			return
		}

		// A count is only meaningful if it could have come from the input.
		// Each entry occupies at least two length bytes plus the fields it
		// declares, so a count above that ceiling means the loop counted
		// something that is not there.
		if ceiling := len(list) / (2 + minSerializedSCT); count > ceiling {
			t.Errorf("counted %d timestamps from %d bytes, which holds at most %d", count, len(list), ceiling)
		}
		if logs > count {
			t.Errorf("counted %d distinct logs from %d timestamps", logs, count)
		}
		if count > 0 && logs == 0 {
			t.Errorf("counted %d timestamps and no log they came from", count)
		}
	})
}
