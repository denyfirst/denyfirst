package tlsprobe

import (
	"strings"
	"testing"
)

// handshakeSCT builds one entry the way Go hands it over: the list framing has
// already been removed, so what arrives is a bare SerializedSCT — a version
// byte, a 32-byte log identifier, an 8-byte timestamp, a two-byte extensions
// length, and a signature nothing here reads.
func handshakeSCT(logID byte, version byte, signatureLen int) []byte {
	out := make([]byte, 0, 43+signatureLen)
	out = append(out, version)
	for i := 0; i < 32; i++ {
		out = append(out, logID)
	}
	out = append(out, make([]byte, 8)...) // timestamp
	out = append(out, 0, 0)               // no extensions
	return append(out, make([]byte, signatureLen)...)
}

// The identifiers are wanted for one reason: so that a log named by both the
// certificate and the handshake is counted once. That makes reading them
// correctly the difference between a report saying four logs and a report
// saying two.
func TestHandshakeLogIDsReadsTheIdentifiers(t *testing.T) {
	got, _ := handshakeLogIDs([][]byte{
		handshakeSCT(0xab, 0, 70),
		handshakeSCT(0xcd, 0, 260),
	})

	if len(got) != 2 {
		t.Fatalf("read %d identifiers, want 2: %v", len(got), got)
	}
	if want := strings.Repeat("ab", 32); got[0] != want {
		t.Errorf("first identifier = %q, want %q", got[0], want)
	}
	if want := strings.Repeat("cd", 32); got[1] != want {
		t.Errorf("second identifier = %q, want %q", got[1], want)
	}
}

// An entry this cannot read is skipped rather than guessed at.
//
// The count beside these in the report says how many arrived, so an entry
// dropped here shows up as a difference between the two numbers rather than
// disappearing. Guessing at the layout of a structure whose version is unknown
// is how a parser reads one field as another.
func TestHandshakeLogIDsSkipsWhatItCannotRead(t *testing.T) {
	cases := []struct {
		name string
		scts [][]byte
	}{
		{"empty entry", [][]byte{{}}},
		{"shorter than the fields it declares", [][]byte{make([]byte, 20)}},
		{"one byte short", [][]byte{handshakeSCT(1, 0, 70)[:42]}},
		{"a version this has not seen", [][]byte{handshakeSCT(1, 9, 70)}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := handshakeLogIDs(tc.scts); len(got) != 0 {
				t.Errorf("read %v from an entry it should have skipped", got)
			}
		})
	}

	// A bad entry beside a good one drops only the bad one.
	got, _ := handshakeLogIDs([][]byte{
		make([]byte, 20),
		handshakeSCT(0xef, 0, 70),
	})
	if len(got) != 1 {
		t.Fatalf("read %d identifiers past a malformed entry, want 1: %v", len(got), got)
	}
}

// Two timestamps from the same log are two timestamps and one log. Both
// numbers are reported, and reading the second as the first is the mistake
// this whole path exists to avoid.
func TestHandshakeLogIDsCountsALogOnce(t *testing.T) {
	got, _ := handshakeLogIDs([][]byte{
		handshakeSCT(7, 0, 70),
		handshakeSCT(7, 0, 70),
		handshakeSCT(8, 0, 70),
	})

	if len(got) != 2 {
		t.Errorf("read %d identifiers from three timestamps naming two logs: %v", len(got), got)
	}
}

// A handshake carrying nothing is the ordinary case, because almost every
// authority embeds the timestamps in the certificate instead.
func TestHandshakeLogIDsOfNothing(t *testing.T) {
	if got, _ := handshakeLogIDs(nil); len(got) != 0 {
		t.Errorf("read %v from no timestamps at all", got)
	}
}
