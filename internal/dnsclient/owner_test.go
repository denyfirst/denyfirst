package dnsclient

import (
	"encoding/binary"
	"testing"
)

// The checks before the records are read establish that the message came from
// something that saw the query. They establish nothing about what is inside
// it.
//
// A resolver — hostile, broken, or expanding a CNAME this client does not
// follow — can put a record set belonging to another name in the answer
// section. Read without checking, that other name's policy is reported as
// this one's: "issuance limited to X (from example.com)" about a record that
// governs nothing of the sort. This package is written on the assumption that
// the resolver is hostile, and this was the one place it took the resolver's
// word.
func TestRecordsForAnotherOwnerAreIgnored(t *testing.T) {
	q := name(t, "denyfirst.dev")
	other := name(t, "attacker.test")

	got, err := parseReply(message(0x1234, flagsAnswer, q, TypeCAA,
		record{other, TypeCAA, caaRecord(0, "issue", "attacker-ca.test")},
	), 0x1234, q, TypeCAA)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if len(got.records) != 0 {
		t.Errorf("read %d records for a name nobody asked about: %+v", len(got.records), got.records)
	}
}

// A record set is not all-or-nothing. One entry for the right owner beside
// one for another must yield the first and only the first.
func TestOnlyTheAskedForOwnerIsKept(t *testing.T) {
	q := name(t, "denyfirst.dev")
	other := name(t, "denyfirst.dev.evil.test")

	got, err := parseReply(message(0x1234, flagsAnswer, q, TypeCAA,
		record{other, TypeCAA, caaRecord(0, "issue", "attacker-ca.test")},
		record{q, TypeCAA, caaRecord(0, "issue", "letsencrypt.org")},
	), 0x1234, q, TypeCAA)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if len(got.records) != 1 {
		t.Fatalf("read %d records, want 1: %+v", len(got.records), got.records)
	}
	if got.records[0].Value != "letsencrypt.org" {
		t.Errorf("kept %q, want letsencrypt.org", got.records[0].Value)
	}
}

// The owner check must not undo the case randomisation, which is the cheapest
// defence this package has against an off-path forger. A resolver echoes the
// question with its case intact and usually points the answer's owner name
// straight back at it, so the comparison has to fold rather than match bytes.
func TestOwnerMatchingIsCaseInsensitive(t *testing.T) {
	asked, err := encodeName("dEnYfIrSt.DeV", false)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	answered := name(t, "DENYFIRST.dev")

	got, err := parseReply(message(0x1234, flagsAnswer, asked, TypeCAA,
		record{answered, TypeCAA, caaRecord(0, "issue", "letsencrypt.org")},
	), 0x1234, asked, TypeCAA)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if len(got.records) != 1 {
		t.Fatalf("read %d records, want 1: DNS comparison is case-insensitive and the query "+
			"deliberately randomises case", len(got.records))
	}
}

// Real replies point the answer's owner name back at the question rather than
// spelling it out again. The check has to see through that, or it would
// discard every record a real resolver sends.
func TestCompressedOwnerNamesMatch(t *testing.T) {
	q := name(t, "denyfirst.dev")

	// A pointer to offset 12, where the question's name begins.
	pointer := make([]byte, 2)
	binary.BigEndian.PutUint16(pointer, 0xC000|uint16(headerLen))

	got, err := parseReply(message(0x1234, flagsAnswer, q, TypeCAA,
		record{pointer, TypeCAA, caaRecord(0, "issue", "letsencrypt.org")},
	), 0x1234, q, TypeCAA)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if len(got.records) != 1 {
		t.Fatalf("read %d records, want 1: a compressed owner name is the same name", len(got.records))
	}
	if got.records[0].Value != "letsencrypt.org" {
		t.Errorf("read %q", got.records[0].Value)
	}
}

// skipName is a wrapper over readName so that one walker handles compression
// pointers. This pins that they agree about where a record continues, since
// the fuzz target drives skipName and the owner check drives readName.
func TestSkipNameAndReadNameAgree(t *testing.T) {
	raw := name(t, "a.longer.example.test")
	raw = append(raw, 0xAB, 0xCD) // whatever follows the name

	next, err := skipName(raw, 0)
	if err != nil {
		t.Fatalf("skipName: %v", err)
	}
	read, next2, err := readName(raw, 0)
	if err != nil {
		t.Fatalf("readName: %v", err)
	}
	if next != next2 {
		t.Errorf("skipName ended at %d and readName at %d", next, next2)
	}
	if got, want := readableName(read), "a.longer.example.test"; got != want {
		t.Errorf("readName gave %q, want %q", got, want)
	}
}
