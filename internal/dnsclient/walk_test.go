package dnsclient

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

// fakeResolver answers from a table, so the walk can be exercised without a
// network. The key is the name in lower case, since the question that reaches
// it carries randomised case.
type fakeResolver struct {
	answers map[string][]record
	missing map[string]bool // names the resolver says do not exist
	asked   []string
}

func (f *fakeResolver) conn(t *testing.T) func(context.Context, string, string) (net.Conn, error) {
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

			// The question begins after the header and ends at the root
			// label. Read it back as text so the table can be keyed by name,
			// and echo the bytes unchanged so the caller's comparison holds.
			end, err := skipName(raw, headerLen)
			if err != nil {
				return
			}
			question := raw[headerLen:end]
			asked := lowerName(readableName(question))
			f.asked = append(f.asked, asked)

			flags := uint16(flagsAnswerValidated)
			if f.missing[asked] {
				flags = 0x8183 // NXDOMAIN, and no AD
			}

			out := message(
				binary.BigEndian.Uint16(raw[0:2]),
				flags,
				question,
				TypeCAA,
				f.answers[asked]...,
			)
			_, _ = server.Write(out)
		}()

		return client, nil
	}
}

// The walk stops at the first name carrying records, and says where.
func TestWalkStopsWhereItFindsRecords(t *testing.T) {
	q := name(t, "microsoft.com")
	fake := &fakeResolver{
		answers: map[string][]record{
			"microsoft.com": {{q, TypeCAA, caaRecord(0, "contactemail", "someone@example.com")}},
		},
	}

	c := &Client{Server: "resolver.invalid:53", Dial: fake.conn(t)}
	got, err := c.LookupCAA(context.Background(), "www.microsoft.com")
	if err != nil {
		t.Fatalf("LookupCAA: %v", err)
	}

	if got.Name != "microsoft.com" {
		t.Errorf("records reported at %q, want microsoft.com", got.Name)
	}
	if got.Queries != 2 {
		t.Errorf("took %d queries, want 2", got.Queries)
	}
	if len(got.Records) != 1 || got.Records[0].Tag != "contactemail" {
		t.Errorf("records are %+v", got.Records)
	}
}

// The bug this test exists for.
//
// Existed was taken from whichever query the walk ended on, so a name that
// does not exist would be reported as existing the moment its parent did —
// and the parent almost always does. The field describes the name that was
// asked about; nothing else can be said in one boolean.
func TestExistedDescribesTheNameAskedAbout(t *testing.T) {
	fake := &fakeResolver{
		answers: map[string][]record{},
		missing: map[string]bool{"nosuchname.example.com": true},
	}

	c := &Client{Server: "resolver.invalid:53", Dial: fake.conn(t)}
	got, err := c.LookupCAA(context.Background(), "nosuchname.example.com")
	if err != nil {
		t.Fatalf("LookupCAA: %v", err)
	}

	if got.Existed {
		t.Error("a name the resolver says does not exist is reported as existing, because its parent does")
	}
	if got.Queries < 2 {
		t.Errorf("took %d queries; the walk should continue past a missing name to find a parent policy", got.Queries)
	}
}

// A name that exists and carries no CAA is a different answer from one that
// does not exist, and both produce no records.
func TestExistingNameWithNoRecords(t *testing.T) {
	fake := &fakeResolver{answers: map[string][]record{}}

	c := &Client{Server: "resolver.invalid:53", Dial: fake.conn(t)}
	got, err := c.LookupCAA(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupCAA: %v", err)
	}

	if !got.Existed {
		t.Error("a name the resolver answered for is reported as missing")
	}
	if len(got.Records) != 0 {
		t.Errorf("records appeared from nowhere: %+v", got.Records)
	}
}

// The walk is bounded. Each step tells the resolver about another name, and a
// hostname with many labels would otherwise spend a scan's budget on DNS.
func TestWalkIsBounded(t *testing.T) {
	fake := &fakeResolver{answers: map[string][]record{}}

	c := &Client{Server: "resolver.invalid:53", MaxQueries: 2, Dial: fake.conn(t)}
	got, err := c.LookupCAA(context.Background(), "a.b.c.d.e.example.com")
	if err != nil {
		t.Fatalf("LookupCAA: %v", err)
	}

	if got.Queries != 2 {
		t.Errorf("took %d queries with a budget of 2", got.Queries)
	}
}

// Without a resolver there is nothing to ask, and that is reported rather than
// guessed at. The command line tool runs on a machine with no resolv.conf.
func TestNoResolverIsAnError(t *testing.T) {
	c := &Client{Server: ""}
	if _, err := c.LookupCAA(context.Background(), "example.com"); err != nil {
		if !errors.Is(err, ErrNoResolver) {
			t.Skipf("this machine has a resolver: %v", err)
		}
		return
	}
	t.Skip("this machine has a resolver configured")
}

func lowerName(s string) string {
	out := []byte(s)
	for i, b := range out {
		if b >= 'A' && b <= 'Z' {
			out[i] = b + 32
		}
	}
	return string(out)
}
