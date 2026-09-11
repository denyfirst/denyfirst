package dnsclient

import (
	"context"
	"errors"
	"net"
	"testing"
)

// A machine configures a second resolver because the first is allowed to be
// unreachable. These are the tests that this client behaves the way the
// machine's own stub resolver does.
//
// The defect they were written for is not hypothetical. Until 2026-09-11 this
// asked one resolver, and every scan on this project's development machine
// reported that the CAA check had not happened — because the primary resolver
// there belongs to a virtual adapter and does not answer, while the second one,
// which Windows was using for everything else, was never tried.

// What a platform found becomes a list a lookup will ask, and the rules are the
// same on every platform because they are in one place.
//
// They were in two, one per platform file, and that is why this test exists: a
// sabotage that stopped suppressing duplicates passed everything, because the
// only test that could see it ran against whatever the developer's machine
// happened to be configured with, and that machine has none.
func TestTheResolverListDropsWhatCannotBeAsked(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "order is kept",
			in:   []string{"192.0.2.1", "192.0.2.2"},
			want: []string{"192.0.2.1:53", "192.0.2.2:53"},
		},
		{
			// One router's address under a wired and a wireless adapter. Asking
			// it twice pays the same timeout twice.
			name: "a repeat is dropped",
			in:   []string{"192.0.2.1", "192.0.2.1", "192.0.2.2"},
			want: []string{"192.0.2.1:53", "192.0.2.2:53"},
		},
		{
			// 0.0.0.0 is how a Windows registry spells a placeholder.
			name: "an unspecified address is not a resolver",
			in:   []string{"0.0.0.0", "::", "192.0.2.3"},
			want: []string{"192.0.2.3:53"},
		},
		{
			name: "what will not parse is skipped",
			in:   []string{"not-an-address", "", "  ", "192.0.2.4"},
			want: []string{"192.0.2.4:53"},
		},
		{
			name: "surrounding space is trimmed rather than refused",
			in:   []string{" 192.0.2.5 "},
			want: []string{"192.0.2.5:53"},
		},
		{
			name: "an address is bracketed so host:port parses",
			in:   []string{"2001:db8::1"},
			want: []string{"[2001:db8::1]:53"},
		},
		{
			name: "nothing usable is an empty list rather than a bad entry",
			in:   []string{"0.0.0.0", "nonsense"},
			want: nil,
		},
	} {
		got := resolverList(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("%s: resolverList(%v) = %v, want %v", tc.name, tc.in, got, tc.want)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("%s: resolverList(%v)[%d] = %q, want %q",
					tc.name, tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

// The list is bounded, whatever a platform hands it.
func TestTheResolverListIsBounded(t *testing.T) {
	var many []string
	for i := 0; i < maxResolvers+5; i++ {
		many = append(many, net.IPv4(198, 51, 100, byte(i+1)).String())
	}

	got := resolverList(many)
	if len(got) != maxResolvers {
		t.Errorf("resolverList returned %d of %d addresses, want the bound of %d: a lookup "+
			"trying every entry of a long list outlasts the scan that asked for it",
			len(got), len(many), maxResolvers)
	}
}

// diallerFor answers for one address and fails for every other, recording each
// address it was asked for.
func diallerFor(t *testing.T, live string, answers map[string][]record, dialled *[]string) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()

	fake := &fakeResolver{answers: answers}
	inner := fake.conn(t)

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		*dialled = append(*dialled, address)
		if address != live {
			return nil, errors.New("nothing is listening")
		}
		return inner(ctx, network, address)
	}
}

// A resolver that cannot be reached is followed by the next one.
func TestADeadResolverIsFollowedByTheNextOne(t *testing.T) {
	q := name(t, "example.test")
	var dialled []string

	c := &Client{Dial: diallerFor(t, "192.0.2.2:53", map[string][]record{
		"example.test": {{q, TypeCAA, caaRecord(0, "issue", "letsencrypt.org")}},
	}, &dialled)}

	set := &resolverSet{servers: []string{"192.0.2.1:53", "192.0.2.2:53"}}

	got, err := c.ask(context.Background(), set, "example.test", TypeCAA)
	if err != nil {
		t.Fatalf("ask returned %v; the second resolver answers and should have been tried", err)
	}
	if len(got.records) != 1 || got.records[0].Value != "letsencrypt.org" {
		t.Errorf("records are %+v", got.records)
	}
	if len(dialled) != 2 || dialled[0] != "192.0.2.1:53" || dialled[1] != "192.0.2.2:53" {
		t.Errorf("dialled %v, want the dead one then the live one in order", dialled)
	}
}

// The resolver that answered is the one asked first next time.
//
// A CAA walk makes up to six queries. Paying a dead resolver's timeout on every
// one of them would spend more of the scan budget than the check is worth, and
// on a tight deadline it would turn a working check into a timeout.
func TestTheResolverThatAnsweredIsAskedFirstNextTime(t *testing.T) {
	q := name(t, "example.test")
	var dialled []string

	c := &Client{Dial: diallerFor(t, "192.0.2.2:53", map[string][]record{
		"example.test": {{q, TypeCAA, caaRecord(0, "issue", "letsencrypt.org")}},
	}, &dialled)}

	set := &resolverSet{servers: []string{"192.0.2.1:53", "192.0.2.2:53"}}

	if _, err := c.ask(context.Background(), set, "example.test", TypeCAA); err != nil {
		t.Fatalf("first ask: %v", err)
	}
	dialled = nil

	if _, err := c.ask(context.Background(), set, "example.test", TypeCAA); err != nil {
		t.Fatalf("second ask: %v", err)
	}

	if len(dialled) != 1 || dialled[0] != "192.0.2.2:53" {
		t.Errorf("the second lookup dialled %v; it should have gone straight to the resolver "+
			"that answered rather than paying the dead one's timeout again", dialled)
	}
}

// Every resolver failing reports the first reason rather than the last.
//
// The caller distinguishes ErrRefused from ErrServerFail and from a transport
// failure, and those lead a reader to different places: one is a resolver
// declining, one is a resolver breaking, one is a network. Returning whatever
// the last resolver happened to say reports the least informative one as often
// as not — and a report explaining a missing CAA row has only that sentence to
// work from.
//
// The first version of this test asserted that an error came back and that both
// resolvers were tried, which is not what its name says. A sabotage replacing
// the first reason with the last passed it.
func TestEveryResolverFailingKeepsTheFirstReason(t *testing.T) {
	firstReason := errors.New("the reason the first resolver gave")
	lastReason := errors.New("the reason the last resolver gave")

	var dialled []string
	c := &Client{Dial: func(_ context.Context, _, address string) (net.Conn, error) {
		dialled = append(dialled, address)
		if address == "192.0.2.1:53" {
			return nil, firstReason
		}
		return nil, lastReason
	}}
	set := &resolverSet{servers: []string{"192.0.2.1:53", "192.0.2.2:53"}}

	_, err := c.ask(context.Background(), set, "example.test", TypeCAA)
	if err == nil {
		t.Fatal("ask succeeded with no reachable resolver")
	}
	if len(dialled) != 2 {
		t.Errorf("dialled %v, want both resolvers tried before giving up", dialled)
	}
	if !errors.Is(err, firstReason) {
		t.Errorf("ask returned %v, want the reason the first resolver gave", err)
	}
	if errors.Is(err, lastReason) {
		t.Errorf("ask returned the last resolver's reason: %v", err)
	}
}

// A set with nothing in it is a configuration failure, not a lookup failure.
func TestAnEmptyResolverSetSaysSo(t *testing.T) {
	c := &Client{}

	_, err := c.ask(context.Background(), &resolverSet{}, "example.test", TypeCAA)
	if !errors.Is(err, ErrNoResolver) {
		t.Errorf("ask returned %v, want ErrNoResolver", err)
	}
}

// An explicitly configured resolver is the only one asked.
//
// An operator who names one has said something, and quietly adding the
// machine's own list to it would send queries they did not ask to send — to
// resolvers they may have chosen this flag to avoid.
func TestAConfiguredResolverIsTheOnlyOneAsked(t *testing.T) {
	c := &Client{Server: "192.0.2.9:53"}

	got, err := c.servers()
	if err != nil {
		t.Fatalf("servers: %v", err)
	}
	if len(got) != 1 || got[0] != "192.0.2.9:53" {
		t.Errorf("servers() = %v, want only the configured one", got)
	}
}
