package spf

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// budgetZone answers from a table and counts what it was asked. A name in fail
// returns a resolver error; a name absent from records does not exist.
type budgetZone struct {
	records map[string]string
	fail    map[string]bool
	asked   int
}

func (z *budgetZone) LookupTXT(_ context.Context, name string) ([]string, bool, error) {
	z.asked++
	if z.fail[name] {
		return nil, false, errors.New("dial udp 192.0.2.53:53: i/o timeout")
	}
	v, ok := z.records[name]
	if !ok {
		return nil, false, nil
	}
	return []string{v}, true, nil
}

// wide is a policy that includes n names, each carrying a policy of its own.
func wide(n int) *budgetZone {
	z := &budgetZone{records: map[string]string{}}
	root := "v=spf1"
	for i := range n {
		name := fmt.Sprintf("c%d.test", i)
		root += " include:" + name
		z.records[name] = "v=spf1 ip4:192.0.2.0/24 -all"
	}
	z.records["root.test"] = root + " -all"
	return z
}

// A policy past the limit is not walked past it.
//
// A receiver stops with a permanent error at the eleventh lookup, and so does
// this. Before the 2026-09-16 audit (A12) thirty includes cost thirty-one
// queries, and a budgetZone whose includes each named more had no ceiling at all.
func TestTheWalkStopsWhereAReceiverStops(t *testing.T) {
	z := wide(30)
	got := Check(context.Background(), z, "root.test")

	if !got.LookupLimit {
		t.Error("thirty includes are not over the limit")
	}
	if !got.LookupsAtLeast {
		t.Error("a count that stopped at the limit is not said to be a lower bound")
	}
	if z.asked > 1+maxLookups+1 {
		t.Errorf("%d queries were made; a receiver makes at most one for the record and one per lookup to the limit", z.asked)
	}
	if got.Lookups != 30 {
		t.Errorf("counted %d lookups in a record with thirty includes; the terms are counted even where they are not followed", got.Lookups)
	}
}

// A policy under the limit is walked in full, and its count is exact.
func TestAPolicyUnderTheLimitIsWalkedInFull(t *testing.T) {
	z := wide(5)
	got := Check(context.Background(), z, "root.test")
	if got.LookupLimit || got.LookupsAtLeast || got.Unread != 0 {
		t.Errorf("five includes: limit %v, at least %v, unread %d", got.LookupLimit, got.LookupsAtLeast, got.Unread)
	}
	if got.Lookups != 5 || z.asked != 6 {
		t.Errorf("%d lookups and %d queries, want 5 and 6", got.Lookups, z.asked)
	}
}

// An include the resolver could not answer is not a void lookup.
//
// RFC 7208 counts a name with no records as void. A resolver timing out says
// nothing about the name, and counting it as void would turn this machine's
// failure into a finding about somebody's domain.
func TestAnUnreadIncludeIsNotAVoidLookup(t *testing.T) {
	z := &budgetZone{
		records: map[string]string{"root.test": "v=spf1 include:gone.test include:down.test include:down2.test -all"},
		fail:    map[string]bool{"down.test": true, "down2.test": true},
	}
	got := Check(context.Background(), z, "root.test")
	if got.VoidLookups != 1 {
		t.Errorf("%d void lookups, want 1: only gone.test answered with nothing", got.VoidLookups)
	}
	if got.VoidLimit {
		t.Error("two includes the resolver could not answer pushed the policy over the void limit")
	}
	if got.Unread != 2 || !got.LookupsAtLeast {
		t.Errorf("unread %d, at least %v; want 2 and true", got.Unread, got.LookupsAtLeast)
	}
	if strings.Contains(got.Reason, "192.0.2.53") {
		t.Errorf("the reason names the resolver: %q", got.Reason)
	}
}

// A walk whose caller has given up asks nothing more.
func TestACancelledWalkAsksNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	z := wide(3)
	got := Check(ctx, z, "root.test")
	if z.asked != 0 {
		t.Errorf("%d queries after the caller gave up", z.asked)
	}
	if got.Reason == "" {
		t.Error("a walk that asked nothing gives no reason")
	}
}

// The tenth lookup is still followed, because a receiver follows it: a policy
// whose tenth include pulls in one more is over the limit, and one with ten and
// nothing more is exactly at it.
//
// A sabotage stopping a lookup early escaped the tests above on 2026-09-16.
func TestTheTenthLookupIsFollowed(t *testing.T) {
	exact := wide(maxLookups)
	got := Check(context.Background(), exact, "root.test")
	if got.Lookups != maxLookups || got.LookupLimit || got.LookupsAtLeast {
		t.Errorf("ten includes: %d lookups, limit %v, at least %v; want exactly ten and within it",
			got.Lookups, got.LookupLimit, got.LookupsAtLeast)
	}

	over := wide(maxLookups)
	over.records["c9.test"] = "v=spf1 include:deeper.test -all"
	over.records["deeper.test"] = "v=spf1 -all"
	got = Check(context.Background(), over, "root.test")
	if got.Lookups != maxLookups+1 || !got.LookupLimit {
		t.Errorf("a tenth include pulling in one more: %d lookups, limit %v; want eleven and over", got.Lookups, got.LookupLimit)
	}
}
