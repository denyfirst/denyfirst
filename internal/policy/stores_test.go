package policy

import (
	"strings"
	"testing"
)

func allFour(verdict string) StoreFacts {
	f := StoreFacts{Retrieved: "2026-09-14"}
	for _, s := range []string{"Mozilla", "Chrome", "Microsoft", "Apple"} {
		f.Stores = append(f.Stores, StoreTrust{Store: s, Verdict: verdict, Root: "ISRG Root X1"})
	}
	return f
}

// The line names every store under what it said, with the stores' date.
func TestTheStoresLineGroupsByWhatEachSaid(t *testing.T) {
	if got := StoresLine(allFour(storeTrusted)); got != "trusted by Mozilla, Chrome, Microsoft and Apple (stores of 2026-09-14)" {
		t.Errorf("all four trusting reads %q", got)
	}

	mixed := StoreFacts{Retrieved: "2026-09-14", Stores: []StoreTrust{
		{Store: "Mozilla", Verdict: storeDistrusted, Root: "Old Root", After: "2026-04-15"},
		{Store: "Chrome", Verdict: storeConditional, Root: "Old Root"},
		{Store: "Microsoft", Verdict: storeTrusted, Root: "Old Root"},
		{Store: "Apple", Verdict: storeNotTrusted},
	}}
	got := StoresLine(mixed)
	for _, want := range []string{
		"trusted by Microsoft", "conditionally by Chrome",
		"distrusted by Mozilla for certificates issued after 2026-04-15", "not trusted by Apple",
		"(stores of 2026-09-14)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the line %q does not carry %q", got, want)
		}
	}
}

// All four trusting is one sentence, not four.
func TestAllStoresTrustingIsOneSentence(t *testing.T) {
	notes := DescribeStores(allFour(storeTrusted))
	if len(notes) != 1 || !strings.Contains(notes[0].Text, "2026-09-14") {
		t.Errorf("all four trusting gave %v", Texts(notes))
	}
}

// A store that refuses the chain is said beside the verdict, not folded into it.
//
// The verdict rests on this machine's store. A client relying on another store
// refuses the connection whatever that verdict says, and a reader deciding who
// can reach their server needs both halves.
func TestAStoreThatRefusesIsSaidBesideTheVerdict(t *testing.T) {
	f := allFour(storeTrusted)
	f.Stores[3] = StoreTrust{Store: "Apple", Verdict: storeNotTrusted}

	text := strings.Join(Texts(DescribeStores(f)), " ")
	for _, want := range []string{"Apple includes no root", "refuses the connection", "machine that ran this scan"} {
		if !strings.Contains(text, want) {
			t.Errorf("the notes do not carry %q: %s", want, text)
		}
	}
}

// A conditional store is unsettled, never trusted or refused.
func TestAConditionalStoreIsUnsettled(t *testing.T) {
	f := allFour(storeTrusted)
	f.Stores[1] = StoreTrust{Store: "Chrome", Verdict: storeConditional, Root: "Some Root"}

	unsettled := strings.Join(Texts(NotesOfKind(DescribeStores(f), KindUnsettled)), " ")
	if !strings.Contains(unsettled, "Chrome includes the root") || !strings.Contains(unsettled, "not established") {
		t.Errorf("a conditional store is not unsettled: %s", unsettled)
	}
}

// A distrust date that applies is said with the date and the root.
func TestADistrustDateThatAppliesIsSaid(t *testing.T) {
	f := allFour(storeTrusted)
	f.Stores[0] = StoreTrust{Store: "Mozilla", Verdict: storeDistrusted, Root: "Izenpe.com", After: "2026-04-15"}

	text := strings.Join(Texts(DescribeStores(f)), " ")
	if !strings.Contains(text, "Mozilla stopped trusting Izenpe.com for certificates issued after 2026-04-15") {
		t.Errorf("the distrust is not said: %s", text)
	}
}

// Stores that could not be used are unsettled, with the reason, and the line is
// empty rather than claiming anything.
func TestStoresNotUsedAreUnsettledWithTheReason(t *testing.T) {
	f := StoreFacts{Reason: "this build carries no root stores"}
	if got := StoresLine(f); got != "" {
		t.Errorf("the line says %q about stores nobody consulted", got)
	}
	unsettled := strings.Join(Texts(NotesOfKind(DescribeStores(f), KindUnsettled)), " ")
	if !strings.Contains(unsettled, f.Reason) {
		t.Errorf("the reason is not given: %s", unsettled)
	}
}

// The standing limit says the verdict rests on one store and the others are
// dated copies with only some conditions applied.
func TestTheTrustStoreLimitSaysWhatTheOtherStoresAre(t *testing.T) {
	text := LimitOneTrustStore.Text
	for _, want := range []string{
		"the verdict rests on that store", "machine that ran this scan",
		"Mozilla", "Chrome", "Microsoft", "Apple", "dated", "named, not applied",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the limit does not say %q: %s", want, text)
		}
	}

	// The old sentence treated the other stores as a warning about what could
	// not be known. They are now said beside the verdict, and a limit still
	// calling this one store among several, with nothing more, would read as
	// though they were not. A sabotage restoring that phrase escaped a test
	// that only checked for the store names.
	if strings.Contains(text, "one store among several") {
		t.Errorf("the limit still reads as though no other store is consulted: %s", text)
	}
}
