package policy

import (
	"strings"
	"testing"
)

// checked is a logged certificate whose receipts were all checked and verified.
func checked() TransparencyFacts {
	return TransparencyFacts{
		Embedded: 2, FromLogs: 2, Trusted: true,
		Checked: true, ListVersion: "91.4", ListDate: "2026-09-13", Verified: 2,
	}
}

// Every receipt verified, and the report names the list it was checked against.
//
// The date is the point. A judgement from a carried list is only as good as the
// list is recent, and a reader who cannot see how old it is has been asked to
// take that on trust.
func TestVerifiedReceiptsNameTheListTheyWereCheckedAgainst(t *testing.T) {
	text := strings.Join(Texts(DescribeTransparency(checked())), " ")
	for _, want := range []string{"every signature verifies", "2026-09-13", "91.4"} {
		if !strings.Contains(text, want) {
			t.Errorf("the note does not carry %q: %s", want, text)
		}
	}
	if strings.Contains(text, "not verified") {
		t.Errorf("receipts that verified are described as not verified: %s", text)
	}
}

// Receipts nobody checked are said not to be verified, with the reason.
func TestUncheckedReceiptsAreSaidNotToBeVerified(t *testing.T) {
	f := checked()
	f.Checked, f.Verified = false, 0
	f.ListReason = "the log list this build carries did not verify against Google's key, so it was not used"

	notes := DescribeTransparency(f)
	unsettled := strings.Join(Texts(NotesOfKind(notes, KindUnsettled)), " ")
	if !strings.Contains(unsettled, "not verified") || !strings.Contains(unsettled, f.ListReason) {
		t.Errorf("an unchecked receipt is not said to be unverified, with its reason: %s", unsettled)
	}
}

// A receipt whose signature fails vouches for nothing, and is said to — without
// a verdict.
func TestABadSignatureIsSaidAndNotGraded(t *testing.T) {
	f := checked()
	f.Verified, f.BadSignature = 1, 1

	text := strings.Join(Texts(DescribeTransparency(f)), " ")
	for _, want := range []string{"1 receipt of the 2 verify", "did not verify", "vouches for nothing"} {
		if !strings.Contains(text, want) {
			t.Errorf("the note does not carry %q: %s", want, text)
		}
	}
	if strings.Contains(text, "every signature verifies") {
		t.Errorf("a failed signature is reported alongside a claim that every one verifies: %s", text)
	}
}

// A receipt from a log the list does not name is unsettled, never false.
//
// A log newer than the carried list, or one another browser trusts, looks exactly
// like this. Calling it a failed signature would accuse a certificate on the
// strength of an old list.
func TestAReceiptFromAnUnlistedLogIsUnsettledNotFalse(t *testing.T) {
	f := checked()
	f.Verified, f.UnknownLog = 1, 1

	notes := DescribeTransparency(f)
	unsettled := strings.Join(Texts(NotesOfKind(notes, KindUnsettled)), " ")
	if !strings.Contains(unsettled, "does not name") || !strings.Contains(unsettled, "not established that the receipt is false") {
		t.Errorf("a receipt from an unlisted log is not described as unsettled: %s", unsettled)
	}
	for _, n := range notes {
		if strings.Contains(n.Text, "did not verify") {
			t.Errorf("a receipt with no key to check is described as failing: %s", n.Text)
		}
	}
}

// A receipt that could not be read is unsettled.
func TestAnUnreadableReceiptIsUnsettled(t *testing.T) {
	f := checked()
	f.Verified, f.Unreadable = 1, 1
	unsettled := strings.Join(Texts(NotesOfKind(DescribeTransparency(f), KindUnsettled)), " ")
	if !strings.Contains(unsettled, "could not be checked") {
		t.Errorf("an unreadable receipt is not said to be unchecked: %s", unsettled)
	}
}

// The line says how many signatures verified, and nothing when none were checked.
func TestTheTransparencyLineSaysHowManySignaturesVerified(t *testing.T) {
	if got := TransparencyLine(checked()); !strings.HasSuffix(got, ", all signatures verified") {
		t.Errorf("every receipt verified and the line says %q", got)
	}

	partial := checked()
	partial.Verified, partial.UnknownLog = 1, 1
	if got := TransparencyLine(partial); !strings.HasSuffix(got, ", 1 of the 2 signatures verified") {
		t.Errorf("one of two verified and the line says %q", got)
	}

	unchecked := checked()
	unchecked.Checked, unchecked.Verified = false, 0
	if got := TransparencyLine(unchecked); strings.Contains(got, "verified") {
		t.Errorf("receipts nobody checked and the line mentions verification: %q", got)
	}
}

// Coverage says "verified" only when every receipt was.
func TestCoverageSaysVerifiedOnlyWhenEveryReceiptWas(t *testing.T) {
	f := full()
	f.TransparencyVerified = true
	if got := Coverage(f); !strings.Contains(got, "transparency receipts were verified") {
		t.Errorf("every receipt verified and coverage says: %s", got)
	}

	f.TransparencyVerified = false
	if got := Coverage(f); !strings.Contains(got, "transparency receipts were counted") || strings.Contains(got, "verified") {
		t.Errorf("receipts not all verified and coverage says: %s", got)
	}
}

// The standing limit names the list and claims no browser's policy.
func TestTheReceiptsLimitNamesTheListAndNoPolicy(t *testing.T) {
	text := LimitTransparencyReceipts.Text
	for _, want := range []string{"Chrome's log list", "date", "nothing here decides"} {
		if !strings.Contains(text, want) {
			t.Errorf("the limit does not say %q: %s", want, text)
		}
	}
	if strings.Contains(text, "carries no copy") {
		t.Errorf("the limit still says no list is carried: %s", text)
	}
}
