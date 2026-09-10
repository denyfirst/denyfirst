package web

import (
	"reflect"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/httpapi"
)

// describedOnThePrivacyPage maps every figure /api/v1/stats publishes to the
// words on the privacy page that describe it.
//
// The page ends its list with "that is the whole record", which is a claim
// worth making only if something checks it. It was not checked, and it drifted:
// the page said one number per scan plus strong, weak and insecure long after
// the service had also begun publishing ungraded, a block per check naming its
// own rule set, a count of refusals by reason, and three figures about dates.
// None of that describes anybody — it is not a privacy failure — but a page
// that understates what is kept is a page a reader cannot use to check
// anything, and this one is the last place to be approximate.
//
// So a figure cannot be added to the published snapshot without this failing,
// and the fix is to say so on the page rather than to edit this table.
var describedOnThePrivacyPage = map[string]string{
	"scansTotal": "one number goes up",
	"strong":     "strong, weak, insecure, or ungraded",
	"weak":       "strong, weak, insecure, or ungraded",
	"insecure":   "strong, weak, insecure, or ungraded",
	"ungraded":   "nothing was measured rather than nothing was wrong",
	"scansToday": "the day&rsquo;s total",
	"todayDate":  "whether it is still today",
	"since":      "when counting began",
	"refused":    "how many requests were turned away and for which reason",
	"checks":     "each check keeps its own block",
	"policy":     "naming the rules that graded them",
}

// publishedFigures are the JSON names a reader of /api/v1/stats can see, taken
// from the types rather than from a list somebody keeps in step by hand.
func publishedFigures() map[string]bool {
	out := map[string]bool{}

	for _, t := range []reflect.Type{
		reflect.TypeOf(httpapi.Snapshot{}),
		reflect.TypeOf(httpapi.CheckCounts{}),
	} {
		for i := 0; i < t.NumField(); i++ {
			tag := t.Field(i).Tag.Get("json")
			if tag == "" || tag == "-" {
				continue
			}
			out[strings.Split(tag, ",")[0]] = true
		}
	}
	return out
}

// The page names every figure the service publishes, and no figure it does not.
func TestThePrivacyPageDescribesEveryPublishedFigure(t *testing.T) {
	body, err := assets.ReadFile("assets/privacy.html")
	if err != nil {
		t.Fatalf("reading the privacy page: %v", err)
	}

	// The source is wrapped, so a sentence on the page is several lines in the
	// file. Comparing without collapsing that would make this test a test of
	// where somebody's editor broke a line.
	page := strings.ToLower(strings.Join(strings.Fields(string(body)), " "))

	published := publishedFigures()

	for figure := range published {
		phrase, described := describedOnThePrivacyPage[figure]
		if !described {
			t.Errorf("/api/v1/stats publishes %q and the privacy page does not describe it. "+
				"The page says that is the whole record, and a reader believes the page.", figure)
			continue
		}
		if !strings.Contains(page, strings.ToLower(phrase)) {
			t.Errorf("the privacy page no longer contains %q, which is how it described %q. "+
				"If the wording changed, change it here too; if the figure is gone, both "+
				"have to say so.", phrase, figure)
		}
	}

	for figure := range describedOnThePrivacyPage {
		if !published[figure] {
			t.Errorf("the privacy page describes %q, which /api/v1/stats no longer publishes. "+
				"A page claiming more is kept than is kept is wrong in the direction that "+
				"looks harmless and is not.", figure)
		}
	}
}

// The claim the table above exists to protect is still on the page.
//
// Without this, deleting the sentence would leave the test passing over a page
// that no longer promises anything — the list would be complete and pointless.
func TestThePrivacyPageStillClaimsThatIsTheWholeRecord(t *testing.T) {
	body, err := assets.ReadFile("assets/privacy.html")
	if err != nil {
		t.Fatalf("reading the privacy page: %v", err)
	}
	page := strings.ToLower(strings.Join(strings.Fields(string(body)), " "))

	if !strings.Contains(page, "that is the whole record") {
		t.Error("the privacy page no longer says the list is the whole record. That sentence " +
			"is what the figure table is checked against; without it the page describes " +
			"some of what is kept and promises nothing about the rest")
	}
	if !strings.Contains(page, "/api/v1/stats") {
		t.Error("the privacy page no longer names the address the figures are served at, so a " +
			"reader has no way to check the list against the thing itself")
	}
}
