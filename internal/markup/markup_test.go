package markup

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// pageHost is the origin the fixtures below are served from, so a reference to
// any other name is somebody else's.
const pageHost = "site.example"

func read(t *testing.T, page string) Facts {
	t.Helper()
	return Read(strings.NewReader(page), pageHost)
}

func hosts(f Facts, kind Kind) []string {
	var out []string
	for _, r := range f.References {
		if r.Kind == kind {
			out = append(out, r.Host)
		}
	}
	return out
}

// hasHost asks whether a host was reported at all, whatever it was reported as.
func hasHost(f Facts, host string) bool {
	for _, r := range f.References {
		if r.Host == host {
			return true
		}
	}
	return false
}

func has(f Facts, kind Kind, host string) bool {
	for _, r := range f.References {
		if r.Kind == kind && r.Host == host {
			return true
		}
	}
	return false
}

// The elements a browser refuses to load over plaintext, and the ones it does
// not, are kept apart.
func TestWhatABrowserBlocksIsSeparatedFromWhatItDoesNot(t *testing.T) {
	f := read(t, `
		<script src="http://cdn.example/a.js"></script>
		<link rel="stylesheet" href="http://cdn.example/a.css">
		<iframe src="http://ads.example/frame"></iframe>
		<img src="http://images.example/logo.png">
		<video src="http://media.example/clip.mp4"></video>
	`)

	for _, want := range []struct {
		kind     Kind
		host     string
		blocking bool
	}{
		{KindScript, "cdn.example", true},
		{KindStyle, "cdn.example", true},
		{KindFrame, "ads.example", true},
		{KindImage, "images.example", false},
		{KindMedia, "media.example", false},
	} {
		found := false
		for _, r := range f.References {
			if r.Kind != want.kind || r.Host != want.host {
				continue
			}
			found = true
			if r.Blocking != want.blocking {
				t.Errorf("%s at %s: blocking = %v, want %v. A blocked script is a broken page "+
					"today; an image is a browser's own decision, and reporting them alike would "+
					"claim something the specification leaves open.",
					want.kind, want.host, r.Blocking, want.blocking)
			}
		}
		if !found {
			t.Errorf("%s at %s was not seen: %+v", want.kind, want.host, f.References)
		}
	}
}

// Only an explicit http address is plaintext.
//
// The false alarm that would matter most. A relative address inherits the
// page's scheme and a scheme-relative one does too, so reporting either as
// mixed content would mark a correctly built site down — and a reader who has
// seen one false finding stops believing the true ones.
func TestOnlyAnExplicitPlaintextAddressCounts(t *testing.T) {
	f := read(t, `
		<script src="/local.js"></script>
		<script src="app.js"></script>
		<script src="//cdn.example/a.js"></script>
		<script src="https://cdn.example/b.js"></script>
		<script src="HTTPS://cdn.example/c.js"></script>
		<img src="data:image/png;base64,AAAA">
		<iframe src="about:blank"></iframe>
		<a href="http://example.com/">a link is not a subresource</a>
	`)

	// Nothing here is plaintext. The two https scripts are recorded, because
	// they are another origin and a rule reads that — but neither is mixed
	// content, and a scanner that confused the two would mark a correctly
	// built site down.
	for _, r := range f.References {
		if r.Plaintext {
			t.Errorf("%+v was reported as plaintext", r)
		}
	}

	// The scheme-relative one is recorded, and as another origin rather than
	// as plaintext. It inherits the page's scheme, which is TLS here, and
	// "//cdn.example/jquery.js" is how a great many older pages load their
	// scripts — the pages least likely to carry an integrity attribute, and so
	// the ones that rule is most for.
	if !hasHost(f, "cdn.example") {
		t.Errorf("no reference to cdn.example survived: %+v", f.References)
	}
	for _, r := range f.References {
		if r.Host == "" {
			t.Errorf("a reference with no host was recorded: %+v", r)
		}
	}
}

// A scheme-relative address is another origin, and never mixed content.
func TestASchemeRelativeAddressIsReadAsThePagesOwnScheme(t *testing.T) {
	f := read(t, `
		<script src="//cdn.example/jquery.js"></script>
		<script src="//`+pageHost+`/own.js"></script>
	`)

	if len(f.References) != 1 {
		t.Fatalf("got %+v", f.References)
	}
	r := f.References[0]
	if r.Host != "cdn.example" {
		t.Errorf("host = %q, want cdn.example", r.Host)
	}
	if r.Plaintext {
		t.Error("a scheme-relative address on a page reached over TLS was called plaintext")
	}
	if !r.ThirdParty {
		t.Error("a scheme-relative address to another host was not called another origin")
	}
}

// A relative address is nobody else's origin and is never recorded.
//
// The false alarm that would matter most. A page loading its own scripts from
// its own host is the ordinary case, and recording it would put every correctly
// built site in a list of things to look at.
func TestAPageLoadingItsOwnThingsRecordsNothing(t *testing.T) {
	f := read(t, `
		<script src="/local.js"></script>
		<script src="app.js"></script>
		<script src="https://`+pageHost+`/own.js"></script>
		<link rel="stylesheet" href="https://`+pageHost+`/own.css">
		<img src="/logo.png">
		<form action="/search"></form>
		<img src="data:image/png;base64,AAAA">
		<iframe src="about:blank"></iframe>
	`)

	if len(f.References) != 0 {
		t.Errorf("a page loading only its own things was reported as loading %+v", f.References)
	}
	if f.ReferencesTotal != 0 {
		t.Errorf("ReferencesTotal = %d, want 0", f.ReferencesTotal)
	}
}

// http is matched whatever its case, because a scheme is case-insensitive and
// a page written in capitals is not a page without mixed content.
func TestTheSchemeIsMatchedWhateverItsCase(t *testing.T) {
	f := read(t, `<script src="HTTP://cdn.example/a.js"></script>`)
	if !has(f, KindScript, "cdn.example") {
		t.Errorf("HTTP:// was not read as plaintext: %+v", f.References)
	}
}

// What is kept is the host and nothing else.
//
// The condition this package was allowed to exist on. A path, a query and
// userinfo each routinely carry a token, and a report is a thing people paste
// into issue trackers.
func TestNothingButTheHostSurvives(t *testing.T) {
	f := read(t, `
		<script src="http://cdn.example/secret/path.js?token=s3cr3t#frag"></script>
		<img src="http://user:hunter2@images.example/a.png">
		<iframe src="http://frames.example:8080/x"></iframe>
	`)

	if len(f.References) != 3 {
		t.Fatalf("got %+v", f.References)
	}
	for _, r := range f.References {
		for _, forbidden := range []string{"/", "?", "#", "@", ":", "token", "s3cr3t", "hunter2", "secret"} {
			if strings.Contains(r.Host, forbidden) {
				t.Errorf("%q survived into the report inside %q", forbidden, r.Host)
			}
		}
	}
	for _, want := range []string{"cdn.example", "images.example", "frames.example"} {
		found := false
		for _, r := range f.References {
			if r.Host == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is not among %+v, so the host was lost along with the rest", want, f.References)
		}
	}
}

// A form posting in the clear is about the visitor, not about the page.
func TestAFormPostingInTheClearIsSeen(t *testing.T) {
	f := read(t, `<form action="http://forms.example/login" method="post"></form>`)
	if !has(f, KindForm, "forms.example") {
		t.Errorf("the form was not seen: %+v", f.References)
	}
	for _, r := range f.References {
		if r.Kind == KindForm && r.Blocking {
			t.Error("the form is marked as blocked, and a browser submits it — with whatever was " +
				"typed into it, in the clear")
		}
	}
}

// A commented-out reference is not a reference.
//
// The false alarm a scanner produces most easily, and the one a reader can
// least argue with, because the markup really does contain the string.
func TestACommentedOutReferenceIsNotOne(t *testing.T) {
	f := read(t, `
		<!-- <script src="http://old.example/a.js"></script> -->
		<!--
		  <img src="http://old.example/b.png">
		-->
		<script src="http://live.example/c.js"></script>
	`)

	if has(f, KindScript, "old.example") || has(f, KindImage, "old.example") {
		t.Errorf("a commented-out reference was reported: %+v", f.References)
	}
	if !has(f, KindScript, "live.example") {
		t.Errorf("the live reference after the comment was lost: %+v", f.References)
	}

	// A comment carrying a ">" of its own, which is what tells a comment apart
	// from a doctype.
	//
	// Both are "<!", and skipping to the first ">" handles a doctype correctly
	// and a comment only by luck — the luck being that most comments have no
	// ">" before the thing inside them. Here the first ">" is in the prose, so
	// a scanner without a comment branch resumes inside the comment and reports
	// the tag after it as live. A sabotage removing that branch escaped on
	// 2026-09-11 because every fixture above was one of the lucky ones.
	f = read(t, `
		<!-- disabled: a > b so this was removed
		  <script src="http://old.example/d.js"></script>
		-->
		<img src="http://live.example/e.png">
	`)

	if has(f, KindScript, "old.example") {
		t.Errorf("a reference inside a comment holding a \"> \" was reported as live: %+v", f.References)
	}
	if !has(f, KindImage, "live.example") {
		t.Errorf("the live reference after that comment was lost: %+v", f.References)
	}
}

// An unterminated comment swallows the rest of the page, which is what a
// browser does with one.
func TestAnUnterminatedCommentEndsThePage(t *testing.T) {
	f := read(t, `<!-- <script src="http://old.example/a.js"></script>`)
	if len(f.References) != 0 {
		t.Errorf("markup inside an unterminated comment was read: %+v", f.References)
	}
}

// A script's text is program text, not markup.
//
// Without this the "<" in a comparison begins a tag, and a script mentioning an
// http address in a string produces a finding about something the page never
// loads.
func TestWhatIsInsideAScriptIsNotMarkup(t *testing.T) {
	f := read(t, `
		<script>
		  if (a < b) { var s = "<img src='http://phantom.example/x.png'>"; }
		  var url = "http://phantom.example/api";
		</script>
		<img src="http://real.example/logo.png">
	`)

	if has(f, KindImage, "phantom.example") {
		t.Errorf("an address inside a script's text was reported as a subresource: %+v", f.References)
	}
	if !has(f, KindImage, "real.example") {
		t.Errorf("the real reference after the script was lost: %+v", f.References)
	}
}

// A closing tag in capitals still closes.
//
// The failure would be silent and would point the reassuring way: everything
// after the script becomes program text, nothing is found, and the page is
// reported clean.
func TestAClosingTagInCapitalsStillCloses(t *testing.T) {
	f := read(t, `<script>var x = 1;</SCRIPT><img src="http://real.example/a.png">`)
	if !has(f, KindImage, "real.example") {
		t.Errorf("a closing tag in capitals was not recognised, so the rest of the page was "+
			"read as program text: %+v", f.References)
	}
}

// "</scriptx>" does not close a script.
func TestAnEndTagMustEndAtTheName(t *testing.T) {
	f := read(t, `<script>"</scriptx>"<img src="http://phantom.example/a.png"></script><img src="http://real.example/b.png">`)
	if has(f, KindImage, "phantom.example") {
		t.Errorf("a near-miss end tag closed the script: %+v", f.References)
	}
	if !has(f, KindImage, "real.example") {
		t.Errorf("the reference after the real end tag was lost: %+v", f.References)
	}
}

// A style element's content is not markup either.
func TestWhatIsInsideStyleIsNotMarkup(t *testing.T) {
	f := read(t, `<style>/* <img src="http://phantom.example/a.png"> */</style><img src="http://real.example/b.png">`)
	if has(f, KindImage, "phantom.example") {
		t.Errorf("markup inside a style element was read: %+v", f.References)
	}
	if !has(f, KindImage, "real.example") {
		t.Errorf("the reference after the style element was lost: %+v", f.References)
	}
}

// A self-closing raw-text element has no content to skip.
func TestASelfClosingScriptDoesNotSwallowThePage(t *testing.T) {
	f := read(t, `<script src="https://cdn.example/a.js"/><img src="http://real.example/b.png">`)
	if !has(f, KindImage, "real.example") {
		t.Errorf("a self-closing script swallowed the rest of the page: %+v", f.References)
	}
}

// A policy declared in the markup is a policy.
//
// The defect this fixes shipped: CSP was read from headers alone, so a site
// using <meta http-equiv> was told it had no policy — and then told a second
// time that it was missing framing protection, because the rule that lets a
// policy supersede X-Frame-Options could not see the policy either.
func TestAPolicyInTheMarkupIsSeen(t *testing.T) {
	f := read(t, `<meta http-equiv="Content-Security-Policy" content="default-src 'self'">`)
	if !f.MetaCSP {
		t.Error("a meta Content-Security-Policy was not seen")
	}

	f = read(t, `<meta HTTP-EQUIV="content-security-policy-report-only" content="default-src 'self'">`)
	if !f.MetaCSPReportOnly {
		t.Error("a report-only meta policy was not seen")
	}
	if f.MetaCSP {
		t.Error("a report-only policy was counted as an enforcing one, which would credit a site " +
			"with protection it deliberately has not switched on yet")
	}
}

// A meta tag that is not http-equiv is not a policy.
//
// No browser applies it. Counting it would credit a site with a policy that
// does nothing, which is worse than reporting the absence: the absence is true.
func TestAMetaThatIsNotHTTPEquivIsNotAPolicy(t *testing.T) {
	for _, page := range []string{
		`<meta name="Content-Security-Policy" content="default-src 'self'">`,
		`<meta content="Content-Security-Policy">`,
		`<meta property="content-security-policy" content="default-src 'self'">`,
	} {
		if f := read(t, page); f.MetaCSP {
			t.Errorf("%s was counted as a policy", page)
		}
	}
}

// Attribute spellings a browser accepts are accepted here.
func TestAttributesAreReadHoweverTheyAreSpelled(t *testing.T) {
	for _, page := range []string{
		`<script src="http://cdn.example/a.js"></script>`,
		`<script src='http://cdn.example/a.js'></script>`,
		`<script src=http://cdn.example/a.js></script>`,
		`<script  SRC = "http://cdn.example/a.js" async></script>`,
		`<script defer src="http://cdn.example/a.js"></script>`,
	} {
		if f := read(t, page); !has(f, KindScript, "cdn.example") {
			t.Errorf("%s was not read: %+v", page, f.References)
		}
	}
}

// A repeated attribute is read the way a browser reads it: the first wins.
func TestARepeatedAttributeIsReadLikeABrowserReadsIt(t *testing.T) {
	f := read(t, `<script src="https://safe.example/a.js" src="http://ignored.example/b.js"></script>`)
	if has(f, KindScript, "ignored.example") {
		t.Errorf("the second src was read, and no browser reads it: %+v", f.References)
	}
}

// A link relation that fetches nothing a page depends on is not a subresource.
func TestOnlyTheRelationsThatFetchSomethingCount(t *testing.T) {
	f := read(t, `
		<link rel="dns-prefetch" href="http://hint.example">
		<link rel="alternate" href="http://alt.example/feed">
		<link rel="stylesheet" href="http://cdn.example/a.css">
	`)

	// By host, not by kind.
	//
	// Asked by kind this passed over a scanner that reported the hints as
	// scripts, which is worse than reporting them as stylesheets: a hint
	// reported as blockable mixed content is a graded finding about a line that
	// fetches nothing the page depends on. The sabotage that found this on
	// 2026-09-11 added dns-prefetch to the preload case, and preload records a
	// script.
	for _, host := range []string{"hint.example", "alt.example"} {
		if hasHost(f, host) {
			t.Errorf("%q fetches nothing this page depends on and was reported as a "+
				"subresource: %+v", host, f.References)
		}
	}
	if !has(f, KindStyle, "cdn.example") {
		t.Errorf("the stylesheet was not seen: %+v", f.References)
	}
}

// The same reference forty times is one entry and forty references.
//
// A list alone cannot tell one host referenced repeatedly from many hosts, and
// they are different situations for whoever has to fix it.
func TestOneHostManyTimesIsOneEntry(t *testing.T) {
	page := strings.Repeat(`<img src="http://images.example/a.png">`, 40)
	f := read(t, page)

	if got := hosts(f, KindImage); len(got) != 1 {
		t.Errorf("got %d entries, want 1: %v", len(got), got)
	}
	if f.ReferencesTotal != 40 {
		t.Errorf("PlaintextTotal = %d, want 40", f.ReferencesTotal)
	}
	if f.MoreThanListed {
		t.Error("one host was reported as more than the list can hold")
	}
}

// A page composed to fill a report is bounded, and says it was.
func TestAPageFullOfHostsIsBoundedAndSaysSo(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxReferences*3; i++ {
		b.WriteString(`<img src="http://h`)
		b.WriteString(strings.Repeat("x", i%5))
		b.WriteString(string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)))
		b.WriteString(`.example/a.png">`)
	}
	f := read(t, b.String())

	if len(f.References) > maxReferences {
		t.Errorf("%d entries reached the report, and the bound is %d", len(f.References), maxReferences)
	}
	if !f.MoreThanListed {
		t.Error("the list is a sample and does not say so, so a reader would read it as the set")
	}
}

// Past the bound, nothing was seen — and an empty list must not read as a clean
// page (R4).
func TestALongPageIsTruncatedAndSaysSo(t *testing.T) {
	padding := strings.Repeat(" ", MaxBytes)
	f := read(t, padding+`<script src="http://late.example/a.js"></script>`)

	if !f.Truncated {
		t.Fatal("a page longer than the bound did not say it was truncated")
	}
	if has(f, KindScript, "late.example") {
		t.Error("markup past the bound was read, so the bound is not one")
	}
	if !f.Read {
		t.Error("a truncated page reads as one that was never read")
	}
}

// A page at exactly the bound is not truncated.
func TestAPageThatFitsIsNotCalledTruncated(t *testing.T) {
	tail := `<script src="http://fits.example/a.js"></script>`
	f := read(t, strings.Repeat(" ", MaxBytes-len(tail))+tail)

	if f.Truncated {
		t.Error("a page of exactly the permitted length was called truncated")
	}
	if !has(f, KindScript, "fits.example") {
		t.Errorf("the last reference on a page that fits was lost: %+v", f.References)
	}
}

// A body that stops early is what was seen, not a page with nothing in it.
func TestAReadThatFailsPartWayIsWhatWasSeen(t *testing.T) {
	f := Read(io.MultiReader(
		strings.NewReader(`<script src="http://cdn.example/a.js"></script>`),
		errorReader{},
	), pageHost)

	if !f.Read {
		t.Error("a body that was read and then failed reads as one that was never read")
	}
	if !has(f, KindScript, "cdn.example") {
		t.Errorf("what was read before the failure was discarded: %+v", f.References)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("the connection went away") }

// A response that is not HTML produces no findings and no panic.
func TestSomethingThatIsNotAPageIsNotAFinding(t *testing.T) {
	for _, body := range []string{
		"",
		"{\"json\": true}",
		"<<<<<<",
		"<",
		"</",
		"<!",
		"<!--",
		"<script",
		"<img src=",
		"<img src=\"",
		strings.Repeat("<", 1000),
		"\x00\x01\x02",
	} {
		f := read(t, body)
		if len(f.References) != 0 {
			t.Errorf("%q produced %+v", body, f.References)
		}
	}
}

// A host is stripped before it travels (I5).
func TestAHostIsStrippedBeforeItTravels(t *testing.T) {
	f := read(t, "<img src=\"http://evil\r\n.example/a.png\">")
	for _, r := range f.References {
		if strings.ContainsAny(r.Host, "\r\n") {
			t.Errorf("a newline survived into %q, which forges a line in a terminal report", r.Host)
		}
	}
}

// An enormous host is bounded.
func TestAnEnormousHostIsBounded(t *testing.T) {
	f := read(t, `<img src="http://`+strings.Repeat("a", 5000)+`.example/x.png">`)
	for _, r := range f.References {
		if len(r.Host) > maxHostLength {
			t.Errorf("a %d-byte host reached the report", len(r.Host))
		}
	}
}

// Read is the only thing that says a body was read.
//
// The zero value has to be distinguishable from a page with nothing wrong,
// because every deployment that does not read bodies produces the zero value
// and a report must not present it as a clean page.
func TestTheZeroValueIsNotACleanPage(t *testing.T) {
	var f Facts
	if f.Read {
		t.Error("the zero value claims a body was read")
	}
}

// countingReader reports how much was actually drawn from the source.
type countingReader struct {
	src  io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	c.read += n
	return n, err
}

// The bound bounds the read, not the result.
//
// A sabotage replacing the limited reader with io.ReadAll escaped every other
// test here on 2026-09-11, because trimming afterwards produces identical
// facts. It is a real defect: the page is chosen by whoever is being measured,
// so a body sized to exhaust this process is a body somebody serves on purpose,
// and a bound applied after the bytes are already in memory has not bounded
// anything.
func TestTheBoundBoundsTheReadRatherThanTheResult(t *testing.T) {
	source := &countingReader{src: infinite{}}

	facts := Read(source, pageHost)
	if !facts.Truncated {
		t.Fatal("an endless page did not come back truncated")
	}

	// A block of slack, because io.ReadAll grows a buffer and the last Read
	// may overshoot the limit by whatever the source hands it.
	if source.read > MaxBytes+(1<<20) {
		t.Errorf("%d bytes were drawn for a read bounded at %d", source.read, MaxBytes)
	}
}

// infinite is a page that never ends.
type infinite struct{}

func (infinite) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

// Another origin is recorded, whether or not the address is plaintext.
func TestAnotherOriginIsRecorded(t *testing.T) {
	f := read(t, `
		<script src="https://cdn.example/a.js"></script>
		<link rel="stylesheet" href="https://cdn.example/a.css">
		<form action="https://payments.example/checkout"></form>
	`)

	for _, want := range []struct {
		kind Kind
		host string
	}{
		{KindScript, "cdn.example"},
		{KindStyle, "cdn.example"},
		{KindForm, "payments.example"},
	} {
		found := false
		for _, r := range f.References {
			if r.Kind != want.kind || r.Host != want.host {
				continue
			}
			found = true
			if !r.ThirdParty {
				t.Errorf("%s at %s is not marked as another origin", want.kind, want.host)
			}
			if r.Plaintext {
				t.Errorf("%s at %s is marked plaintext and the address was https", want.kind, want.host)
			}
		}
		if !found {
			t.Errorf("%s at %s was not seen: %+v", want.kind, want.host, f.References)
		}
	}
}

// An origin is a host, not a registrable domain.
//
// Subresource integrity and CORS both work on origins, so a sibling subdomain
// is somebody else as far as a browser is concerned. Folding them together
// would report a site as loading nothing from elsewhere while a browser treats
// it as exactly that.
func TestASiblingSubdomainIsAnotherOrigin(t *testing.T) {
	f := read(t, `<script src="https://static.`+pageHost+`/a.js"></script>`)

	if len(f.References) != 1 {
		t.Fatalf("got %+v", f.References)
	}
	if !f.References[0].ThirdParty {
		t.Error("a sibling subdomain was folded into the page's own origin")
	}
}

// The page's own host is compared the way every other name in this project is.
func TestThePagesOwnHostIsFolded(t *testing.T) {
	for _, host := range []string{pageHost, strings.ToUpper(pageHost), pageHost + ".", " " + pageHost + " "} {
		f := Read(strings.NewReader(`<script src="https://`+pageHost+`/own.js"></script>`), host)
		if len(f.References) != 0 {
			t.Errorf("served from %q, the page's own script was recorded as somebody else's: %+v",
				host, f.References)
		}
	}
}

// With no host to compare against, nothing is anybody else's.
//
// Silence rather than a guess. A caller that could not say where the page came
// from has not established whose the references are, and marking them all third
// party would invent a finding out of a missing field (R4).
func TestWithNoHostNothingIsThirdParty(t *testing.T) {
	f := Read(strings.NewReader(`
		<script src="https://cdn.example/a.js"></script>
		<script src="http://cdn.example/b.js"></script>
	`), "")

	for _, r := range f.References {
		if r.ThirdParty {
			t.Errorf("%+v was called another origin by a read that did not know the page's own", r)
		}
	}

	// The plaintext one is still plaintext: that question needs no host.
	if len(f.References) != 1 || !f.References[0].Plaintext {
		t.Errorf("the plaintext reference was lost with the host: %+v", f.References)
	}
}

// An integrity attribute is read, and an empty one is not an attribute.
func TestIntegrityIsReadWhereABrowserReadsIt(t *testing.T) {
	f := read(t, `
		<script src="https://cdn.example/a.js" integrity="sha384-abc"></script>
		<script src="https://cdn.example/b.js"></script>
		<script src="https://cdn.example/c.js" integrity=""></script>
		<script src="https://cdn.example/d.js" integrity="   "></script>
		<link rel="stylesheet" href="https://cdn.example/a.css" INTEGRITY="sha512-def">
	`)

	var pinned, loose int
	for _, r := range f.References {
		if r.Integrity {
			pinned++
		} else {
			loose++
		}
	}

	// One script and one stylesheet carry a usable attribute; three scripts do
	// not, and they dedupe to one entry because kind, host and every flag
	// match.
	if pinned != 2 {
		t.Errorf("%d references carry integrity, want 2: %+v", pinned, f.References)
	}
	if loose != 1 {
		t.Errorf("%d references carry none, want 1: %+v", loose, f.References)
	}
}

// An empty integrity attribute is not a guarantee.
//
// A browser given integrity="" checks nothing, so crediting it would tell a
// site it has a protection its visitors do not get — the reassuring direction,
// which is the one that matters.
func TestAnEmptyIntegrityIsNotIntegrity(t *testing.T) {
	f := read(t, `<script src="https://cdn.example/a.js" integrity=""></script>`)
	if len(f.References) != 1 {
		t.Fatalf("got %+v", f.References)
	}
	if f.References[0].Integrity {
		t.Error("integrity=\"\" was credited as a guarantee a browser does not make")
	}
}

// Integrity is recorded only where it means something.
//
// Subresource integrity covers script and link. An integrity attribute on an
// image is markup nobody acts on, and recording it would invite a rule about a
// guarantee no browser makes.
func TestIntegrityIsNotRecordedWhereItDoesNothing(t *testing.T) {
	f := read(t, `
		<img src="https://images.example/a.png" integrity="sha384-abc">
		<iframe src="https://frames.example/x" integrity="sha384-abc"></iframe>
	`)

	for _, r := range f.References {
		if r.Integrity {
			t.Errorf("%s carries integrity, and no browser checks one there", r.Kind)
		}
	}
}

// A plaintext reference to another origin is both, and the flags say so.
func TestAReferenceCanBeBothPlaintextAndAnotherOrigin(t *testing.T) {
	f := read(t, `<script src="http://cdn.example/a.js"></script>`)

	if len(f.References) != 1 {
		t.Fatalf("got %+v", f.References)
	}
	r := f.References[0]
	if !r.Plaintext || !r.ThirdParty || !r.Blocking {
		t.Errorf("a blocked plaintext script from elsewhere is recorded as %+v", r)
	}
}

// Blocking is about plaintext, not about the element.
//
// A script from another origin over TLS is loaded, not blocked. Marking it
// blocked would be reporting a page as broken when it works.
func TestNothingOverTLSIsBlocked(t *testing.T) {
	f := read(t, `
		<script src="https://cdn.example/a.js"></script>
		<iframe src="https://frames.example/x"></iframe>
	`)

	for _, r := range f.References {
		if r.Blocking {
			t.Errorf("%+v is marked as refused by a browser, and a browser loads it", r)
		}
	}
}
