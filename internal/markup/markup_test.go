package markup

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func read(t *testing.T, page string) Facts {
	t.Helper()
	return Read(strings.NewReader(page))
}

func hosts(f Facts, kind Kind) []string {
	var out []string
	for _, r := range f.Plaintext {
		if r.Kind == kind {
			out = append(out, r.Host)
		}
	}
	return out
}

// hasHost asks whether a host was reported at all, whatever it was reported as.
func hasHost(f Facts, host string) bool {
	for _, r := range f.Plaintext {
		if r.Host == host {
			return true
		}
	}
	return false
}

func has(f Facts, kind Kind, host string) bool {
	for _, r := range f.Plaintext {
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
		for _, r := range f.Plaintext {
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
			t.Errorf("%s at %s was not seen: %+v", want.kind, want.host, f.Plaintext)
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

	if len(f.Plaintext) != 0 {
		t.Errorf("a page loading nothing over plaintext was reported as loading %+v", f.Plaintext)
	}
	if f.PlaintextTotal != 0 {
		t.Errorf("PlaintextTotal = %d, want 0", f.PlaintextTotal)
	}
}

// http is matched whatever its case, because a scheme is case-insensitive and
// a page written in capitals is not a page without mixed content.
func TestTheSchemeIsMatchedWhateverItsCase(t *testing.T) {
	f := read(t, `<script src="HTTP://cdn.example/a.js"></script>`)
	if !has(f, KindScript, "cdn.example") {
		t.Errorf("HTTP:// was not read as plaintext: %+v", f.Plaintext)
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

	if len(f.Plaintext) != 3 {
		t.Fatalf("got %+v", f.Plaintext)
	}
	for _, r := range f.Plaintext {
		for _, forbidden := range []string{"/", "?", "#", "@", ":", "token", "s3cr3t", "hunter2", "secret"} {
			if strings.Contains(r.Host, forbidden) {
				t.Errorf("%q survived into the report inside %q", forbidden, r.Host)
			}
		}
	}
	for _, want := range []string{"cdn.example", "images.example", "frames.example"} {
		found := false
		for _, r := range f.Plaintext {
			if r.Host == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is not among %+v, so the host was lost along with the rest", want, f.Plaintext)
		}
	}
}

// A form posting in the clear is about the visitor, not about the page.
func TestAFormPostingInTheClearIsSeen(t *testing.T) {
	f := read(t, `<form action="http://forms.example/login" method="post"></form>`)
	if !has(f, KindForm, "forms.example") {
		t.Errorf("the form was not seen: %+v", f.Plaintext)
	}
	for _, r := range f.Plaintext {
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
		t.Errorf("a commented-out reference was reported: %+v", f.Plaintext)
	}
	if !has(f, KindScript, "live.example") {
		t.Errorf("the live reference after the comment was lost: %+v", f.Plaintext)
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
		t.Errorf("a reference inside a comment holding a \"> \" was reported as live: %+v", f.Plaintext)
	}
	if !has(f, KindImage, "live.example") {
		t.Errorf("the live reference after that comment was lost: %+v", f.Plaintext)
	}
}

// An unterminated comment swallows the rest of the page, which is what a
// browser does with one.
func TestAnUnterminatedCommentEndsThePage(t *testing.T) {
	f := read(t, `<!-- <script src="http://old.example/a.js"></script>`)
	if len(f.Plaintext) != 0 {
		t.Errorf("markup inside an unterminated comment was read: %+v", f.Plaintext)
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
		t.Errorf("an address inside a script's text was reported as a subresource: %+v", f.Plaintext)
	}
	if !has(f, KindImage, "real.example") {
		t.Errorf("the real reference after the script was lost: %+v", f.Plaintext)
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
			"read as program text: %+v", f.Plaintext)
	}
}

// "</scriptx>" does not close a script.
func TestAnEndTagMustEndAtTheName(t *testing.T) {
	f := read(t, `<script>"</scriptx>"<img src="http://phantom.example/a.png"></script><img src="http://real.example/b.png">`)
	if has(f, KindImage, "phantom.example") {
		t.Errorf("a near-miss end tag closed the script: %+v", f.Plaintext)
	}
	if !has(f, KindImage, "real.example") {
		t.Errorf("the reference after the real end tag was lost: %+v", f.Plaintext)
	}
}

// A style element's content is not markup either.
func TestWhatIsInsideStyleIsNotMarkup(t *testing.T) {
	f := read(t, `<style>/* <img src="http://phantom.example/a.png"> */</style><img src="http://real.example/b.png">`)
	if has(f, KindImage, "phantom.example") {
		t.Errorf("markup inside a style element was read: %+v", f.Plaintext)
	}
	if !has(f, KindImage, "real.example") {
		t.Errorf("the reference after the style element was lost: %+v", f.Plaintext)
	}
}

// A self-closing raw-text element has no content to skip.
func TestASelfClosingScriptDoesNotSwallowThePage(t *testing.T) {
	f := read(t, `<script src="https://cdn.example/a.js"/><img src="http://real.example/b.png">`)
	if !has(f, KindImage, "real.example") {
		t.Errorf("a self-closing script swallowed the rest of the page: %+v", f.Plaintext)
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
			t.Errorf("%s was not read: %+v", page, f.Plaintext)
		}
	}
}

// A repeated attribute is read the way a browser reads it: the first wins.
func TestARepeatedAttributeIsReadLikeABrowserReadsIt(t *testing.T) {
	f := read(t, `<script src="https://safe.example/a.js" src="http://ignored.example/b.js"></script>`)
	if has(f, KindScript, "ignored.example") {
		t.Errorf("the second src was read, and no browser reads it: %+v", f.Plaintext)
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
				"subresource: %+v", host, f.Plaintext)
		}
	}
	if !has(f, KindStyle, "cdn.example") {
		t.Errorf("the stylesheet was not seen: %+v", f.Plaintext)
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
	if f.PlaintextTotal != 40 {
		t.Errorf("PlaintextTotal = %d, want 40", f.PlaintextTotal)
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

	if len(f.Plaintext) > maxReferences {
		t.Errorf("%d entries reached the report, and the bound is %d", len(f.Plaintext), maxReferences)
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
		t.Errorf("the last reference on a page that fits was lost: %+v", f.Plaintext)
	}
}

// A body that stops early is what was seen, not a page with nothing in it.
func TestAReadThatFailsPartWayIsWhatWasSeen(t *testing.T) {
	f := Read(io.MultiReader(
		strings.NewReader(`<script src="http://cdn.example/a.js"></script>`),
		errorReader{},
	))

	if !f.Read {
		t.Error("a body that was read and then failed reads as one that was never read")
	}
	if !has(f, KindScript, "cdn.example") {
		t.Errorf("what was read before the failure was discarded: %+v", f.Plaintext)
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
		if len(f.Plaintext) != 0 {
			t.Errorf("%q produced %+v", body, f.Plaintext)
		}
	}
}

// A host is stripped before it travels (I5).
func TestAHostIsStrippedBeforeItTravels(t *testing.T) {
	f := read(t, "<img src=\"http://evil\r\n.example/a.png\">")
	for _, r := range f.Plaintext {
		if strings.ContainsAny(r.Host, "\r\n") {
			t.Errorf("a newline survived into %q, which forges a line in a terminal report", r.Host)
		}
	}
}

// An enormous host is bounded.
func TestAnEnormousHostIsBounded(t *testing.T) {
	f := read(t, `<img src="http://`+strings.Repeat("a", 5000)+`.example/x.png">`)
	for _, r := range f.Plaintext {
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

	facts := Read(source)
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
