// Package web serves the pages a person sees.
//
// Everything is embedded in the binary. That is not only a convenience: a
// handler that reads from disk has a path to get wrong, a directory that can
// be listed, and a traversal to defend. An embedded filesystem has fixed
// contents decided at build time, so none of those questions arise.
//
// The routes are an explicit table rather than a file server. The same
// reasoning applies as to hostname characters elsewhere in this project:
// listing what is allowed cannot be surprised by something nobody thought to
// forbid.
//
// Pages share one layout. Four copies of a header would be four places for
// it to drift, and a footer that disagrees with itself is a small thing that
// costs more than it looks on a site whose argument is that it can be
// checked. Each page is a fragment; the shell is applied once at startup and
// the result is served as fixed bytes.
package web

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
	"strconv"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/policy"
)

//go:embed assets
var assets embed.FS

// contentSecurityPolicy is deliberately not the one the API uses.
//
// The API returns JSON and needs nothing at all, so its policy denies
// everything. A page needs a stylesheet and, on one route, a script, so its
// policy must be looser. Sharing one policy between them is the usual way a
// strict header quietly becomes a permissive one: the page forces 'self' into
// it, and the API silently inherits permission it never needed.
//
// There is no 'unsafe-inline' anywhere, which is what makes this policy worth
// having. That in turn is why there is no inline style or script in any asset.
// The two trusted-types directives are the same rule as the test in
// internal/web that forbids innerHTML in app.js, moved from build time to run
// time. The test reads the file this repository ships; the header binds the
// script the browser actually ran. They answer different questions and the
// second is the one a user is exposed to, so a page that argues its script
// cannot reach a markup parser should say so where a browser can enforce it.
//
// 'none' rather than a policy name because app.js creates no policy: it builds
// every node with createElement and textContent, so there is no sink to feed
// and nothing to allow. Browsers that do not implement this ignore both
// directives, which costs nothing and is why they are safe to send.
const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self'; " +
	"connect-src 'self'; " +
	"form-action 'none'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'; " +
	"require-trusted-types-for 'script'; " +
	"trusted-types 'none'"

// SecurityTxtPath is where RFC 9116 requires the file to be served.
//
// Exported because the test parses the same file the handler serves, and a
// second copy of this string is a second thing to keep in step.
const SecurityTxtPath = "/.well-known/security.txt"

// PGPKeyPath serves the key a reporter encrypts to.
const PGPKeyPath = "/pgp-key.txt"

// PGPFingerprint identifies the key at PGPKeyPath.
//
// A key served from this domain and identified only by this domain proves
// nothing: whoever takes the domain serves their own key beside their own
// fingerprint, and a reporter encrypts an unpublished vulnerability straight
// to them. The fingerprint is therefore also in SECURITY.md, which lives on
// GitHub behind a different account and a different set of credentials. A
// reporter compares the two; taking one is not taking both.
//
// A test fails if the two copies disagree, because two sources that always
// agree because nobody checks are one source written twice.
const PGPFingerprint = "75B7A18A89715E3775DBCA2EA8D994D1221AA045"

// page is one rendered document.
type page struct {
	Title       string
	Description string

	// Fragment names the file holding the body.
	Fragment string

	// Script is true only where one is needed. A page that carries no script
	// should not load one, however harmless it is: the fewer routes that
	// execute code, the smaller the question of what that code does.
	Script bool

	// Data, when set, means the fragment is a template rather than fixed
	// markup, and is executed with this value before the layout wraps it.
	//
	// One page needs it. The limits of this method are declared once in
	// internal/policy, where the code that emits them lives, and the page
	// that explains them ranges over that declaration. Copying the sentences
	// into the markup would put them in two places, and two places drift —
	// which is the whole argument of R16, applied to a third renderer.
	Data any

	// Method is the page the footer's "How a report is read" link points at.
	//
	// It was one address in the layout while there was one check. The moment
	// there were two, a shared footer meant a reader of a web report was sent
	// to the limits of a TLS handshake — the exact confusion the method pages
	// are separate to prevent, arriving through the one piece of markup every
	// page has in common.
	//
	// Empty takes defaultMethodPage. A page that is not a check's has to point
	// somewhere, and the transport check is the one this project has had
	// longest and the one a reader is likeliest to have a report from.
	Method string

	// Body is filled in at startup. It is template.HTML because the fragment
	// is a file in this repository rather than anything a user supplied.
	Body template.HTML
}

// defaultMethodPage is where a page that is not a check's own sends a reader
// asking how to read a report.
const defaultMethodPage = "/tls/method"

// pages is the whole site.
//
// There were five of these and now there are three. Splitting the
// explanation across separate pages for scanning, privacy and guarantees
// meant a reader had to already know which one answered their question, and
// somebody who arrives because a scan reached their server does not. One page
// with headings and a set of jump links reads better than three that each
// tell a third of the story.
var pages = map[string]*page{
	// The scanner has an address of its own.
	//
	// It was at "/", which is the project's address rather than this check's.
	// One service and one site were the same thing while there was one
	// service; they stop being the same thing the moment there is a second,
	// and by then every report anybody has shared points at "/" — so the
	// front page cannot become a front page without moving the tool out from
	// under those links.
	//
	// Moved now, while nobody is hurt by it. What is at "/" today is a
	// temporary redirect here, and when the project has a front page to put
	// there the redirect goes and this address does not move.
	"/tls": {
		Title:       "denyfirst — check what a server actually negotiates",
		Description: "Check a server's TLS configuration and certificate against cited standards. Nothing about the scan is recorded.",
		Fragment:    "assets/index.html",
		Script:      true,

		// The page has to say which deployment it is, because the two answer
		// differently and a visitor who cannot tell them apart will read a
		// refusal as a fault. One template, branching once, rather than two
		// pages that drift.
		Data: scanPage{Demo: demo.Enabled, Hosts: demo.Hosts()},
	},
	"/privacy": {
		Title:       "Privacy, and what a scan does — denyfirst",
		Description: "What this service records, what a scan sends, what it never does, and how to have a domain excluded.",
		Fragment:    "assets/privacy.html",
	},
	"/terms": {
		Title:       "Terms of use — denyfirst",
		Description: "What you agree to when you use this service, and what it does not promise.",
		Fragment:    "assets/terms.html",
	},

	// A fourth page, on a site that deliberately went from five to three.
	//
	// The consolidation was about pages a reader has to choose between: three
	// explanations split across scanning, privacy and guarantees meant
	// somebody arriving cold had to already know which one held their answer.
	// Nobody arrives here cold. This page is reached from a link in the
	// report it explains, at the moment the question comes up, and it exists
	// so that four sentences true of every scan stop being printed on every
	// report — where they read as findings about the reader's own server.
	//
	// Under the service and not at the root, because the limits on it are
	// this instrument's. What a TLS scan cannot establish is not what a mail
	// check will not establish, and a page that tried to be both would be
	// true of neither.
	"/tls/method": {
		Title:       "What this can see, and what it cannot — denyfirst",
		Description: "How to read a report, and the limits of the method: what every scan here cannot establish, whatever server it looks at.",
		Fragment:    "assets/method.html",
		Data:        methodPage{Limits: policy.StandingLimits(), Demo: demo.Enabled},
	},

	// The web check, beside the TLS one rather than under it.
	//
	// Neither is a subset of the other. A site can negotiate TLS 1.3 with a
	// clean chain and still serve content on port 80 with no policy declared,
	// and the handshake check grades that host strong — correctly, and while
	// saying nothing about the way it is actually reached. Two checks, two
	// addresses, two rule sets, and a front page at "/" later that runs both
	// against one name.
	"/web": {
		Title:       "denyfirst — check how a site is actually reached",
		Description: "Check how a website is reached over HTTP and HTTPS: redirects, transport, and the policy a browser would end up holding. Nothing about the scan is recorded.",
		Fragment:    "assets/web.html",
		Script:      true,
		Method:      "/web/method",
		Data:        scanPage{Demo: demo.Enabled, Hosts: demo.Hosts()},
	},

	// The address the web check puts in its own user agent.
	//
	// N7 says a probe identifies itself and names a page explaining exactly
	// what it sent, because a probe that hides is one an administrator can
	// only be alarmed by while one that identifies itself is one they can
	// make a decision about. webprobe.DefaultUserAgent has named this address
	// since the check was written, and it answered 404 until the check had a
	// service surface — at which point the promise started being made to
	// strangers' access logs for real.
	//
	// So this page answers the log reader before it answers the report
	// reader. Somebody who arrives from a log line did not ask to be here and
	// wants one thing: what reached their server, exactly, and that there is
	// nothing else to look for.
	"/web/method": {
		Title:       "What the web check sends, and what it cannot see — denyfirst",
		Description: "Exactly what a web check sends to a server, how to read the report it produces, and the limits of the method.",
		Fragment:    "assets/web-method.html",
		Method:      "/web/method",
		Data:        methodPage{Limits: policy.WebStandingLimits(), Demo: demo.Enabled},
	},
}

// scanPage is what assets/index.html branches on.
type scanPage struct {
	// Demo is true in the build that runs on denyfirst.dev.
	Demo bool

	// Hosts is what that build offers, and is empty in the other one.
	Hosts []demo.Host
}

// ToolName is what this tool is called on the pages it serves.
//
// One constant, because the name appears in a heading, in a page title and in a
// description, and three copies of a name is three places for it to be changed
// in two. It is deliberately not the rule-set names: those carry the name too,
// and they are declared in internal/policy where the rules are, so that a
// report and the page that explains it cannot disagree about which tool graded
// it.
const ToolName = "denyfirst"

// consoleCheck is one row of the console's check list.
//
// Built from internal/policy rather than written into the markup, so the rule
// set a box offers is the rule set the report comes back carrying. A page that
// named its own would be a second source for the one string a reader uses to
// decide whether two reports are comparable.
type consoleCheck struct {
	ID     string
	Label  string
	Says   string
	Policy string
}

// consolePage is what assets/console.html reads.
type consolePage struct {
	Tool   string
	Checks []consoleCheck

	// Verified says this installation was given a boundary, and ReadsPages
	// follows from it: a page is read only where control was proven.
	//
	// Both are on the page because an operator reading a report has to know
	// which were true when it was produced. A report silent about mixed content
	// because no body was read looks exactly like one silent because the page
	// had none, and only one of those is a fact about the site (R4).
	Verified   bool
	ReadsPages bool
}

// consoleChecks is the list the console offers, in the order it runs them.
//
// Named for what each one reads rather than for how hard it pushes. docs/scope.md
// refuses the words full, deep and active, because each quietly authorises
// something this project has already declined to do, and a control labelled
// "Full scan" would undo that argument in the one place a user actually looks.
func consoleChecks() []consoleCheck {
	return []consoleCheck{
		{"tls", "Transport", "the handshake and the certificate behind it", policy.TLSVersion},
		{"web", "Reach", "how the site is reached over HTTP and HTTPS", policy.WebVersion},
		{"mail", "Mail", "what the domain's DNS says about its mail", policy.MailVersion},
	}
}

// methodPage is what assets/method.html ranges over.
type methodPage struct {
	Limits []policy.StandingLimit

	// Demo is true in the build that runs on denyfirst.dev.
	//
	// The web method page needs it because one of its paragraphs stopped being
	// true of every installation on 2026-09-11: the demonstration reads no
	// response body and an installation somebody runs themselves may read the
	// page. The user agent names one address from every installation, so a log
	// reader arrives here whichever one reached them — and a page that said
	// "this deployment reads no body" from a build that does would be a
	// scanning notice misdescribing the scan.
	//
	// It says both either way, and this decides which one it says first.
	Demo bool
}

// moved are paths that used to be pages of their own, or that a reader is
// likely to guess.
//
// A permanent redirect rather than a 404, because the old address is the one
// printed on a scanning notice and may be sitting in somebody's notes.
//
// /security.txt is here for a different reason. RFC 9116 puts the file under
// /.well-known/ and treats the top-level path as legacy, but a person looking
// for a way to report a vulnerability will try the short one, and answering
// that with a 404 costs a report. Redirecting rather than serving two copies
// keeps the canonical URL in the file true.
var moved = map[string]string{
	"/scanning":     "/privacy#scans",
	"/about":        "/privacy",
	"/security.txt": SecurityTxtPath,

	// The method page moved under the service it describes. Permanent: it is
	// not coming back to the root, and the address is printed in reports that
	// have already been shared.
	"/method": "/tls/method",
}

// standingIn are addresses serving something other than what they will serve.
//
// "/" is the project's address. Today the project has one check, so "/" sends
// a visitor to it; when there is a front page to put there, "/" will stop
// redirecting and /tls will not have moved. That is the whole reason for the
// split, and it is why this redirect is *temporary* while the one above is
// permanent — a permanent redirect is a promise that the address is finished
// changing, and this one is not.
//
// Every response here carries Cache-Control: no-store, so neither kind is
// cached in practice. The status code is still the honest one, because it is
// read by people and by intermediaries that ignore the header.
// standingIn holds the temporary redirects, and it is built rather than
// declared because the root differs by deployment.
//
// On the demonstration, "/" still stands in for /tls. That deployment exists to
// explain a check to somebody who arrived from a log line, and a console asking
// them to pick checks answers a question they did not ask.
//
// On an installation somebody runs themselves, "/" is the tool. Nobody there
// needs persuading that scanning is safe — they installed it — and what they
// want on the first screen is a field. Serving the same page to both was the
// thing that made a self-hosted installation feel like the website running
// locally rather than like an instrument.
var standingIn = rootRedirect()

func rootRedirect() map[string]string {
	if demo.Enabled {
		return map[string]string{"/": "/tls"}
	}
	return map[string]string{}
}

// files are the assets served as they are.
var files = map[string]struct {
	name        string
	contentType string
}{
	"/style.css":    {"assets/style.css", "text/css; charset=utf-8"},
	"/app.js":       {"assets/app.js", "text/javascript; charset=utf-8"},
	"/favicon.svg":  {"assets/favicon.svg", "image/svg+xml"},
	SecurityTxtPath: {"assets/security.txt", "text/plain; charset=utf-8"},

	// text/plain rather than application/pgp-keys, so a browser shows it
	// instead of offering to download a file a reporter then has to find.
	// gpg reads it either way.
	PGPKeyPath: {"assets/pgp-key.txt", "text/plain; charset=utf-8"},
}

// rendered holds every page as finished bytes.
//
// Built once at startup rather than per request. A template executed on every
// request is a small cost and a large surface: nothing here varies per
// visitor, so nothing here should be assembled per visitor.
var rendered = map[string][]byte{}

func init() {
	for path, p := range pages {
		body, err := render(p)
		if err != nil {
			// At startup, so a broken page stops the process instead of
			// reaching a visitor with a hole in it.
			panic("web: rendering " + path + ": " + err.Error())
		}
		rendered[path] = body
	}

	// The console, with nothing configured yet. Configure replaces it once the
	// program knows what this installation is; until then it describes the
	// stricter reading of its own state, which is the safe way round.
	//
	// Rendered here at all so that every path in the table answers from the
	// moment the package loads, including in a test that never calls Configure.
	if !demo.Enabled {
		rendered["/"] = renderConsole(false)
	}
}

// render turns one page into the bytes served for it.
//
// Split out of init() so that a page whose content depends on how the program
// was started can be built later, through exactly the same steps. Two rendering
// paths would be two chances for the shell, the method link or the escaping to
// differ between pages, and the one that differs is the one nobody is looking
// at.
func render(p *page) ([]byte, error) {
	layout, err := template.ParseFS(assets, "assets/layout.html")
	if err != nil {
		return nil, err
	}

	if p.Method == "" {
		p.Method = defaultMethodPage
	}

	fragment, err := assets.ReadFile(p.Fragment)
	if err != nil {
		return nil, err
	}
	if p.Data != nil {
		// Parsed as a template, and its values escaped by html/template on the
		// way in. They come from this repository either way; the escaping is
		// not a defence against them but the reason a sentence containing an
		// angle bracket cannot silently become markup.
		body, err := template.New(p.Fragment).Parse(string(fragment))
		if err != nil {
			return nil, err
		}

		var filled bytes.Buffer
		if err := body.Execute(&filled, p.Data); err != nil {
			return nil, err
		}
		fragment = filled.Bytes()
	}
	p.Body = template.HTML(fragment) //nolint:gosec // a file in this repository, not user input

	var out bytes.Buffer
	if err := layout.Execute(&out, p); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Handler serves the site.
// Configure tells the pages what this installation is.
//
// Called once, before Handler, by whatever builds the service. Everything else
// here is rendered at init() from facts that are true at build time; this is
// the one thing that is not, because whether a boundary was configured is
// decided on the command line.
//
// Not calling it leaves the console saying no proof of control is required and
// no page is read, which is the safe direction for it to be wrong in. A page
// claiming a boundary that is not there would tell an operator their service is
// safe to expose when it is not; a page understating one costs them a second
// look at a flag.
func Configure(verified bool) {
	rendered["/"] = renderConsole(verified)
}

// renderConsole builds the tool surface.
//
// A function rather than an entry in the pages table, because it is the one
// page whose content depends on how the program was started. It is rendered at
// init() too, so that a caller who never calls Configure still gets a page
// rather than a blank response.
func renderConsole(verified bool) []byte {
	p := &page{
		Title:       ToolName + " — check a name you run",
		Description: "Run this project's checks against one name: the handshake and certificate, how the site is reached, and what the domain's DNS says about its mail.",
		Fragment:    "assets/console.html",
		Script:      true,
		Method:      defaultMethodPage,
		Data: consolePage{
			Tool:   ToolName,
			Checks: consoleChecks(),

			// ReadsPages follows from Verified rather than being passed
			// beside it. They are one fact — internal/httpapi sets
			// ReadMarkup from the same scope — and two fields could be made
			// to disagree by a caller, which would put a claim about what
			// was read on a page with nothing behind it.
			Verified:   verified,
			ReadsPages: verified,
		},
	}

	body, err := render(p)
	if err != nil {
		// At startup, so a broken template stops the process rather than
		// serving half a page to whoever asks first.
		panic("rendering the console: " + err.Error())
	}
	return body
}

func Handler() http.Handler {
	return http.HandlerFunc(serve)
}

func serve(w http.ResponseWriter, r *http.Request) {
	setHeaders(w, r)

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Only GET and HEAD are served here.", http.StatusMethodNotAllowed)
		return
	}

	if to, found := moved[r.URL.Path]; found {
		http.Redirect(w, r, to, http.StatusMovedPermanently)
		return
	}

	if to, found := standingIn[r.URL.Path]; found {
		http.Redirect(w, r, to, http.StatusFound)
		return
	}

	if body, found := rendered[r.URL.Path]; found {
		write(w, r, "text/html; charset=utf-8", body)
		return
	}

	if file, found := files[r.URL.Path]; found {
		body, err := assets.ReadFile(file.name)
		if err != nil {
			// Unreachable unless the table and the embedded tree disagree,
			// which a test checks.
			http.Error(w, "That page is unavailable.", http.StatusInternalServerError)
			return
		}
		write(w, r, file.contentType, body)
		return
	}

	http.Error(w, "There is nothing at that address.", http.StatusNotFound)
}

func write(w http.ResponseWriter, r *http.Request, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))

	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func setHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()

	h.Set("Content-Security-Policy", contentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")

	// The privacy page promises no fonts from elsewhere, no content delivery
	// network, and no tag of any kind. That promise currently holds because
	// nobody has added one. This makes a browser refuse the resource if
	// somebody does: same-origin subresources need nothing extra, so it costs
	// nothing today and fails loudly the first time it would stop being true.
	h.Set("Cross-Origin-Embedder-Policy", "require-corp")

	h.Set("Permissions-Policy",
		"accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")

	// The whole site is a few kilobytes, so revalidating costs almost
	// nothing, and a cache that holds nothing cannot leak anything.
	h.Set("Cache-Control", "no-store")

	if r.TLS != nil {
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}
}
