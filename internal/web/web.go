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
// Pages share one layout. Three copies of a header would be three places for
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
const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self'; " +
	"connect-src 'self'; " +
	"form-action 'none'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'"

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

	// Body is filled in at startup. It is template.HTML because the fragment
	// is a file in this repository rather than anything a user supplied.
	Body template.HTML
}

// pages is the whole site.
//
// There were five of these and now there are three. Splitting the
// explanation across separate pages for scanning, privacy and guarantees
// meant a reader had to already know which one answered their question, and
// somebody who arrives because a scan reached their server does not. One page
// with headings and a set of jump links reads better than three that each
// tell a third of the story.
var pages = map[string]*page{
	"/": {
		Title:       "denyfirst — check what a server actually negotiates",
		Description: "Check a server's TLS configuration and certificate against cited standards. Nothing about the scan is recorded.",
		Fragment:    "assets/index.html",
		Script:      true,
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
	layout := template.Must(template.ParseFS(assets, "assets/layout.html"))

	for path, p := range pages {
		fragment, err := assets.ReadFile(p.Fragment)
		if err != nil {
			// At startup, so a missing fragment stops the process instead of
			// producing a page with a hole in it.
			panic("web: reading " + p.Fragment + ": " + err.Error())
		}
		p.Body = template.HTML(fragment) //nolint:gosec // a file in this repository, not user input

		var out bytes.Buffer
		if err := layout.Execute(&out, p); err != nil {
			panic("web: rendering " + path + ": " + err.Error())
		}
		rendered[path] = out.Bytes()
	}
}

// Handler serves the site.
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
	h.Set("Permissions-Policy",
		"accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")

	// The whole site is a few kilobytes, so revalidating costs almost
	// nothing, and a cache that holds nothing cannot leak anything.
	h.Set("Cache-Control", "no-store")

	if r.TLS != nil {
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}
}
