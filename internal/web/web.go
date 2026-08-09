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
package web

import (
	"embed"
	"net/http"
	"strconv"
	"time"
)

//go:embed assets
var assets embed.FS

// buildTime is when the binary was built, used for conditional requests. It
// is fixed for the life of the process, which is what makes it usable as a
// validator.
var buildTime = time.Now().UTC().Truncate(time.Second)

// contentSecurityPolicy is deliberately not the one the API uses.
//
// The API returns JSON and needs nothing at all, so its policy denies
// everything. A page needs a stylesheet and a script, so its policy must be
// looser. Sharing one policy between them is the usual way a strict header
// quietly becomes a permissive one: the page forces 'self' into it, and the
// API silently inherits permission it never needed.
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

type asset struct {
	file        string
	contentType string
}

// routes is the complete list of what this handler will serve. A request for
// anything else is a 404, including anything that would have been reachable
// by walking the embedded tree.
var routes = map[string]asset{
	"/":            {"assets/index.html", "text/html; charset=utf-8"},
	"/style.css":   {"assets/style.css", "text/css; charset=utf-8"},
	"/app.js":      {"assets/app.js", "text/javascript; charset=utf-8"},
	"/favicon.svg": {"assets/favicon.svg", "image/svg+xml"},
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

	route, found := routes[r.URL.Path]
	if !found {
		http.Error(w, "There is nothing at that address.", http.StatusNotFound)
		return
	}

	body, err := assets.ReadFile(route.file)
	if err != nil {
		// Unreachable unless the table and the embedded tree disagree, which
		// a test checks at build time.
		http.Error(w, "That page is unavailable.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", route.contentType)
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
