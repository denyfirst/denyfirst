// Package httpapi serves the scanner over HTTP.
//
// The command line tool takes its input from the operator. This package takes
// it from strangers, and that difference is the whole design.
//
// Seven limits apply. Six are per request: how large the body may be, how long
// the work may take, how often one client may ask for a scan, how often one
// client may ask for anything at all, how many scans may run at once, and how
// often any one host may be scanned. The seventh is per connection, in
// LimitListener, because a TLS handshake costs real work before any request
// exists to limit.
//
// The fourth of those reads oddly beside the third, so it is worth a line. A
// request turned away before it reaches the scan allowance is cheap, but it is
// not free: it takes the counter lock, and it moves a figure this service
// publishes. An unlimited refusal path is therefore both a way to spend this
// machine's processor and a way to write into the only numbers an operator has
// to watch. A read allowance, kept apart from the scan one, closes that
// without letting a cross-site request spend the visitor's scan budget on
// their behalf. /healthz and /api/v1/stats draw on that same allowance, for
// the same reason: they do no scanning and should never be free to call in a
// loop.
//
// All but one protect this service. The per-host limit protects the server
// being measured, which had no say in whether it is measured at all.
//
// Every refusal is counted by reason. An operator running a public service
// has to be able to see a change in the shape of what arrives, and asking
// users to trust somebody who is not watching would be its own kind of
// carelessness. The counts name reasons rather than requesters, so they can
// be published without describing anybody.
//
// There is no equivalent of the command line switches. The scanner reaches
// the network through safedial, which refuses private, loopback, link-local
// and reserved destinations; it dials only implicit-TLS ports; and it takes
// hostnames rather than addresses. None of that is configurable here. A
// public endpoint that dials arbitrary addresses is an open proxy into
// whatever network it runs in.
//
// Nothing about a request is logged: not the target, not the client address,
// not the result. The addresses held for rate limiting live in memory and are
// swept as they go idle. This is the claim the project is built on, so it is
// enforced by there being no code that could write it down.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/scan"
)

// Defaults chosen to be comfortable by hand and unattractive in bulk.
const (
	DefaultRequestTimeout  = 30 * time.Second
	DefaultMaxRequestBytes = 4 << 10 // 4 KiB; the body is one JSON field
	DefaultMaxConcurrent   = 8
	DefaultBurst           = 5
	DefaultRefill          = 12 * time.Second // five at once, then one per twelve
	DefaultMaxTrackedIPs   = 20_000

	// readBurst and readRefill govern /healthz and /api/v1/stats. Generous,
	// because a monitor polling every few seconds is the intended use; bounded,
	// because neither endpoint should be free to call in a loop.
	readBurst  = 60
	readRefill = time.Second
)

// Limits configures the guards. A zero value takes every default above.
type Limits struct {
	RequestTimeout  time.Duration
	MaxRequestBytes int64
	MaxConcurrent   int

	// Burst is how many scans a client may run back to back; Refill is how
	// long one token takes to return.
	Burst  int
	Refill time.Duration

	// MaxTrackedIPs caps the rate limiter's memory. Once reached, unknown
	// clients are refused rather than admitted.
	MaxTrackedIPs int

	// TrustedProxies are the networks a reverse proxy connects from, and
	// TrustedProxyHops is how many of them stand in front of this service.
	//
	// Both are required before X-Forwarded-For is read at all. The hop count
	// alone says a proxy exists; the network list says the request in hand
	// actually came through it.
	//
	// That second check is the one that is easy to omit. A reverse proxy
	// hides an origin server but rarely removes it — the address turns up in
	// certificate transparency logs, in old DNS records, or in a scanning
	// service — and a client that reaches it directly writes whatever
	// X-Forwarded-For it likes. Trusting the header on the strength of a
	// configuration flag hands such a client a fresh rate limit key for every
	// request, which is the same as having no limit.
	TrustedProxies   []netip.Prefix
	TrustedProxyHops int
}

func (l Limits) withDefaults() Limits {
	if l.RequestTimeout <= 0 {
		l.RequestTimeout = DefaultRequestTimeout
	}
	if l.MaxRequestBytes <= 0 {
		l.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if l.MaxConcurrent <= 0 {
		l.MaxConcurrent = DefaultMaxConcurrent
	}
	if l.Burst <= 0 {
		l.Burst = DefaultBurst
	}
	if l.Refill <= 0 {
		l.Refill = DefaultRefill
	}
	if l.MaxTrackedIPs <= 0 {
		l.MaxTrackedIPs = DefaultMaxTrackedIPs
	}
	if l.TrustedProxyHops < 0 {
		l.TrustedProxyHops = 0
	}
	if len(l.TrustedProxies) == 0 {
		// A hop count with no network to check against would mean reading a
		// header any client can write. Falling back to the connection's own
		// address is the safe reading of an incomplete configuration.
		l.TrustedProxyHops = 0
	}
	return l
}

// Server is the HTTP surface. Use New; the zero value is not usable.
type Server struct {
	scanner *scan.Scanner
	limits  Limits
	rate    *limiter

	// reads limits the endpoints that do no scanning. Kept apart from rate
	// so that polling a health check can never consume a scan allowance, or
	// the reverse.
	reads *limiter

	sem     semaphore
	counts  *counters
	targets *targetLimiter
	mux     *http.ServeMux
}

// New builds a server. A nil scanner gets the default one, which dials
// through safedial.
func New(scanner *scan.Scanner, limits Limits, now func() time.Time) *Server {
	if scanner == nil {
		scanner = &scan.Scanner{}
	}
	limits = limits.withDefaults()

	s := &Server{
		scanner: scanner,
		limits:  limits,
		rate:    newLimiter(limits.Burst, limits.Refill, limits.MaxTrackedIPs, now),
		reads:   newLimiter(readBurst, readRefill, limits.MaxTrackedIPs, now),
		sem:     newSemaphore(limits.MaxConcurrent),
		counts:  newCounters(now),
		targets: newTargetLimiter(now),
		mux:     http.NewServeMux(),
	}

	s.mux.HandleFunc("POST /api/v1/scan", s.handleScan)
	s.mux.HandleFunc("GET /healthz", s.readLimited(s.handleHealth))
	s.mux.HandleFunc("GET /api/v1/stats", s.readLimited(s.handleStats))

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w, r)
	s.mux.ServeHTTP(w, r)
}

// scanRequest is the whole request body.
//
// The target travels in the body rather than in a query string on purpose. A
// URL is written to browser history, to the Referer header of anything the
// page later loads, and to the access log of every proxy on the path. This
// project undertakes not to record what was scanned; putting it in a URL
// would hand that record to everyone else.
type scanRequest struct {
	Target string `json:"target"`
}

type scanResponse struct {
	*scan.Result
	Findings []policy.Finding `json:"findings,omitempty"`
	Notes    []string         `json:"notes,omitempty"`
}

type errorResponse struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	key := clientKey(r, s.limits.TrustedProxies, s.limits.TrustedProxyHops)

	// Everything below this line costs something, including the refusals.
	//
	// The two checks that follow used to sit in front of the rate limiter, so
	// that a cross-site request could not spend the victim's scan allowance
	// on their behalf. That reasoning is right and is kept: the allowance
	// spent here is the read one, not the scan one. What was wrong was the
	// conclusion drawn from it — that a request refused early is free. It is
	// not. It takes the counter lock, and it moves a figure this service
	// publishes, so an unlimited refusal path is both a way to spend this
	// machine's processor and a way to write into the only numbers an
	// operator has to watch.
	if !s.reads.allow("read:" + key) {
		w.Header().Set("Retry-After", "1")
		s.refuse(w, http.StatusTooManyRequests, "rate_limited",
			"Too many requests from this address. Try again shortly.")
		return
	}

	// A page on another site can make a browser send this request, and it
	// would arrive carrying the visitor's address rather than the attacker's.
	// The victim's rate limit is spent, and a scan they never asked for is
	// attributed to them.
	//
	// That is already blocked, but only as a side effect: a cross-origin
	// request with a JSON content type needs a preflight, no CORS header is
	// sent, and the browser drops it; with a simple content type it arrives
	// and is refused for the wrong reason. Relying on that means the
	// protection disappears the day somebody relaxes the content type check
	// for a good reason.
	//
	// Sec-Fetch-Site says outright where the request came from and cannot be
	// set by script. An absent header is a client that is not a browser, and
	// so is not subject to this at all.
	//
	// Written as a list of what is allowed rather than a test for
	// "cross-site", which is the same choice made for hostname characters and
	// for the asset routes. The registry has four values today; a fifth added
	// later would pass a deny list silently, and silently is the only way
	// this check can fail.
	switch site := r.Header.Get("Sec-Fetch-Site"); site {
	case "",
		// Not a browser, or a browser too old to send it. Neither is subject
		// to this at all: the header exists to describe a browser's own
		// navigation, and a client that does not send it is not one a page on
		// another site can steer.
		"none",        // typed in, or opened from a bookmark
		"same-origin", // this page
		"same-site":   // another name on this site — scanner.denyfirst.dev
	default:
		s.refuse(w, http.StatusForbidden, "cross_site",
			"This endpoint is not available to other sites. Use it from this page, "+
				"from the command line tool, or from your own instance.")
		return
	}

	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		s.refuse(w, http.StatusUnsupportedMediaType, "unsupported_media",
			"Send application/json.")
		return
	}

	if !s.rate.allow(key) {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(s.limits.Refill)))
		s.refuse(w, http.StatusTooManyRequests, "rate_limited",
			"Too many scans from this address. Try again shortly.")
		return
	}

	// The reader is capped before any parsing, so an oversized body is
	// refused rather than buffered.
	body := http.MaxBytesReader(w, r.Body, s.limits.MaxRequestBytes)

	var req scanRequest
	dec := json.NewDecoder(body)
	// Unknown fields are rejected so a misspelled key fails loudly instead of
	// being silently ignored.
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.refuse(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				"The request body is larger than this endpoint accepts.")
			return
		}
		s.refuse(w, http.StatusBadRequest, "bad_request",
			"The body must be a JSON object with a single \"target\" field.")
		return
	}
	if dec.More() {
		s.refuse(w, http.StatusBadRequest, "bad_request",
			"The body must contain exactly one JSON object.")
		return
	}

	host, port, err := scan.SplitTarget(req.Target)
	if err != nil {
		// The message describes the rule rather than echoing the input, so
		// nothing a caller sent is reflected back.
		s.refuse(w, http.StatusBadRequest, "invalid_target",
			"The target must be a hostname, optionally with a port, and must not contain spaces or control characters.")
		return
	}

	if err := scan.CheckPort(port); err != nil {
		// The rule is described rather than the input repeated. SplitHostPort
		// does not require a port to be numeric, so err.Error() would carry
		// back whatever the caller sent.
		s.refuse(w, http.StatusBadRequest, "port_not_allowed",
			"That port is not scannable. This service connects only to "+
				strings.Join(scan.AllowedPorts, ", ")+".")
		return
	}

	// The command line accepts addresses; this does not. A scan of a name
	// carries that name in the client hello, which is what every browser
	// does, and a scan of an address carries none, which is what a scanner
	// does. It also declines to lend this address to working through a range
	// one entry at a time.
	if scan.IsIPTarget(host) {
		s.refuse(w, http.StatusBadRequest, "hostname_required",
			"Give a hostname rather than an address. A scan of a name looks like "+
				"an ordinary client to the server receiving it, which is how this "+
				"service prefers to appear. The command line tool accepts addresses "+
				"and runs from your own machine.")
		return
	}

	// A short list of defence and intelligence names, plus anyone who asked
	// to be left out. The message does not repeat the name back.
	if scan.IsExcluded(host) {
		s.refuse(w, http.StatusForbidden, "excluded",
			"This service does not scan that domain. A small number of names are "+
				"excluded, and any domain owner can ask to be added.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.limits.RequestTimeout)
	defer cancel()

	if err := s.sem.acquire(ctx); err != nil {
		w.Header().Set("Retry-After", "5")
		s.refuse(w, http.StatusServiceUnavailable, "too_busy",
			"Too many scans are in flight. Try again shortly.")
		return
	}
	defer s.sem.release()

	// Every other limit here protects this service. This one protects the
	// server about to be scanned, which had no say in the matter: one request
	// becomes up to fifty handshakes at the other end, and several users
	// aiming at one host multiply that.
	//
	// Checked after the semaphore rather than before it. A slot spent on a
	// request that is then turned away for being too busy is a slot the
	// target loses for a scan that never reached it — a small unfairness in
	// the one budget here that belongs to somebody else.
	//
	// The message does not name the target, and the limiter does not keep it
	// either. See targetlimit.go for how a repeated host is recognised
	// without being recorded.
	if !s.targets.allow(host, port) {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(targetRefill)))
		s.refuse(w, http.StatusTooManyRequests, "target_busy",
			"That server was scanned very recently. Each host has its own budget, "+
				"regardless of who asks, so that this service cannot be pointed at one "+
				"server in bulk. Try again in a moment.")
		return
	}

	result, err := s.scanner.Scan(ctx, net.JoinHostPort(host, port))

	// The deadline is checked whether or not the scan reported an error, and
	// that is the whole of this change.
	//
	// A probe does not fail. It measures, and a host that refused every
	// connection is a measurement — the report says so, and saying so is what
	// this project is for. So Scan returns nil almost always, and the branch
	// below used to be reached only through an error that could not happen:
	// the timeout was announced inside a 200 and the figure counting timeouts
	// was permanently zero. A counter that cannot move is not a low number, it
	// is silence, and an operator reads silence as nothing happening.
	if ctx.Err() != nil {
		s.refuse(w, http.StatusGatewayTimeout, "timeout",
			"The scan did not finish within the time allowed.")
		return
	}
	if err != nil {
		// Nothing reachable produces this today, which is why it is written
		// as a refusal rather than left out: Scan is allowed to fail by its
		// signature, and a failure that reached a caller uncounted would be
		// the same hole in a different place. See the reachability test in
		// refusal_test.go, which names this as the one code it cannot drive.
		//
		// The underlying error can name resolver internals and addresses, so
		// only the shape of the failure is returned.
		s.refuse(w, http.StatusBadGateway, "scan_failed",
			"The target could not be reached.")
		return
	}

	// A name that resolves only to a private, loopback, link-local or
	// reserved address. safedial refused every attempt, so nothing was
	// dialled and there is nothing to report about the host.
	//
	// Answered as a refusal rather than as a report of four failed
	// handshakes, for two reasons. A reader who scanned an internal name by
	// mistake is told why in one sentence instead of reading four identical
	// errors. And it is the only place this can be counted: the counter
	// exists so an operator can see attempts to use this service as a proxy
	// into whatever network it runs in, and until this line existed the
	// figure was always zero — the reason was in the report and never in the
	// numbers.
	//
	// The message names no address, so nothing about the resolution comes
	// back to the caller.
	if result.TLS != nil && result.TLS.BlockedDestination {
		s.refuse(w, http.StatusForbidden, "blocked_destination",
			"That name resolves only to addresses this service will not connect to — "+
				"private, loopback, link-local or reserved. Scanning one of those from here "+
				"would make this service a way into somebody else's network. The command "+
				"line tool runs on your own machine and has a switch for it.")
		return
	}

	// Counted only on success, and only as a number. Nothing about which
	// target produced it is kept, so the figure can be published without
	// describing anybody.
	s.counts.record(result.Verdict)

	writeJSON(w, http.StatusOK, scanResponse{
		Result:   result,
		Findings: result.Findings(),
		Notes:    result.Notes(),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"policy": policy.Version,
	})
}

// readLimited puts the cheap endpoints behind a limit of their own.
//
// Neither of them scans anything, so they were left open. That was a gap
// rather than a decision: /api/v1/stats clones a map on every call, and a
// client asking a few thousand times a second turns a health check into a way
// of spending this machine's processor.
//
// The allowance is separate from the one that governs scans and far larger,
// because a monitor polling every few seconds is exactly what these are for.
// The key is the same, so a client cannot spend one budget to refill the
// other.
func (s *Server) readLimited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := "read:" + clientKey(r, s.limits.TrustedProxies, s.limits.TrustedProxyHops)
		if !s.reads.allow(key) {
			w.Header().Set("Retry-After", "1")
			s.refuse(w, http.StatusTooManyRequests, "rate_limited",
				"Too many requests from this address. Try again shortly.")
			return
		}
		next(w, r)
	}
}

// setSecurityHeaders applies the same restrictions to every response.
//
// The API returns JSON and needs no resources at all, so the policy denies
// everything rather than allowing a narrower set. HTML pages need their own,
// looser policy; sharing this one with them would be the usual way a strict
// header quietly becomes a permissive one.
func setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()

	h.Set("Content-Security-Policy",
		"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Permissions-Policy",
		"accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")

	// Results are never cached: a shared cache would hold what someone
	// scanned, which is exactly what this project undertakes not to keep.
	h.Set("Cache-Control", "no-store")

	// Only meaningful over TLS. Asserting it over plaintext teaches a browser
	// nothing it can act on.
	if r.TLS != nil {
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	// The response is already committed by this point, so an encoding failure
	// can only be dropped. It is not logged, because the only thing worth
	// recording would identify the request.
	_ = enc.Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: apiError{Code: code, Message: message}})
}

// refuse writes an error and counts it.
//
// The handler uses this rather than writeError so that a refusal cannot be
// added without being counted. A figure that describes some refusals and not
// others is worse than none at all: an operator reads it as the whole
// picture and concludes that nothing happened.
func (s *Server) refuse(w http.ResponseWriter, status int, code, message string) {
	s.counts.refuse(code)
	writeError(w, status, code, message)
}

func retryAfterSeconds(d time.Duration) int {
	if s := int(d.Seconds()); s > 0 {
		return s
	}
	return 1
}

// Compile-time assurance that the server satisfies http.Handler.
var _ http.Handler = (*Server)(nil)

// SilentErrorLog returns the logger to give http.Server.ErrorLog.
//
// The default logger writes lines such as "http: panic serving 203.0.113.7"
// to standard error. That is a client address in a log file, which is exactly
// what this project undertakes not to keep — and it would appear without any
// code here ever writing it. A promise that depends on a library's default
// staying convenient is not a promise.
//
// Discarding these lines costs the ability to diagnose a panic from its log.
// The exchange is deliberate: a panic is reproducible from a stack trace in a
// test, and a leaked address cannot be taken back.
func SilentErrorLog() *log.Logger {
	return log.New(io.Discard, "", 0)
}
