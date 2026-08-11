// Package httpapi serves the scanner over HTTP.
//
// The command line tool takes its input from the operator. This package takes
// it from strangers, and that difference is the whole design.
//
// Four limits apply to every request: how large the body may be, how long the
// work may take, how often one client may ask, and how many scans may run at
// once. Each closes a way of turning the service against itself or against a
// third party.
//
// There is no equivalent of the command line -allow-private switch. The
// scanner reaches the network through safedial, which refuses private,
// loopback, link-local, and reserved destinations, and here that is not
// configurable. A public endpoint that dials arbitrary addresses is an open
// proxy into whatever network it runs in.
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

	// TrustedProxyHops is the number of reverse proxies in front of this
	// service. Leave it at zero unless there really is one: a service that
	// trusts X-Forwarded-For without a proxy lets every client choose its own
	// rate limit key.
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
	return l
}

// Server is the HTTP surface. Use New; the zero value is not usable.
type Server struct {
	scanner *scan.Scanner
	limits  Limits
	rate    *limiter
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
		sem:     newSemaphore(limits.MaxConcurrent),
		counts:  newCounters(now),
		targets: newTargetLimiter(now),
		mux:     http.NewServeMux(),
	}

	s.mux.HandleFunc("POST /api/v1/scan", s.handleScan)
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/stats", s.handleStats)

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
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type",
			"Send application/json.")
		return
	}

	if !s.rate.allow(clientKey(r, s.limits.TrustedProxyHops)) {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(s.limits.Refill)))
		writeError(w, http.StatusTooManyRequests, "rate_limited",
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
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				"The request body is larger than this endpoint accepts.")
			return
		}
		writeError(w, http.StatusBadRequest, "bad_request",
			"The body must be a JSON object with a single \"target\" field.")
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "bad_request",
			"The body must contain exactly one JSON object.")
		return
	}

	host, port, err := scan.SplitTarget(req.Target)
	if err != nil {
		// The message describes the rule rather than echoing the input, so
		// nothing a caller sent is reflected back.
		writeError(w, http.StatusBadRequest, "invalid_target",
			"The target must be a hostname, optionally with a port, and must not contain spaces or control characters.")
		return
	}
	if err := scan.CheckPort(port); err != nil {
		// The rule is described rather than the input repeated. SplitHostPort
		// does not require a port to be numeric, so err.Error() would carry
		// back whatever the caller sent.
		writeError(w, http.StatusBadRequest, "port_not_allowed",
			"That port is not scannable. This service connects only to "+
				strings.Join(scan.AllowedPorts, ", ")+".")
		return
	}
	// Every other limit here protects this service. This one protects the
	// server about to be scanned, which had no say in the matter: one request
	// becomes roughly thirty handshakes at the other end, and several users
	// aiming at one host multiply that.
	//
	// The message does not name the target, and the limiter does not keep it
	// either. See targetlimit.go for how a repeated host is recognised
	// without being recorded.
	if !s.targets.allow(host, port) {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(targetRefill)))
		writeError(w, http.StatusTooManyRequests, "target_busy",
			"That server was scanned very recently. Each host has its own budget, "+
				"regardless of who asks, so that this service cannot be pointed at one "+
				"server in bulk. Try again in a moment.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.limits.RequestTimeout)
	defer cancel()

	if err := s.sem.acquire(ctx); err != nil {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, "too_busy",
			"Too many scans are in flight. Try again shortly.")
		return
	}
	defer s.sem.release()

	result, err := s.scanner.Scan(ctx, net.JoinHostPort(host, port))
	if err != nil {
		if ctx.Err() != nil {
			writeError(w, http.StatusGatewayTimeout, "timeout",
				"The scan did not finish within the time allowed.")
			return
		}
		// The underlying error can name resolver internals and addresses, so
		// only the shape of the failure is returned.
		writeError(w, http.StatusBadGateway, "scan_failed",
			"The target could not be reached.")
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

// setSecurityHeaders applies the same restrictions to every response.
//
// The API returns JSON and needs no resources at all, so the policy denies
// everything rather than allowing a narrower set. HTML pages will need their
// own, looser policy; sharing this one with them would be the usual way a
// strict header quietly becomes a permissive one.
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
