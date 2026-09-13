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
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/dkim"
	"github.com/denyfirst/denyfirst/internal/exclusion"
	"github.com/denyfirst/denyfirst/internal/mailscan"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/results"
	"github.com/denyfirst/denyfirst/internal/scan"
	"github.com/denyfirst/denyfirst/internal/verify"
	"github.com/denyfirst/denyfirst/internal/webscan"
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

	// web runs the web check. Set by New, replaceable before serving so a
	// test can hand it a prober that reaches a server it started.
	web    *webscan.Scanner
	mail   *mailscan.Scanner
	limits Limits
	rate   *limiter

	// reads limits the endpoints that do no scanning. Kept apart from rate
	// so that polling a health check can never consume a scan allowance, or
	// the reverse.
	reads *limiter

	routes []route

	// store keeps results, where the operator asked for them to be kept. Nil
	// keeps nothing, which is the default and what the demonstration gets.
	store *results.Store

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

		// The web check is built from the boundary the caller configured
		// rather than from nothing.
		//
		// It was built from nothing, and that was a hole. porchd passed a
		// verification scope to the TLS scanner and never touched this one, so
		// the same service refused an unproven host on /api/v1/tls/scan and
		// scanned it on /api/v1/web/scan. Every guard was in place, every unit
		// test passed, and the deployment had no boundary on half its surface:
		// the component was secure and the composition was not.
		//
		// N6 says a guard belongs where the connection is made rather than in
		// the handler that calls it today, and it does. What that rule does not
		// say, and what this line is, is that a guard every constructor has to
		// remember to pass is a guard somebody forgets. So the caller
		// configures the boundary once, on the scanner it hands in, and every
		// check this service adds inherits it here.
		// Roots travels with the boundary and for the same reason. A service
		// that read its own trust store, checked it was not empty and refused
		// to start without one handed it to the TLS scanner; the web check was
		// built without it and judged its chains against whatever the platform
		// picks (R7). One kind of omission, two fields.
		// ReadMarkup follows the proof rather than the deployment's name. A
		// service that requires proof of control is reading a page belonging to
		// whoever asked about it; one configured without a scope is scanning
		// names nobody proved anything about, which N9 says a service must not
		// do — and until somebody fixes that, it does not also read their
		// pages. The demonstration is refused at the response in webprobe, so
		// this line is not what protects it.
		web: &webscan.Scanner{
			Verify:     scanner.Verify,
			Roots:      scanner.Roots,
			ReadMarkup: scanner.Verify != nil,
		},

		// The mail check carries the boundary, and now the trust store with it.
		//
		// It said "no trust store, because it verifies no certificate" until
		// the MTA-STS policy could be read, and that stopped being true the day
		// it could: the policy is fetched over HTTPS and the certificate must
		// verify, so this check judges a chain and R7 says which store decides
		// that cannot depend on the platform. One line behind one feature, and
		// it is the third time this exact field has been the omission.
		//
		// ReadSTSPolicy follows the proof, exactly as ReadMarkup does above and
		// for the argument written out there. A service configured with a scope
		// fetches the policy of a domain somebody has shown is theirs; one
		// configured without a scope is scanning names nobody proved anything
		// about, which N9 says a service must not do — and until that is fixed,
		// it does not also fetch their files.
		//
		// The resolver is set below rather than here, and that is not tidiness.
		// Documented selectors by default, and the operator's own are not
		// offered here: a service takes one field, and a list of selectors in
		// a request body is a field somebody else fills in. The command line
		// is where an operator names their own.
		mail: &mailscan.Scanner{
			Verify:        scanner.Verify,
			Roots:         scanner.Roots,
			ReadSTSPolicy: scanner.Verify != nil,
			DKIMSelectors: dkim.DocumentedSelectors(),
		},
		limits:  limits,
		rate:    newLimiter(limits.Burst, limits.Refill, limits.MaxTrackedIPs, now),
		reads:   newLimiter(readBurst, readRefill, limits.MaxTrackedIPs, now),
		sem:     newSemaphore(limits.MaxConcurrent),
		counts:  newCounters(now),
		targets: newTargetLimiter(now),
		mux:     http.NewServeMux(),
	}

	// Two paths, one handler, and deliberately not a redirect.
	//
	// The check is addressed under its own name now that the project expects
	// more than one, and /api/v1/scan is what every script written against
	// this service already says. A redirect would be the tidy answer for a
	// page and is the wrong one here: 307 and 308 preserve a POST body, 301
	// and 302 do not, and clients disagree about which they follow. A caller
	// whose body is silently dropped gets an error that looks like ours.
	//
	// So the old path keeps working, identically, until something says
	// otherwise in writing.
	// The resolver travels only when there is one.
	//
	// mailscan.Scanner.Resolver is an interface and scan.Scanner.Resolver is a
	// *dnsclient.Client. Assigning a nil pointer to an interface field produces
	// an interface that is *not* nil — it is a non-nil interface holding a nil
	// pointer — so mailscan's "nil means build a default one" never fires and
	// the first lookup dereferences nothing. That is not a hypothetical: it
	// panicked on the first real request to /api/v1/mail/scan, while every test
	// in this package passed, because the fixtures all supply a resolver.
	//
	// So the assignment is guarded here, and mailscan refuses a nil client of
	// its own accord as well. Two places, because the trap is in the language
	// rather than in either of them, and the next field of this shape will be
	// written by somebody who has not read this comment.
	if scanner.Resolver != nil {
		s.mail.Resolver = scanner.Resolver
	}

	tls, web := s.tlsCheck(), s.webCheck()
	s.routes = []route{
		{http.MethodPost, "/api/v1/tls/scan", s.scanHandler(tls)},
		{http.MethodPost, "/api/v1/scan", s.scanHandler(tls)},

		// The web check's address. Every guard the TLS endpoint has applies to
		// it, because there is one chain and both endpoints walk it — see
		// checks.go.
		{http.MethodPost, "/api/v1/web/scan", s.scanHandler(web)},

		// The mail check's address. It opens no connection, and it walks the
		// same chain of guards anyway: a lookup a stranger caused this service
		// to make is still a lookup this service made.
		{http.MethodPost, "/api/v1/mail/scan", s.scanHandler(s.mailCheck())},

		{http.MethodGet, "/healthz", s.readLimited(s.handleHealth)},
		{http.MethodGet, "/api/v1/stats", s.readLimited(s.handleStats)},
	}
	for _, rt := range s.routes {
		s.mux.HandleFunc(rt.method+" "+rt.path, rt.handler)
	}

	return s
}

// route is one address this service answers.
type route struct {
	method  string
	path    string
	handler http.HandlerFunc
}

// Paths are the addresses this service answers, for whatever mounts it.
//
// Exported because cmd/porchd routes the API and the pages separately —
// they need different security headers, and one policy for both would mean the
// API inherits permission it never needed. That separation requires the mount
// to name each API path, and a second hand-written list is a list that falls
// behind: /api/v1/mail/scan was registered here and unreachable in the binary
// for exactly as long as it took to try it, because main.go did not know about
// it and nothing compared the two.
//
// One list, two readers. TestEveryPathThisServiceAnswersIsMounted holds them
// together.
func (s *Server) Paths() []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(s.routes))
	for _, rt := range s.routes {
		if seen[rt.path] {
			continue
		}
		seen[rt.path] = true
		out = append(out, rt.path)
	}
	return out
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

	// Notes carry their kind. Until 2026-09-01 they were bare strings and
	// every consumer, this project's own page included, had to guess which
	// of them were results and which were limits. It guessed wrong: it filed
	// all of them under a heading saying nothing had been measured.
	Notes []policy.Note `json:"notes,omitempty"`
}

type errorResponse struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// scanHandler builds the endpoint for one check.
//
// Every guard below applies to every check. What differs is described by the
// check itself: how a target is parsed, what budget it spends, what it runs,
// and what it writes. See checks.go for why this is one chain rather than one
// handler per endpoint.
func (s *Server) scanHandler(c check) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.handleScan(w, r, c)
	}
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request, c check) {
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

	// What a target is depends on the check. The TLS check takes a hostname
	// and optionally a port; the web check takes a bare hostname, because it
	// reads a site over 80 and 443 the way a browser reaches an address
	// somebody types.
	//
	// Validity before permission, so that somebody who mistyped is told they
	// mistyped rather than told this deployment does not do that (N6).
	t, refused := c.parse(req.Target)
	if refused != nil {
		s.refuse(w, refused.status, refused.code, refused.message)
		return
	}
	host := t.host

	// A short list of defence and intelligence names, plus anyone who asked
	// to be left out. The message does not repeat the name back.
	if exclusion.Covers(host) {
		s.refuse(w, http.StatusForbidden, "excluded",
			"This service does not scan that domain. A small number of names are "+
				"excluded, and any domain owner can ask to be added.")
		return
	}

	// This deployment connects only to hosts this project owns.
	//
	// Scanner.Scan refuses the same host, and that is where the property
	// lives — this is here so a visitor gets a sentence and a way forward
	// rather than a scan that failed, and so the refusal is counted as what
	// it is rather than as a host that could not be reached.
	if demo.Refusal(host) {
		s.refuse(w, http.StatusForbidden, "not_demonstrated",
			"This deployment scans only hosts this project owns. Run the tool on your "+
				"own machine to scan anything else: github.com/denyfirst/denyfirst")
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
	if !s.targets.allow(host, t.scope) {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(targetRefill)))
		s.refuse(w, http.StatusTooManyRequests, "target_busy",
			"That server was scanned very recently. Each host has its own budget, "+
				"regardless of who asks, so that this service cannot be pointed at one "+
				"server in bulk. Try again in a moment.")
		return
	}

	out, err := c.run(ctx, t)

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
	// A name this deployment has not been shown control of.
	//
	// Recognised here rather than asked here, and that is the difference
	// between this boundary and the two above it. The exclusion list and the
	// demonstration list are tables, so asking them in the handler costs
	// nothing. This one is a lookup, and asking it before the scan and again
	// inside the scanner would be two queries somebody else's resolver serves
	// for one request. So the scanner asks it — which is where N6 wants it, at
	// the connection, so that a check added later cannot walk around it — and
	// this reads the answer.
	//
	// Reading it is not cosmetic. Without this line the refusal arrived as
	// scan_failed with a 502 saying the target could not be reached: a
	// sentence about somebody else's server for a decision made entirely
	// here. An operator reads a network fault, checks the host, finds it
	// healthy, and has been told nothing about the record they never
	// published. It also counted a deliberate refusal as a failure, in the one
	// set of figures anybody has to watch this service by.
	if errors.Is(err, verify.ErrNotVerified) {
		s.refuse(w, http.StatusForbidden, "not_verified",
			"This deployment scans only domains it has been shown control of. Publish a TXT "+
				"record at "+verify.Label+" beneath the domain, carrying the token this "+
				"deployment expects for it, and ask again. The operator can print that token.")
		return
	}

	if err != nil {
		// Nothing reachable produces this today, on either check, which is
		// why it is written as a refusal rather than left out: both scanners
		// are allowed to fail by their signature, and a failure that reached
		// a caller uncounted would be the same hole in a different place.
		//
		// The TLS scanner cannot fail once the handler has validated the
		// target. The web scanner returns an error only for a target its
		// probe refuses or a name outside the lists, and all of those are
		// asked above. See the reachability test in refusal_test.go, which
		// names this as the one code it cannot drive.
		//
		// A deployment that requires proof of control adds one way through
		// here that a deployment without it does not have: the challenge
		// lookup itself failing. That is not the domain being unverified —
		// which is answered above and says so — it is this service being
		// unable to ask, and "could not be reached" is the honest shape of
		// it. The alternative would tell an operator to publish a record they
		// have already published.
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
	// Both checks carry the fact as a field rather than as prose, so this
	// reads the same for either.
	if out.blocked {
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
	//
	// Counted against its own check, because a verdict stopped meaning one
	// thing the moment a second check existed (R22).
	s.counts.record(c.name, out.verdict)

	// Kept, where the operator asked for results to be kept.
	//
	// This is the one place in this package that writes a target down, and it
	// happens only because somebody named a directory. A failure is reported to
	// the service's own error output and never to the caller: the scan ran, the
	// report is about to be sent, and losing the copy is not the requester's
	// problem to be told about.
	if s.store.Enabled() {
		if err := s.store.Put(c.name, t.historyName(), string(out.verdict), out.policy, out.findings); err != nil {
			log.Printf("a result was not kept: %v", err)
		}
	}

	writeJSON(w, http.StatusOK, out.body)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"policy": policy.TLSVersion,
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

// KeepResults tells this service where to write what it measured.
//
// Nil or an unset store keeps nothing, which is the default. Called before
// serving, like every other piece of configuration here: a service that could
// start keeping records while running would be one whose promise depends on
// when somebody looked.
//
// What is written is the report that was already produced. Nothing here is
// served back — see internal/results for why a browsable history of an estate's
// weaknesses is not something a service with no authentication should offer.
func (s *Server) KeepResults(store *results.Store) {
	s.store = store
}

// UseWebScanner replaces the scanner behind the web check.
//
// Call it before serving; it is not safe once requests are being handled, for
// the same reason RestoreStats is not.
//
// It exists because New takes the TLS scanner as an argument and widening that
// signature would touch every caller and every test to say nothing new. A
// caller that wants the default — which dials through safedial and reaches only
// ports 80 and 443 — passes nothing and gets it.
func (s *Server) UseWebScanner(w *webscan.Scanner) {
	if w == nil {
		return
	}

	// The boundary is carried over rather than replaced.
	//
	// This is a door for tests, and a door for tests is how a boundary comes
	// to be off in production — the replacement carries a prober and no scope,
	// and the service that configured one silently stops asking. Whatever a
	// caller hands in, the scope this server was built with survives it.
	//
	// A caller that genuinely wants no verification builds a server without
	// one, which is what every test here does and what the command line is.
	if w.Verify == nil {
		w.Verify = s.scanner.Verify
	}

	// And the trust store, for the same reason. A replacement handed in to
	// reach a test server carries no store, and a service that resolved one
	// would silently stop judging web chains against it.
	if w.Roots == nil {
		w.Roots = s.scanner.Roots
	}

	s.web = w
}
