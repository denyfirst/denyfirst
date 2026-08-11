// Command denyfirstd serves the scanner over HTTP.
//
// The handler in internal/httpapi guards what arrives in a request. This
// binary guards what happens before a request is complete — the part
// http.Server owns and leaves unbounded by default.
//
// Usage:
//
//	denyfirstd -listen 127.0.0.1:8080
//	denyfirstd -listen :443 -tls-cert /etc/ssl/denyfirst.pem -tls-key /etc/ssl/denyfirst.key
//
// Certificates are read from disk rather than obtained through an ACME
// library, because every Go ACME client is a third-party module and this
// project has none. A renewal tool writes the files; this process notices and
// reloads them without restarting.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/denyfirst/denyfirst/internal/httpapi"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/scan"
	"github.com/denyfirst/denyfirst/internal/web"
)

const (
	// shutdownGrace is how long in-flight requests have to finish once a
	// signal arrives. A scan can hold a connection for the whole request
	// timeout, so this must exceed it or a clean stop truncates responses.
	shutdownGrace = 45 * time.Second

	// maxHeaderBytes caps request headers. The default of 1 MiB is generous
	// for an endpoint whose entire request is one JSON field.
	maxHeaderBytes = 16 << 10

	// writeMargin is added to the scan budget to produce WriteTimeout.
	//
	// WriteTimeout covers the whole exchange, so setting it at or below the
	// scan budget cuts the response off mid-encode. The user then sees a
	// truncated body with no explanation, which is worse than an error.
	writeMargin = 10 * time.Second

	// statsInterval is how often the counters are written to disk.
	//
	// On a timer rather than per request. Writing per request would put disk
	// latency in the scan path and, worse, would make the file's modification
	// time a record of when somebody used the service.
	statsInterval = time.Minute
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		listen = flag.String("listen", "127.0.0.1:8080",
			"address to listen on; loopback by default so an accidental start\n"+
				"\tis not immediately public")

		tlsCert = flag.String("tls-cert", "", "path to a PEM certificate chain; empty serves plain HTTP")
		tlsKey  = flag.String("tls-key", "", "path to the matching private key")

		requestTimeout = flag.Duration("request-timeout", httpapi.DefaultRequestTimeout,
			"budget for one scan")
		maxConcurrent = flag.Int("max-concurrent", httpapi.DefaultMaxConcurrent,
			"scans allowed to run at the same time")
		maxConnections = flag.Int("max-connections", httpapi.DefaultMaxConnections,
			"connections allowed to be open at once, before any request exists")
		burst = flag.Int("burst", httpapi.DefaultBurst,
			"scans one client may run back to back")
		refill = flag.Duration("refill", httpapi.DefaultRefill,
			"how long one rate limit token takes to return")
		maxTracked = flag.Int("max-tracked-clients", httpapi.DefaultMaxTrackedIPs,
			"how many clients the rate limiter remembers before refusing new ones")

		trustedProxyHops = flag.Int("trusted-proxy-hops", 0,
			"number of reverse proxies in front of this service; leave at zero unless\n"+
				"\tthere really is one, because trusting X-Forwarded-For without a proxy\n"+
				"\tlets every client choose its own rate limit key")

		statsFile = flag.String("stats-file", "",
			"path to a file holding the aggregate counters; empty keeps them in\n"+
				"\tmemory only, so a restart resets the published total")

		showVersion = flag.Bool("version", false, "print the policy version and exit")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "denyfirstd serves the denyfirst scanner over HTTP.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  %s [flags]\n\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Println(policy.Version)
		return 0
	}

	if (*tlsCert == "") != (*tlsKey == "") {
		fmt.Fprintln(os.Stderr, "-tls-cert and -tls-key must be given together")
		return 2
	}

	limits := httpapi.Limits{
		RequestTimeout:   *requestTimeout,
		MaxConcurrent:    *maxConcurrent,
		Burst:            *burst,
		Refill:           *refill,
		MaxTrackedIPs:    *maxTracked,
		TrustedProxyHops: *trustedProxyHops,
	}

	// The scanner is left at its defaults on purpose. It dials through
	// safedial, enforces the port allow list, and takes hostnames rather than
	// addresses. There is no flag here that would turn any of it off.
	api := httpapi.New(&scan.Scanner{}, limits, nil)

	if *statsFile != "" {
		if snapshot, err := loadStats(*statsFile); err == nil {
			api.RestoreStats(snapshot)
		} else if !os.IsNotExist(err) {
			// A corrupt or unreadable file costs a counter, not a service.
			// Starting from zero is wrong; refusing to start is worse.
			fmt.Fprintf(os.Stderr, "counters could not be read from %s, starting from zero: %v\n", *statsFile, err)
		}
	}

	// The API and the pages are routed separately because they need different
	// security headers. The API needs no resources at all and denies
	// everything; a page needs its own stylesheet and script. Serving both
	// through one policy would mean the API inherits permission it never
	// needed, which is the usual way a strict header becomes a loose one.
	root := http.NewServeMux()
	root.Handle("/api/v1/scan", api)
	root.Handle("/api/v1/stats", api)
	root.Handle("/healthz", api)
	root.Handle("/", web.Handler())

	srv := &http.Server{
		Handler: root,

		// ReadHeaderTimeout is the one that matters most. Without it, a
		// client can open a connection and send headers one byte at a time
		// for as long as it likes, holding a slot the whole while. A few
		// hundred such connections exhaust the server without sending a
		// single complete request. Go leaves this unset by default.
		ReadHeaderTimeout: 5 * time.Second,

		// ReadTimeout covers headers and body together, so a slow body gets
		// no more room than a slow header.
		ReadTimeout: 10 * time.Second,

		// WriteTimeout must outlast the scan or the response is truncated
		// while it is still being written.
		WriteTimeout: *requestTimeout + writeMargin,

		// IdleTimeout closes kept-alive connections that have gone quiet,
		// so an idle client cannot hold a slot indefinitely.
		IdleTimeout: 60 * time.Second,

		MaxHeaderBytes: maxHeaderBytes,

		// The default logger writes lines such as "http: panic serving
		// 203.0.113.7" to standard error. That is a client address in a log
		// file, which this project undertakes not to keep. The promise has to
		// survive a library default, so the logger is replaced rather than
		// trusted to stay quiet.
		ErrorLog: httpapi.SilentErrorLog(),

		// HTTP/2 is switched off. A non-nil but empty TLSNextProto is what
		// stops http.Server from enabling it alongside TLS.
		//
		// Its concurrent stream handling and its priority scheme have each
		// produced denial-of-service classes, Rapid Reset among them, and
		// tuning either needs golang.org/x/net/http2, which this project does
		// not carry. Removing the protocol removes the question rather than
		// leaving it to a default somebody would have to keep watching.
		//
		// What it costs is multiplexing. This site is four small files and
		// one request, which keep-alive over HTTP/1.1 covers entirely.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}

	if *tlsCert != "" {
		reloader, err := newCertReloader(*tlsCert, *tlsKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "loading the certificate: %v\n", err)
			return 1
		}

		srv.TLSConfig = &tls.Config{
			// GetCertificate is consulted per handshake, so a renewal that
			// rewrites the files is picked up without a restart. Reading the
			// certificate once at startup would mean an outage every sixty
			// days, or a restart script nobody tests.
			GetCertificate: reloader.get,

			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},

			// HTTP/2 is not offered, so it is not advertised either. A server
			// that names a protocol it will not speak invites a client to
			// select it and then fail.
			NextProtos: []string{"http/1.1"},
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *statsFile != "" {
		go persistStats(ctx, api, *statsFile, statsInterval)
	}

	// Request-level limits arrive too late for one attack: a TLS handshake
	// costs an elliptic curve operation before any HTTP is parsed, so a
	// client that connects, completes a handshake and then does nothing never
	// reaches a single one of them.
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listening on %s: %v\n", *listen, err)
		return 1
	}
	listener = httpapi.LimitListener(listener, *maxConnections)

	errc := make(chan error, 1)
	go func() {
		if *tlsCert != "" {
			// The paths are already in TLSConfig.GetCertificate.
			errc <- srv.ServeTLS(listener, "", "")
			return
		}
		errc <- srv.Serve(listener)
	}()

	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
	}
	// The only line this process prints in normal operation. It names the
	// service, not a request.
	fmt.Fprintf(os.Stderr, "denyfirstd listening on %s://%s, policy %s\n",
		scheme, *listen, policy.Version)

	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "server stopped: %v\n", err)
			return 1
		}
		return 0

	case <-ctx.Done():
	}

	// Stop accepting, then give in-flight scans their remaining budget.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	shutdownErr := srv.Shutdown(shutdownCtx)

	// Written after the shutdown so the figure includes the scans that were
	// still running when the signal arrived. The timer writes at most a
	// minute behind; this makes the last write exact.
	if *statsFile != "" {
		if err := saveStats(*statsFile, api.Stats()); err != nil {
			fmt.Fprintf(os.Stderr, "counters could not be written to %s: %v\n", *statsFile, err)
		}
	}

	if shutdownErr != nil {
		// Forcing the close loses in-flight responses, which is the point of
		// reporting it rather than exiting quietly.
		fmt.Fprintf(os.Stderr, "shutdown did not complete within %s: %v\n", shutdownGrace, shutdownErr)
		_ = srv.Close()
		return 1
	}

	fmt.Fprintln(os.Stderr, "denyfirstd stopped")
	return 0
}

// loadStats reads the counters left by a previous run.
func loadStats(path string) (httpapi.Snapshot, error) {
	var snapshot httpapi.Snapshot

	// The path comes from a command line flag set by whoever runs this
	// process. Nothing a stranger sends reaches here: the service has no
	// endpoint that names a file, and internal/httpapi touches no filesystem
	// at all. An operator who can pass this flag can already read the file
	// themselves.
	//
	// #nosec G304 -- operator-supplied path, never request-supplied
	body, err := os.ReadFile(path)
	if err != nil {
		return snapshot, err
	}
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return snapshot, fmt.Errorf("parsing %s: %w", path, err)
	}
	return snapshot, nil
}

// saveStats writes the counters.
//
// The file holds totals and nothing else: no hostname, no address, no
// per-request timestamp. Whoever seizes this machine learns that the service
// was used and by how much, which is already published on the site, and
// learns nothing about who used it or what they looked at.
//
// The write goes to a temporary file and is then renamed, because a process
// killed mid-write would otherwise leave a truncated file that the next start
// cannot read. Rename is atomic on the filesystems this runs on, so a reader
// sees either the old file or the new one.
func saveStats(path string, snapshot httpapi.Snapshot) error {
	body, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}

	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(body, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// persistStats writes the counters periodically until the context ends.
func persistStats(ctx context.Context, api *httpapi.Server, path string, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	var last httpapi.Snapshot

	for {
		select {
		case <-ctx.Done():
			// The final write happens in run, after the shutdown, so that it
			// includes whatever finished during the grace period.
			return

		case <-ticker.C:
			current := api.Stats()
			if current.Equal(last) {
				// Nothing happened, so nothing is written. An idle service
				// leaves an idle file, and the modification time then says
				// only when the service last did something.
				continue
			}
			if err := saveStats(path, current); err != nil {
				fmt.Fprintf(os.Stderr, "counters could not be written to %s: %v\n", path, err)
				continue
			}
			last = current
		}
	}
}

// certReloader serves the current certificate from disk.
//
// Certificates now last a matter of weeks and are renewed by a timer. A
// process that reads the files once at startup goes on presenting an expired
// certificate until somebody notices, so the files are re-read when they
// change on disk.
type certReloader struct {
	certPath string
	keyPath  string

	mu       sync.RWMutex
	cert     *tls.Certificate
	certMod  time.Time
	keyMod   time.Time
	lastStat time.Time
}

// statInterval bounds how often the files are checked, so a busy server does
// not stat twice per handshake.
const statInterval = 30 * time.Second

func newCertReloader(certPath, keyPath string) (*certReloader, error) {
	r := &certReloader{certPath: certPath, keyPath: keyPath}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	cert, last := r.cert, r.lastStat
	r.mu.RUnlock()

	if time.Since(last) < statInterval {
		return cert, nil
	}

	if changed, err := r.changed(); err == nil && changed {
		// A failed reload leaves the previous certificate in place. Serving a
		// certificate that worked a moment ago beats refusing every
		// handshake because a renewal wrote a partial file.
		_ = r.reload()
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

func (r *certReloader) changed() (bool, error) {
	certInfo, err := os.Stat(r.certPath)
	if err != nil {
		return false, err
	}
	keyInfo, err := os.Stat(r.keyPath)
	if err != nil {
		return false, err
	}

	r.mu.Lock()
	r.lastStat = time.Now()
	same := certInfo.ModTime().Equal(r.certMod) && keyInfo.ModTime().Equal(r.keyMod)
	r.mu.Unlock()

	return !same, nil
}

func (r *certReloader) reload() error {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("reading %s and %s: %w", r.certPath, r.keyPath, err)
	}

	certInfo, err := os.Stat(r.certPath)
	if err != nil {
		return err
	}
	keyInfo, err := os.Stat(r.keyPath)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.cert = &cert
	r.certMod = certInfo.ModTime()
	r.keyMod = keyInfo.ModTime()
	r.lastStat = time.Now()
	return nil
}
