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
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/denyfirst/denyfirst/internal/httpapi"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/scan"
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
	// safedial and enforces the port allow list, and there is no flag here
	// that would turn either off.
	api := httpapi.New(&scan.Scanner{}, limits, nil)

	srv := &http.Server{
		Addr:    *listen,
		Handler: api,

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
			NextProtos: []string{"h2", "http/1.1"},
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		if *tlsCert != "" {
			// The paths are already in TLSConfig.GetCertificate.
			errc <- srv.ListenAndServeTLS("", "")
			return
		}
		errc <- srv.ListenAndServe()
	}()

	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
	}
	// The only line this process ever prints. It names the service, not a
	// request.
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

	if err := srv.Shutdown(shutdownCtx); err != nil {
		// Forcing the close loses in-flight responses, which is the point of
		// reporting it rather than exiting quietly.
		fmt.Fprintf(os.Stderr, "shutdown did not complete within %s: %v\n", shutdownGrace, err)
		_ = srv.Close()
		return 1
	}

	fmt.Fprintln(os.Stderr, "denyfirstd stopped")
	return 0
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
