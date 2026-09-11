package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/scan"
)

// Every path this service answers is mounted by the binary that serves it.
//
// cmd/porchd routes the API and the pages separately, because they need
// different security headers and one policy for both would mean the API
// inherits permission it never needed. That separation means the mount has to
// name each API path — and a second hand-written list is a list that falls
// behind.
//
// One did. /api/v1/mail/scan was registered here, tested here, and answered
// "Only GET and HEAD are served here" in the actual binary, because the page
// handler caught it: main.go had never heard of the path. Every test in this
// package passed. The first thing that noticed was a curl.
//
// Paths() is now the one list and main.go ranges over it. This test says so, by
// reading the file rather than by trusting it.
func TestEveryPathThisServiceAnswersIsMounted(t *testing.T) {
	s := New(offlineScanner(), Limits{}, nil)

	paths := s.Paths()
	if len(paths) == 0 {
		t.Fatal("this service answers no paths, so this test is checking nothing")
	}
	for _, want := range []string{
		"/api/v1/scan", "/api/v1/tls/scan", "/api/v1/web/scan", "/api/v1/mail/scan",
		"/api/v1/stats", "/healthz",
	} {
		found := false
		for _, got := range paths {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not among the paths this service reports answering: %v", want, paths)
		}
	}

	body, err := os.ReadFile("../../cmd/porchd/main.go")
	if err != nil {
		t.Fatalf("reading the binary that mounts this: %v", err)
	}
	if !strings.Contains(string(body), "api.Paths()") {
		t.Error("cmd/porchd no longer mounts the API from Paths(). Whatever it lists instead " +
			"is a second list, and the last one fell behind by an entire endpoint.")
	}
}

// And every path actually answers when it is asked.
//
// Paths() saying a path exists is not the same as the mux serving it. A typo in
// the table would put a path in the list and register it under a name nothing
// reaches, which is the same silence with a different cause.
func TestEveryMountedPathAnswers(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000}, nil)

	for _, rt := range s.routes {
		var body *strings.Reader
		if rt.method == http.MethodPost {
			body = strings.NewReader(`{"target":"example.test"}`)
		} else {
			body = strings.NewReader("")
		}

		r := httptest.NewRequest(rt.method, rt.path, body)
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "203.0.113.77:5000"

		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)

		if w.Code == http.StatusNotFound || w.Code == http.StatusMethodNotAllowed {
			t.Errorf("%s %s answered %d, so it is listed and not served", rt.method, rt.path, w.Code)
		}
	}
}

// The mail check has an address, and it takes a domain.
func TestTheMailCheckAnswersOnItsOwnAddress(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000}, nil)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/mail/scan",
		strings.NewReader(`{"target":"example.test:25"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "203.0.113.78:5000"

	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	if got := errorCode(t, w); got != "port_not_accepted" {
		t.Errorf("a port on a mail target was refused with %q, want port_not_accepted", got)
	}

	// An address has no zone under it to hold any of these records.
	r = httptest.NewRequest(http.MethodPost, "/api/v1/mail/scan",
		strings.NewReader(`{"target":"93.184.216.34"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "203.0.113.79:5000"

	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)

	if got := errorCode(t, w); got != "hostname_required" {
		t.Errorf("an address was refused with %q, want hostname_required", got)
	}
}

// A service built with no resolver does not crash on a mail scan.
//
// A nil *dnsclient.Client assigned to mailscan's interface field produces an
// interface that is not nil, so "nil means build a default one" never fires and
// the first lookup dereferences nothing. It panicked on the first real request
// to this endpoint on 2026-09-11 while every test in this package passed,
// because every fixture here supplies a resolver.
//
// So this one deliberately does not. New(&scan.Scanner{}, ...) is what
// porchd does when nobody passed -resolver, which is the ordinary case.
func TestAServiceWithNoResolverDoesNotCrashOnAMailScan(t *testing.T) {
	s := New(&scan.Scanner{}, Limits{Burst: 1000}, nil)

	if s.mail.Resolver != nil {
		t.Errorf("the mail scanner holds a %T rather than nothing. A typed nil in an interface "+
			"field is not nil, and mailscan's default never fires.", s.mail.Resolver)
	}

	r := httptest.NewRequest(http.MethodPost, "/api/v1/mail/scan",
		strings.NewReader(`{"target":"example.test"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "203.0.113.91:5000"

	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	// Whatever the answer is, there has to be one. A panic reaches a client as
	// an empty reply, which is indistinguishable from the service being down.
	if w.Code == 0 || w.Body.Len() == 0 {
		t.Fatalf("no answer: status %d, %d bytes", w.Code, w.Body.Len())
	}
}
