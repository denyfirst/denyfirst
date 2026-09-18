package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"
)

type keptReport struct {
	check, target, verdict, policy string
	report                         []byte
}

type fakeKeeper struct {
	kept []keptReport
	err  error
}

func (k *fakeKeeper) Keep(check, target, verdict, policy string, report []byte) error {
	k.kept = append(k.kept, keptReport{check, target, verdict, policy, report})
	return k.err
}

// Every report answered is kept whole, where a keeper was given: the same
// bytes the caller received, under the check and the target it was about.
func TestEveryReportAnsweredIsKeptWhole(t *testing.T) {
	k := &fakeKeeper{}
	s := webServer(t, offlineWebScanner())
	s.KeepReports(k)

	w := postWeb(t, s, `{"target":"kept.test"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	if len(k.kept) != 1 {
		t.Fatalf("%d reports kept for one answered", len(k.kept))
	}
	got := k.kept[0]
	if got.check != "web" || got.target != "kept.test" || got.policy != "porch-web-v3" {
		t.Errorf("the report was kept under %s %s %q %s", got.check, got.target, got.verdict, got.policy)
	}
	if !bytes.Equal(bytes.TrimSpace(got.report), bytes.TrimSpace(w.Body.Bytes())) {
		t.Errorf("what was kept is not what was answered:\nkept:     %s\nanswered: %s", got.report, w.Body.String())
	}
}

// A report that could not be kept is still answered, and the failure is said
// in the log without the target, as a result not kept always was.
func TestAReportNotKeptIsStillAnswered(t *testing.T) {
	var said bytes.Buffer
	previous := notKeptLog
	notKeptLog = &said
	t.Cleanup(func() { notKeptLog = previous })

	s := webServer(t, offlineWebScanner())
	s.KeepReports(&fakeKeeper{err: errors.New("nothing can be kept or read until somebody signs in")})

	w := postWeb(t, s, `{"target":"secret-internal-name.test"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("a failure to keep turned into %d", w.Code)
	}
	if !strings.HasPrefix(said.String(), "a result was not kept") || strings.Contains(said.String(), "secret-internal-name") {
		t.Errorf("the failure was not said, or said with the target: %q", said.String())
	}
}

// Without a keeper nothing is kept, which is the default and the promise.
func TestWithoutAKeeperNothingIsKept(t *testing.T) {
	s := webServer(t, offlineWebScanner())
	if s.keeper != nil {
		t.Fatal("a service keeps reports without being told to")
	}
	if w := postWeb(t, s, `{"target":"kept.test"}`); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
}

// A kept report is listed under the name as typed: the port only where it is
// not the one the check assumes, and never the filename separator the old
// results store needed.
func TestAKeptReportIsListedUnderTheNameAsTyped(t *testing.T) {
	for _, tc := range []struct {
		target target
		want   string
	}{
		{target{host: "example.com"}, "example.com"},
		{target{host: "example.com", port: "443"}, "example.com"},
		{target{host: "example.com", port: "8443"}, "example.com:8443"},
	} {
		if got := tc.target.displayName(); got != tc.want {
			t.Errorf("%+v is listed as %q, want %q", tc.target, got, tc.want)
		}
	}
}
