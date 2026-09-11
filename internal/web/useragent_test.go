package web

import (
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/challenge"
	"github.com/denyfirst/denyfirst/internal/crl"
	"github.com/denyfirst/denyfirst/internal/ctsearch"
	"github.com/denyfirst/denyfirst/internal/webprobe"
)

// Every request this project makes to a stranger names the tool that made it.
//
// The user agent is the one string an administrator has when a scan turns up in
// their access log, and N7 rests on it: a probe that identifies itself is one
// they can make a decision about, where an anonymous one is one they can only
// be alarmed by. That only works if the name is the instrument's.
//
// It says "porch" rather than "denyfirst" since 2026-09-12. denyfirst is the
// brand this is published under and it will carry more than one product; a log
// line naming the brand tells an administrator which company reached them and
// not which tool, which is the wrong half of the answer when they are trying to
// work out what was sent.
//
// Four strings, one identity, and a sabotage putting the brand back escaped
// every test in this repository. This is that test.
func TestEveryRequestThisProjectMakesNamesTheTool(t *testing.T) {
	for _, tc := range []struct {
		what string
		sent string
	}{
		{"the web probe", webprobe.DefaultUserAgent},
		{"the revocation list fetch", crl.UserAgent},
		{"the transparency log search", ctsearch.UserAgent},
		{"the verification file fetch", challenge.UserAgent},
	} {
		if !strings.HasPrefix(tc.sent, ToolName+"/") {
			t.Errorf("%s identifies itself as %q, which does not begin with %q. An administrator "+
				"reading it should learn which tool reached them.", tc.what, tc.sent, ToolName)
		}

		// And it still points at a page on this site, which is the other half
		// of the promise. Checked in full by
		// TestEveryAddressThisProjectSendsOutResolves; named here so a change
		// that dropped the address fails beside the one that dropped the name.
		if !strings.Contains(tc.sent, "https://denyfirst.dev/") {
			t.Errorf("%s names no page explaining what it sends: %q", tc.what, tc.sent)
		}
	}
}
