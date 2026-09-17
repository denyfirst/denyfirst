package main

import (
	"strings"
	"testing"
)

// The service takes an EHLO name, checks it before serving, and hands it on.
//
// Read from the source for the reason the trust store test is: run() parses
// flags and binds a port (audit A26).
func TestTheEHLONameIsCheckedAndReachesTheService(t *testing.T) {
	source := repoFile(t, "cmd/porchd/main.go")

	for _, want := range []string{`flag.String("helo"`, "smtptls.CheckHeloName(*heloName)", "api.UseHeloName(*heloName)"} {
		if !strings.Contains(source, want) {
			t.Errorf("run() does not contain %s", want)
		}
	}
	check := strings.Index(source, "smtptls.CheckHeloName(")
	serve := strings.Index(source, "ListenAndServe")
	if serve >= 0 && check > serve {
		t.Error("the EHLO name is checked after the service is already answering")
	}
}
