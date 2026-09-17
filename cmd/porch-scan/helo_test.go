package main

import (
	"os"
	"strings"
	"testing"
)

// A -helo that would not be sent is refused before anything is dialled, rather
// than replaced by this machine's own name (audit A26).
func TestAnUnusableEHLONameStopsTheCommand(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	check := strings.Index(src, "smtptls.CheckHeloName(*heloName)")
	if check < 0 {
		t.Fatal("run() does not check -helo")
	}
	if run := strings.Index(src, "runMail(ctx"); run >= 0 && check > run {
		t.Error("-helo is checked after the mail check has started")
	}
}
