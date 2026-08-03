package main

import (
	"strings"
	"testing"
)

func TestWrapBreaksOnWords(t *testing.T) {
	const text = "The session key is derived from a long-term key, so anyone who later " +
		"obtains the server's private key can decrypt traffic captured months earlier."

	got := wrap(text, 40, "  ")

	for _, line := range strings.Split(got, "\n") {
		if len(strings.TrimSpace(line)) > 40 {
			t.Errorf("line exceeds the requested width: %q", line)
		}
	}

	// Wrapping must not lose or reorder words.
	if strings.Join(strings.Fields(got), " ") != strings.Join(strings.Fields(text), " ") {
		t.Error("wrap changed the text")
	}
}

func TestWrapHandlesEmptyInput(t *testing.T) {
	if got := wrap("", 40, "  "); got != "" {
		t.Errorf("wrap(\"\") = %q, want empty", got)
	}
}
