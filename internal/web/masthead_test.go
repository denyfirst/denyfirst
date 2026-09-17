package web

import (
	"strings"
	"testing"
)

// The header names the tool and nothing else; the maker is in the footer.
//
// The header carried the denyfirst wordmark and slogan beside the console's own
// "porch", two names for one thing on the first screen of an installation.
func TestTheHeaderNamesTheToolAndTheFooterTheMaker(t *testing.T) {
	for path := range pages {
		body := get(t, path).Body.String()

		head, rest, ok := strings.Cut(body, "</header>")
		if !ok {
			t.Fatalf("%s has no header", path)
		}
		head = head[strings.Index(head, `<header class="masthead">`):]
		if !strings.Contains(head, `<a class="wordmark" href="/">`+ToolName+`</a>`) {
			t.Errorf("%s: the header does not name %s:\n%s", path, ToolName, head)
		}
		if strings.Contains(strings.ToLower(head), "denyfirst") || strings.Contains(head, "Records nothing") {
			t.Errorf("%s: the header still carries the maker:\n%s", path, head)
		}

		_, foot, ok := strings.Cut(rest, `<footer class="colophon">`)
		if !ok || !strings.Contains(foot, ToolName+`, by <span class="colophon-brand">denyfirst</span>`) {
			t.Errorf("%s: the footer does not name the maker", path)
		}
	}
}
