package web

import (
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// The header names what the site is, and the footer who makes it.
//
// An installation somebody runs is porch: the header says porch and the footer
// says it is by denyfirst, because two names on the first screen of a tool is
// one too many. The demonstration is the denyfirst site, and carries the
// wordmark.
func TestTheHeaderNamesTheToolAndTheFooterTheMaker(t *testing.T) {
	for path := range pages {
		body := get(t, path).Body.String()

		// What comes before the page: the masthead on the demonstration, the
		// rail and top bar on an installation.
		head, rest, ok := strings.Cut(body, "<main>")
		if !ok {
			t.Fatalf("%s has no main", path)
		}
		_, head, _ = strings.Cut(head, "<body")
		_, foot, ok := strings.Cut(rest, `<footer class="colophon">`)
		if !ok {
			t.Fatalf("%s has no footer", path)
		}

		if demo.Enabled {
			if !strings.Contains(head, `<span class="wordmark-deny">deny</span>first.</a>`) {
				t.Errorf("%s: the demonstration's header does not carry the wordmark:\n%s", path, head)
			}
			if !strings.Contains(foot, `<span class="colophon-brand"><span class="wordmark-deny">deny</span>first.</span>`) {
				t.Errorf("%s: the demonstration's footer does not name denyfirst", path)
			}
			continue
		}

		if !strings.Contains(head, `<a class="wordmark" href="/">`+ToolName+`</a>`) {
			t.Errorf("%s: the header does not name %s:\n%s", path, ToolName, head)
		}
		if strings.Contains(strings.ToLower(head), "denyfirst") || strings.Contains(head, "Records nothing") {
			t.Errorf("%s: the header still carries the maker:\n%s", path, head)
		}
		if !strings.Contains(foot, `<p class="colophon-line">by <span class="colophon-brand"><span class="wordmark-deny">deny</span>first.</span>`) {
			t.Errorf("%s: the footer does not name the maker", path)
		}
	}
}

// Every page can switch its colour scheme, and the switch is only shown where
// the script that makes it work has loaded.
func TestEveryPageCanSwitchItsColourScheme(t *testing.T) {
	for path := range pages {
		body := get(t, path).Body.String()
		head, _, _ := strings.Cut(body, "</head>")
		if !strings.Contains(head, `<script src="/theme.js"></script>`) {
			t.Errorf("%s does not load theme.js before it is drawn", path)
		}
		if !strings.Contains(body, `<button class="theme-toggle" id="theme-toggle" type="button" hidden>`) {
			t.Errorf("%s has no switch, or shows it before the script can work it", path)
		}
	}
	if w := get(t, "/theme.js"); w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
		t.Errorf("/theme.js is not served as a script: %d %s", w.Code, w.Header().Get("Content-Type"))
	}

	src, err := assets.ReadFile("assets/theme.js")
	if err != nil {
		t.Fatal(err)
	}
	// It remembers one of two words and reads nothing else.
	for _, want := range []string{`const KEY = "theme";`, `value === "light" || value === "dark"`, `root.dataset.theme = next;`} {
		if !strings.Contains(string(src), want) {
			t.Errorf("theme.js no longer contains %q", want)
		}
	}
	for _, never := range []string{"fetch(", "XMLHttpRequest", "innerHTML", "document.cookie", "sendBeacon"} {
		if strings.Contains(string(src), never) {
			t.Errorf("theme.js contains %q, and it has no business doing so", never)
		}
	}
}
