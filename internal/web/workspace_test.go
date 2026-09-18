package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// An installation is a workspace: four parts, each an address, and the rail
// says which one a page is.
//
// The rail is links rather than tabs drawn by the script, so every part works
// without it and can be bookmarked, and the current one is said to assistive
// technology with aria-current as well as drawn. The demonstration is a site
// and has none of this.
func TestAnInstallationIsAWorkspaceOfFourParts(t *testing.T) {
	parts := map[string]string{
		"/":             "New check",
		"/domains":      "Domains",
		"/history":      "History",
		"/installation": "This installation",
	}
	for path, name := range parts {
		w := get(t, path)
		if demo.Enabled {
			if path != "/" && w.Code != http.StatusNotFound {
				t.Errorf("%s answered %d on the demonstration, which has no workspace", path, w.Code)
			}
			continue
		}
		if w.Code != http.StatusOK {
			t.Errorf("%s answered %d", path, w.Code)
			continue
		}
		body := w.Body.String()
		rail, _, _ := strings.Cut(body, "<main>")

		// Every part is in the rail, and only this one is current.
		for other := range parts {
			if !strings.Contains(rail, `<a class="rail-item" href="`+other+`"`) {
				t.Errorf("%s: the rail does not lead to %s", path, other)
			}
		}
		if n := strings.Count(rail, `aria-current="page"`); n != 1 {
			t.Errorf("%s: %d rail items are marked current, want one", path, n)
		}
		if !strings.Contains(rail, `href="`+path+`" aria-current="page">`) {
			t.Errorf("%s: the rail does not mark this page as current", path)
		}
		if !strings.Contains(rail, "<strong>"+name+"</strong>") {
			t.Errorf("%s: the top bar does not name the page %q", path, name)
		}
		if !strings.Contains(body, "<h1>"+name+"</h1>") {
			t.Errorf("%s: the page is not headed %q", path, name)
		}
	}
}

// A document is in the workspace's reference section, named by its own
// title without the maker.
func TestADocumentIsNamedInTheTopBarWithoutTheMaker(t *testing.T) {
	if demo.Enabled {
		t.Skip("the demonstration has no top bar")
	}
	for path, want := range map[string]string{
		"/privacy": "Privacy, and what a scan does",
		"/docs":    "Documentation",
		"/tls":     "check what a server actually negotiates",
	} {
		body := get(t, path).Body.String()
		rail, _, _ := strings.Cut(body, "<main>")
		_, rail, _ = strings.Cut(rail, "<body")
		if !strings.Contains(rail, "<span>Reference</span>") || !strings.Contains(rail, "<strong>"+want+"</strong>") {
			t.Errorf("%s: the top bar does not read Reference / %s", path, want)
		}
		if strings.Contains(strings.ToLower(rail), "denyfirst") {
			t.Errorf("%s: the rail or top bar names the maker", path)
		}
	}
}
