package web

import (
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/demo"
)

// The lens over the front page is decoration, and behaves like it.
//
// It reads the pointer and writes two properties; it asks nothing of any
// server and keeps nothing. It stands down for a reader who asked for less
// motion and on a screen with no hovering pointer, and what it reveals is
// hidden from assistive technology, because it is texture rather than text.
func TestTheHeroLensIsDecorationAndNothingMore(t *testing.T) {
	src, err := assets.ReadFile("assets/hero.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	for _, want := range []string{
		`"(hover: hover) and (pointer: fine)"`,
		`"(prefers-reduced-motion: reduce)"`,
		`lens.style.setProperty("--lens-x", x + "px");`,
		`hero.classList.remove("hero-lit")`,
		"window.requestAnimationFrame(",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("hero.js no longer contains %q", want)
		}
	}
	for _, never := range []string{"fetch(", "XMLHttpRequest", "sendBeacon", "localStorage", "sessionStorage", "document.cookie", "innerHTML", "setAttribute(\"style\""} {
		if strings.Contains(js, never) {
			t.Errorf("hero.js contains %q, and decoration has no business doing so", never)
		}
	}
	if w := get(t, "/hero.js"); w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
		t.Errorf("/hero.js is not served as a script: %d", w.Code)
	}

	css, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"@property --lens-r {",
		"initial-value: 0px;",
		".hero-lit .hero-lens { --lens-r: 15rem; }",
		"pointer-events: none;",
	} {
		if !strings.Contains(string(css), want) {
			t.Errorf("style.css no longer contains %q", want)
		}
	}

	// Only the front page carries it.
	for path, body := range rendered {
		carries := strings.Contains(string(body), `<script src="/hero.js" defer></script>`)
		front := demo.Enabled && path == "/"
		if carries != front {
			t.Errorf("%s: loads hero.js %v, want %v", path, carries, front)
		}
		if front && !strings.Contains(string(body), `<div class="hero-lens" aria-hidden="true">`) {
			t.Errorf("the lens is missing, or read aloud")
		}
	}
}
