package markup

import "testing"

// An address is read the way a browser resolves it, not as the text reads.
//
// Every case here is an address a browser fetches over plaintext, and before the
// 2026-09-16 audit (A17) each was read as a relative address on the page's own
// origin — nothing to report.
func TestAnAddressIsReadAsABrowserResolvesIt(t *testing.T) {
	for name, src := range map[string]string{
		"a decimal character reference": `http&#58;//cdn.example/a.js`,
		"a hex character reference":     `http&#x3A;//cdn.example/a.js`,
		"a named character reference":   `http&colon;//cdn.example/a.js`,
		"an encoded scheme":             `&#104;ttp://cdn.example/a.js`,
		"a newline in the scheme":       "ht\ntp://cdn.example/a.js",
		"a tab after the colon":         "http:\t//cdn.example/a.js",
		"backslashes":                   `http:\\cdn.example\a.js`,
		"one slash":                     `http:/cdn.example/a.js`,
		"no slash":                      `http:cdn.example/a.js`,
		"three slashes":                 `http:///cdn.example/a.js`,
		"leading space and controls":    "\x01 http://cdn.example/a.js",
	} {
		f := read(t, `<script src="`+src+`"></script>`)
		if len(f.References) != 1 {
			t.Errorf("%s: %+v", name, f.References)
			continue
		}
		if r := f.References[0]; r.Host != "cdn.example" || !r.Plaintext || !r.Blocking {
			t.Errorf("%s: read as %+v, want a blocked plaintext script from cdn.example", name, r)
		}
	}

	// The same forms over TLS are another origin and nothing more.
	for name, src := range map[string]string{
		"https with backslashes":   `https:\\cdn.example\a.js`,
		"scheme-relative with one": `\/cdn.example/a.js`,
		"a named reference":        `https&colon;//cdn.example/a.js`,
	} {
		f := read(t, `<script src="`+src+`"></script>`)
		if len(f.References) != 1 || f.References[0].Plaintext || !f.References[0].ThirdParty ||
			f.References[0].Host != "cdn.example" {
			t.Errorf("%s: %+v", name, f.References)
		}
	}

	// And what fetches nothing still records nothing.
	for _, src := range []string{"", "   ", "https:app.js", "app.js", "/app.js", "javascript:alert(1)",
		"data:text/javascript,1", "about:blank", "&#106;avascript:x"} {
		if f := read(t, `<script src="`+src+`"></script>`); len(f.References) != 0 {
			t.Errorf("%q recorded %+v", src, f.References)
		}
	}
}

// A base element moves every relative address after it.
func TestABaseElementMovesRelativeAddresses(t *testing.T) {
	f := read(t, `
		<script src="before.js"></script>
		<base href="http://cdn.example/assets/">
		<base href="https://ignored.example/">
		<script src="app.js"></script>
		<img src="//images.example/logo.png">
	`)
	if !has(f, KindScript, "cdn.example") {
		t.Errorf("a relative script after a plaintext base is not a plaintext script: %+v", f.References)
	}
	for _, r := range f.References {
		if r.Host == "cdn.example" && (!r.Plaintext || !r.Blocking) {
			t.Errorf("the plaintext base did not make its script plaintext: %+v", r)
		}
		if r.Host == "ignored.example" {
			t.Errorf("a second base element was used: %+v", r)
		}
		if r.Host == "images.example" && !r.Plaintext {
			t.Errorf("a scheme-relative address did not take the base's scheme: %+v", r)
		}
	}
	if len(f.References) != 2 {
		t.Errorf("want the script and the image, and nothing from before the base: %+v", f.References)
	}

	// A base on the page's own origin, or a relative one, moves nothing
	// anywhere a rule asks about.
	for _, href := range []string{"/assets/", "https://site.example/assets/", "assets/", ""} {
		if f := read(t, `<base href="`+href+`"><script src="app.js"></script>`); len(f.References) != 0 {
			t.Errorf("base %q: %+v", href, f.References)
		}
	}

	// A base without an href is not the one that counts.
	f = read(t, `<base target="_top"><base href="https://cdn.example/"><script src="app.js"></script>`)
	if !has(f, KindScript, "cdn.example") {
		t.Errorf("a base without an href took the place of the one with it: %+v", f.References)
	}
}

// Another port on the page's own host is another origin.
func TestAnotherPortIsAnotherOrigin(t *testing.T) {
	f := read(t, `<script src="https://site.example:8443/a.js"></script>`)
	if len(f.References) != 1 || !f.References[0].ThirdParty {
		t.Errorf("another port on the page's host is not another origin: %+v", f.References)
	}
	for _, src := range []string{"https://site.example:443/a.js", "https://site.example:0443/a.js",
		"https://SITE.example./a.js", "https://site.example:/a.js"} {
		if f := read(t, `<script src="`+src+`"></script>`); len(f.References) != 0 {
			t.Errorf("%q, the page's own origin, recorded %+v", src, f.References)
		}
	}
	if f := read(t, `<img src="http://site.example:80/a.png">`); len(f.References) != 1 ||
		f.References[0].ThirdParty != true || !f.References[0].Plaintext {
		t.Errorf("plaintext on the page's host is another origin and plaintext: %+v", f.References)
	}
}

// Every address in a srcset is fetched by somebody's browser.
func TestEveryAddressInASrcsetIsRead(t *testing.T) {
	f := read(t, `
		<img src="logo.png" srcset="http://a.example/1x.png 1x, http://b.example/2x.png 2x">
		<picture><source srcset="https://c.example/w.webp 480w,
			data:image/png;base64,iVBOR 1x"></picture>
	`)
	for _, h := range []string{"a.example", "b.example"} {
		if !has(f, KindImage, h) {
			t.Errorf("%s in a srcset was not read: %+v", h, f.References)
		}
	}
	if !has(f, KindImage, "c.example") {
		t.Errorf("a source's srcset was not read: %+v", f.References)
	}
	if len(f.References) != 3 {
		t.Errorf("want three references, and nothing out of a data address: %+v", f.References)
	}
	for _, r := range f.References {
		if r.Blocking {
			t.Errorf("an image is blocking: %+v", r)
		}
	}
}

// A control's formaction is where that control submits.
func TestAFormActionOnAControlIsAFormAction(t *testing.T) {
	f := read(t, `<form action="/save">
		<button formaction="http://forms.example/save">Save</button>
		<input type="submit" formaction="https://other.example/x">
		<input name="q">
	</form>`)
	if !has(f, KindForm, "forms.example") || !has(f, KindForm, "other.example") {
		t.Errorf("formaction was not read: %+v", f.References)
	}
	if len(f.References) != 2 {
		t.Errorf("%+v", f.References)
	}
}

// rel is a list of words.
func TestAStylesheetAmongOtherRelationsIsAStylesheet(t *testing.T) {
	f := read(t, `<link rel="preload stylesheet" href="http://cdn.example/a.css">
		<link rel=" Alternate  STYLESHEET " href="http://alt.example/a.css">
		<link rel="dns-prefetch preconnect" href="http://hint.example/">`)
	if !has(f, KindStyle, "cdn.example") || !has(f, KindStyle, "alt.example") {
		t.Errorf("a stylesheet among other relations was missed: %+v", f.References)
	}
	if hasHost(f, "hint.example") {
		t.Errorf("a hint was read as a fetch: %+v", f.References)
	}
}

// An empty address fetches nothing, wherever the base points.
func TestAnEmptyAddressIsNotABaseReference(t *testing.T) {
	f := read(t, `<base href="http://cdn.example/"><script src=""></script><img src="  "><iframe src="&#32;"></iframe>`)
	if len(f.References) != 0 {
		t.Errorf("an empty address was read as the base: %+v", f.References)
	}
}
