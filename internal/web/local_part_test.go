package web

import (
	"strings"
	"testing"
)

// A mail address never leaves the browser whole.
//
// Every check's request goes through check(), so the local part is dropped
// there, before the body is built (audit A32). Read from the source: nothing in
// this repository runs the script, and a check that the reduction exists and
// precedes the request is the claim the privacy page makes.
func TestThePageSendsOnlyTheDomainOfAnAddress(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	fn := strings.Index(src, "function domainOnly(target) {")
	if fn < 0 {
		t.Fatal("the page has no domainOnly")
	}
	if !strings.Contains(src[fn:], `const at = target.lastIndexOf("@");`) ||
		!strings.Contains(src[fn:], "target.slice(at + 1)") {
		t.Error("domainOnly does not cut at the last @")
	}

	start := strings.Index(src, "async function check(target, spec) {")
	if start < 0 {
		t.Fatal("the page has no check()")
	}
	reduce := strings.Index(src[start:], "target = domainOnly(target);")
	send := strings.Index(src[start:], "fetch(spec.endpoint")
	if reduce < 0 || send < 0 || reduce > send {
		t.Error("check() sends the target before reducing it to a domain")
	}
}
