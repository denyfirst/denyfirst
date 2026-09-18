//go:build !demo

package web

import (
	"strings"
	"testing"
)

// Domains offers to add one only where proof is required. Where it is not,
// there is nothing to prove, and a form asking for a record would send an
// operator to publish one that changes nothing.
func TestDomainsOffersAProofOnlyWhereOneIsRequired(t *testing.T) {
	proved := workspaceWith(t, "/domains", true, false)
	if !strings.Contains(proved, `id="domain-form"`) || !strings.Contains(proved, ">Add domain</button>") {
		t.Error("an installation that requires proof offers no way to add a domain")
	}
	open := workspaceWith(t, "/domains", false, false)
	if strings.Contains(open, `id="domain-form"`) {
		t.Error("an installation that requires no proof asks for one")
	}
	if !strings.Contains(open, "No proof of control is required here") {
		t.Error("an installation that requires no proof does not say why there is nothing to add")
	}
}

// The privacy page says where the clipboard is written, because it is.
func TestThePrivacyPageSaysWhatIsCopied(t *testing.T) {
	page := workspaceWith(t, "/privacy", true, false)
	if strings.Contains(page, "Nothing is written to the clipboard") {
		t.Error("the privacy page says nothing is copied, and the Copy button beside a record copies it")
	}
	if !strings.Contains(page, "A report is never put there") {
		t.Error("the privacy page does not say a report stays out of the clipboard")
	}
}
