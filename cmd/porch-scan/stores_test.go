package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/certinfo"
	"github.com/denyfirst/porch/internal/scan"
)

// The certificate block prints the stores line certinfo wrote, as it wrote it.
//
// The page reads the same field, so the two faces of a report say the same thing
// about which clients accept a chain (R16).
func TestTheReportPrintsTheStoresLine(t *testing.T) {
	line := "trusted by Mozilla, Chrome, Microsoft and Apple (stores of 2026-09-14)"
	r := result{Result: &scan.Result{Certificate: &certinfo.Report{
		Chain:      []certinfo.Certificate{{}},
		Trusted:    true,
		StoresLine: line,
	}}}

	var buf bytes.Buffer
	printCertificate(&buf, r)
	flat := strings.Join(strings.Fields(buf.String()), " ")
	if !strings.Contains(flat, "Stores "+line) {
		t.Errorf("the certificate block does not carry the stores line:\n%s", buf.String())
	}
}
